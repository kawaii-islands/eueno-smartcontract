use std::{
    fs::OpenOptions,
    io::{BufReader, Read, Seek, Write},
    path::Path,
};

use crate::{
    add_piece, clear_cache, generate_piece_commitment, get_seal_inputs, seal_commit_phase1,
    seal_commit_phase2, seal_pre_commit_phase1, seal_pre_commit_phase2,
    types::{
        Commitment, PaddedBytesAmount, PieceInfo, PoRepConfig, ProverId, SealCommitOutput,
        SealPreCommitOutput, SealPreCommitPhase1Output, UnpaddedBytesAmount, Ticket,
    },
    validate_cache_for_commit, validate_cache_for_precommit_phase2, verify_seal,
};
use anyhow::{ensure, Result};
use blstrs::Scalar as Fr;

use proofs_core::{api_version::ApiVersion, merkle::MerkleTreeTrait, sector::SectorId};
use rand::{Rng, RngCore};

use tempfile::{tempdir, NamedTempFile, TempDir};

fn generate_piece_file(path: &Path, sector_size: u64) -> Result<NamedTempFile> {
    let file = OpenOptions::new().read(true).open(path)?;
    let mut reader = BufReader::new(file);
    let mut buf: Vec<u8> = Vec::new();

    reader.read_to_end(&mut buf)?;

    let number_of_bytes_in_piece = UnpaddedBytesAmount::from(PaddedBytesAmount(sector_size));
    buf.resize(number_of_bytes_in_piece.0 as usize, 0);

    let mut piece_file = NamedTempFile::new()?;
    piece_file.write_all(&buf)?;
    piece_file.as_file_mut().sync_all()?;
    piece_file.as_file_mut().rewind()?;

    Ok(piece_file)
}

pub fn porep_config(sector_size: u64, porep_id: [u8; 32], api_version: ApiVersion) -> PoRepConfig {
    PoRepConfig::new_groth16(sector_size, porep_id, api_version)
}

fn run_seal_pre_commit_phase1<Tree: 'static + MerkleTreeTrait>(
    config: &PoRepConfig,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: [u8; 32],
    cache_dir: &TempDir,
    mut piece_file: &mut NamedTempFile,
    sealed_sector_file: &NamedTempFile,
) -> Result<(Vec<PieceInfo>, SealPreCommitPhase1Output<Tree>)> {
    let number_of_bytes_in_piece = config.unpadded_bytes_amount();

    let piece_info = generate_piece_commitment(piece_file.as_file_mut(), number_of_bytes_in_piece)?;
    piece_file.as_file_mut().rewind()?;

    let mut staged_sector_file = NamedTempFile::new()?;
    add_piece(
        &mut piece_file,
        &mut staged_sector_file,
        number_of_bytes_in_piece,
        &[],
    )?;

    let piece_infos = vec![piece_info];

    let phase1_output = seal_pre_commit_phase1::<_, _, _, Tree>(
        config,
        cache_dir.path(),
        staged_sector_file.path(),
        sealed_sector_file.path(),
        prover_id,
        sector_id,
        ticket,
        &piece_infos,
    )?;

    validate_cache_for_precommit_phase2(
        cache_dir.path(),
        staged_sector_file.path(),
        &phase1_output,
    )?;

    Ok((piece_infos, phase1_output))
}

#[allow(clippy::too_many_arguments)]
fn generate_proof<Tree: 'static + MerkleTreeTrait, R: RngCore>(
    config: &PoRepConfig,
    cache_dir_path: &Path,
    sealed_sector_file: &NamedTempFile,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: [u8; 32],
    seed: [u8; 32],
    pre_commit_output: &SealPreCommitOutput,
    piece_infos: &[PieceInfo],
    rng: Option<&mut R>,
) -> Result<(SealCommitOutput, Vec<Vec<Fr>>, [u8; 32], [u8; 32])> {
    let phase1_output = seal_commit_phase1::<_, Tree>(
        config,
        cache_dir_path,
        sealed_sector_file.path(),
        prover_id,
        sector_id,
        ticket,
        seed,
        pre_commit_output.clone(),
        piece_infos,
    )?;

    clear_cache::<Tree>(cache_dir_path)?;

    ensure!(
        seed == phase1_output.seed,
        "seed and phase1 output seed do not match"
    );
    ensure!(
        ticket == phase1_output.ticket,
        "seed and phase1 output ticket do not match"
    );

    let comm_r = phase1_output.comm_r;
    let inputs = get_seal_inputs::<Tree>(
        config,
        phase1_output.comm_r,
        phase1_output.comm_d,
        prover_id,
        sector_id,
        phase1_output.ticket,
        phase1_output.seed,
    )?;
    let result = seal_commit_phase2(config, phase1_output, prover_id, sector_id, rng)?;

    Ok((result, inputs, seed, comm_r))
}

#[allow(clippy::too_many_arguments)]
fn unseal<Tree: 'static + MerkleTreeTrait, R: RngCore>(
    config: &PoRepConfig,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: [u8; 32],
    seed: [u8; 32],
    pre_commit_output: &SealPreCommitOutput,
    commit_output: &SealCommitOutput,
    rng: Option<&mut R>,
) -> Result<()> {
    let comm_d = pre_commit_output.comm_d;
    let comm_r = pre_commit_output.comm_r;

    let verified = verify_seal::<Tree, R>(
        config,
        comm_r,
        comm_d,
        prover_id,
        sector_id,
        ticket,
        seed,
        &commit_output.proof,
        rng,
    )?;
    assert!(verified, "failed to verify valid seal");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn proof_and_unseal<Tree: 'static + MerkleTreeTrait, R: RngCore>(
    config: &PoRepConfig,
    cache_dir_path: &Path,
    sealed_sector_file: &NamedTempFile,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: [u8; 32],
    seed: [u8; 32],
    pre_commit_output: SealPreCommitOutput,
    piece_infos: &[PieceInfo],
    rng: &mut R,
) -> Result<()> {
    let (commit_output, _commit_inputs, _seed, _comm_r) = generate_proof::<Tree, R>(
        config,
        cache_dir_path,
        sealed_sector_file,
        prover_id,
        sector_id,
        ticket,
        seed,
        &pre_commit_output,
        piece_infos,
        Some(rng),
    )?;

    unseal::<Tree, R>(
        config,
        prover_id,
        sector_id,
        ticket,
        seed,
        &pre_commit_output,
        &commit_output,
        Some(rng),
    )
}

pub fn create_seal<R: Rng, Tree: 'static + MerkleTreeTrait>(
    rng: &mut R,
    sector_size: u64,
    prover_id: ProverId,
    skip_proof: bool,
    porep_id: &[u8; 32],
    api_version: ApiVersion,
    path: &Path,
) -> Result<(SectorId, NamedTempFile, Commitment, TempDir)> {
    let mut piece_file = generate_piece_file(path, sector_size)?;
    let sealed_sector_file = NamedTempFile::new()?;
    let cache_dir = tempdir().expect("failed to create temp dir");

    let config = porep_config(sector_size, *porep_id, api_version);
    let ticket = rng.gen();
    let seed = rng.gen();
    let sector_id = rng.gen::<u64>().into();

    let (piece_infos, phase1_output) = run_seal_pre_commit_phase1::<Tree>(
        &config,
        prover_id,
        sector_id,
        ticket,
        &cache_dir,
        &mut piece_file,
        &sealed_sector_file,
    )?;

    let pre_commit_output = seal_pre_commit_phase2(
        &config,
        phase1_output,
        cache_dir.path(),
        sealed_sector_file.path(),
    )?;

    let comm_r = pre_commit_output.comm_r;

    validate_cache_for_commit::<_, _, Tree>(cache_dir.path(), sealed_sector_file.path())?;

    if skip_proof {
        clear_cache::<Tree>(cache_dir.path())?;
    } else {
        proof_and_unseal::<Tree, R>(
            &config,
            cache_dir.path(),
            &sealed_sector_file,
            prover_id,
            sector_id,
            ticket,
            seed,
            pre_commit_output,
            &piece_infos,
            rng,
        )
        .expect("failed to proof_and_unseal");
    }

    Ok((sector_id, sealed_sector_file, comm_r, cache_dir))
}

pub fn seal<R: Rng, Tree: 'static + MerkleTreeTrait>(
    rng: &mut R,
    sector_size: u64,
    prover_id: ProverId,
    porep_id: &[u8; 32],
    ticket: &Ticket,
    seed: &[u8; 32],
    sector_id: SectorId,
    api_version: ApiVersion,
    path: &Path,
) -> Result<(SealPreCommitOutput, SealCommitOutput)> {
    let mut piece_file = generate_piece_file(path, sector_size)?;
    let sealed_sector_file = NamedTempFile::new()?;
    let cache_dir = tempdir().expect("failed to create temp dir");

    let config = porep_config(sector_size, *porep_id, api_version);

    let (piece_infos, phase1_output) = run_seal_pre_commit_phase1::<Tree>(
        &config,
        prover_id,
        sector_id,
        ticket.clone(),
        &cache_dir,
        &mut piece_file,
        &sealed_sector_file,
    )?;

    let pre_commit_output = seal_pre_commit_phase2(
        &config,
        phase1_output,
        cache_dir.path(),
        sealed_sector_file.path(),
    )?;

    validate_cache_for_commit::<_, _, Tree>(cache_dir.path(), sealed_sector_file.path())?;

    let (commit_output, _commit_inputs, _seed, _comm_r) = generate_proof::<Tree, R>(
        &config,
        cache_dir.path(),
        &sealed_sector_file,
        prover_id,
        sector_id,
        ticket.clone(),
        seed.clone(),
        &pre_commit_output,
        &piece_infos,
        Some(rng),
    )?;


    Ok((pre_commit_output, commit_output))
}
#[cfg(test)]
mod test {

    use std::path::Path;

    use crate::{
        constants::{DefaultTreeDomain, SectorShape2KiB, SECTOR_SIZE_2_KIB},
        file_processor::create_seal,
    };
    use anyhow::Result;
    use blstrs::Scalar as Fr;
    use ff::Field;
    use log::info;
    use proofs_core::{api_version::ApiVersion, merkle::MerkleTreeTrait, TEST_SEED};
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;

    fn seal_lifecycle<Tree: 'static + MerkleTreeTrait>(
        sector_size: u64,
        porep_id: &[u8; 32],
        api_version: ApiVersion,
        path: &Path,
    ) -> Result<()> {
        let mut rng = XorShiftRng::from_seed(TEST_SEED);
        let prover_fr: DefaultTreeDomain = Fr::random(&mut rng).into();
        let mut prover_id = [0u8; 32];
        prover_id.copy_from_slice(AsRef::<[u8]>::as_ref(&prover_fr));

        info!(
            "Creating seal proof with ApiVersion {} and PoRep ID {:?}",
            api_version, porep_id
        );
        let (_, replica, _, _) = create_seal::<_, Tree>(
            &mut rng,
            sector_size,
            prover_id,
            false,
            porep_id,
            api_version,
            path,
        )?;
        replica.close()?;

        Ok(())
    }

    // Use a fixed PoRep ID, so that the parents cache can be re-used between some tests.
    // Note however, that parents caches cannot be shared when testing the differences
    // between API v1 and v2 behaviour (since the parent caches will be different for the
    // same porep_ids).
    const ARBITRARY_POREP_ID_V1_0_0: [u8; 32] = [127; 32];

    #[test]
    #[ignore]
    fn test_seal_lifecycle_2kib_base_8() -> Result<()> {
        let test_inputs = vec![
            (ARBITRARY_POREP_ID_V1_0_0, ApiVersion::V1_0_0),
            // (ARBITRARY_POREP_ID_V1_1_0, ApiVersion::V1_1_0),
        ];

        let path = Path::new("file_2kiB.txt");
        for (porep_id, api_version) in test_inputs {
            seal_lifecycle::<SectorShape2KiB>(SECTOR_SIZE_2_KIB, &porep_id, api_version, path)?;
        }

        Ok(())
    }
}
