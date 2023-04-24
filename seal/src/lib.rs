mod caches;
mod commitment_reader;
mod constants;
mod file_processor;
mod parameters;
mod pieces;
mod types;
mod util;

#[cfg(test)]
mod test;

use bellperson::groth16::{Proof, VerifyingKey};
pub use caches::*;
pub use constants::*;
pub use file_processor::*;

use fr32::Fr32Reader;
use hashers::sha256::Sha256Hasher;
use proofs_core::drgraph::Graph;
use proofs_core::merkle::get_base_tree_count;
use proofs_core::pieces::generate_piece_commitment_bytes_from_source;
use rand::RngCore;
use std::fs::{self, metadata, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use typenum::Unsigned;

use anyhow::{ensure, Context, Result};
use bincode::{deserialize, serialize};
use blstrs::{Bls12, Scalar as Fr};
use hashers::{Domain, Hasher};
use log::{info, trace};
use memmap2::MmapOptions;
use merkletree::store::{DiskStore, LevelCacheStore, Store, StoreConfig};
use proofs_core::{
    cache_key::CacheKey,
    compound_proof::{self, CompoundProof},
    measurements::{measure_op, Operation},
    merkle::{create_base_merkle_tree, BinaryMerkleTree, MerkleTreeTrait},
    multi_proof::MultiProof,
    proof::ProofScheme,
    sector::SectorId,
    util::default_rows_to_discard,
    Data,
};
use proofs_porep::stacked::{
    self, generate_replica_id, ChallengeRequirements, PersistentAux, StackedCompound, StackedDrg,
    Tau, TemporaryAux, TemporaryAuxCache,
};
use rayon::prelude::*;
use types::{
    Commitment, PieceInfo, PoRepConfig, ProverId, SealCommitOutput, SealCommitPhase1Output,
    SealPreCommitOutput, SealPreCommitPhase1Output, Ticket, UnpaddedBytesAmount,
};

use crate::caches::{get_stacked_params, get_stacked_verifying_key};
use crate::commitment_reader::CommitmentReader;
use crate::constants::{
    DefaultBinaryTree, DefaultOctTree, DefaultPieceDomain, DefaultPieceHasher,
    MINIMUM_RESERVED_BYTES_FOR_PIECE_IN_FULLY_ALIGNED_SECTOR as MINIMUM_PIECE_SIZE,
    POREP_MINIMUM_CHALLENGES, SINGLE_PARTITION_PROOF_LEN,
};
use crate::parameters::setup_params;
use crate::pieces::{get_piece_alignment, sum_piece_bytes_with_alignment, verify_pieces};
use crate::types::{PaddedBytesAmount, BINARY_ARITY};
use crate::util::{
    as_safe_commitment, commitment_from_fr, get_base_tree_leafs, get_base_tree_size,
};

#[allow(clippy::too_many_arguments)]
pub fn seal_pre_commit_phase1<R, S, T, Tree: 'static + MerkleTreeTrait>(
    porep_config: &PoRepConfig,
    cache_path: R,
    in_path: S,
    out_path: T,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: Ticket,
    piece_infos: &[PieceInfo],
) -> Result<SealPreCommitPhase1Output<Tree>>
where
    R: AsRef<Path>,
    S: AsRef<Path>,
    T: AsRef<Path>,
{
    info!("seal_pre_commit_phase1:start: {:?}", sector_id);

    let in_path_is_dev_zero = in_path.as_ref() == Path::new("/dev/zero");
    if in_path_is_dev_zero {
        trace!("using unreplicated data file /dev/zero");
    }

    // Sanity check all input path types.
    //
    // In the special case where `in_path` is `/dev/zero`, `.is_file()` is `false` as `/dev/zero` is
    // not a "normal" unix file.
    ensure!(
        in_path_is_dev_zero || metadata(in_path.as_ref())?.is_file(),
        "in_path must be a file or /dev/zero",
    );
    ensure!(
        metadata(out_path.as_ref())?.is_file(),
        "out_path must be a file"
    );
    ensure!(
        metadata(cache_path.as_ref())?.is_dir(),
        "cache_path must be a directory"
    );

    let sector_bytes = usize::from(porep_config.padded_bytes_amount());
    fs::metadata(&in_path)
        .with_context(|| format!("could not read in_path={:?})", in_path.as_ref().display()))?;

    fs::metadata(&out_path)
        .with_context(|| format!("could not read out_path={:?}", out_path.as_ref().display()))?;

    // Copy unsealed data to output location, where it will be sealed in place.
    //
    // When `in_path` is `/dev/zero`, the output file's data will be set to all zeros when the
    // output file's length is set to the sector size.
    if !in_path_is_dev_zero {
        fs::copy(&in_path, &out_path).with_context(|| {
            format!(
                "could not copy in_path={:?} to out_path={:?}",
                in_path.as_ref().display(),
                out_path.as_ref().display()
            )
        })?;
    }

    let f_data = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&out_path)
        .with_context(|| format!("could not open out_path={:?}", out_path.as_ref().display()))?;

    // Extend the underlying file with `0` bytes until it's length is the requested sector size.
    f_data.set_len(sector_bytes as u64)?;

    let data = unsafe {
        MmapOptions::new()
            .map_mut(&f_data)
            .with_context(|| format!("could not mmap out_path={:?}", out_path.as_ref().display()))?
    };

    let compound_setup_params = compound_proof::SetupParams {
        vanilla_params: setup_params(
            porep_config.padded_bytes_amount(),
            1,
            porep_config.porep_id,
            porep_config.api_version,
        )?,
        partitions: Some(1),
        priority: false,
    };

    let compound_public_params = <StackedCompound<Tree, DefaultPieceHasher> as CompoundProof<
        StackedDrg<'_, Tree, DefaultPieceHasher>,
        _,
    >>::setup(&compound_setup_params)?;

    trace!("building merkle tree for the original data");
    let (config, comm_d) = measure_op(Operation::CommD, || -> Result<_> {
        let base_tree_size = get_base_tree_size::<DefaultBinaryTree>(porep_config.sector_size)?;
        let base_tree_leafs = get_base_tree_leafs::<DefaultBinaryTree>(base_tree_size)?;
        ensure!(
            compound_public_params.vanilla_params.graph.size() == base_tree_leafs,
            "graph size and leaf size don't match"
        );

        trace!(
            "seal phase 1: sector_size {}, base tree size {}, base tree leafs {}",
            u64::from(porep_config.sector_size),
            base_tree_size,
            base_tree_leafs,
        );

        let mut config = StoreConfig::new(
            cache_path.as_ref(),
            CacheKey::CommDTree.to_string(),
            default_rows_to_discard(base_tree_leafs, BINARY_ARITY),
        );

        let data_tree = create_base_merkle_tree::<BinaryMerkleTree<DefaultPieceHasher>>(
            Some(config.clone()),
            base_tree_leafs,
            &data,
        )?;
        drop(data);

        config.size = Some(data_tree.len());
        let comm_d_root: Fr = data_tree.root().into();
        let comm_d = commitment_from_fr(comm_d_root);

        drop(data_tree);

        Ok((config, comm_d))
    })?;

    trace!("verifying pieces");

    ensure!(
        verify_pieces(&comm_d, piece_infos, porep_config.sector_size)?,
        "pieces and comm_d do not match"
    );
    let replica_id = generate_replica_id::<Tree::Hasher, _>(
        &prover_id,
        sector_id.into(),
        &ticket,
        comm_d,
        &porep_config.porep_id,
    );

    let labels = StackedDrg::<Tree, DefaultPieceHasher>::replicate_phase1(
        &compound_public_params.vanilla_params,
        &replica_id,
        config.clone(),
    )?;

    let out = SealPreCommitPhase1Output {
        labels,
        config,
        comm_d,
    };

    info!("seal_pre_commit_phase1:finish: {:?}", sector_id);
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
pub fn seal_pre_commit_phase2<R, S, Tree: 'static + MerkleTreeTrait>(
    porep_config: &PoRepConfig,
    phase1_output: SealPreCommitPhase1Output<Tree>,
    cache_path: S,
    replica_path: R,
) -> Result<SealPreCommitOutput>
where
    R: AsRef<Path>,
    S: AsRef<Path>,
{
    info!("seal_pre_commit_phase2:start");

    // Sanity check all input path types.
    ensure!(
        metadata(cache_path.as_ref())?.is_dir(),
        "cache_path must be a directory"
    );
    ensure!(
        metadata(replica_path.as_ref())?.is_file(),
        "replica_path must be a file"
    );

    let SealPreCommitPhase1Output {
        mut labels,
        mut config,
        comm_d,
        ..
    } = phase1_output;

    labels.update_root(cache_path.as_ref());
    config.path = cache_path.as_ref().into();

    let f_data = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&replica_path)
        .with_context(|| {
            format!(
                "could not open replica_path={:?}",
                replica_path.as_ref().display()
            )
        })?;
    let data = unsafe {
        MmapOptions::new().map_mut(&f_data).with_context(|| {
            format!(
                "could not mmap replica_path={:?}",
                replica_path.as_ref().display()
            )
        })?
    };
    let data: Data<'_> = (data, PathBuf::from(replica_path.as_ref())).into();

    // Load data tree from disk
    let data_tree = {
        let base_tree_size = get_base_tree_size::<DefaultBinaryTree>(porep_config.sector_size)?;
        let base_tree_leafs = get_base_tree_leafs::<DefaultBinaryTree>(base_tree_size)?;

        trace!(
            "seal phase 2: base tree size {}, base tree leafs {}, rows to discard {}",
            base_tree_size,
            base_tree_leafs,
            default_rows_to_discard(base_tree_leafs, BINARY_ARITY)
        );
        ensure!(
            config.rows_to_discard == default_rows_to_discard(base_tree_leafs, BINARY_ARITY),
            "Invalid cache size specified"
        );

        let store: DiskStore<DefaultPieceDomain> =
            DiskStore::new_from_disk(base_tree_size, BINARY_ARITY, &config)?;
        BinaryMerkleTree::<DefaultPieceHasher>::from_data_store(store, base_tree_leafs)?
    };

    let compound_setup_params = compound_proof::SetupParams {
        vanilla_params: setup_params(
            porep_config.padded_bytes_amount(),
            1,
            porep_config.porep_id,
            porep_config.api_version,
        )?,
        partitions: Some(1),
        priority: false,
    };

    let compound_public_params = <StackedCompound<Tree, DefaultPieceHasher> as CompoundProof<
        StackedDrg<'_, Tree, DefaultPieceHasher>,
        _,
    >>::setup(&compound_setup_params)?;

    let (tau, (p_aux, t_aux)) = StackedDrg::<Tree, DefaultPieceHasher>::replicate_phase2(
        &compound_public_params.vanilla_params,
        labels,
        data,
        data_tree,
        config,
        replica_path.as_ref().to_path_buf(),
    )?;

    let comm_r = commitment_from_fr(tau.comm_r.into());

    // Persist p_aux and t_aux here
    let p_aux_path = cache_path.as_ref().join(CacheKey::PAux.to_string());
    let mut f_p_aux = File::create(&p_aux_path)
        .with_context(|| format!("could not create file p_aux={:?}", p_aux_path))?;
    let p_aux_bytes = serialize(&p_aux)?;
    f_p_aux
        .write_all(&p_aux_bytes)
        .with_context(|| format!("could not write to file p_aux={:?}", p_aux_path))?;

    let t_aux_path = cache_path.as_ref().join(CacheKey::TAux.to_string());
    let mut f_t_aux = File::create(&t_aux_path)
        .with_context(|| format!("could not create file t_aux={:?}", t_aux_path))?;
    let t_aux_bytes = serialize(&t_aux)?;
    f_t_aux
        .write_all(&t_aux_bytes)
        .with_context(|| format!("could not write to file t_aux={:?}", t_aux_path))?;

    let out = SealPreCommitOutput { comm_r, comm_d };

    info!("seal_pre_commit_phase2:finish");
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
pub fn seal_commit_phase1<T: AsRef<Path>, Tree: 'static + MerkleTreeTrait>(
    porep_config: &PoRepConfig,
    cache_path: T,
    replica_path: T,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: Ticket,
    seed: Ticket,
    pre_commit: SealPreCommitOutput,
    piece_infos: &[PieceInfo],
) -> Result<SealCommitPhase1Output<Tree>> {
    info!("seal_commit_phase1:start: {:?}", sector_id);

    // Sanity check all input path types.
    ensure!(
        metadata(cache_path.as_ref())?.is_dir(),
        "cache_path must be a directory"
    );
    ensure!(
        metadata(replica_path.as_ref())?.is_file(),
        "replica_path must be a file"
    );

    let SealPreCommitOutput { comm_d, comm_r } = pre_commit;

    ensure!(comm_d != [0; 32], "Invalid all zero commitment (comm_d)");
    ensure!(comm_r != [0; 32], "Invalid all zero commitment (comm_r)");
    ensure!(
        verify_pieces(&comm_d, piece_infos, porep_config.sector_size)?,
        "pieces and comm_d do not match"
    );

    let p_aux = {
        let p_aux_path = cache_path.as_ref().join(CacheKey::PAux.to_string());
        let p_aux_bytes = fs::read(&p_aux_path)
            .with_context(|| format!("could not read file p_aux={:?}", p_aux_path))?;

        deserialize(&p_aux_bytes)
    }?;

    let t_aux = {
        let t_aux_path = cache_path.as_ref().join(CacheKey::TAux.to_string());
        let t_aux_bytes = fs::read(&t_aux_path)
            .with_context(|| format!("could not read file t_aux={:?}", t_aux_path))?;

        let mut res: TemporaryAux<_, _> = deserialize(&t_aux_bytes)?;

        // Switch t_aux to the passed in cache_path
        res.set_cache_path(cache_path);
        res
    };

    // Convert TemporaryAux to TemporaryAuxCache, which instantiates all
    // elements based on the configs stored in TemporaryAux.
    let t_aux_cache: TemporaryAuxCache<Tree, DefaultPieceHasher> =
        TemporaryAuxCache::new(&t_aux, replica_path.as_ref().to_path_buf())
            .context("failed to restore contents of t_aux")?;

    let comm_r_safe = as_safe_commitment(&comm_r, "comm_r")?;
    let comm_d_safe = DefaultPieceDomain::try_from_bytes(&comm_d)?;

    let replica_id = generate_replica_id::<Tree::Hasher, _>(
        &prover_id,
        sector_id.into(),
        &ticket,
        comm_d_safe,
        &porep_config.porep_id,
    );

    let public_inputs = stacked::PublicInputs {
        replica_id,
        tau: Some(stacked::Tau {
            comm_d: comm_d_safe,
            comm_r: comm_r_safe,
        }),
        k: None,
        seed,
    };

    let private_inputs = stacked::PrivateInputs::<Tree, DefaultPieceHasher> {
        p_aux,
        t_aux: t_aux_cache,
    };

    let compound_setup_params = compound_proof::SetupParams {
        vanilla_params: setup_params(
            porep_config.padded_bytes_amount(),
            1,
            porep_config.porep_id,
            porep_config.api_version,
        )?,
        partitions: Some(1),
        priority: false,
    };

    let compound_public_params = <StackedCompound<Tree, DefaultPieceHasher> as CompoundProof<
        StackedDrg<'_, Tree, DefaultPieceHasher>,
        _,
    >>::setup(&compound_setup_params)?;

    let vanilla_proofs = StackedDrg::prove_all_partitions(
        &compound_public_params.vanilla_params,
        &public_inputs,
        &private_inputs,
        StackedCompound::partition_count(&compound_public_params),
    )?;

    let sanity_check = StackedDrg::<Tree, DefaultPieceHasher>::verify_all_partitions(
        &compound_public_params.vanilla_params,
        &public_inputs,
        &vanilla_proofs,
    )?;
    ensure!(sanity_check, "Invalid vanilla proof generated");

    let out = SealCommitPhase1Output {
        vanilla_proofs,
        comm_r,
        comm_d,
        replica_id,
        seed,
        ticket,
    };

    info!("seal_commit_phase1:finish: {:?}", sector_id);
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
pub fn seal_commit_phase2<Tree: 'static + MerkleTreeTrait, R: RngCore>(
    porep_config: &PoRepConfig,
    phase1_output: SealCommitPhase1Output<Tree>,
    _prover_id: ProverId,
    sector_id: SectorId,
    rng: Option<&mut R>,
) -> Result<SealCommitOutput> {
    info!("seal_commit_phase2:start: {:?}", sector_id);

    let SealCommitPhase1Output {
        vanilla_proofs,
        comm_d,
        comm_r,
        replica_id,
        seed,
        ticket: _,
    } = phase1_output;

    ensure!(comm_d != [0; 32], "Invalid all zero commitment (comm_d)");
    ensure!(comm_r != [0; 32], "Invalid all zero commitment (comm_r)");

    let comm_r_safe = as_safe_commitment(&comm_r, "comm_r")?;
    let comm_d_safe = DefaultPieceDomain::try_from_bytes(&comm_d)?;

    let public_inputs = stacked::PublicInputs {
        replica_id,
        tau: Some(stacked::Tau {
            comm_d: comm_d_safe,
            comm_r: comm_r_safe,
        }),
        k: None,
        seed,
    };

    let groth_params = get_stacked_params::<Tree, R>(porep_config, rng)?;

    trace!(
        "got groth params ({}) while sealing",
        u64::from(porep_config.padded_bytes_amount())
    );

    let compound_setup_params = compound_proof::SetupParams {
        vanilla_params: setup_params(
            porep_config.padded_bytes_amount(),
            1,
            porep_config.porep_id,
            porep_config.api_version,
        )?,
        partitions: Some(1),
        priority: false,
    };

    let compound_public_params = <StackedCompound<Tree, DefaultPieceHasher> as CompoundProof<
        StackedDrg<'_, Tree, DefaultPieceHasher>,
        _,
    >>::setup(&compound_setup_params)?;

    trace!("snark_proof:start");
    let groth_proofs = StackedCompound::<Tree, DefaultPieceHasher>::circuit_proofs(
        &public_inputs,
        vanilla_proofs,
        &compound_public_params.vanilla_params,
        &groth_params,
        compound_public_params.priority,
    )?;
    trace!("snark_proof:finish");

    let proof = MultiProof::new(groth_proofs, &groth_params.pvk);

    let mut buf = Vec::with_capacity(SINGLE_PARTITION_PROOF_LEN);

    proof.write(&mut buf)?;

    let out = SealCommitOutput { proof: buf };

    info!("seal_commit_phase2:finish: {:?}", sector_id);
    Ok(out)
}

/// Given the specified arguments, this method returns the inputs that were used to
/// generate the seal proof.  This can be useful for proof aggregation, as verification
/// requires these inputs.
///
/// This method allows them to be retrieved when needed, rather than storing them for
/// some amount of time.
///
/// # Arguments
///
/// * `porep_config` - this sector's porep config that contains the number of bytes in the sector.
/// * `comm_r` - a commitment to a sector's replica.
/// * `comm_d` - a commitment to a sector's data.
/// * `prover_id` - the prover_id used to seal this sector.
/// * `sector_id` - the sector_id of this sector.
/// * `ticket` - the ticket used to generate this sector's replica-id.
/// * `seed` - the seed used to derive the porep challenges.
pub fn get_seal_inputs<Tree: 'static + MerkleTreeTrait>(
    porep_config: &PoRepConfig,
    comm_r: Commitment,
    comm_d: Commitment,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: Ticket,
    seed: Ticket,
) -> Result<Vec<Vec<Fr>>> {
    trace!("get_seal_inputs:start");

    ensure!(comm_d != [0; 32], "Invalid all zero commitment (comm_d)");
    ensure!(comm_r != [0; 32], "Invalid all zero commitment (comm_r)");

    let replica_id = generate_replica_id::<Tree::Hasher, _>(
        &prover_id,
        sector_id.into(),
        &ticket,
        comm_d,
        &porep_config.porep_id,
    );

    let comm_r_safe = as_safe_commitment(&comm_r, "comm_r")?;
    let comm_d_safe = DefaultPieceDomain::try_from_bytes(&comm_d)?;

    let public_inputs = stacked::PublicInputs {
        replica_id,
        tau: Some(stacked::Tau {
            comm_d: comm_d_safe,
            comm_r: comm_r_safe,
        }),
        k: None,
        seed,
    };

    let compound_setup_params = compound_proof::SetupParams {
        vanilla_params: setup_params(
            porep_config.padded_bytes_amount(),
            1,
            porep_config.porep_id,
            porep_config.api_version,
        )?,
        partitions: Some(1),
        priority: false,
    };

    let compound_public_params = <StackedCompound<Tree, DefaultPieceHasher> as CompoundProof<
        StackedDrg<'_, Tree, DefaultPieceHasher>,
        _,
    >>::setup(&compound_setup_params)?;

    let partitions = <StackedCompound<Tree, DefaultPieceHasher> as CompoundProof<
        StackedDrg<'_, Tree, DefaultPieceHasher>,
        _,
    >>::partition_count(&compound_public_params);

    // These are returned for aggregated proof verification.
    let inputs: Vec<_> = (0..partitions)
        .into_par_iter()
        .map(|k| {
            StackedCompound::<Tree, DefaultPieceHasher>::generate_public_inputs(
                &public_inputs,
                &compound_public_params.vanilla_params,
                Some(k),
            )
        })
        .collect::<Result<_>>()?;

    trace!("get_seal_inputs:finish");

    Ok(inputs)
}

/// Verifies the output of some previously-run seal operation.
///
/// # Arguments
///
/// * `porep_config` - this sector's porep config that contains the number of bytes in this sector.
/// * `comm_r_in` - commitment to the sector's replica (`comm_r`).
/// * `comm_d_in` - commitment to the sector's data (`comm_d`).
/// * `prover_id` - the prover-id that sealed this sector.
/// * `sector_id` - this sector's sector-id.
/// * `ticket` - the ticket that was used to generate this sector's replica-id.
/// * `seed` - the seed used to derive the porep challenges.
/// * `proof_vec` - the porep circuit proof serialized into a vector of bytes.
#[allow(clippy::too_many_arguments)]
pub fn verify_seal<Tree: 'static + MerkleTreeTrait, R: RngCore>(
    porep_config: &PoRepConfig,
    comm_r_in: Commitment,
    comm_d_in: Commitment,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: Ticket,
    seed: Ticket,
    proof_vec: &[u8],
    rng: Option<&mut R>,
) -> Result<bool> {
    info!("verify_seal:start: {:?}", sector_id);

    ensure!(comm_d_in != [0; 32], "Invalid all zero commitment (comm_d)");
    ensure!(comm_r_in != [0; 32], "Invalid all zero commitment (comm_r)");
    ensure!(!proof_vec.is_empty(), "Invalid proof bytes (empty vector)");

    let replica_id = generate_replica_id::<Tree::Hasher, _>(
        &prover_id,
        sector_id.into(),
        &ticket,
        comm_d_in,
        &porep_config.porep_id,
    );

    let comm_r: <Tree::Hasher as Hasher>::Domain = as_safe_commitment(&comm_r_in, "comm_r")?;
    let comm_d: DefaultPieceDomain = as_safe_commitment(&comm_d_in, "comm_d")?;

    let compound_setup_params = compound_proof::SetupParams {
        vanilla_params: setup_params(
            porep_config.padded_bytes_amount(),
            1,
            porep_config.porep_id,
            porep_config.api_version,
        )?,
        partitions: Some(1),
        priority: false,
    };

    let compound_public_params: compound_proof::PublicParams<
        '_,
        StackedDrg<'_, Tree, DefaultPieceHasher>,
    > = StackedCompound::setup(&compound_setup_params)?;

    let public_inputs =
        stacked::PublicInputs::<<Tree::Hasher as Hasher>::Domain, DefaultPieceDomain> {
            replica_id,
            tau: Some(Tau { comm_r, comm_d }),
            seed,
            k: None,
        };

    let result = {
        let sector_bytes = porep_config.padded_bytes_amount();
        let verifying_key = get_stacked_verifying_key::<Tree, R>(porep_config, rng)?;

        trace!(
            "got verifying key ({}) while verifying seal",
            u64::from(sector_bytes)
        );

        let proof = MultiProof::new_from_reader(Some(1), proof_vec, &verifying_key)?;

        StackedCompound::verify(
            &compound_public_params,
            &public_inputs,
            &proof,
            &ChallengeRequirements {
                minimum_challenges: POREP_MINIMUM_CHALLENGES
                    .from_sector_size(u64::from(porep_config.sector_size)),
            },
        )
    };

    info!("verify_seal:finish: {:?}", sector_id);
    result
}

/// Verifies the output of some previously-run seal operation.
///
/// # Arguments
///
/// * `porep_config` - this sector's porep config that contains the number of bytes in this sector.
/// * `comm_r_in` - commitment to the sector's replica (`comm_r`).
/// * `comm_d_in` - commitment to the sector's data (`comm_d`).
/// * `prover_id` - the prover-id that sealed this sector.
/// * `sector_id` - this sector's sector-id.
/// * `ticket` - the ticket that was used to generate this sector's replica-id.
/// * `seed` - the seed used to derive the porep challenges.
/// * `proof_vec` - the porep circuit proof serialized into a vector of bytes.
#[allow(clippy::too_many_arguments)]
pub fn generate_setup_params<Tree: 'static + MerkleTreeTrait, R: RngCore>(
    porep_config: &PoRepConfig,
    rng: Option<&mut R>,
) -> Result<
    (
        proofs_core::compound_proof::SetupParams<'static, StackedDrg<'static, Tree, Sha256Hasher>>,
        VerifyingKey<Bls12>,
        ChallengeRequirements,
    ),
    anyhow::Error,
> {
    let compound_setup_params = compound_proof::SetupParams {
        vanilla_params: setup_params(
            porep_config.padded_bytes_amount(),
            1,
            porep_config.porep_id,
            porep_config.api_version,
        )?,
        partitions: Some(1),
        priority: false,
    };

    let verifying_key = generate_verifier_key::<Tree, R>(porep_config, rng)?;

    let challenge_requirements = ChallengeRequirements {
        minimum_challenges: POREP_MINIMUM_CHALLENGES
            .from_sector_size(u64::from(porep_config.sector_size)),
    };

    Ok((compound_setup_params, verifying_key, challenge_requirements))
}

/// Verifies the output of some previously-run seal operation.
///
/// # Arguments
///
/// * `porep_config` - this sector's porep config that contains the number of bytes in this sector.
/// * `comm_r_in` - commitment to the sector's replica (`comm_r`).
/// * `comm_d_in` - commitment to the sector's data (`comm_d`).
/// * `prover_id` - the prover-id that sealed this sector.
/// * `sector_id` - this sector's sector-id.
/// * `ticket` - the ticket that was used to generate this sector's replica-id.
/// * `seed` - the seed used to derive the porep challenges.
/// * `proof_vec` - the porep circuit proof serialized into a vector of bytes.
#[allow(clippy::too_many_arguments)]
pub fn generate_proof_and_public_inputs<Tree: 'static + MerkleTreeTrait, R: RngCore>(
    porep_config: &PoRepConfig,
    comm_r_in: Commitment,
    comm_d_in: Commitment,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: Ticket,
    seed: Ticket,
    proof_vec: &[u8],
    rng: Option<&mut R>,
) -> Result<
    (
        proofs_porep::stacked::PublicInputs<
            <<Tree as MerkleTreeTrait>::Hasher as hashers::Hasher>::Domain,
            DefaultPieceDomain,
        >,
        Vec<Proof<Bls12>>,
    ),
    anyhow::Error,
> {
    info!("verify_seal:start: {:?}", sector_id);

    ensure!(comm_d_in != [0; 32], "Invalid all zero commitment (comm_d)");
    ensure!(comm_r_in != [0; 32], "Invalid all zero commitment (comm_r)");
    ensure!(!proof_vec.is_empty(), "Invalid proof bytes (empty vector)");

    let comm_r: <Tree::Hasher as Hasher>::Domain = as_safe_commitment(&comm_r_in, "comm_r")?;
    let comm_d: DefaultPieceDomain = as_safe_commitment(&comm_d_in, "comm_d")?;

    let replica_id = generate_replica_id::<Tree::Hasher, _>(
        &prover_id,
        sector_id.into(),
        &ticket,
        comm_d,
        &porep_config.porep_id,
    );

    let public_inputs =
        stacked::PublicInputs::<<Tree::Hasher as Hasher>::Domain, DefaultPieceDomain> {
            replica_id,
            tau: Some(Tau { comm_r, comm_d }),
            seed,
            k: None,
        };
    let sector_bytes = porep_config.padded_bytes_amount();
    let prepared_verifying_key = get_stacked_verifying_key::<Tree, R>(porep_config, rng)?;

    trace!(
        "got verifying key ({}) while verifying seal",
        u64::from(sector_bytes)
    );

    let proof = MultiProof::new_from_reader(Some(1), proof_vec, &prepared_verifying_key)?;

    Ok((public_inputs, proof.circuit_proofs))
}

/// Generates a piece commitment for the provided byte source. Returns an error
/// if the byte source produced more than `piece_size` bytes.
///
/// # Arguments
///
/// * `source` - a readable source of unprocessed piece bytes. The piece's commitment will be
/// generated for the bytes read from the source plus any added padding.
/// * `piece_size` - the number of unpadded user-bytes which can be read from source before EOF.
pub fn generate_piece_commitment<T: Read>(
    source: T,
    piece_size: UnpaddedBytesAmount,
) -> Result<PieceInfo> {
    trace!("generate_piece_commitment:start");

    let result = measure_op(Operation::GeneratePieceCommitment, || {
        ensure_piece_size(piece_size)?;

        // send the source through the preprocessor
        let source = BufReader::new(source);
        let mut fr32_reader = Fr32Reader::new(source);

        let commitment = generate_piece_commitment_bytes_from_source::<DefaultPieceHasher>(
            &mut fr32_reader,
            PaddedBytesAmount::from(piece_size).into(),
        )?;

        PieceInfo::new(commitment, piece_size)
    });

    trace!("generate_piece_commitment:finish");
    result
}

fn ensure_piece_size(piece_size: UnpaddedBytesAmount) -> Result<()> {
    ensure!(
        piece_size >= UnpaddedBytesAmount(MINIMUM_PIECE_SIZE),
        "Piece must be at least {} bytes",
        MINIMUM_PIECE_SIZE
    );

    let padded_piece_size: PaddedBytesAmount = piece_size.into();
    ensure!(
        u64::from(padded_piece_size).is_power_of_two(),
        "Bit-padded piece size must be a power of 2 ({:?})",
        padded_piece_size,
    );

    Ok(())
}

/// Computes a NUL-byte prefix and/or suffix for `source` using the provided
/// `piece_lengths` and `piece_size` (such that the `source`, after
/// preprocessing, will occupy a subtree of a merkle tree built using the bytes
/// from `target`), runs the resultant byte stream through the preprocessor,
/// and writes the result to `target`. Returns a tuple containing the number of
/// bytes written to `target` (`source` plus alignment) and the commitment.
///
/// WARNING: Depending on the ordering and size of the pieces in
/// `piece_lengths`, this function could write a prefix of NUL bytes which
/// wastes ($SIZESECTORSIZE/2)-$MINIMUM_PIECE_SIZE space. This function will be
/// deprecated in favor of `write_and_preprocess`, and miners will be prevented
/// from sealing sectors containing more than $TOOMUCH alignment bytes.
///
/// # Arguments
///
/// * `source` - a readable source of unprocessed piece bytes.
/// * `target` - a writer where we will write the processed piece bytes.
/// * `piece_size` - the number of unpadded user-bytes which can be read from source before EOF.
/// * `piece_lengths` - the number of bytes for each previous piece in the sector.
pub fn add_piece<R, W>(
    source: R,
    target: W,
    piece_size: UnpaddedBytesAmount,
    piece_lengths: &[UnpaddedBytesAmount],
) -> Result<(PieceInfo, UnpaddedBytesAmount)>
where
    R: Read,
    W: Write,
{
    trace!("add_piece:start");

    let result = measure_op(Operation::AddPiece, || {
        ensure_piece_size(piece_size)?;

        let source = BufReader::new(source);
        let mut target = BufWriter::new(target);

        let written_bytes = sum_piece_bytes_with_alignment(piece_lengths);
        let piece_alignment = get_piece_alignment(written_bytes, piece_size);
        let fr32_reader = Fr32Reader::new(source);

        // write left alignment
        for _ in 0..usize::from(PaddedBytesAmount::from(piece_alignment.left_bytes)) {
            target.write_all(&[0u8][..])?;
        }

        let mut commitment_reader = CommitmentReader::new(fr32_reader);
        let n = io::copy(&mut commitment_reader, &mut target)
            .context("failed to write and preprocess bytes")?;

        ensure!(n != 0, "add_piece: read 0 bytes before EOF from source");
        let n = PaddedBytesAmount(n);
        let n: UnpaddedBytesAmount = n.into();

        ensure!(n == piece_size, "add_piece: invalid bytes amount written");

        // write right alignment
        for _ in 0..usize::from(PaddedBytesAmount::from(piece_alignment.right_bytes)) {
            target.write_all(&[0u8][..])?;
        }

        let commitment = commitment_reader.finish()?;
        let mut comm = [0u8; 32];
        comm.copy_from_slice(commitment.as_ref());

        let written = piece_alignment.left_bytes + piece_alignment.right_bytes + piece_size;

        Ok((PieceInfo::new(comm, n)?, written))
    });

    trace!("add_piece:finish");
    result
}

// Verifies if a DiskStore specified by a config (or set of 'required_configs' is consistent).
fn verify_store(config: &StoreConfig, arity: usize, required_configs: usize) -> Result<()> {
    let store_path = StoreConfig::data_path(&config.path, &config.id);
    if !Path::new(&store_path).exists() {
        // Configs may have split due to sector size, so we need to
        // check deterministic paths from here.
        let orig_path = store_path
            .clone()
            .into_os_string()
            .into_string()
            .expect("failed to convert store_path to string");
        let mut configs: Vec<StoreConfig> = Vec::with_capacity(required_configs);
        for i in 0..required_configs {
            let cur_path = orig_path
                .clone()
                .replace(".dat", format!("-{}.dat", i).as_str());

            if Path::new(&cur_path).exists() {
                let path_str = cur_path.as_str();
                let tree_names = vec!["tree-d", "tree-c", "tree-r-last"];
                for name in tree_names {
                    if path_str.contains(name) {
                        configs.push(StoreConfig::from_config(
                            config,
                            format!("{}-{}", name, i),
                            None,
                        ));
                        break;
                    }
                }
            }
        }

        ensure!(
            configs.len() == required_configs,
            "Missing store file (or associated split paths): {}",
            store_path.display()
        );

        let store_len = config.size.expect("disk store size not configured");
        for config in &configs {
            let data_path = StoreConfig::data_path(&config.path, &config.id);
            trace!(
                "verify_store: {:?} has length {} bytes",
                &data_path,
                std::fs::metadata(&data_path)?.len()
            );
            ensure!(
                DiskStore::<DefaultPieceDomain>::is_consistent(store_len, arity, config,)?,
                "Store is inconsistent: {:?}",
                &data_path
            );
        }
    } else {
        trace!(
            "verify_store: {:?} has length {}",
            &store_path,
            std::fs::metadata(&store_path)?.len()
        );
        ensure!(
            DiskStore::<DefaultPieceDomain>::is_consistent(
                config.size.expect("disk store size not configured"),
                arity,
                config,
            )?,
            "Store is inconsistent: {:?}",
            store_path
        );
    }

    Ok(())
}

// Verifies if a LevelCacheStore specified by a config is consistent.
fn verify_level_cache_store<Tree: MerkleTreeTrait>(config: &StoreConfig) -> Result<()> {
    let store_path = StoreConfig::data_path(&config.path, &config.id);
    if !Path::new(&store_path).exists() {
        let required_configs = get_base_tree_count::<Tree>();

        // Configs may have split due to sector size, so we need to
        // check deterministic paths from here.
        let orig_path = store_path
            .clone()
            .into_os_string()
            .into_string()
            .expect("failed to convert store_path to string");
        let mut configs: Vec<StoreConfig> = Vec::with_capacity(required_configs);
        for i in 0..required_configs {
            let cur_path = orig_path
                .clone()
                .replace(".dat", format!("-{}.dat", i).as_str());

            if Path::new(&cur_path).exists() {
                let path_str = cur_path.as_str();
                let tree_names = vec!["tree-d", "tree-c", "tree-r-last"];
                for name in tree_names {
                    if path_str.contains(name) {
                        configs.push(StoreConfig::from_config(
                            config,
                            format!("{}-{}", name, i),
                            None,
                        ));
                        break;
                    }
                }
            }
        }

        ensure!(
            configs.len() == required_configs,
            "Missing store file (or associated split paths): {}",
            store_path.display()
        );

        let store_len = config.size.expect("disk store size not configured");
        for config in &configs {
            let data_path = StoreConfig::data_path(&config.path, &config.id);
            trace!(
                "verify_store: {:?} has length {}",
                &data_path,
                std::fs::metadata(&data_path)?.len()
            );
            ensure!(
                LevelCacheStore::<DefaultPieceDomain, File>::is_consistent(
                    store_len,
                    Tree::Arity::to_usize(),
                    config,
                )?,
                "Store is inconsistent: {:?}",
                &data_path
            );
        }
    } else {
        trace!(
            "verify_store: {:?} has length {}",
            &store_path,
            std::fs::metadata(&store_path)?.len()
        );
        ensure!(
            LevelCacheStore::<DefaultPieceDomain, File>::is_consistent(
                config.size.expect("disk store size not configured"),
                Tree::Arity::to_usize(),
                config,
            )?,
            "Store is inconsistent: {:?}",
            store_path
        );
    }

    Ok(())
}

// Checks for the existence of the tree d store, the replica, and all generated labels.
pub fn validate_cache_for_precommit_phase2<R, T, Tree: MerkleTreeTrait>(
    cache_path: R,
    replica_path: T,
    seal_precommit_phase1_output: &SealPreCommitPhase1Output<Tree>,
) -> Result<()>
where
    R: AsRef<Path>,
    T: AsRef<Path>,
{
    info!("validate_cache_for_precommit_phase2:start");

    ensure!(
        replica_path.as_ref().exists(),
        "Missing replica: {}",
        replica_path.as_ref().to_path_buf().display()
    );

    // Verify all stores/labels within the Labels object, but
    // respecting the current cache_path.
    let cache = cache_path.as_ref().to_path_buf();
    seal_precommit_phase1_output
        .labels
        .verify_stores(verify_store, &cache)?;

    // Update the previous phase store path to the current cache_path.
    let mut config = StoreConfig::from_config(
        &seal_precommit_phase1_output.config,
        &seal_precommit_phase1_output.config.id,
        seal_precommit_phase1_output.config.size,
    );
    config.path = cache_path.as_ref().into();

    let result = verify_store(
        &config,
        <DefaultBinaryTree as MerkleTreeTrait>::Arity::to_usize(),
        get_base_tree_count::<Tree>(),
    );

    info!("validate_cache_for_precommit_phase2:finish");
    result
}

// Checks for the existence of the replica data and t_aux, which in
// turn allows us to verify the tree d, tree r, tree c, and the
// labels.
pub fn validate_cache_for_commit<R, T, Tree: MerkleTreeTrait>(
    cache_path: R,
    replica_path: T,
) -> Result<()>
where
    R: AsRef<Path>,
    T: AsRef<Path>,
{
    info!("validate_cache_for_commit:start");

    // Verify that the replica exists and is not empty.
    ensure!(
        replica_path.as_ref().exists(),
        "Missing replica: {}",
        replica_path.as_ref().to_path_buf().display()
    );

    let metadata = File::open(&replica_path)?.metadata()?;
    ensure!(
        metadata.len() > 0,
        "Replica {} exists, but is empty!",
        replica_path.as_ref().to_path_buf().display()
    );

    let cache = &cache_path.as_ref();

    // Make sure p_aux exists and is valid.
    let p_aux_path = cache.join(CacheKey::PAux.to_string());
    let p_aux_bytes = fs::read(&p_aux_path)
        .with_context(|| format!("could not read file p_aux={:?}", p_aux_path))?;

    let _: PersistentAux<<Tree::Hasher as Hasher>::Domain> = deserialize(&p_aux_bytes)?;
    drop(p_aux_bytes);

    // Make sure t_aux exists and is valid.
    let t_aux = {
        let t_aux_path = cache.join(CacheKey::TAux.to_string());
        let t_aux_bytes = fs::read(&t_aux_path)
            .with_context(|| format!("could not read file t_aux={:?}", t_aux_path))?;

        let mut res: TemporaryAux<Tree, DefaultPieceHasher> = deserialize(&t_aux_bytes)?;

        // Switch t_aux to the passed in cache_path
        res.set_cache_path(&cache_path);
        res
    };

    // Verify all stores/labels within the Labels object.
    let cache = cache_path.as_ref().to_path_buf();
    t_aux.labels.verify_stores(verify_store, &cache)?;

    // Verify each tree disk store.
    verify_store(
        &t_aux.tree_d_config,
        <DefaultBinaryTree as MerkleTreeTrait>::Arity::to_usize(),
        get_base_tree_count::<Tree>(),
    )?;
    verify_store(
        &t_aux.tree_c_config,
        <DefaultOctTree as MerkleTreeTrait>::Arity::to_usize(),
        get_base_tree_count::<Tree>(),
    )?;
    verify_level_cache_store::<DefaultOctTree>(&t_aux.tree_r_last_config)?;

    info!("validate_cache_for_commit:finish");

    Ok(())
}

// Ensure that any associated cached data persisted is discarded.
pub fn clear_cache<Tree: MerkleTreeTrait>(cache_dir: &Path) -> Result<()> {
    info!("clear_cache:start");

    let mut t_aux: TemporaryAux<Tree, Sha256Hasher> = {
        let f_aux_path = cache_dir.to_path_buf().join(CacheKey::TAux.to_string());
        let aux_bytes = fs::read(&f_aux_path)
            .with_context(|| format!("could not read from path={:?}", f_aux_path))?;

        deserialize(&aux_bytes)
    }?;

    t_aux.set_cache_path(cache_dir);
    let result = TemporaryAux::<Tree, DefaultPieceHasher>::clear_temp(t_aux);

    info!("clear_cache:finish");

    result
}
