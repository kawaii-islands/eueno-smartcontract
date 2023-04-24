use crate::{
    constants::{DefaultPieceHasher, DRG_DEGREE, EXP_DEGREE, LAYERS},
    types::{MerkleTreeTrait, PaddedBytesAmount},
    POREP_MINIMUM_CHALLENGES,
};
use anyhow::{ensure, Result};
use proofs_core::{api_version::ApiVersion, proof::ProofScheme};
use proofs_porep::stacked::{self, LayerChallenges, StackedDrg};

pub fn public_params<Tree: 'static + MerkleTreeTrait>(
    sector_bytes: PaddedBytesAmount,
    partitions: usize,
    porep_id: [u8; 32],
    api_version: ApiVersion,
) -> Result<stacked::PublicParams<Tree>> {
    StackedDrg::<Tree, DefaultPieceHasher>::setup(&setup_params(
        sector_bytes,
        partitions,
        porep_id,
        api_version,
    )?)
}

pub fn setup_params(
    sector_bytes: PaddedBytesAmount,
    partitions: usize,
    porep_id: [u8; 32],
    api_version: ApiVersion,
) -> Result<stacked::SetupParams> {
    let layer_challenges = select_challenges(
        partitions,
        POREP_MINIMUM_CHALLENGES.from_sector_size(u64::from(sector_bytes)),
        *LAYERS
            .read()
            .expect("LAYERS poisoned")
            .get(&u64::from(sector_bytes))
            .expect("unknown sector size"),
    );
    let sector_bytes = u64::from(sector_bytes);

    ensure!(
        sector_bytes % 32 == 0,
        "sector_bytes ({}) must be a multiple of 32",
        sector_bytes,
    );

    let nodes = (sector_bytes / 32) as usize;
    let degree = DRG_DEGREE;
    let expansion_degree = EXP_DEGREE;

    Ok(stacked::SetupParams {
        nodes,
        degree,
        expansion_degree,
        porep_id,
        layer_challenges,
        api_version,
    })
}

fn select_challenges(
    partitions: usize,
    minimum_total_challenges: usize,
    layers: usize,
) -> LayerChallenges {
    let mut count = 1;
    let mut guess = LayerChallenges::new(layers, count);
    while partitions * guess.challenges_count_all() < minimum_total_challenges {
        count += 1;
        guess = LayerChallenges::new(layers, count);
    }

    guess
}


