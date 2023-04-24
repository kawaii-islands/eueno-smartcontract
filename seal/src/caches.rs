use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use bellperson::groth16::{self, prepare_verifying_key};
use blstrs::Bls12;
use lazy_static::lazy_static;
use log::info;
use proofs_core::{compound_proof::CompoundProof, merkle::MerkleTreeTrait};
use proofs_porep::stacked::{StackedCompound, StackedDrg};
use rand::RngCore;

use crate::{constants::DefaultPieceHasher, parameters::public_params, types::PoRepConfig};

type Bls12GrothParams = groth16::MappedParameters<Bls12>;
pub type Bls12PreparedVerifyingKey = groth16::PreparedVerifyingKey<Bls12>;
pub type Bls12VerifyingKey = groth16::VerifyingKey<Bls12>;

type Cache<G> = HashMap<String, Arc<G>>;
type GrothMemCache = Cache<Bls12GrothParams>;
type VerifyingKeyMemCache = Cache<Bls12PreparedVerifyingKey>;

lazy_static! {
    static ref GROTH_PARAM_MEMORY_CACHE: Mutex<GrothMemCache> = Default::default();
    static ref VERIFYING_KEY_MEMORY_CACHE: Mutex<VerifyingKeyMemCache> = Default::default();
}

pub fn cache_lookup<F, G>(
    cache_ref: &Mutex<Cache<G>>,
    identifier: String,
    generator: F,
) -> Result<Arc<G>>
where
    F: FnOnce() -> Result<G>,
    G: Send + Sync,
{
    info!("trying parameters memory cache for: {}", &identifier);
    {
        let cache = (*cache_ref).lock().expect("poisoned cache");

        if let Some(entry) = cache.get(&identifier) {
            info!("found params in memory cache for {}", &identifier);
            return Ok(entry.clone());
        }
    }

    info!("no params in memory cache for {}", &identifier);

    let new_entry = Arc::new(generator()?);
    let res = new_entry.clone();
    {
        let cache = &mut (*cache_ref).lock().expect("poisoned cache");
        cache.insert(identifier, new_entry);
    }

    Ok(res)
}

#[inline]
pub fn lookup_groth_params<F>(identifier: String, generator: F) -> Result<Arc<Bls12GrothParams>>
where
    F: FnOnce() -> Result<Bls12GrothParams>,
{
    cache_lookup(&*GROTH_PARAM_MEMORY_CACHE, identifier, generator)
}

#[inline]
pub fn lookup_verifying_key<F>(
    identifier: String,
    generator: F,
) -> Result<Arc<Bls12PreparedVerifyingKey>>
where
    F: FnOnce() -> Result<Bls12PreparedVerifyingKey>,
{
    let vk_identifier = format!("{}-verifying-key", &identifier);
    cache_lookup(&*VERIFYING_KEY_MEMORY_CACHE, vk_identifier, generator)
}

pub fn get_stacked_params<Tree: 'static + MerkleTreeTrait, R: RngCore>(
    porep_config: &PoRepConfig,
    rng: Option<&mut R>,
) -> Result<Arc<Bls12GrothParams>> {
    let public_params = public_params::<Tree>(
        porep_config.padded_bytes_amount(),
        1,
        porep_config.porep_id,
        porep_config.api_version,
    )?;

    let parameters_generator = || {
        <StackedCompound<Tree, DefaultPieceHasher> as CompoundProof<
            StackedDrg<'_, Tree, DefaultPieceHasher>,
            _,
        >>::groth_params(rng, &public_params)
        .map_err(Into::into)
    };

    lookup_groth_params(
        format!(
            "STACKED[{}]",
            usize::from(porep_config.padded_bytes_amount())
        ),
        parameters_generator,
    )
}

pub fn get_stacked_verifying_key<Tree: 'static + MerkleTreeTrait, R: RngCore>(
    porep_config: &PoRepConfig,
    rng: Option<&mut R>,
) -> Result<Arc<Bls12PreparedVerifyingKey>> {
    let public_params = public_params(
        porep_config.padded_bytes_amount(),
        1,
        porep_config.porep_id,
        porep_config.api_version,
    )?;

    let vk_generator = || {
        let vk = <StackedCompound<Tree, DefaultPieceHasher> as CompoundProof<
            StackedDrg<'_, Tree, DefaultPieceHasher>,
            _,
        >>::verifying_key(rng, &public_params)?;
        Ok(prepare_verifying_key(&vk))
    };

    lookup_verifying_key(
        format!(
            "STACKED[{}]",
            usize::from(porep_config.padded_bytes_amount())
        ),
        vk_generator,
    )
}

pub fn generate_verifier_key<Tree: 'static + MerkleTreeTrait, R: RngCore>(
    porep_config: &PoRepConfig,
    rng: Option<&mut R>,
) -> Result<Bls12VerifyingKey> {
    let public_params = public_params(
        porep_config.padded_bytes_amount(),
        1,
        porep_config.porep_id,
        porep_config.api_version,
    )?;
    <StackedCompound<Tree, DefaultPieceHasher> as CompoundProof<
        StackedDrg<'_, Tree, DefaultPieceHasher>,
        _,
    >>::verifying_key(rng, &public_params)
}
