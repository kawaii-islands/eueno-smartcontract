use ark_bls12_381::Fr;
use ark_ff::PrimeField;
use sha2::{Digest, Sha256};

use crate::domain::Domain;

/// Generate the replica id as expected for Stacked DRG.
pub fn generate_replica_id<D: Domain, T: AsRef<[u8]>>(
    prover_id: &[u8; 32],
    sector_id: u64,
    ticket: &[u8; 32],
    comm_d: T,
    porep_seed: &[u8; 32],
) -> D {
    let hash = Sha256::new()
        .chain_update(prover_id)
        .chain_update(&sector_id.to_be_bytes())
        .chain_update(ticket)
        .chain_update(&comm_d)
        .chain_update(porep_seed)
        .finalize();

    Fr::from_le_bytes_mod_order(hash.as_ref()).into()
}
