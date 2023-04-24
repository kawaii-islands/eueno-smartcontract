use crate::{domain::Domain, utils::ApiVersion};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::marker::PhantomData;

use super::challenges::LayerChallenges;

use super::verifier_graph::VerifierStackedBucketGraph;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, JsonSchema)]
pub struct SetupParams {
    // Number of nodes
    pub nodes: u64,

    // Base degree of DRG
    pub degree: u64,

    pub expansion_degree: u64,

    pub porep_id: [u8; 32],
    pub layer_challenges: LayerChallenges,
    pub api_version: ApiVersion,
}

pub struct PublicParams<D>
where
    D: 'static + Domain,
{
    pub graph: VerifierStackedBucketGraph<D>,
    pub layer_challenges: LayerChallenges,
    _d: PhantomData<D>,
}

impl<D: Domain> Clone for PublicParams<D> {
    fn clone(&self) -> Self {
        Self {
            graph: self.graph.clone(),
            layer_challenges: self.layer_challenges.clone(),
            _d: Default::default(),
        }
    }
}

impl<D: Domain> PublicParams<D> {
    pub fn new(graph: VerifierStackedBucketGraph<D>, layer_challenges: LayerChallenges) -> Self {
        PublicParams {
            graph,
            layer_challenges,
            _d: PhantomData,
        }
    }
}

impl<'a, D: Domain> From<&'a PublicParams<D>> for PublicParams<D> {
    fn from(other: &PublicParams<D>) -> PublicParams<D> {
        PublicParams::new(other.graph.clone(), other.layer_challenges.clone())
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize, JsonSchema, Debug)]
pub struct PublicInputs<T: Domain, S: Domain> {
    #[serde(bound = "")]
    pub replica_id: T,
    pub seed: [u8; 32],
    #[serde(bound = "")]
    pub tau: Option<Tau<T, S>>,
    /// Partition index
    pub k: Option<u64>,
}

impl<T: Domain, S: Domain> PublicInputs<T, S> {
    pub fn challenges(
        &self,
        layer_challenges: &LayerChallenges,
        leaves: usize,
        partition_k: Option<usize>,
    ) -> Vec<usize> {
        let k = partition_k.unwrap_or(0);

        layer_challenges.derive::<T>(leaves, &self.replica_id, &self.seed, k as u8)
    }
}

/// Tau for a single parition.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Debug)]
pub struct Tau<D: Domain, E: Domain> {
    #[serde(bound = "")]
    pub comm_d: E,
    #[serde(bound = "")]
    pub comm_r: D,
}


/// Generate the replica id as expected for Stacked DRG.
pub fn check_replica_id<D: Domain, T: AsRef<[u8]>>(
    prover_id: &[u8],
    sector_id: u64,
    ticket: &[u8],
    comm_d: T,
    porep_seed: &[u8],
    replica_id: D,
) -> bool {
    let mut hash: [u8; 32] = Sha256::new()
        .chain_update(prover_id)
        .chain_update(&sector_id.to_be_bytes())
        .chain_update(ticket)
        .chain_update(&comm_d)
        .chain_update(porep_seed)
        .finalize()
        .into();

    hash[31] &= 0b0011_1111;
    let hash = hash.to_vec();
    
    let replica_id_le = replica_id.into_bytes();

    hash == replica_id_le
}
