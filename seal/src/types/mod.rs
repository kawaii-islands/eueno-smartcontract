mod byte_amounts;
mod piece_info;
mod porep_config;
mod sector_size;

pub use byte_amounts::*;
pub use piece_info::*;
pub use porep_config::*;
pub use sector_size::*;

pub use merkletree::store::StoreConfig;
pub use proofs_core::merkle::{MerkleProof, MerkleTreeTrait};
pub use proofs_porep::stacked::{Labels, PersistentAux, TemporaryAux};

use hashers::Hasher;
use proofs_porep::stacked;
use serde::{Deserialize, Serialize};

use crate::constants::DefaultPieceHasher;

pub type Commitment = [u8; 32];
pub type ProverId = [u8; 32];
pub type Ticket = [u8; 32];

/// Arity for binary trees, used for comm_d.
pub const BINARY_ARITY: usize = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealPreCommitOutput {
    pub comm_r: Commitment,
    pub comm_d: Commitment,
}

pub type VanillaSealProof<Tree> = stacked::Proof<Tree, DefaultPieceHasher>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealCommitPhase1Output<Tree: MerkleTreeTrait> {
    #[serde(bound(
        serialize = "VanillaSealProof<Tree>: Serialize",
        deserialize = "VanillaSealProof<Tree>: Deserialize<'de>"
    ))]
    pub vanilla_proofs: Vec<Vec<VanillaSealProof<Tree>>>,
    pub comm_r: Commitment,
    pub comm_d: Commitment,
    pub replica_id: <Tree::Hasher as Hasher>::Domain,
    pub seed: Ticket,
    pub ticket: Ticket,
}

#[derive(Clone, Debug)]
pub struct SealCommitOutput {
    pub proof: Vec<u8>
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SealPreCommitPhase1Output<Tree: MerkleTreeTrait> {
    #[serde(bound(
        serialize = "Labels<Tree>: Serialize",
        deserialize = "Labels<Tree>: Deserialize<'de>"
    ))]
    pub labels: Labels<Tree>,
    pub config: StoreConfig,
    pub comm_d: Commitment,
}
