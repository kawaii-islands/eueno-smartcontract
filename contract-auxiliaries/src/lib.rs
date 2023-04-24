use crate::drg::stacked::VerifierSetupParams;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
pub mod crypto;
pub mod deserializer;
pub mod domain;
pub mod drg;
pub mod utils;

pub type PoRepID = [u8; 32];

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, JsonSchema)]
pub struct VerifierParameters {
    pub setup_params: VerifierSetupParams,
    pub vk: Vec<u8>,
    pub minimum_challenges: u64,
}
