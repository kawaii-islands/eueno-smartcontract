use contract_auxiliaries::drg::stacked::VerifierSetupParams;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Binary, StdResult, Storage};
use cosmwasm_storage::{Bucket, ReadonlyBucket, ReadonlySingleton, Singleton};
use cw_storage_plus::{Item, Map};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[cw_serde]
pub struct VerifierParameters {
    pub setup_params: VerifierSetupParams,
    pub vk: Binary,
    pub minimum_challenges: u64,
}

#[cw_serde]
pub struct Config {
    pub owner: Addr,
    pub contract: String,
    pub version: String,
}

pub fn params_write(
    storage: &mut dyn Storage,
    pair_key: &[u8],
    params: &VerifierParameters,
) -> StdResult<()> {
    Bucket::new(storage, PARAMS_KEY).save(pair_key, params)
}

pub fn config_write(storage: &mut dyn Storage, data: &Config) -> StdResult<()> {
    Singleton::new(storage, CONFIG_KEY).save(data)
}
pub fn config_read(storage: &dyn Storage) -> StdResult<Config> {
    ReadonlySingleton::new(storage, CONFIG_KEY).load()
}

// do not return error, by default it return no precision and zero min offer amount
pub fn params_read(storage: &dyn Storage, pair_key: &[u8]) -> StdResult<VerifierParameters> {
    ReadonlyBucket::new(storage, PARAMS_KEY).load(pair_key)
}

//handle save round info
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InfoRound {
    pub time_expire: u64,
    pub porep_id: [u8; 32],
}

pub const PARAMS_KEY: &[u8] = b"PARAMS";
pub const CONFIG_KEY: &[u8] = b"CONFIG";
pub const CURRENT_ROUND: Item<i32> = Item::new("current_round");
pub const ROUND_INFO: Map<String, InfoRound> = Map::new("round_info");
pub const USER_REWARD: Map<String, i32> = Map::new("user_reward");
pub const SUBMIT_SUCCESS: Map<(String, String), bool> = Map::new("submit_success");
// pub static PREFIX_SUBMIT_SUCCESS: &[u8] = b"submit_proof_success"; // this is tick with value is the total orders
