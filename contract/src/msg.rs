use contract_auxiliaries::{
    domain::{poseidon::PoseidonDomain, sha256::Sha256Domain},
    drg::stacked::{verifier_params::PublicInputs, VerifierStackedDrg},
    utils::ApiVersion,
};
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Addr, Binary};

use crate::state::VerifierParameters;

pub type PublicInputsPorep = PublicInputs<PoseidonDomain, Sha256Domain>;
pub type VerifierStackedDrgPorep = VerifierStackedDrg<PoseidonDomain, Sha256Domain>;

#[cw_serde]
pub struct MigrateMsg {}

#[cw_serde]
pub enum SupportedSectorSize {
    SectorSize2Kib,
    SectorSize4Kib,
    SectorSize16Kib,
    SectorSize32Kib,
    SectorSize8Mib,
    SectorSize16Mib,
    SectorSize512Mib,
    SectorSize1Gib,
    SectorSize32Gib,
    SectorSize64Gib,
}

#[cw_serde]
pub struct InstantiateMsg {}

#[cw_serde]
pub enum ExecuteMsg {
    SetVerifierParams {
        sector_size: SupportedSectorSize,
        params: VerifierParameters,
        duration: u64,
    },
    SetOwner {
        new_owner: Addr,
    },
    SubmitProof {
        proof_raw: Binary,
        public_inputs: PublicInputsPorep,
        porep_id: Binary,
        sector_size: SupportedSectorSize,
        api_version: ApiVersion,
        prover_id: Binary,
        sector_id: u64,
        ticket: Binary,
    },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(CurrentRoundResponse)]
    QueryRoundCurrent {},
    #[returns(i32)]
    QueryUserReward { user: String },
    #[returns(Vec<String>)]
    QueryListUser {
        limit: u32,
        last_value: Option<String>,
    },
    #[returns(bool)]
    VerifyProof {
        porep_id: Binary,
        sector_size: SupportedSectorSize,
        api_version: ApiVersion,
        proof_raw: Binary,
        public_inputs: PublicInputsPorep,
        prover_id: Binary,
        sector_id: u64,
        ticket: Binary,
    },
}
// We define a custom struct for each query response
#[cw_serde]
pub struct CurrentRoundResponse {
    pub current_round: i32,
}
