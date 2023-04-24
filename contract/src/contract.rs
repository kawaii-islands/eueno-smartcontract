#[cfg(not(feature = "library"))]
use ark_groth16::{prepare_verifying_key, verify_proof as groth16_verify, Proof, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use contract_auxiliaries::drg::stacked::challenges::ChallengeRequirements;
use contract_auxiliaries::drg::stacked::verifier_params::check_replica_id;
use contract_auxiliaries::utils::ApiVersion;
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_binary, Addr, Binary, Deps, DepsMut, Env, MessageInfo, Order, Response, StdError, StdResult,
};
use cw_storage_plus::Bound;
use sha2::{Digest, Sha256};

use crate::error::ContractError;
use crate::msg::{
    CurrentRoundResponse, ExecuteMsg, InstantiateMsg, PublicInputsPorep, QueryMsg,
    SupportedSectorSize, VerifierStackedDrgPorep,MigrateMsg
};
use crate::state::{
    config_read, config_write, params_read, params_write, Config, InfoRound, VerifierParameters,
    CURRENT_ROUND, ROUND_INFO, SUBMIT_SUCCESS, USER_REWARD,
};

// version info for migration info
const CONTRACT_NAME: &str = "stacked-drg";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn porep_key(
    porep_id: &[u8],
    sector_size: SupportedSectorSize,
    api_version: &ApiVersion,
) -> StdResult<Vec<u8>> {
    let mut messages = porep_id.to_vec();
    messages.push(sector_size as u8);
    messages.push(match api_version {
        ApiVersion::V1_0_0 => 0u8,
        ApiVersion::V1_1_0 => 1u8,
    });

    let hash = Sha256::new().chain_update(&messages).finalize();
    Ok(hash.to_vec())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    _msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    config_write(
        deps.storage,
        &Config {
            contract: CONTRACT_NAME.to_string(),
            version: CONTRACT_VERSION.to_string(),
            owner: info.sender,
        },
    )?;
    let round_init: i32 = 1;
    CURRENT_ROUND.save(deps.storage, &round_init)?;

    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::SetVerifierParams {
            sector_size,
            params,
            duration,
        } => setup_round_new(deps, env, info, sector_size, params, duration),
        ExecuteMsg::SetOwner { new_owner } => set_owner(deps, info, new_owner),
        ExecuteMsg::SubmitProof {
            proof_raw,
            public_inputs,
            porep_id,
            sector_size,
            api_version,
            prover_id,
            sector_id,
            ticket,
        } => submit_proof(
            deps,
            env,
            info,
            proof_raw,
            public_inputs,
            porep_id,
            sector_size,
            prover_id,
            sector_id,
            ticket,
            api_version,
        ),
    }
}

pub fn setup_round_new(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    sector_size: SupportedSectorSize,
    params: VerifierParameters,
    duration: u64,
) -> Result<Response, ContractError> {
    let current_round = CURRENT_ROUND.load(deps.storage)?;
    let now = env.block.time.seconds();

    ROUND_INFO.update(
        deps.storage,
        current_round.to_string(),
        |old_state: Option<InfoRound>| -> Result<InfoRound, ContractError> {
            match old_state {
                None => Ok(InfoRound {
                    time_expire: now + duration,
                    porep_id: params.setup_params.porep_id,
                }),
                Some(_x) => return Err(ContractError::KeyNotFound {})?,
            }
        },
    )?;

    CURRENT_ROUND.save(deps.storage, &(current_round + 1))?;

    let key = porep_key(
        &params.setup_params.porep_id,
        sector_size,
        &params.setup_params.api_version,
    )?;
    set_params(deps, info, &key, params)?;

    Ok(Response::default())
}

pub fn submit_proof(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    proof_raw: Binary,
    public_inputs: PublicInputsPorep,
    porep_id: Binary,
    sector_size: SupportedSectorSize,
    prover_id: Binary,
    sector_id: u64,
    ticket: Binary,
    api_version: ApiVersion,
) -> Result<Response, ContractError> {
    let user = info.sender;
    let round_current = query_current_round(deps.as_ref())?.current_round - 1;

    if ROUND_INFO.load(deps.storage, round_current.to_string())?.time_expire < env.block.time.seconds() {
        return Err(ContractError::Timeout {  });
    }


    let hash_user = Binary(
        Sha256::new()
            .chain_update(user.as_bytes())
            .finalize()
            .to_vec(),
    );

    if hash_user != prover_id {
        return Err(ContractError::VerifyHash {});
    }


    let key = (user.to_string(), round_current.to_string());
    let is_submit = match SUBMIT_SUCCESS.may_load(deps.storage, key.clone())? {
        Some(x) => x,
        None => false,
    };
    if is_submit {
        return Err(ContractError::AlreadySubmitProof {});
    }
    SUBMIT_SUCCESS.update(
        deps.storage,
        key,
        |_old_state: Option<bool>| -> Result<bool, ContractError> { Ok(true) },
    )?;
    let key = porep_key(&porep_id, sector_size, &api_version)?;
    let result = verify_proof(
        deps.as_ref(),
        &key,
        &proof_raw,
        &public_inputs,
        &porep_id,
        &prover_id,
        sector_id,
        &ticket,
    )?;
    if result {
        USER_REWARD.update(
            deps.storage,
            user.to_string(),
            |old_state: Option<i32>| -> Result<i32, ContractError> {
                match old_state {
                    Some(x) => Ok(x + 1),
                    None => Ok(1),
                }
            },
        )?;
        Ok(Response::default())
    } else {
        Err(ContractError::VerifyProof {})
    }
}

pub fn set_params(
    deps: DepsMut,
    info: MessageInfo,
    key: &[u8],
    params: VerifierParameters,
) -> Result<Response, ContractError> {
    if info.sender == config_read(deps.storage)?.owner {
        params_write(deps.storage, key, &params)?;
        Ok(Response::default())
    } else {
        Err(ContractError::Unauthorized {})
    }
}

pub fn set_owner(
    deps: DepsMut,
    info: MessageInfo,
    new_owner: Addr,
) -> Result<Response, ContractError> {
    let mut config = config_read(deps.storage)?;
    if info.sender == config.owner {
        config.owner = new_owner;
        config_write(deps.storage, &config)?;
        Ok(Response::default())
    } else {
        Err(ContractError::Unauthorized {})
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(_deps: DepsMut, _env: Env, _msg: MigrateMsg) -> StdResult<Response> {
    Ok(Response::default())
}

// ---------Query------>
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::QueryRoundCurrent {} => to_binary(&query_current_round(deps)?),
        QueryMsg::QueryUserReward { user } => to_binary(&query_user_reward(deps, user)?),
        QueryMsg::QueryListUser { limit, last_value } => query_users(deps, limit, last_value),
        QueryMsg::VerifyProof {
            proof_raw,
            public_inputs,
            porep_id,
            sector_size,
            api_version,
            prover_id,
            sector_id,
            ticket,
        } => to_binary(&verify_proof(
            deps,
            &porep_key(&porep_id, sector_size, &api_version)?,
            &proof_raw,
            &public_inputs,
            &porep_id,
            &prover_id,
            sector_id,
            &ticket,
        )?),
    }
}

fn query_current_round(deps: Deps) -> StdResult<CurrentRoundResponse> {
    let round = CURRENT_ROUND.load(deps.storage)?;
    Ok(CurrentRoundResponse {
        current_round: round,
    })
}

fn query_user_reward(deps: Deps, user: String) -> StdResult<i32> {
    let reward = USER_REWARD.load(deps.storage, user).unwrap_or_default();
    Ok(reward)
}

pub fn verify_proof(
    deps: Deps,
    key: &[u8],
    proof_raw: &[u8],
    public_inputs: &PublicInputsPorep,
    porep_id: &[u8],
    prover_id: &[u8],
    sector_id: u64,
    ticket: &[u8],
) -> StdResult<bool> {
    let params = params_read(deps.storage, key)?;

    let replica_id = public_inputs.replica_id;
    let comm_d = public_inputs
        .tau
        .as_ref()
        .ok_or(StdError::generic_err("missing_tau"))?
        .comm_d;

    if !check_replica_id(prover_id, sector_id, ticket, comm_d, porep_id, replica_id) {
        return Ok(false);
    }

    let public_params = VerifierStackedDrgPorep::setup(&params.setup_params).unwrap();

    let requirements = ChallengeRequirements {
        minimum_challenges: params.minimum_challenges,
    };

    if !VerifierStackedDrgPorep::satisfies_requirements(&public_params, &requirements, 1) {
        return Err(StdError::generic_err("failed to satisfy requirements"));
    }

    let inputs =
        VerifierStackedDrgPorep::generate_public_inputs(public_inputs, &public_params, Some(0))
            .unwrap();

    // using groth16_verify
    let res = groth16_verify(
        &prepare_verifying_key(
            &VerifyingKey::<ark_bls12_381::Bls12_381>::deserialize(&params.vk as &[u8]).unwrap(),
        ),
        &Proof::deserialize(proof_raw).unwrap(),
        &inputs,
    );

    // let res = deps.api.groth16_verify(
    //     &arkworks_native_gadgets::from_field_elements(&inputs).unwrap(),
    //     proof_raw,
    //     &params.vk,
    //     0,
    // );

    res.map_err(|err| StdError::generic_err(err.to_string()))
}

pub fn query_users(deps: Deps, limit: u32, last_value: Option<String>) -> StdResult<Binary> {
    let users: StdResult<Vec<String>> = match last_value {
        Some(x) => USER_REWARD
            .keys(
                deps.storage,
                Some(Bound::exclusive(x)),
                None,
                Order::Ascending,
            )
            .take(limit as usize)
            .collect(),
        None => USER_REWARD
            .keys(deps.storage, None, None, Order::Ascending)
            .take(limit as usize)
            .collect(),
    };

    to_binary(&users?)
}
