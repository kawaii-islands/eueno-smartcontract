use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Unauthorized")]
    Unauthorized {},

    #[error("verify hash address failed")]
    VerifyHash {},

    #[error("verify proof failed")]
    VerifyProof {},

    #[error("time out")]
    Timeout {},

    #[error("Key doesn't exist")]
    KeyNotFound {},

    #[error("Update status submit proof of user failed")]
    UpdateStatusUserSubmitProof {},

    #[error("Already submit proof")]
    AlreadySubmitProof {},
    // Add any other custom errors you like here.
    // Look at https://docs.rs/thiserror/1.0.21/thiserror/ for details.
}
