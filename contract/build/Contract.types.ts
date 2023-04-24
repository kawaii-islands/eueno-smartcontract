import {ApiVersion, Binary, SupportedSectorSize, Addr, PoseidonDomain, Sha256Domain, VerifierParameters, SetupParams, LayerChallenges, PublicInputsForPoseidonDomainAndSha256Domain, TauForPoseidonDomainAndSha256Domain, ArrayOfString, Int32, Boolean} from "./types";
export interface InstantiateMsg {}
export type ExecuteMsg = {
  set_verifier_params: {
    duration: number;
    params: VerifierParameters;
    sector_size: SupportedSectorSize;
  };
} | {
  set_owner: {
    new_owner: Addr;
  };
} | {
  submit_proof: {
    api_version: ApiVersion;
    porep_id: Binary;
    proof_raw: Binary;
    prover_id: Binary;
    public_inputs: PublicInputsForPoseidonDomainAndSha256Domain;
    sector_id: number;
    sector_size: SupportedSectorSize;
    ticket: Binary;
  };
};
export type QueryMsg = {
  query_round_current: {};
} | {
  query_user_reward: {
    user: string;
  };
} | {
  query_list_user: {
    last_value?: string | null;
    limit: number;
  };
} | {
  verify_proof: {
    api_version: ApiVersion;
    porep_id: Binary;
    proof_raw: Binary;
    prover_id: Binary;
    public_inputs: PublicInputsForPoseidonDomainAndSha256Domain;
    sector_id: number;
    sector_size: SupportedSectorSize;
    ticket: Binary;
  };
};
export interface CurrentRoundResponse {
  current_round: number;
}