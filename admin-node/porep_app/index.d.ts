/* tslint:disable */
/* eslint-disable */

import { ApiVersion, Binary, PublicInputsForPoseidonDomainAndSha256Domain, SetupParams, SupportedSectorSize } from '../contract/types';

export interface SetupResult {
  setup_params: SetupParams;
  vk_raw: Binary;
}

export interface Setup {
  sector_size: SupportedSectorSize;
  porep_id: string;
  api_version: ApiVersion;
}

export interface SealResult {
  sector_size: number;
  proof_raw: Binary;
  public_inputs: PublicInputsForPoseidonDomainAndSha256Domain;
}

export interface Seal {
  // setup
  porep_id: string;
  api_version: ApiVersion;

  // public input
  file_path: string;
  prover_id: string; // base64
  sector_id: number; // base64
  ticket: string; // base64
  seed?: string; // base64,
}

/**
 * @param {Setup} args
 * @returns {string}
 */
export function setup(args: Setup): SetupResult;
/**
 * @param {UinSealt8Array} args
 * @returns {string}
 */
export function seal(args: Seal): SealResult;
