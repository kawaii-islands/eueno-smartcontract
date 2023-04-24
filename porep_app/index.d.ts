declare module 'porep_app' {
  /* tslint:disable */
  /* eslint-disable */

  export type SupportedSectorSize = 'SectorSize2Kib' | 'SectorSize4Kib' | 'SectorSize16Kib' | 'SectorSize32Kib' | 'SectorSize8Mib' | 'SectorSize16Mib' | 'SectorSize512Mib' | 'SectorSize1Gib' | 'SectorSize32Gib' | 'SectorSize64Gib';

  export type ApiVersion = '1.0.0' | '1.1.0';

  export interface SetupParams {
    nodes: number;
    degree: number;
    expansion_degree: number;
    porep_id: string;
    layer_challenges: {
      layers: number;
      max_count: number;
    };
    api_version: ApiVersion;
  }

  export interface SetupResult {
    setup_params: SetupParams;
    vk_le: string;
  }

  export interface Setup {
    sector_size: SupportedSectorSize;
    porep_id: string;
    api_version: ApiVersion;
  }

  export interface SealResult {
    sector_size: number;
    proof_le: string;
    public_inputs: string;
  }

  export interface Seal {
    // setup
    setup_params: SetupParams;

    // public input
    file_path: string;
    prover_id?: string; // hex
    sector_id?: string; // dec
    seed?: string; // hex,
    ticket?: string; // hex
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
}
