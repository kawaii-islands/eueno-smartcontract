export type ApiVersion = "V1_0_0" | "V1_1_0";
export type Binary = string;
export type SupportedSectorSize = "sector_size2_kib" | "sector_size4_kib" | "sector_size16_kib" | "sector_size32_kib" | "sector_size8_mib" | "sector_size16_mib" | "sector_size512_mib" | "sector_size1_gib" | "sector_size32_gib" | "sector_size64_gib";
export type Addr = string;
export type PoseidonDomain = [number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number];
export type Sha256Domain = [number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number];
export interface VerifierParameters {
  minimum_challenges: number;
  setup_params: SetupParams;
  vk: Binary;
}
export interface SetupParams {
  api_version: ApiVersion;
  degree: number;
  expansion_degree: number;
  layer_challenges: LayerChallenges;
  nodes: number;
  porep_id: [number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number];
  [k: string]: unknown;
}
export interface LayerChallenges {
  layers: number;
  max_count: number;
  [k: string]: unknown;
}
export interface PublicInputsForPoseidonDomainAndSha256Domain {
  k?: number | null;
  replica_id: PoseidonDomain;
  seed: [number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number];
  tau?: TauForPoseidonDomainAndSha256Domain | null;
  [k: string]: unknown;
}
export interface TauForPoseidonDomainAndSha256Domain {
  comm_d: Sha256Domain;
  comm_r: PoseidonDomain;
  [k: string]: unknown;
}
export type ArrayOfString = string[];
export type Int32 = number;
export type Boolean = boolean;