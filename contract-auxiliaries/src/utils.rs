use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

#[derive(Copy, Clone, Eq, PartialEq, Deserialize, Debug, Serialize, JsonSchema)]
pub enum ApiVersion {
    V1_0_0,
    V1_1_0,
}

pub const NODE_SIZE: usize = 32;

/// Returns the start position of the data, 0-indexed.
pub fn data_at_node_offset(v: usize) -> usize {
    v * NODE_SIZE
}

pub fn porep_key(porep_id: String, sector_size: u64, api_version: ApiVersion) -> String {
    let porep_id = hex::decode(&porep_id).unwrap();
    let hash = Sha256::new()
        .chain_update(&porep_id)
        .chain_update(sector_size.to_le_bytes())
        .chain_update(match api_version {
            ApiVersion::V1_0_0 => &[0],
            ApiVersion::V1_1_0 => &[1],
        })
        .finalize();
    let bytes: [u8; 32] = hash.into();
    hex::encode(bytes)
}
