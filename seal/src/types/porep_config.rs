use proofs_core::api_version::ApiVersion;

use crate::types::{PaddedBytesAmount, SectorSize, UnpaddedBytesAmount};

#[derive(Clone, Debug)]
pub struct PoRepConfig {
    pub sector_size: SectorSize,
    pub porep_id: [u8; 32],
    pub api_version: ApiVersion,
}

impl From<PoRepConfig> for PaddedBytesAmount {
    fn from(x: PoRepConfig) -> Self {
        let PoRepConfig { sector_size, .. } = x;
        PaddedBytesAmount::from(sector_size)
    }
}

impl From<PoRepConfig> for UnpaddedBytesAmount {
    fn from(x: PoRepConfig) -> Self {
        let PoRepConfig { sector_size, .. } = x;
        PaddedBytesAmount::from(sector_size).into()
    }
}

impl From<PoRepConfig> for SectorSize {
    fn from(cfg: PoRepConfig) -> Self {
        let PoRepConfig { sector_size, .. } = cfg;
        sector_size
    }
}

impl PoRepConfig {
    /// construct PoRepConfig by groth16
    pub fn new_groth16(sector_size: u64, porep_id: [u8; 32], api_version: ApiVersion) -> Self {
        Self {
            sector_size: SectorSize(sector_size),
            porep_id,
            api_version,
        }
    }

    #[inline]
    pub fn padded_bytes_amount(&self) -> PaddedBytesAmount {
        PaddedBytesAmount::from(self.sector_size)
    }

    #[inline]
    pub fn unpadded_bytes_amount(&self) -> UnpaddedBytesAmount {
        self.padded_bytes_amount().into()
    }

    // /// Returns the cache identifier as used by `storage-proofs::parameter_cache`.
    // pub fn get_cache_identifier<Tree: 'static + MerkleTreeTrait>(&self) -> Result<String> {
    //     let params = public_params::<Tree>(
    //         self.sector_size.into(),
    //         self.partitions.into(),
    //         self.porep_id,
    //         self.api_version,
    //     )?;

    //     Ok(
    //         <StackedCompound<Tree, DefaultPieceHasher> as CacheableParameters<
    //             StackedCircuit<'_, Tree, DefaultPieceHasher>,
    //             _,
    //         >>::cache_identifier(&params),
    //     )
    // }

    // pub fn get_cache_metadata_path<Tree: 'static + MerkleTreeTrait>(&self) -> Result<PathBuf> {
    //     let id = self.get_cache_identifier::<Tree>()?;
    //     Ok(parameter_cache_metadata_path(&id))
    // }

    // pub fn get_cache_verifying_key_path<Tree: 'static + MerkleTreeTrait>(&self) -> Result<PathBuf> {
    //     let id = self.get_cache_identifier::<Tree>()?;
    //     Ok(parameter_cache_verifying_key_path(&id))
    // }

    // pub fn get_cache_params_path<Tree: 'static + MerkleTreeTrait>(&self) -> Result<PathBuf> {
    //     let id = self.get_cache_identifier::<Tree>()?;
    //     Ok(parameter_cache_params_path(&id))
    // }
}
