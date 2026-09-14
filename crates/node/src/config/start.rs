use launcher_interface::types::{PccsEndpointConfig, TeeAuthorityConfig, TeeConfig};
use near_mpc_bounded_collections::NonEmptyVec;
use tee_authority::tee_authority::{
    DstackTeeAuthorityConfig, LocalTeeAuthorityConfig, TeeAuthority, validate_pccs_endpoints,
};

pub trait TeeAuthorityImpl {
    fn into_tee_authority(
        self,
        pccs_endpoints: NonEmptyVec<PccsEndpointConfig>,
    ) -> anyhow::Result<TeeAuthority>;
}

impl TeeAuthorityImpl for TeeConfig {
    fn into_tee_authority(
        self,
        pccs_endpoints: NonEmptyVec<PccsEndpointConfig>,
    ) -> anyhow::Result<TeeAuthority> {
        validate_pccs_endpoints(&pccs_endpoints)?;
        Ok(match self.authority {
            TeeAuthorityConfig::Local => LocalTeeAuthorityConfig::default().into(),
            TeeAuthorityConfig::Dstack { dstack_endpoint } => {
                DstackTeeAuthorityConfig::new(dstack_endpoint, pccs_endpoints).into()
            }
        })
    }
}

#[cfg(feature = "embedded-node")]
mod embedded;
#[cfg(feature = "embedded-node")]
pub(crate) use embedded::read_near_config_json;
#[cfg(feature = "embedded-node")]
pub use embedded::{NearInitConfigExt, StartConfigExt};
