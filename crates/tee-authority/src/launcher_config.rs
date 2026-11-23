use crate::tee_authority::{
    DstackTeeAuthorityConfig, LocalTeeAuthorityConfig, TeeAuthority, validate_pccs_endpoints,
};
use launcher_interface::types::{PccsEndpointConfig, TeeAuthorityConfig};
use near_mpc_bounded_collections::NonEmptyVec;

impl TeeAuthority {
    /// Builds the [`TeeAuthority`] the launcher configured. Fails when a PCCS endpoint's TLS
    /// trust override cannot be built.
    pub fn new(
        authority: TeeAuthorityConfig,
        pccs_endpoints: NonEmptyVec<PccsEndpointConfig>,
    ) -> anyhow::Result<Self> {
        validate_pccs_endpoints(&pccs_endpoints)?;
        Ok(match authority {
            TeeAuthorityConfig::Local => LocalTeeAuthorityConfig::default().into(),
            TeeAuthorityConfig::Dstack { dstack_endpoint } => {
                DstackTeeAuthorityConfig::new(dstack_endpoint, pccs_endpoints).into()
            }
        })
    }
}
