use crate::{attestation::Attestation, report_data::ReportData};

pub struct LocalTeeAuthorityConfig;

pub struct DstackTeeAuthorityConfig;

pub enum TeeAuthority {
    Local(LocalTeeAuthorityConfig),
    Dstack(DstackTeeAuthorityConfig),
}

impl TeeAuthority {
    // TODO(#644): Implement the attestation quote generation logic in the attestation module
    pub async fn generate_attestation(&self, _report_data: ReportData) -> Attestation {
        match self {
            TeeAuthority::Local(_config) => {
                // Generate attestation using local TEE authority
                todo!("Implement local TEE attestation generation")
            }
            TeeAuthority::Dstack(_config) => {
                // Generate attestation using Dstack TEE authority
                todo!("Implement Dstack TEE attestation generation")
            }
        }
    }
}
