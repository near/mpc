use crate::{attestation::Attestation, report_data::ReportData};

pub struct LocalTeeAuthorityConfig;

pub struct DstackTeeAuthorityConfig;

enum TeeAuthority {
    Local(LocalTeeAuthorityConfig),
    Dstack(DstackTeeAuthorityConfig),
}

impl TeeAuthority {
    async fn generate_attestation(&self, _report_data: ReportData) -> Attestation {
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
