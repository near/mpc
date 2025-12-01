pub use attestation::{
    attestation::{DstackAttestation, MockAttestation, VerificationError},
    measurements::ExpectedMeasurements,
    report_data::ReportData,
};

use mpc_primitives::hash::{LauncherDockerComposeHash, MpcDockerImageHash};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::measurements::EXPECTED_LOCAL_SGX_EVENT_DIGEST;

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Serialize, Deserialize, BorshDeserialize, BorshSerialize)]
pub enum Attestation {
    Dstack(DstackAttestation),
    Mock(MockAttestation),
}

impl Attestation {
    pub fn verify(
        &self,
        expected_report_data: ReportData,
        timestamp_seconds: u64,
        allowed_mpc_docker_image_hashes: &[MpcDockerImageHash],
        allowed_launcher_docker_compose_hashes: &[LauncherDockerComposeHash],
    ) -> Result<(), VerificationError> {
        let attestation = match self {
            // TODO: we should avoid the clone here, but doing so will
            // probably require changing API
            Self::Dstack(dstack_attestation) => {
                attestation::attestation::Attestation::Dstack(dstack_attestation.clone())
            }
            Self::Mock(mock_attestation) => {
                attestation::attestation::Attestation::Mock(mock_attestation.clone())
            }
        };

        // Embedded JSON assets
        const TCB_INFO_STRING_PROD: &str = include_str!("../assets/tcb_info.json");
        // TODO Security #1433 - remove dev measurements from production builds after testing is complete.
        const TCB_INFO_STRING_DEV: &str = include_str!("../assets/tcb_info_dev.json");

        let expected_measurements_list = ExpectedMeasurements::from_embedded_tcb_info(&[
            TCB_INFO_STRING_PROD,
            TCB_INFO_STRING_DEV,
        ])
        .map_err(VerificationError::EmbeddedMeasurementsParsing)?;

        attestation.verify(
            expected_report_data,
            timestamp_seconds,
            allowed_mpc_docker_image_hashes,
            allowed_launcher_docker_compose_hashes,
            &expected_measurements_list,
            &EXPECTED_LOCAL_SGX_EVENT_DIGEST,
        )
    }
}
