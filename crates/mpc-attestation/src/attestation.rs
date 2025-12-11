use attestation::{
    TcbInfo,
    app_compose::AppCompose,
    attestation::{GetSingleEvent as _, OrErr as _},
    measurements::ExpectedMeasurements,
    report_data::ReportData,
};

include!(concat!(env!("OUT_DIR"), "/measurements_generated.rs"));

/// Returns all statically compiled TCB measurement sets.
///
/// This combines prod/dev (or any future) measurement JSON files
/// into a single slice generated at build time.
pub fn all_expected_measurements() -> &'static [ExpectedMeasurements] {
    EXPECTED_MEASUREMENTS
}

pub use attestation::attestation::{DstackAttestation, VerificationError};

use mpc_primitives::hash::{LauncherDockerComposeHash, MpcDockerImageHash};

use borsh::{BorshDeserialize, BorshSerialize};
use core::ops::Deref as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::alloc::format;
use crate::alloc::string::ToString;

const MPC_IMAGE_HASH_EVENT: &str = "mpc-image-digest";

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
            Self::Dstack(dstack_attestation) => {
                // Makes MPC related attestation verification first
                if allowed_mpc_docker_image_hashes.is_empty() {
                    return Err(VerificationError::Custom(
                        "the allowed mpc image hashes list is empty".to_string(),
                    ));
                }
                if allowed_launcher_docker_compose_hashes.is_empty() {
                    return Err(VerificationError::Custom(
                        "the allowed mpc laucher compose hashes list is empty".to_string(),
                    ));
                }
                self.verify_mpc_hash(
                    &dstack_attestation.tcb_info,
                    allowed_mpc_docker_image_hashes,
                )?;
                self.verify_launcher_compose_hash(
                    &dstack_attestation.tcb_info,
                    allowed_launcher_docker_compose_hashes,
                )?;

                dstack_attestation
            }
            Self::Mock(mock_attestation) => {
                // Override attestation verification for this case
                return verify_mock_attestation(
                    mock_attestation,
                    allowed_mpc_docker_image_hashes,
                    allowed_launcher_docker_compose_hashes,
                    timestamp_seconds,
                );
            }
        };

        let accepted_measurements = all_expected_measurements();

        attestation.verify(
            expected_report_data,
            timestamp_seconds,
            accepted_measurements,
        )
    }

    /// Verifies MPC node image hash is in allowed list.
    fn verify_mpc_hash(
        &self,
        tcb_info: &TcbInfo,
        allowed_hashes: &[MpcDockerImageHash],
    ) -> Result<(), VerificationError> {
        let event = tcb_info.get_single_event(MPC_IMAGE_HASH_EVENT)?;

        allowed_hashes
            .iter()
            .any(|hash| hash.as_hex() == *event.event_payload)
            .or_err(|| {
                VerificationError::Custom(format!(
                    "MPC image hash {} is not in the allowed hashes list",
                    event.event_payload.clone()
                ))
            })
    }

    fn verify_launcher_compose_hash(
        &self,
        tcb_info: &TcbInfo,
        allowed_hashes: &[LauncherDockerComposeHash],
    ) -> Result<(), VerificationError> {
        let app_compose: AppCompose = serde_json::from_str(&tcb_info.app_compose)
            .map_err(|e| VerificationError::AppComposeParsing(e.to_string()))?;

        let launcher_bytes: [u8; 32] =
            Sha256::digest(app_compose.docker_compose_file.as_bytes()).into();

        allowed_hashes
            .iter()
            .any(|hash| hash.deref() == &launcher_bytes)
            .or_err(|| {
                VerificationError::Custom(format!(
                    "launcher compose hash {} is not in the allowed hashes list",
                    hex::encode(launcher_bytes.as_ref(),)
                ))
            })
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, BorshDeserialize, BorshSerialize)]
pub enum MockAttestation {
    #[default]
    /// Always pass validation
    Valid,
    /// Always fails validation
    Invalid,
    /// Pass validation depending on the set constraints
    WithConstraints {
        mpc_docker_image_hash: Option<MpcDockerImageHash>,
        launcher_docker_compose_hash: Option<LauncherDockerComposeHash>,

        /// Unix time stamp for when this attestation expires.  
        expiry_time_stamp_seconds: Option<u64>,
    },
}

pub(crate) fn verify_mock_attestation(
    mock_attestation: &MockAttestation,
    allowed_mpc_docker_image_hashes: &[MpcDockerImageHash],
    allowed_launcher_docker_compose_hashes: &[LauncherDockerComposeHash],
    timestamp_seconds: u64,
) -> Result<(), VerificationError> {
    match mock_attestation {
        MockAttestation::Valid => Ok(()),
        MockAttestation::Invalid => Err(VerificationError::InvalidMockAttestation),
        MockAttestation::WithConstraints {
            mpc_docker_image_hash,
            launcher_docker_compose_hash,
            expiry_time_stamp_seconds: expiry_timestamp_seconds,
        } => {
            if let Some(hash) = mpc_docker_image_hash {
                if allowed_mpc_docker_image_hashes.is_empty() {
                    return Err(VerificationError::Custom(
                        "the allowed mpc image hashes list is empty".to_string(),
                    ));
                }
                allowed_mpc_docker_image_hashes.contains(hash).or_err(|| {
                    VerificationError::Custom(format!(
                        "MPC image hash {} is not in the allowed hashes list",
                        hex::encode(hash.as_ref(),)
                    ))
                })?;
            };

            if let Some(hash) = launcher_docker_compose_hash {
                if allowed_launcher_docker_compose_hashes.is_empty() {
                    return Err(VerificationError::Custom(
                        "the allowed mpc laucher compose hashes list is empty".to_string(),
                    ));
                }
                allowed_launcher_docker_compose_hashes
                    .contains(hash)
                    .or_err(|| {
                        VerificationError::Custom(format!(
                            "launcher compose hash {} is not in the allowed hashes list",
                            hex::encode(hash.as_ref(),)
                        ))
                    })?;
            };
            if let Some(expiry_timestamp) = expiry_timestamp_seconds {
                (timestamp_seconds < *expiry_timestamp).or_err(|| {
                    VerificationError::ExpiredCertificate {
                        attestation_time: timestamp_seconds,
                        expiry_time: *expiry_timestamp,
                    }
                })?;
            };

            Ok(())
        }
    }
}
