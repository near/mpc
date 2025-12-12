use alloc::vec::Vec;
use attestation::{
    app_compose::AppCompose,
    attestation::{GetSingleEvent as _, OrErr as _},
    measurements::ExpectedMeasurements,
    report_data::ReportData,
};

pub use attestation::attestation::{DstackAttestation, VerificationError};
use mpc_primitives::hash::{LauncherDockerComposeHash, MpcDockerImageHash};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::alloc::format;
use crate::alloc::string::ToString;

const MPC_IMAGE_HASH_EVENT: &str = "mpc-image-digest";

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Attestation {
    Mock(MockAttestation),
    Dstack(DstackAttestation),
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Serialize, Deserialize, BorshDeserialize, BorshSerialize)]
pub enum VerifiedAttestation {
    Mock(MockAttestation),
    Dstack(ValidatedDstackAttestation),
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshDeserialize, BorshSerialize)]
pub struct ValidatedDstackAttestation {
    pub mpc_image_hash: MpcDockerImageHash,
    pub launcher_compose_hash: LauncherDockerComposeHash,
    // TODO: This timestamp can not come from the contract,
    // but should be extracted from the certificate itself.
    pub creation_time_stamp_seonds: u64,
}

impl VerifiedAttestation {
    pub fn re_verify(
        &self,
        timestamp_seconds: u64,
        max_attestation_age_seconds: u64,
        allowed_mpc_docker_image_hashes: &[MpcDockerImageHash],
        allowed_launcher_docker_compose_hashes: &[LauncherDockerComposeHash],
    ) -> Result<(), VerificationError> {
        match self {
            Self::Dstack(ValidatedDstackAttestation {
                mpc_image_hash,
                launcher_compose_hash,
                creation_time_stamp_seonds,
            }) => {
                let expiry_time = creation_time_stamp_seonds + max_attestation_age_seconds;
                let attestation_has_expired = expiry_time < timestamp_seconds;

                if attestation_has_expired {
                    return Err(VerificationError::Custom(format!(
                        "The attestation expired at t = {:?}, time_now = {:?}",
                        expiry_time, timestamp_seconds
                    )));
                }

                let () = verify_mpc_hash(mpc_image_hash, allowed_mpc_docker_image_hashes)?;
                let () = verify_launcher_compose_hash(
                    launcher_compose_hash,
                    allowed_launcher_docker_compose_hashes,
                )?;

                Ok(())
            }
            Self::Mock(mock_attestation) => {
                // Only kick out enforce max age of attestation, if it's constrained
                verify_mock_attestation(
                    mock_attestation,
                    allowed_mpc_docker_image_hashes,
                    allowed_launcher_docker_compose_hashes,
                    timestamp_seconds,
                    Some(max_attestation_age_seconds),
                )
            }
        }
    }
}

impl Attestation {
    pub fn verify(
        &self,
        expected_report_data: ReportData,
        creation_timestamp_seconds: u64,
        allowed_mpc_docker_image_hashes: &[MpcDockerImageHash],
        allowed_launcher_docker_compose_hashes: &[LauncherDockerComposeHash],
    ) -> Result<VerifiedAttestation, VerificationError> {
        match self {
            Self::Dstack(dstack_attestation) => {
                // Makes MPC related attestation verification first
                let mpc_image_hash: MpcDockerImageHash = {
                    let mpc_image_hash_payload = &dstack_attestation
                        .tcb_info
                        .get_single_event(MPC_IMAGE_HASH_EVENT)?
                        .event_payload;

                    let mpc_image_hash_bytes: Vec<u8> = hex::decode(mpc_image_hash_payload)
                        .map_err(|err| {
                            VerificationError::Custom(format!(
                                "provided mpc image is not hex encoded: {:?}",
                                err
                            ))
                        })?;
                    let mpc_image_hash_bytes: [u8; 32] =
                        mpc_image_hash_bytes.try_into().map_err(|_| {
                            VerificationError::Custom(
                                "The provided MPC image hash is not 32 bytes".to_string(),
                            )
                        })?;
                    MpcDockerImageHash::from(mpc_image_hash_bytes)
                };

                let () = verify_mpc_hash(&mpc_image_hash, allowed_mpc_docker_image_hashes)?;

                let launcher_compose_hash: LauncherDockerComposeHash = {
                    let app_compose: AppCompose =
                        serde_json::from_str(&dstack_attestation.tcb_info.app_compose)
                            .map_err(|e| VerificationError::AppComposeParsing(e.to_string()))?;

                    let launcher_compose_hash_bytes: [u8; 32] =
                        Sha256::digest(app_compose.docker_compose_file.as_bytes()).into();

                    LauncherDockerComposeHash::from(launcher_compose_hash_bytes)
                };

                let () = verify_launcher_compose_hash(
                    &launcher_compose_hash,
                    allowed_launcher_docker_compose_hashes,
                )?;

                // Embedded JSON assets
                const TCB_INFO_STRING_PROD: &str = include_str!("../assets/tcb_info.json");
                // TODO Security #1433 - remove dev measurements from production builds after testing is complete.
                const TCB_INFO_STRING_DEV: &str = include_str!("../assets/tcb_info_dev.json");

                let accepted_measurements = ExpectedMeasurements::from_embedded_tcb_info(&[
                    TCB_INFO_STRING_PROD,
                    TCB_INFO_STRING_DEV,
                ])
                .map_err(VerificationError::EmbeddedMeasurementsParsing)?;

                dstack_attestation.verify(
                    expected_report_data,
                    creation_timestamp_seconds,
                    &accepted_measurements,
                )?;

                Ok(VerifiedAttestation::Dstack(ValidatedDstackAttestation {
                    mpc_image_hash,
                    launcher_compose_hash,
                    creation_time_stamp_seonds: creation_timestamp_seconds,
                }))
            }
            Self::Mock(mock_attestation) => {
                // Override attestation verification for this case
                verify_mock_attestation(
                    mock_attestation,
                    allowed_mpc_docker_image_hashes,
                    allowed_launcher_docker_compose_hashes,
                    creation_timestamp_seconds,
                    None,
                )?;

                Ok(VerifiedAttestation::Mock(mock_attestation.clone()))
            }
        }
    }
}

/// Verifies MPC node image hash is in allowed list.
fn verify_mpc_hash(
    image_hash: &MpcDockerImageHash,
    allowed_hashes: &[MpcDockerImageHash],
) -> Result<(), VerificationError> {
    if allowed_hashes.is_empty() {
        return Err(VerificationError::Custom(
            "the allowed mpc image hashes list is empty".to_string(),
        ));
    }

    let image_hash_is_allowed = allowed_hashes.contains(image_hash);
    if !image_hash_is_allowed {
        return Err(VerificationError::Custom(format!(
            "MPC image hash {:?} is not in the allowed hashes list",
            image_hash
        )));
    }

    Ok(())
}

fn verify_launcher_compose_hash(
    launcher_compose_hash: &LauncherDockerComposeHash,
    allowed_hashes: &[LauncherDockerComposeHash],
) -> Result<(), VerificationError> {
    if allowed_hashes.is_empty() {
        return Err(VerificationError::Custom(
            "the allowed mpc laucher compose hashes list is empty".to_string(),
        ));
    }

    let launcher_compose_hash_is_allowed = allowed_hashes.contains(launcher_compose_hash);

    if !launcher_compose_hash_is_allowed {
        return Err(VerificationError::Custom(format!(
            "MPC launcher compose hash {:?} is not in the allowed hashes list",
            launcher_compose_hash
        )));
    }

    Ok(())
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
        /// Unix time stamp for when this attestation was created.  
        creation_time_stamp_seconds: Option<u64>,
    },
}

pub(crate) fn verify_mock_attestation(
    mock_attestation: &MockAttestation,
    allowed_mpc_docker_image_hashes: &[MpcDockerImageHash],
    allowed_launcher_docker_compose_hashes: &[LauncherDockerComposeHash],
    time_now_seconds: u64,
    creation_timestamp_seconds: u64,
    max_attestation_age_seconds: Option<u64>,
) -> Result<(), VerificationError> {
    match mock_attestation {
        MockAttestation::Valid => Ok(()),
        MockAttestation::Invalid => Err(VerificationError::InvalidMockAttestation),
        MockAttestation::WithConstraints {
            mpc_docker_image_hash,
            launcher_docker_compose_hash,
            creation_time_stamp_seconds,
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

            match (max_attestation_age_seconds, creation_time_stamp_seconds) {
                (Some(max_attestation_age_seconds), Some(creation_time_stamp_seconds)) => {
                    let expiration_time = creation_time_stamp_seconds + max_attestation_age_seconds;
                    let is_expired = time_now_seconds
                        > (creation_timestamp_seconds < *expiry_timestamp).or_err(|| {
                            VerificationError::ExpiredCertificate {
                                attestation_time: creation_timestamp_seconds,
                                expiry_time: *expiry_timestamp,
                            }
                        })?;
                }
                _ => {}
            }

            Ok(())
        }
    }
}
