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

            // Check for expiry
            if let (Some(max_attestation_age_seconds), Some(creation_time_stamp_seconds)) =
                (max_attestation_age_seconds, creation_time_stamp_seconds)
            {
                let expiry_time = creation_time_stamp_seconds + max_attestation_age_seconds;
                let is_valid = time_now_seconds < expiry_time;

                is_valid.or_err(|| VerificationError::ExpiredCertificate {
                    attestation_time: *creation_time_stamp_seconds,
                    expiry_time,
                })?
            }

            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn mock_constrained_verification_passes_if_hash_in_allowed_list() {
        let allowed_hash = MpcDockerImageHash::from([42; 32]);

        let hash_constrained_attestation =
            VerifiedAttestation::Mock(MockAttestation::WithConstraints {
                mpc_docker_image_hash: Some(allowed_hash.clone()),
                launcher_docker_compose_hash: None,
                creation_time_stamp_seconds: None,
            });

        let other_hash = MpcDockerImageHash::from([1; 32]);
        let allowed_mpc_hashes: Vec<MpcDockerImageHash> = vec![other_hash, allowed_hash];

        hash_constrained_attestation
            .re_verify(0, 0, &allowed_mpc_hashes, &[])
            .expect("constrained mpc image hash is allowed and should therefore pass validation");
    }

    #[test]
    fn mock_constrained_verification_fails_if_hash_not_in_allowed_list() {
        let restricted_hash = MpcDockerImageHash::from([42; 32]);

        let hash_constrained_attestation =
            VerifiedAttestation::Mock(MockAttestation::WithConstraints {
                mpc_docker_image_hash: Some(restricted_hash),
                launcher_docker_compose_hash: None,
                creation_time_stamp_seconds: None,
            });

        let other_hash = MpcDockerImageHash::from([1; 32]);
        let allowed_mpc_hashes: Vec<MpcDockerImageHash> = vec![other_hash];

        let result = hash_constrained_attestation.re_verify(0, 0, &allowed_mpc_hashes, &[]);

        match result {
            Err(VerificationError::Custom(msg)) => {
                assert!(
                    msg.contains("MPC image hash"),
                    "Expected error message regarding MPC image hash, got: {}",
                    msg
                );
            }
            _ => panic!("Expected Custom VerificationError, got: {:?}", result),
        }
    }

    #[test]
    fn mock_constrained_verification_fails_if_allowed_list_is_empty() {
        let restricted_hash = MpcDockerImageHash::from([42; 32]);

        let hash_constrained_attestation =
            VerifiedAttestation::Mock(MockAttestation::WithConstraints {
                mpc_docker_image_hash: Some(restricted_hash),
                launcher_docker_compose_hash: None,
                creation_time_stamp_seconds: None,
            });

        let allowed_mpc_hashes: Vec<MpcDockerImageHash> = vec![];

        let result = hash_constrained_attestation.re_verify(0, 0, &allowed_mpc_hashes, &[]);

        match result {
            Err(VerificationError::Custom(msg)) => {
                assert!(msg.contains("list is empty"));
            }
            _ => panic!("Expected empty list error, got: {:?}", result),
        }
    }

    #[test]
    fn launcher_constraint_passes_if_hash_in_allowed_list() {
        let allowed_hash = LauncherDockerComposeHash::from([99; 32]);

        let hash_constrained_attestation =
            VerifiedAttestation::Mock(MockAttestation::WithConstraints {
                mpc_docker_image_hash: None,
                launcher_docker_compose_hash: Some(allowed_hash.clone()),
                creation_time_stamp_seconds: None,
            });

        let other_hash = LauncherDockerComposeHash::from([1; 32]);
        let allowed_launcher_hashes: Vec<LauncherDockerComposeHash> =
            vec![other_hash, allowed_hash];

        hash_constrained_attestation
            .re_verify(0, 0, &[], &allowed_launcher_hashes)
            .expect("constrained launcher hash is allowed and should therefore pass validation");
    }

    #[test]
    fn launcher_constraint_fails_if_hash_not_in_allowed_list() {
        let restricted_hash = LauncherDockerComposeHash::from([99; 32]);

        let hash_constrained_attestation =
            VerifiedAttestation::Mock(MockAttestation::WithConstraints {
                mpc_docker_image_hash: None,
                launcher_docker_compose_hash: Some(restricted_hash),
                creation_time_stamp_seconds: None,
            });

        let other_hash = LauncherDockerComposeHash::from([1; 32]);
        let allowed_launcher_hashes: Vec<LauncherDockerComposeHash> = vec![other_hash];

        let result = hash_constrained_attestation.re_verify(0, 0, &[], &allowed_launcher_hashes);

        match result {
            Err(VerificationError::Custom(msg)) => {
                assert!(msg.contains("launcher compose hash"));
            }
            _ => panic!("Expected Custom VerificationError, got: {:?}", result),
        }
    }

    #[test]
    fn mock_time_constraint_passes_if_time_is_within_expiry_window() {
        let creation_time = 1000;
        let max_age = 100;
        let time_now = 1050; // 1000 + 100 > 1050

        let time_constrained_attestation =
            VerifiedAttestation::Mock(MockAttestation::WithConstraints {
                mpc_docker_image_hash: None,
                launcher_docker_compose_hash: None,
                creation_time_stamp_seconds: Some(creation_time),
            });

        // NOTE: This test will FAIL with the current implementation because
        // the logic `expiry_time < timestamp_seconds` inside `re_verify` is inverted.
        time_constrained_attestation
            .re_verify(time_now, max_age, &[], &[])
            .expect("Attestation is within valid time window and should pass");
    }

    #[test]
    fn time_constraint_fails_if_time_is_past_expiry_window() {
        let creation_time = 1000;
        let max_age = 100;
        let time_now = 1200; // 1000 + 100 < 1200

        let time_constrained_attestation =
            VerifiedAttestation::Mock(MockAttestation::WithConstraints {
                mpc_docker_image_hash: None,
                launcher_docker_compose_hash: None,
                creation_time_stamp_seconds: Some(creation_time),
            });

        let verification_result =
            time_constrained_attestation.re_verify(time_now, max_age, &[], &[]);

        assert_matches::assert_matches!(
            verification_result,
            Err(VerificationError::ExpiredCertificate {
                attestation_time,
                expiry_time,
            }) if attestation_time == creation_time && expiry_time == creation_time + max_age
        );
    }
}
