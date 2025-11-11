use crate::{
    app_compose::AppCompose,
    collateral::Collateral,
    measurements::{ExpectedMeasurements, MeasurementsError},
    quote::QuoteBytes,
    report_data::ReportData,
};
use alloc::{
    format,
    string::{String, ToString},
};
use borsh::{BorshDeserialize, BorshSerialize};
use core::{fmt, ops::Deref as _};
use dcap_qvl::verify::VerifiedReport;
use derive_more::Constructor;
use dstack_sdk_types::dstack::{EventLog, TcbInfo};
use mpc_primitives::hash::{LauncherDockerComposeHash, MpcDockerImageHash};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256, Sha384};

/// Expected TCB status for a successfully verified TEE quote.
const EXPECTED_QUOTE_STATUS: &str = "UpToDate";

// DSTACK_EVENT_TYPE is defined in https://github.com/Dstack-TEE/dstack/blob/cfa4cc4e8a4f525d537883b1a0ba5d9fbfd87f1e/tdx-attest/src/lib.rs#L28
// It is the same for all events
const DSTACK_EVENT_TYPE: u32 = 134217729;

const COMPOSE_HASH_EVENT: &str = "compose-hash";
const KEY_PROVIDER_EVENT: &str = "key-provider";
const MPC_IMAGE_HASH_EVENT: &str = "mpc-image-digest";

const RTMR3_INDEX: u32 = 3;

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Serialize, Deserialize, BorshDeserialize, BorshSerialize)]
pub enum Attestation {
    Dstack(DstackAttestation),
    Mock(MockAttestation),
}

#[derive(Clone, Constructor, Serialize, Deserialize, BorshDeserialize, BorshSerialize)]
pub struct DstackAttestation {
    pub quote: QuoteBytes,
    pub collateral: Collateral,
    pub tcb_info: TcbInfo,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum VerificationError {
    #[error("could not parse embedded measurements: {0}")]
    EmbeddedMeasurementsParsing(MeasurementsError),
    #[error("dcap verification failed: {0}")]
    DcapVerification(String),
    #[error("verification report is not TD10")]
    ReportNotTd10,
    #[error("TCB status `{0}` is not up to date")]
    TcbStatusNotUpToDate(String),
    #[error("ouststanding advisories reported: {0}")]
    NonEmptyAdvisoryIds(String),
    #[error("wrong {name} hash (found {found} expected {expected})")]
    WrongHash {
        name: &'static str,
        found: String,
        expected: String,
    },
    #[error("invalid event type {0}")]
    InvalidEventType(u32),
    #[error("failed to decode event digest `{0}`")]
    EventDecoding(String),
    #[error("failed to parse app compose JSON: {0}")]
    AppComposeParsing(String),
    #[error("no {0} event in event log")]
    MissingEvent(&'static str),
    #[error("duplicate {0} events in event log")]
    DuplicateEvent(&'static str),
    #[error("invalid app compose config: `{0}`")]
    InvalidAppComposeConfig(String),
    #[error("app-compose event payload had an unexpected size of {0}")]
    AppComposeEventPayloadWrongSize(usize),
    #[error("app-compose event payload `{0}` is not a hex string")]
    AppComposeEventPayloadNotHex(String),
    #[error("MPC image hash {0} is not in the allowed hashes list")]
    MpcImageHashNotInAllowedHashesList(String),
    #[error("launcher compose hash {0} is not in the allowed hashes list")]
    LauncherComposeHashNotInAllowedHashesList(String),
    #[error(
        "the attestation certificate with timestap {attestation_time} has expired since {expiry_time}"
    )]
    ExpiredCertificate {
        attestation_time: u64,
        expiry_time: u64,
    },
    #[error("the mock attestation is invalid per definition")]
    InvalidMockAttestation,
    #[error("the allowed mpc image hashes list is empty")]
    EmptyAllowedMpcImageHashesList,
    #[error("the allowed mpc laucher compose hashes list is empty")]
    EmptyAllowedMpcLauncherComposeHashesList,
}

impl fmt::Debug for DstackAttestation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const MAX_BYTES: usize = 2048;

        fn truncate_debug<T: fmt::Debug>(value: &T, max_bytes: usize) -> String {
            let debug_str = format!("{:?}", value);
            if debug_str.len() <= max_bytes {
                debug_str
            } else {
                format!(
                    "{}... (truncated {} bytes)",
                    &debug_str[..max_bytes],
                    debug_str.len() - max_bytes
                )
            }
        }

        f.debug_struct("DstackAttestation")
            .field("quote", &truncate_debug(&self.quote, MAX_BYTES))
            .field("collateral", &truncate_debug(&self.collateral, MAX_BYTES))
            .field("tcb_info", &truncate_debug(&self.tcb_info, MAX_BYTES))
            .finish()
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
    timestamp_seconds: u64,
    allowed_mpc_docker_image_hashes: &[MpcDockerImageHash],
    allowed_launcher_docker_compose_hashes: &[LauncherDockerComposeHash],
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
                    return Err(VerificationError::EmptyAllowedMpcImageHashesList);
                }
                allowed_mpc_docker_image_hashes.contains(hash).or_err(|| {
                    VerificationError::MpcImageHashNotInAllowedHashesList(hex::encode(
                        hash.as_ref(),
                    ))
                })?;
            };

            if let Some(hash) = launcher_docker_compose_hash {
                if allowed_launcher_docker_compose_hashes.is_empty() {
                    return Err(VerificationError::EmptyAllowedMpcLauncherComposeHashesList);
                }
                allowed_launcher_docker_compose_hashes
                    .contains(hash)
                    .or_err(|| {
                        VerificationError::LauncherComposeHashNotInAllowedHashesList(hex::encode(
                            hash.as_ref(),
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

impl Attestation {
    pub fn verify(
        &self,
        expected_report_data: ReportData,
        timestamp_seconds: u64,
        allowed_mpc_docker_image_hashes: &[MpcDockerImageHash],
        allowed_launcher_docker_compose_hashes: &[LauncherDockerComposeHash],
    ) -> Result<(), VerificationError> {
        match self {
            Self::Dstack(dstack_attestation) => self.verify_attestation(
                dstack_attestation,
                expected_report_data,
                timestamp_seconds,
                allowed_mpc_docker_image_hashes,
                allowed_launcher_docker_compose_hashes,
            ),
            Self::Mock(mock_attestation) => verify_mock_attestation(
                mock_attestation,
                timestamp_seconds,
                allowed_mpc_docker_image_hashes,
                allowed_launcher_docker_compose_hashes,
            ),
        }
    }

    /// Checks whether the node is running the expected environment, including the expected Docker
    /// images (launcher and MPC node), by verifying report_data, replaying RTMR3, and comparing
    /// the relevant event values to expected values.
    fn verify_attestation(
        &self,
        attestation: &DstackAttestation,
        expected_report_data: ReportData,
        timestamp_seconds: u64,
        allowed_mpc_docker_image_hashes: &[MpcDockerImageHash],
        allowed_launcher_docker_compose_hashes: &[LauncherDockerComposeHash],
    ) -> Result<(), VerificationError> {
        if allowed_mpc_docker_image_hashes.is_empty() {
            return Err(VerificationError::EmptyAllowedMpcImageHashesList);
        }
        if allowed_launcher_docker_compose_hashes.is_empty() {
            return Err(VerificationError::EmptyAllowedMpcLauncherComposeHashesList);
        }

        let expected_measurements = ExpectedMeasurements::from_embedded_tcb_info()
            .map_err(VerificationError::EmbeddedMeasurementsParsing)?;

        let verification_result = dcap_qvl::verify::verify(
            &attestation.quote,
            &attestation.collateral,
            timestamp_seconds,
        )
        .map_err(|e| VerificationError::DcapVerification(e.to_string()))?;

        let report_data = verification_result
            .report
            .as_td10()
            .ok_or(VerificationError::ReportNotTd10)?;

        // Verify all attestation components
        self.verify_tcb_status(&verification_result)?;
        self.verify_report_data(&expected_report_data, report_data)?;
        self.verify_static_rtmrs(report_data, &attestation.tcb_info, &expected_measurements)?;
        self.verify_rtmr3(report_data, &attestation.tcb_info)?;
        self.verify_app_compose(&attestation.tcb_info)?;
        self.verify_local_sgx_digest(&attestation.tcb_info, &expected_measurements)?;
        self.verify_mpc_hash(&attestation.tcb_info, allowed_mpc_docker_image_hashes)?;
        self.verify_launcher_compose_hash(
            &attestation.tcb_info,
            allowed_launcher_docker_compose_hashes,
        )
    }

    /// Replays RTMR3 from the event log by hashing all relevant events together and verifies all
    /// digests are correct
    fn verify_event_log_rtmr3(
        event_log: &[EventLog],
        expected_digest: [u8; 48],
    ) -> Result<(), VerificationError> {
        let mut digest = [0u8; 48];

        let filtered_events = event_log.iter().filter(|e| e.imr == RTMR3_INDEX);

        for event in filtered_events {
            // In Dstack, all events measured in RTMR3 are of type DSTACK_EVENT_TYPE
            if event.event_type != DSTACK_EVENT_TYPE {
                return Err(VerificationError::InvalidEventType(event.event_type));
            }
            let mut hasher = Sha384::new();
            hasher.update(digest);
            match hex::decode(event.digest.as_str()) {
                Ok(decoded_digest) => {
                    let payload_bytes = match hex::decode(&event.event_payload) {
                        Ok(bytes) => bytes,
                        Err(e) => {
                            tracing::error!("Failed to decode hex string for: {:?}", e);
                            return Err(VerificationError::EventDecoding(event.digest.clone()));
                        }
                    };
                    let expected_digest =
                        Self::event_digest(event.event_type, &event.event, &payload_bytes);
                    compare_hashes("event_digest", &decoded_digest, &expected_digest)?;

                    hasher.update(decoded_digest.as_slice())
                }
                Err(e) => {
                    tracing::error!(
                        "Failed to decode hex digest in event log; skipping invalid event: {:?}",
                        e
                    );
                    continue;
                }
            }
            digest = hasher.finalize().into();
        }

        compare_hashes("event_log", &digest, &expected_digest)
    }

    fn validate_app_compose_payload(
        expected_event_payload_hex: &str,
        app_compose: &str,
    ) -> Result<(), VerificationError> {
        let expected_payload = match hex::decode(expected_event_payload_hex) {
            Ok(bytes) => match <[u8; 32]>::try_from(bytes.as_slice()) {
                Ok(expected_bytes) => expected_bytes,
                Err(_) => {
                    return Err(VerificationError::AppComposeEventPayloadWrongSize(
                        bytes.len(),
                    ));
                }
            },
            Err(e) => {
                tracing::error!(
                    "Failed to decode hex string for compose-hash event: {:?}",
                    e
                );
                return Err(VerificationError::AppComposeEventPayloadNotHex(
                    expected_event_payload_hex.to_string(),
                ));
            }
        };

        let app_compose_hash: [u8; 32] = Sha256::digest(app_compose.as_bytes()).into();

        compare_hashes("app_compose_payload", &app_compose_hash, &expected_payload)
    }

    /// Verifies TCB status and security advisories.
    fn verify_tcb_status(
        &self,
        verification_result: &VerifiedReport,
    ) -> Result<(), VerificationError> {
        // The "UpToDate" TCB status indicates that the measured platform components (CPU
        // microcode, firmware, etc.) match the latest known good values published by Intel
        // and do not require any updates or mitigations.
        let status_is_up_to_date = verification_result.status == EXPECTED_QUOTE_STATUS;

        // Advisory IDs indicate known security vulnerabilities or issues with the TEE.
        // For a quote to be considered secure, there should be no outstanding advisories.
        let no_security_advisories = verification_result.advisory_ids.is_empty();

        status_is_up_to_date.or_err(|| {
            VerificationError::TcbStatusNotUpToDate(verification_result.status.clone())
        })?;

        no_security_advisories.or_err(|| {
            VerificationError::NonEmptyAdvisoryIds(verification_result.advisory_ids.join(", "))
        })?;

        Ok(())
    }

    /// Verifies report data matches expected values.
    fn verify_report_data(
        &self,
        expected: &ReportData,
        actual: &dcap_qvl::quote::TDReport10,
    ) -> Result<(), VerificationError> {
        // Check if sha384(tls_public_key) matches the hash in report_data. This check effectively
        // proves that tls_public_key was included in the quote's report_data by an app running
        // inside a TDX enclave.
        compare_hashes("report_data", &actual.report_data, &expected.to_bytes())
    }

    /// Verifies static RTMRs match expected values.
    fn verify_static_rtmrs(
        &self,
        report_data: &dcap_qvl::quote::TDReport10,
        tcb_info: &TcbInfo,
        expected_measurements: &ExpectedMeasurements,
    ) -> Result<(), VerificationError> {
        // Check if the RTMRs match the expected values. To learn more about RTMRs and
        // their significance, refer to the TDX documentation:
        // - https://phala.network/posts/understanding-tdx-attestation-reports-a-developers-guide
        // - https://www.kernel.org/doc/Documentation/x86/tdx.rst
        compare_hashes(
            "rtmr0_report_data",
            &report_data.rt_mr0,
            &expected_measurements.rtmrs.rtmr0,
        )?;
        compare_hashes(
            "rtmr1_report_data",
            &report_data.rt_mr1,
            &expected_measurements.rtmrs.rtmr1,
        )?;
        compare_hashes(
            "rtmr2_report_data",
            &report_data.rt_mr2,
            &expected_measurements.rtmrs.rtmr2,
        )?;
        compare_hashes(
            "mrtd_report_data",
            &report_data.mr_td,
            &expected_measurements.rtmrs.mrtd,
        )?;

        compare_hex_hashes(
            "rtmr0_tcb_info",
            &tcb_info.rtmr0,
            &hex::encode(expected_measurements.rtmrs.rtmr0),
        )?;
        compare_hex_hashes(
            "rtmr1_tcb_info",
            &tcb_info.rtmr1,
            &hex::encode(expected_measurements.rtmrs.rtmr1),
        )?;
        compare_hex_hashes(
            "rtmr2_tcb_info",
            &tcb_info.rtmr2,
            &hex::encode(expected_measurements.rtmrs.rtmr2),
        )?;
        compare_hex_hashes(
            "mtrd_tcb_info",
            &tcb_info.mrtd,
            &hex::encode(expected_measurements.rtmrs.mrtd),
        )
    }

    /// Verifies RTMR3 by replaying event log.
    fn verify_rtmr3(
        &self,
        report_data: &dcap_qvl::quote::TDReport10,
        tcb_info: &TcbInfo,
    ) -> Result<(), VerificationError> {
        compare_hex_hashes("rtmr3", &tcb_info.rtmr3, &hex::encode(report_data.rt_mr3))?;

        Self::verify_event_log_rtmr3(&tcb_info.event_log, report_data.rt_mr3)
    }

    /// Verifies app compose configuration and hash. The compose-hash is measured into RTMR3, and
    /// since it's (roughly) a hash of the unmeasured docker_compose_file, this is sufficient to
    /// prove its validity.
    fn verify_app_compose(&self, tcb_info: &TcbInfo) -> Result<(), VerificationError> {
        let app_compose: AppCompose = serde_json::from_str(&tcb_info.app_compose)
            .map_err(|e| VerificationError::AppComposeParsing(e.to_string()))?;

        Self::validate_app_compose_config(&app_compose).or_err(|| {
            VerificationError::InvalidAppComposeConfig(tcb_info.app_compose.to_string())
        })?;

        let app_compose_event = tcb_info.get_single_event(COMPOSE_HASH_EVENT)?;

        compare_hex_hashes(
            "app_compose_event_hash",
            &app_compose_event.event_payload,
            &tcb_info.compose_hash,
        )?;

        Self::validate_app_compose_payload(&app_compose_event.event_payload, &tcb_info.app_compose)
    }

    /// Validates app compose configuration against expected security requirements.
    fn validate_app_compose_config(app_compose: &AppCompose) -> bool {
        app_compose.manifest_version == 2
            && app_compose.runner == "docker-compose"
            && !app_compose.kms_enabled
            && app_compose.gateway_enabled == Some(false)
            && app_compose.public_logs
            && app_compose.public_sysinfo
            && app_compose.local_key_provider_enabled
            && app_compose.allowed_envs.is_empty()
            && app_compose.no_instance_id
            && app_compose.pre_launch_script.is_none()
    }

    /// Verifies local key-provider event digest matches the expected digest.
    fn verify_local_sgx_digest(
        &self,
        tcb_info: &TcbInfo,
        expected_measurements: &ExpectedMeasurements,
    ) -> Result<(), VerificationError> {
        let key_provider_event = tcb_info.get_single_event(KEY_PROVIDER_EVENT)?;

        compare_hex_hashes(
            "sgx_digest",
            &key_provider_event.digest,
            &hex::encode(expected_measurements.local_sgx_event_digest),
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
                VerificationError::MpcImageHashNotInAllowedHashesList(event.event_payload.clone())
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
                VerificationError::LauncherComposeHashNotInAllowedHashesList(hex::encode(
                    launcher_bytes,
                ))
            })
    }

    // Implementation taken to match Dstack's https://github.com/Dstack-TEE/dstack/blob/cfa4cc4e8a4f525d537883b1a0ba5d9fbfd87f1e/cc-eventlog/src/lib.rs#L54
    fn event_digest(event_type: u32, event: &str, payload: &[u8]) -> [u8; 48] {
        let mut hasher = Sha384::new();
        hasher.update(event_type.to_ne_bytes());
        hasher.update(b":");
        hasher.update(event.as_bytes());
        hasher.update(b":");
        hasher.update(payload);
        hasher.finalize().into()
    }
}

fn compare_hashes(
    name: &'static str,
    found: &[u8],
    expected: &[u8],
) -> Result<(), VerificationError> {
    (found == expected).or_err(|| VerificationError::WrongHash {
        name,
        found: hex::encode(found),
        expected: hex::encode(expected),
    })
}

fn compare_hex_hashes<S: ToString + Eq>(
    name: &'static str,
    found: S,
    expected: S,
) -> Result<(), VerificationError> {
    (found == expected).or_err(|| VerificationError::WrongHash {
        name,
        found: found.to_string(),
        expected: expected.to_string(),
    })
}

trait OrErr {
    fn or_err<Error>(self, err: impl FnOnce() -> Error) -> Result<(), Error>;
}

impl OrErr for bool {
    fn or_err<Error>(self, err: impl FnOnce() -> Error) -> Result<(), Error> {
        self.then_some(()).ok_or_else(err)
    }
}

trait GetSingleEvent {
    fn get_single_event(&self, event_name: &'static str) -> Result<&EventLog, VerificationError>;
}

impl GetSingleEvent for TcbInfo {
    fn get_single_event(&self, event_name: &'static str) -> Result<&EventLog, VerificationError> {
        let mut events = self
            .event_log
            .iter()
            .filter(|event| event.event == event_name && event.imr == RTMR3_INDEX);

        let Some(event) = events.next() else {
            return Err(VerificationError::MissingEvent(event_name));
        };

        if events.next().is_some() {
            Err(VerificationError::DuplicateEvent(event_name))
        } else {
            Ok(event)
        }
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use super::*;

    use alloc::{string::ToString, vec::Vec};

    #[test]
    fn validate_app_compose_config__succeeds_on_valid_app_compose() {
        // Given
        let app_compose = valid_app_compose();
        // When
        let result = Attestation::validate_app_compose_config(&app_compose);

        // Then
        assert!(result)
    }

    #[test]
    fn validate_app_compose_config__allows_insecure_time() {
        // Given
        let app_compose = AppCompose {
            secure_time: Some(false),
            ..valid_app_compose()
        };
        // When
        let result = Attestation::validate_app_compose_config(&app_compose);

        // Then
        assert!(result)
    }

    fn valid_app_compose() -> AppCompose {
        AppCompose {
            manifest_version: 2,
            name: "".to_string(),
            runner: "docker-compose".to_string(),
            docker_compose_file: "".to_string().into(),
            kms_enabled: false,
            tproxy_enabled: None,
            gateway_enabled: Some(false),
            public_logs: true,
            public_sysinfo: true,
            local_key_provider_enabled: true,
            key_provider_id: None,
            allowed_envs: Vec::new(),
            no_instance_id: true,
            secure_time: None,
            pre_launch_script: None,
        }
    }
}
