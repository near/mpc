//! Post-DCAP verification helpers.
//!
//! These functions run after `dcap_qvl::verify::verify` has already validated
//! the quote's cryptographic chain and produced a `VerifiedReport`. They
//! take the [`tee_verifier_interface::VerifiedReport`] mirror (not the
//! upstream `dcap_qvl` type), so this module compiles without any
//! `dcap-qvl` dependency and can be linked into consumer contracts.
//!
//! The actual `dcap_qvl::verify::verify` call lives elsewhere — for
//! local-verify in the `attestation` crate, and for cross-contract verify
//! in the `tee-verifier` contract.

use alloc::string::{String, ToString};

use sha2::{Digest as _, Sha256, Sha384};
use tee_verifier_interface::{TDReport10, VerifiedReport};

use crate::{
    app_compose::AppCompose,
    measurements::ExpectedMeasurements,
    report_data::ReportData,
    tcb_info::{EventLog, TcbInfo},
};

/// Expected TCB status for a successfully verified TEE quote.
pub const EXPECTED_QUOTE_STATUS: &str = "UpToDate";

// DSTACK_EVENT_TYPE is defined in https://github.com/Dstack-TEE/dstack/blob/cfa4cc4e8a4f525d537883b1a0ba5d9fbfd87f1e/tdx-attest/src/lib.rs#L28
// It is the same for all events
pub const DSTACK_EVENT_TYPE: u32 = 134217729;

pub const COMPOSE_HASH_EVENT: &str = "compose-hash";
pub const KEY_PROVIDER_EVENT: &str = "key-provider";

pub const RTMR3_INDEX: u32 = 3;

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum VerificationError {
    #[error("could not parse embedded measurements: {0}")]
    EmbeddedMeasurementsParsing(crate::measurements::MeasurementsError),
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
    #[error(
        "the attestation certificate with timestap {attestation_time} has expired since {expiry_time}"
    )]
    ExpiredCertificate {
        attestation_time: u64,
        expiry_time: u64,
    },
    #[error("the mock attestation is invalid per definition")]
    InvalidMockAttestation,
    #[error("the allowed measurements list is empty")]
    EmptyMeasurementsList,
    #[error("the attestation's measurements are not in the allowed set")]
    MeasurementsNotAllowed,
    #[error("custom error: `{0}`")]
    Custom(String),
}

/// Verifies TCB status and security advisories.
pub fn verify_tcb_status(verified_report: &VerifiedReport) -> Result<(), VerificationError> {
    // The "UpToDate" TCB status indicates that the measured platform components (CPU
    // microcode, firmware, etc.) match the latest known good values published by Intel
    // and do not require any updates or mitigations.
    let status_is_up_to_date = verified_report.status == EXPECTED_QUOTE_STATUS;

    // Advisory IDs indicate known security vulnerabilities or issues with the TEE.
    // For a quote to be considered secure, there should be no outstanding advisories.
    let no_security_advisories = verified_report.advisory_ids.is_empty();

    status_is_up_to_date
        .or_err(|| VerificationError::TcbStatusNotUpToDate(verified_report.status.clone()))?;

    no_security_advisories.or_err(|| {
        VerificationError::NonEmptyAdvisoryIds(verified_report.advisory_ids.join(", "))
    })?;

    Ok(())
}

/// Verifies report data matches expected values.
pub fn verify_report_data(
    expected: &ReportData,
    actual: &TDReport10,
) -> Result<(), VerificationError> {
    // Check if sha384(tls_public_key) matches the hash in report_data. This check effectively
    // proves that tls_public_key was included in the quote's report_data by an app running
    // inside a TDX enclave.
    compare_hashes("report_data", &actual.report_data, &expected.to_bytes())
}

/// Verifies RTMR3 by replaying the event log.
pub fn verify_rtmr3(report_data: &TDReport10, tcb_info: &TcbInfo) -> Result<(), VerificationError> {
    compare_hashes("rtmr3", tcb_info.rtmr3.as_slice(), &report_data.rt_mr3)?;
    verify_event_log_rtmr3(&tcb_info.event_log, report_data.rt_mr3)
}

/// Verifies app compose configuration and hash. The compose-hash is measured into RTMR3,
/// and since it's (roughly) a hash of the unmeasured docker_compose_file, this is
/// sufficient to prove its validity.
pub fn verify_app_compose(tcb_info: &TcbInfo) -> Result<(), VerificationError> {
    let app_compose: AppCompose = serde_json::from_str(&tcb_info.app_compose)
        .map_err(|e| VerificationError::AppComposeParsing(e.to_string()))?;

    validate_app_compose_config(&app_compose)
        .or_err(|| VerificationError::InvalidAppComposeConfig(tcb_info.app_compose.to_string()))?;

    let app_compose_event = tcb_info.get_single_event(COMPOSE_HASH_EVENT)?;

    compare_hex_hashes(
        "app_compose_event_hash",
        &app_compose_event.event_payload,
        &hex::encode(*tcb_info.compose_hash),
    )?;

    validate_app_compose_payload(&app_compose_event.event_payload, &tcb_info.app_compose)
}

/// Try to verify static RTMRs and key_provider_digest against multiple expected
/// measurement sets. On success, returns the matched measurements.
pub fn verify_any_measurements(
    report_data: &TDReport10,
    tcb_info: &TcbInfo,
    accepted_measurements: &[ExpectedMeasurements],
) -> Result<ExpectedMeasurements, VerificationError> {
    for expected in accepted_measurements {
        if verify_static_rtmrs(report_data, tcb_info, expected).is_ok()
            && verify_key_provider_digest(tcb_info, &expected.key_provider_event_digest).is_ok()
        {
            return Ok(*expected); // found a valid match
        }
    }

    Err(VerificationError::WrongHash {
        name: "expected_measurements",
        expected: "one of the embedded TCB info sets (prod or dev)".into(),
        found: "none matched".into(),
    })
}

/// Verifies static RTMRs match expected values.
pub fn verify_static_rtmrs(
    report_data: &TDReport10,
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

    compare_hashes(
        "rtmr0_tcb_info",
        tcb_info.rtmr0.as_slice(),
        &expected_measurements.rtmrs.rtmr0,
    )?;
    compare_hashes(
        "rtmr1_tcb_info",
        tcb_info.rtmr1.as_slice(),
        &expected_measurements.rtmrs.rtmr1,
    )?;
    compare_hashes(
        "rtmr2_tcb_info",
        tcb_info.rtmr2.as_slice(),
        &expected_measurements.rtmrs.rtmr2,
    )?;
    compare_hashes(
        "mtrd_tcb_info",
        tcb_info.mrtd.as_slice(),
        &expected_measurements.rtmrs.mrtd,
    )
}

/// Verifies local key-provider event digest matches the expected digest.
pub fn verify_key_provider_digest(
    tcb_info: &TcbInfo,
    expected_digest: &[u8; 48],
) -> Result<(), VerificationError> {
    let key_provider_event = tcb_info.get_single_event(KEY_PROVIDER_EVENT)?;

    compare_hashes(
        "key_provider",
        key_provider_event.digest.as_slice(),
        expected_digest,
    )
}

/// Replays RTMR3 from the event log by hashing all relevant events together and
/// verifies all digests are correct.
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
        let payload_bytes = match hex::decode(&event.event_payload) {
            Ok(bytes) => bytes,
            Err(_) => {
                return Err(VerificationError::EventDecoding(hex::encode(*event.digest)));
            }
        };
        let expected_event_digest = event_digest(event.event_type, &event.event, &payload_bytes);
        compare_hashes(
            "event_digest",
            event.digest.as_slice(),
            &expected_event_digest,
        )?;

        hasher.update(event.digest.as_slice());

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
        Err(_) => {
            return Err(VerificationError::AppComposeEventPayloadNotHex(
                expected_event_payload_hex.to_string(),
            ));
        }
    };

    let app_compose_hash: [u8; 32] = Sha256::digest(app_compose.as_bytes()).into();

    compare_hashes("app_compose_payload", &app_compose_hash, &expected_payload)
}

/// Validates app compose configuration against expected security requirements.
pub fn validate_app_compose_config(app_compose: &AppCompose) -> bool {
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

// Implementation matches Dstack's:
// https://github.com/Dstack-TEE/dstack/blob/cfa4cc4e8a4f525d537883b1a0ba5d9fbfd87f1e/cc-eventlog/src/lib.rs#L54
fn event_digest(event_type: u32, event: &str, payload: &[u8]) -> [u8; 48] {
    let mut hasher = Sha384::new();
    hasher.update(event_type.to_ne_bytes());
    hasher.update(b":");
    hasher.update(event.as_bytes());
    hasher.update(b":");
    hasher.update(payload);
    hasher.finalize().into()
}

pub fn compare_hashes(
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

pub fn compare_hex_hashes<S: ToString + Eq>(
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

pub trait OrErr {
    fn or_err<Error>(self, err: impl FnOnce() -> Error) -> Result<(), Error>;
}

impl OrErr for bool {
    fn or_err<Error>(self, err: impl FnOnce() -> Error) -> Result<(), Error> {
        self.then_some(()).ok_or_else(err)
    }
}

pub trait GetSingleEvent {
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
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use alloc::{string::ToString, vec::Vec};

    #[test]
    fn validate_app_compose_config__succeeds_on_valid_app_compose() {
        // Given
        let app_compose = valid_app_compose();
        // When
        let result = validate_app_compose_config(&app_compose);

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
        let result = validate_app_compose_config(&app_compose);

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
