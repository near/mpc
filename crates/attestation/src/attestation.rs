use crate::{
    app_compose::AppCompose,
    collateral::Collateral,
    measurements::{ExpectedMeasurements, MeasurementsError},
    quote::QuoteBytes,
    report_data::ReportData,
    tcb_info::{EventLog, TcbInfo},
};

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};
use borsh::{BorshDeserialize, BorshSerialize};
use core::fmt;
use derive_more::Constructor;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256, Sha384};
use tee_verifier_interface::{TDReport10, VerifiedReport};

#[cfg(feature = "local-verify")]
use crate::dcap_conversions::{IntoDcapType as _, IntoInterfaceType as _};

/// Expected TCB status for a successfully verified TEE quote.
const EXPECTED_QUOTE_STATUS: &str = "UpToDate";

// DSTACK_EVENT_TYPE is defined in https://github.com/Dstack-TEE/dstack/blob/cfa4cc4e8a4f525d537883b1a0ba5d9fbfd87f1e/tdx-attest/src/lib.rs#L28
// It is the same for all events
const DSTACK_EVENT_TYPE: u32 = 134217729;

const COMPOSE_HASH_EVENT: &str = "compose-hash";
pub(crate) const KEY_PROVIDER_EVENT: &str = "key-provider";

const RTMR3_INDEX: u32 = 3;

#[derive(Clone, Constructor, Serialize, Deserialize, BorshDeserialize, BorshSerialize)]
#[cfg_attr(feature = "borsh-schema", derive(borsh::BorshSchema))]
pub struct DstackAttestation {
    pub quote: QuoteBytes,
    pub collateral: Collateral,
    pub tcb_info: TcbInfo,
}

/// Result of successfully verifying an attestation.
#[derive(Clone, Debug)]
pub struct AcceptedDstackAttestation {
    /// The accepted measurement set this attestation matched.
    pub measurements: ExpectedMeasurements,
    /// Informational advisory IDs (e.g. `INTEL-DOC-10000` post-ESU) surfaced by
    /// Intel's PCS alongside an `UpToDate` TCB status. They are not a security
    /// failure — `UpToDate` is the sole security gate; these advisories convey
    /// platform lifecycle information.
    pub advisory_ids: Vec<String>,
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

impl DstackAttestation {
    /// Runs the post-DCAP checks against an already-verified report.
    pub fn verify_with_report(
        &self,
        report: &VerifiedReport,
        expected_report_data: ReportData,
        accepted_measurements: &[ExpectedMeasurements],
    ) -> Result<AcceptedDstackAttestation, VerificationError> {
        let report_data = report
            .report
            .as_td10()
            .ok_or(VerificationError::ReportNotTd10)?;

        // Verify all attestation components
        let advisory_ids = Self::verify_tcb_status(report)?;
        self.verify_report_data(&expected_report_data, report_data)?;

        self.verify_rtmr3(report_data, &self.tcb_info)?;
        self.verify_app_compose(&self.tcb_info)?;

        let measurements =
            self.verify_any_measurements(report_data, &self.tcb_info, accepted_measurements)?;
        Ok(AcceptedDstackAttestation {
            measurements,
            advisory_ids,
        })
    }

    /// Full local verification: runs `dcap_qvl::verify::verify` and then the
    /// post-DCAP checks via [`Self::verify_with_report`].
    #[cfg(feature = "local-verify")]
    pub fn verify_locally(
        &self,
        expected_report_data: ReportData,
        timestamp_seconds: u64,
        accepted_measurements: &[ExpectedMeasurements],
    ) -> Result<AcceptedDstackAttestation, VerificationError> {
        let report = self.verify_dcap_quote(timestamp_seconds)?;
        self.verify_with_report(&report, expected_report_data, accepted_measurements)
    }

    /// Runs only the DCAP step (`dcap_qvl::verify::verify`) and returns the
    /// resulting report as the `tee-verifier-interface` mirror — the same value
    /// the `tee-verifier` contract returns on-chain.
    #[cfg(feature = "local-verify")]
    pub fn verify_dcap_quote(
        &self,
        timestamp_seconds: u64,
    ) -> Result<VerifiedReport, VerificationError> {
        let collateral = self.collateral.clone().into_dcap_type();
        Ok(
            dcap_qvl::verify::verify(&self.quote.0, &collateral, timestamp_seconds)
                .map_err(|e| VerificationError::DcapVerification(e.to_string()))?
                .into_interface_type(),
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
            let payload_bytes = match hex::decode(&event.event_payload) {
                Ok(bytes) => bytes,
                Err(_) => {
                    return Err(VerificationError::EventDecoding(hex::encode(*event.digest)));
                }
            };
            let expected_event_digest =
                Self::event_digest(event.event_type, &event.event, &payload_bytes);
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

    /// Verifies the TCB status and returns any advisory IDs reported alongside it.
    ///
    /// The "UpToDate" TCB status indicates that the measured platform components (CPU
    /// microcode, firmware, etc.) match the latest known good values published by Intel
    /// and do not require any updates or mitigations — this is the sole security gate.
    ///
    /// Intel's PCS surfaces `advisory_ids` for two distinct purposes:
    ///   1. `INTEL-SA-NNNNN`: real Security Advisories. Intel only attaches these to
    ///      a non-UpToDate TCB status, so they are implicitly rejected by the status
    ///      check below.
    ///   2. `INTEL-DOC-NNNNN`: informational lifecycle markers (e.g. `INTEL-DOC-10000`
    ///      after a product's Extended Servicing Updates date). These may appear with
    ///      `UpToDate` and do not indicate a vulnerability; they are returned so the
    ///      caller can log/expose them.
    fn verify_tcb_status(report: &VerifiedReport) -> Result<Vec<String>, VerificationError> {
        (report.status == EXPECTED_QUOTE_STATUS)
            .or_err(|| VerificationError::TcbStatusNotUpToDate(report.status.clone()))?;

        Ok(report.advisory_ids.clone())
    }

    /// Verifies report data matches expected values.
    fn verify_report_data(
        &self,
        expected: &ReportData,
        actual: &TDReport10,
    ) -> Result<(), VerificationError> {
        // Check if sha384(tls_public_key) matches the hash in report_data. This check effectively
        // proves that tls_public_key was included in the quote's report_data by an app running
        // inside a TDX enclave.
        compare_hashes("report_data", &actual.report_data, &expected.to_bytes())
    }

    /// Try to verify static RTMRs and key_provider_digest against multiple expected measurement sets.
    /// On success, returns the matched measurements.
    fn verify_any_measurements(
        &self,
        report_data: &TDReport10,
        tcb_info: &TcbInfo,
        accepted_measurements: &[ExpectedMeasurements],
    ) -> Result<ExpectedMeasurements, VerificationError> {
        for expected in accepted_measurements {
            if self
                .verify_static_rtmrs(report_data, tcb_info, expected)
                .is_ok()
                && self
                    .verify_key_provider_digest(tcb_info, &expected.key_provider_event_digest)
                    .is_ok()
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
    fn verify_static_rtmrs(
        &self,
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

    /// Verifies RTMR3 by replaying event log.
    fn verify_rtmr3(
        &self,
        report_data: &TDReport10,
        tcb_info: &TcbInfo,
    ) -> Result<(), VerificationError> {
        compare_hashes("rtmr3", tcb_info.rtmr3.as_slice(), &report_data.rt_mr3)?;

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
            &hex::encode(*tcb_info.compose_hash),
        )?;

        Self::validate_app_compose_payload(&app_compose_event.event_payload, &tcb_info.app_compose)
    }

    /// Validates app compose configuration against expected security requirements.
    fn validate_app_compose_config(app_compose: &AppCompose) -> bool {
        app_compose.manifest_version == 2
            && app_compose.runner == "docker-compose"
            && !app_compose.kms_enabled
            // dstack enables the gateway when `gateway_enabled || tproxy_enabled` (the latter is the
            // legacy alias), so both must be disabled.
            && app_compose.gateway_enabled == Some(false)
            && app_compose.tproxy_enabled != Some(true)
            && app_compose.public_logs
            && app_compose.public_sysinfo
            && app_compose.local_key_provider_enabled
            && app_compose.allowed_envs.is_empty()
            && app_compose.no_instance_id
            // Reject all three arbitrary-root-code fields. `pre_launch_script` and `init_script` run
            // unconditionally; `bash_script` only runs when `runner == "bash"` (so the runner pin
            // above already neutralizes it), but we reject it explicitly so the guarantee does not
            // silently depend on that pin.
            && app_compose.pre_launch_script.is_none()
            && app_compose.init_script.is_none()
            && app_compose.bash_script.is_none()
    }

    /// Verifies local key-provider event digest matches the expected digest.
    fn verify_key_provider_digest(
        &self,
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

    use alloc::{string::ToString, vec, vec::Vec};
    use tee_verifier_interface::{
        EnclaveReport, Report, TcbStatus, TcbStatusWithAdvisory, VerifiedReport,
    };

    fn verified_report(status: &str, advisory_ids: Vec<String>) -> VerifiedReport {
        VerifiedReport {
            status: status.to_string(),
            advisory_ids,
            // `verify_tcb_status` does not read any of the fields below; we
            // provide arbitrary zeroed values to satisfy the struct's type.
            report: Report::SgxEnclave(EnclaveReport {
                cpu_svn: [0u8; 16],
                misc_select: 0,
                reserved1: [0u8; 28],
                attributes: [0u8; 16],
                mr_enclave: [0u8; 32],
                reserved2: [0u8; 32],
                mr_signer: [0u8; 32],
                reserved3: [0u8; 96],
                isv_prod_id: 0,
                isv_svn: 0,
                reserved4: [0u8; 60],
                report_data: [0u8; 64],
            }),
            ppid: Vec::new(),
            qe_status: TcbStatusWithAdvisory {
                status: TcbStatus::UpToDate,
                advisory_ids: Vec::new(),
            },
            platform_status: TcbStatusWithAdvisory {
                status: TcbStatus::UpToDate,
                advisory_ids: Vec::new(),
            },
        }
    }

    #[test]
    fn verify_tcb_status__should_accept_uptodate_with_empty_advisories() {
        // Given
        let report = verified_report("UpToDate", vec![]);

        // When
        let result = DstackAttestation::verify_tcb_status(&report);

        // Then
        assert_eq!(result, Ok(vec![]));
    }

    #[test]
    fn verify_tcb_status__should_accept_uptodate_with_informational_advisories() {
        // After Intel's 2026 PCS change, `UpToDate` may ship with informational
        // advisory IDs (e.g. `INTEL-DOC-10000` post-ESU). These must not cause
        // the quote to be rejected; they should be returned so the caller can
        // surface them.

        // Given
        let advisories = vec!["INTEL-DOC-10000".to_string()];
        let report = verified_report("UpToDate", advisories.clone());

        // When
        let result = DstackAttestation::verify_tcb_status(&report);

        // Then
        assert_eq!(result, Ok(advisories));
    }

    #[test]
    fn verify_tcb_status__should_reject_non_uptodate_status() {
        // Given
        let report = verified_report("OutOfDate", vec![]);

        // When
        let result = DstackAttestation::verify_tcb_status(&report);

        // Then
        assert_eq!(
            result,
            Err(VerificationError::TcbStatusNotUpToDate(
                "OutOfDate".to_string()
            ))
        );
    }

    #[test]
    fn verify_tcb_status__should_reject_non_uptodate_status_with_advisories() {
        // Given
        let report = verified_report("OutOfDate", vec!["INTEL-SA-00001".to_string()]);

        // When
        let result = DstackAttestation::verify_tcb_status(&report);

        // Then
        assert_eq!(
            result,
            Err(VerificationError::TcbStatusNotUpToDate(
                "OutOfDate".to_string()
            ))
        );
    }

    #[test]
    fn validate_app_compose_config__succeeds_on_valid_app_compose() {
        // Given
        let app_compose = valid_app_compose();
        // When
        let result = DstackAttestation::validate_app_compose_config(&app_compose);

        // Then
        assert!(result)
    }

    #[test]
    fn validate_app_compose_config__rejects_present_pre_launch_script() {
        // Given
        let app_compose = AppCompose {
            pre_launch_script: Some("echo pwn".to_string()),
            ..valid_app_compose()
        };
        // When
        let result = DstackAttestation::validate_app_compose_config(&app_compose);

        // Then
        assert!(!result)
    }

    #[test]
    fn validate_app_compose_config__rejects_present_init_script() {
        // `init_script` is arbitrary root code run before dockerd. It is
        // measured into the compose hash but not pinned to any allowed value,
        // so verification must reject it outright.

        // Given
        let app_compose = AppCompose {
            init_script: Some("echo pwn".to_string()),
            ..valid_app_compose()
        };
        // When
        let result = DstackAttestation::validate_app_compose_config(&app_compose);

        // Then
        assert!(!result)
    }

    #[test]
    fn validate_app_compose_config__rejects_present_bash_script() {
        // `bash_script` is arbitrary root code; dstack only runs it when `runner == "bash"`, but we
        // reject it explicitly rather than relying solely on the runner pin.

        // Given
        let app_compose = AppCompose {
            bash_script: Some("echo pwn".to_string()),
            ..valid_app_compose()
        };
        // When
        let result = DstackAttestation::validate_app_compose_config(&app_compose);

        // Then
        assert!(!result)
    }

    #[test]
    fn validate_app_compose_config__rejects_tproxy_enabled() {
        // dstack enables the gateway on `gateway_enabled || tproxy_enabled`, so a `tproxy_enabled`
        // set via the legacy alias must be rejected even when `gateway_enabled` is false.

        // Given
        let app_compose = AppCompose {
            tproxy_enabled: Some(true),
            ..valid_app_compose()
        };
        // When
        let result = DstackAttestation::validate_app_compose_config(&app_compose);

        // Then
        assert!(!result)
    }

    #[test]
    fn app_compose__rejects_unknown_field() {
        // `deny_unknown_fields` must make a key dstack might add in the future fail to parse, so it
        // halts verification rather than being silently ignored.

        // Given
        let app_compose_json = r#"{
            "manifest_version": 2,
            "name": "",
            "runner": "docker-compose",
            "docker_compose_file": "",
            "some_future_dstack_field": "whatever"
        }"#;
        // When
        let err = serde_json::from_str::<AppCompose>(app_compose_json).unwrap_err();

        // Then
        assert!(
            err.to_string().contains("unknown field"),
            "expected an unknown-field error, got: {err}"
        );
    }

    #[test]
    fn validate_app_compose_config__allows_insecure_time() {
        // Given
        let app_compose = AppCompose {
            secure_time: Some(false),
            ..valid_app_compose()
        };
        // When
        let result = DstackAttestation::validate_app_compose_config(&app_compose);

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
            init_script: None,
            bash_script: None,
            features: None,
            public_tcbinfo: None,
            key_provider: None,
            storage_fs: None,
            swap_size: None,
            port_policy: None,
            docker_config: None,
        }
    }
}
