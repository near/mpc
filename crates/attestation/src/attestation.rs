use crate::{
    app_compose::AppCompose, collateral::Collateral, measurements::ExpectedMeasurements,
    quote::QuoteBytes, report_data::ReportData,
};
use alloc::{format, string::String};
use borsh::{BorshDeserialize, BorshSerialize};
use core::fmt;
use dcap_qvl::verify::VerifiedReport;
use derive_more::Constructor;
use dstack_sdk_types::dstack::{EventLog, TcbInfo};
use k256::sha2::{Digest as _, Sha384};
use mpc_primitives::hash::{LauncherDockerComposeHash, MpcDockerImageHash};
use near_sdk::env::sha256;
use serde::{Deserialize, Serialize};

#[cfg(all(feature = "abi", not(target_arch = "wasm32")))]
use alloc::string::ToString;

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
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(borsh::BorshSchema)
)]
pub enum Attestation {
    Dstack(DstackAttestation),
    Local(LocalAttestation),
}

#[derive(Clone, Constructor, Serialize, Deserialize, BorshDeserialize, BorshSerialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(borsh::BorshSchema)
)]
pub struct DstackAttestation {
    pub quote: QuoteBytes,
    pub collateral: Collateral,
    pub tcb_info: TcbInfo,
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

#[derive(Debug, Clone, Constructor, Serialize, Deserialize, BorshDeserialize, BorshSerialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(borsh::BorshSchema)
)]
pub struct LocalAttestation {
    verification_result: bool,
}

impl Attestation {
    pub fn verify(
        &self,
        expected_report_data: ReportData,
        timestamp_s: u64,
        allowed_mpc_docker_image_hashes: &[MpcDockerImageHash],
        allowed_launcher_docker_compose_hashes: &[LauncherDockerComposeHash],
    ) -> bool {
        match self {
            Self::Dstack(dstack_attestation) => self.verify_attestation(
                dstack_attestation,
                expected_report_data,
                timestamp_s,
                allowed_mpc_docker_image_hashes,
                allowed_launcher_docker_compose_hashes,
            ),
            Self::Local(config) => config.verification_result,
        }
    }

    /// Checks whether the node is running the expected environment, including the expected Docker
    /// images (launcher and MPC node), by verifying report_data, replaying RTMR3, and comparing
    /// the relevant event values to expected values.
    fn verify_attestation(
        &self,
        attestation: &DstackAttestation,
        expected_report_data: ReportData,
        timestamp_s: u64,
        allowed_mpc_docker_image_hashes: &[MpcDockerImageHash],
        allowed_launcher_docker_compose_hashes: &[LauncherDockerComposeHash],
    ) -> bool {
        let expected_measurements = match ExpectedMeasurements::from_embedded_tcb_info() {
            Ok(measurements) => measurements,
            Err(_) => return false,
        };

        let verification_result = match dcap_qvl::verify::verify(
            &attestation.quote,
            &attestation.collateral,
            timestamp_s,
        ) {
            Ok(result) => result,
            Err(err) => {
                tracing::error!("TEE quote verification failed: {:?}", err);
                return false;
            }
        };

        let Some(report_data) = verification_result.report.as_td10() else {
            tracing::error!(
                "Expected TD10 report data, but got: {:?}",
                verification_result.report
            );
            return false;
        };

        // Verify all attestation components
        self.verify_tcb_status(&verification_result)
            && self.verify_report_data(&expected_report_data, report_data)
            && self.verify_static_rtmrs(report_data, &attestation.tcb_info, &expected_measurements)
            && self.verify_rtmr3(report_data, &attestation.tcb_info)
            && self.verify_app_compose(&attestation.tcb_info)
            && self.verify_local_sgx_digest(&attestation.tcb_info, &expected_measurements)
            && self.verify_mpc_hash(&attestation.tcb_info, allowed_mpc_docker_image_hashes)
            && self.verify_launcher_compose_hash(
                &attestation.tcb_info,
                allowed_launcher_docker_compose_hashes,
            )
    }

    /// Replays RTMR3 from the event log by hashing all relevant events together and verifies all
    /// digests are correct
    fn verify_event_log_rtmr3(event_log: &[EventLog], expected_digest: [u8; 48]) -> bool {
        let mut digest = [0u8; 48];

        let filtered_events = event_log.iter().filter(|e| e.imr == RTMR3_INDEX);

        for event in filtered_events {
            // In Dstack, all events measured in RTMR3 are of type DSTACK_EVENT_TYPE
            if event.event_type != DSTACK_EVENT_TYPE {
                return false;
            }
            let mut hasher = Sha384::new();
            hasher.update(digest);
            match hex::decode(event.digest.as_str()) {
                Ok(decoded_digest) => {
                    let payload_bytes = match hex::decode(&event.event_payload) {
                        Ok(bytes) => bytes,
                        Err(e) => {
                            tracing::error!("Failed to decode hex string for: {:?}", e);
                            return false;
                        }
                    };
                    let expected_digest =
                        Self::event_digest(event.event_type, &event.event, &payload_bytes);
                    if decoded_digest != expected_digest {
                        return false;
                    }

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

        digest == expected_digest
    }

    fn validate_app_compose_payload(expected_event_payload_hex: &str, app_compose: &str) -> bool {
        let expected_payload = match hex::decode(expected_event_payload_hex) {
            Ok(bytes) => match <[u8; 32]>::try_from(bytes.as_slice()) {
                Ok(expected_bytes) => expected_bytes,
                Err(_) => {
                    tracing::error!("Failed to convert decoded hex to [u8; 32] for ");
                    return false;
                }
            },
            Err(e) => {
                tracing::error!(
                    "Failed to decode hex string for compose-hash event: {:?}",
                    e
                );
                return false;
            }
        };

        let app_compose_hash: [u8; 32] = sha256(app_compose.as_bytes()).try_into().unwrap();

        app_compose_hash == expected_payload
    }

    /// Verifies TCB status and security advisories.
    fn verify_tcb_status(&self, verification_result: &VerifiedReport) -> bool {
        // The "UpToDate" TCB status indicates that the measured platform components (CPU
        // microcode, firmware, etc.) match the latest known good values published by Intel
        // and do not require any updates or mitigations.
        let status_is_up_to_date = verification_result.status == EXPECTED_QUOTE_STATUS;

        // Advisory IDs indicate known security vulnerabilities or issues with the TEE.
        // For a quote to be considered secure, there should be no outstanding advisories.
        let no_security_advisories = verification_result.advisory_ids.is_empty();

        status_is_up_to_date && no_security_advisories
    }

    /// Verifies report data matches expected values.
    fn verify_report_data(
        &self,
        expected: &ReportData,
        actual: &dcap_qvl::quote::TDReport10,
    ) -> bool {
        // Check if sha384(tls_public_key) matches the hash in report_data. This check effectively
        // proves that tls_public_key was included in the quote's report_data by an app running
        // inside a TDX enclave.
        expected.to_bytes() == actual.report_data
    }

    /// Verifies static RTMRs match expected values.
    fn verify_static_rtmrs(
        &self,
        report_data: &dcap_qvl::quote::TDReport10,
        tcb_info: &TcbInfo,
        expected_measurements: &ExpectedMeasurements,
    ) -> bool {
        // Check if the RTMRs match the expected values. To learn more about RTMRs and
        // their significance, refer to the TDX documentation:
        // - https://phala.network/posts/understanding-tdx-attestation-reports-a-developers-guide
        // - https://www.kernel.org/doc/Documentation/x86/tdx.rst
        report_data.rt_mr0 == expected_measurements.rtmrs.rtmr0
            && report_data.rt_mr1 == expected_measurements.rtmrs.rtmr1
            && report_data.rt_mr2 == expected_measurements.rtmrs.rtmr2
            && report_data.mr_td == expected_measurements.rtmrs.mrtd
            && tcb_info.rtmr0 == hex::encode(expected_measurements.rtmrs.rtmr0)
            && tcb_info.rtmr1 == hex::encode(expected_measurements.rtmrs.rtmr1)
            && tcb_info.rtmr2 == hex::encode(expected_measurements.rtmrs.rtmr2)
            && tcb_info.mrtd == hex::encode(expected_measurements.rtmrs.mrtd)
    }

    /// Verifies RTMR3 by replaying event log.
    fn verify_rtmr3(&self, report_data: &dcap_qvl::quote::TDReport10, tcb_info: &TcbInfo) -> bool {
        tcb_info.rtmr3 == hex::encode(report_data.rt_mr3)
            && Self::verify_event_log_rtmr3(&tcb_info.event_log, report_data.rt_mr3)
    }

    /// Verifies app compose configuration and hash. The compose-hash is measured into RTMR3, and
    /// since it's (roughly) a hash of the unmeasured docker_compose_file, this is sufficient to
    /// prove its validity.
    fn verify_app_compose(&self, tcb_info: &TcbInfo) -> bool {
        let app_compose: AppCompose = match serde_json::from_str(&tcb_info.app_compose) {
            Ok(compose) => compose,
            Err(e) => {
                tracing::error!("Failed to parse app_compose JSON: {:?}", e);
                return false;
            }
        };

        let mut events = tcb_info
            .event_log
            .iter()
            .filter(|event| event.event == COMPOSE_HASH_EVENT && event.imr == RTMR3_INDEX);

        let payload_is_correct = events.next().is_some_and(|event| {
            event.event_payload == tcb_info.compose_hash
                && Self::validate_app_compose_config(&app_compose)
                && Self::validate_app_compose_payload(&event.event_payload, &tcb_info.app_compose)
        });
        let single_repetition = events.next().is_none();
        single_repetition && payload_is_correct
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
            && app_compose.secure_time == Some(true)
            && app_compose.secure_time == Some(true)
            && app_compose.pre_launch_script.is_none()
    }

    /// Verifies local key-provider event digest matches the expected digest.
    fn verify_local_sgx_digest(
        &self,
        tcb_info: &TcbInfo,
        expected_measurements: &ExpectedMeasurements,
    ) -> bool {
        let mut events = tcb_info
            .event_log
            .iter()
            .filter(|event| event.event == KEY_PROVIDER_EVENT && event.imr == RTMR3_INDEX);
        let digest_is_correct = events.next().is_some_and(|event| {
            event.digest == hex::encode(expected_measurements.local_sgx_event_digest)
        });
        let single_repetition = events.next().is_none();
        single_repetition && digest_is_correct
    }

    /// Verifies MPC node image hash is in allowed list.
    fn verify_mpc_hash(&self, tcb_info: &TcbInfo, allowed_hashes: &[MpcDockerImageHash]) -> bool {
        let mut mpc_image_hash_events = tcb_info
            .event_log
            .iter()
            .filter(|event| event.event == MPC_IMAGE_HASH_EVENT && event.imr == RTMR3_INDEX);

        let digest_is_correct = mpc_image_hash_events.next().is_some_and(|event| {
            allowed_hashes
                .iter()
                .any(|hash| hash.as_hex() == *event.event_payload)
        });
        let single_repetition = mpc_image_hash_events.next().is_none();
        single_repetition && digest_is_correct
    }

    fn verify_launcher_compose_hash(
        &self,
        tcb_info: &TcbInfo,
        allowed_hashes: &[LauncherDockerComposeHash],
    ) -> bool {
        let app_compose: AppCompose = match serde_json::from_str(&tcb_info.app_compose) {
            Ok(compose) => compose,
            Err(e) => {
                tracing::error!("Failed to parse app_compose JSON: {:?}", e);
                return false;
            }
        };
        let launcher_bytes = sha256(app_compose.docker_compose_file.as_bytes());
        allowed_hashes
            .iter()
            .any(|hash| hash.as_hex() == hex::encode(&launcher_bytes))
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
