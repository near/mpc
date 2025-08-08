use crate::{
    app_compose::AppCompose, collateral::Collateral, measurements::ExpectedMeasurements,
    quote::Quote, report_data::ReportData, tcbinfo::TcbInfo,
};
use dcap_qvl::verify::VerifiedReport;
use derive_more::Constructor;
use dstack_sdk_types::dstack::EventLog;
use k256::sha2::{Digest as _, Sha384};
use mpc_primitives::hash::MpcDockerImageHash;
use near_sdk::env::sha256;

/// Expected TCB status for a successfully verified TEE quote.
const EXPECTED_QUOTE_STATUS: &str = "UpToDate";

// DSTACK_EVENT_TYPE is defined in https://github.com/Dstack-TEE/dstack/blob/cfa4cc4e8a4f525d537883b1a0ba5d9fbfd87f1e/tdx-attest/src/lib.rs#L28
// It is the same for all events
const DSTACK_EVENT_TYPE: u32 = 134217729;

const COMPOSE_HASH_EVENT: &str = "compose-hash";
const KEY_PROVIDER_EVENT: &str = "key-provider";
const MPC_IMAGE_HASH_EVENT: &str = "mpc-image-digest";

#[allow(clippy::large_enum_variant)]
pub enum Attestation {
    Dstack(DstackAttestation),
    Local(LocalAttestation),
}

#[allow(dead_code)]
#[derive(Constructor)]
pub struct DstackAttestation {
    pub quote: Quote,
    pub collateral: Collateral,
    pub tcb_info: TcbInfo,
    pub expected_measurements: ExpectedMeasurements,
}

#[derive(Constructor)]
pub struct LocalAttestation {
    verification_result: bool,
}

impl Attestation {
    pub fn verify(
        &self,
        expected_report_data: ReportData,
        timestamp_s: u64,
        allowed_docker_image_hashes: &[MpcDockerImageHash],
    ) -> bool {
        match self {
            Self::Dstack(dstack_attestation) => self.verify_attestation(
                dstack_attestation,
                expected_report_data,
                timestamp_s,
                allowed_docker_image_hashes,
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
        allowed_docker_image_hashes: &[MpcDockerImageHash],
    ) -> bool {
        let quote_bytes = attestation.quote.raw_bytes();

        // TODO(#451): We rely on a forked dcap_qvl crate that has some questionable code changes
        // that could be critical from a security perspective (commented out code section that
        // checks TCB validity time)
        let verification_result =
            match dcap_qvl::verify::verify(quote_bytes, &attestation.collateral, timestamp_s) {
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
            && self.verify_static_rtmrs(
                report_data,
                &attestation.tcb_info,
                &attestation.expected_measurements,
            )
            && self.verify_rtmr3(report_data, &attestation.tcb_info)
            && self.verify_app_compose(&attestation.tcb_info)
            && self
                .verify_local_sgx_digest(&attestation.tcb_info, &attestation.expected_measurements)
            && self
                .verify_local_sgx_digest(&attestation.tcb_info, &attestation.expected_measurements)
            && self.verify_mpc_hash(&attestation.tcb_info, allowed_docker_image_hashes)
    }

    /// Replays RTMR3 from the event log by hashing all relevant events together and verifies all digests
    /// are correct
    fn verify_event_log_rtmr3(event_log: &[EventLog], expected_digest: [u8; 48]) -> bool {
        const IMR: u32 = 3;
        let mut digest = [0u8; 48];

        let filtered_events = event_log.iter().filter(|e| e.imr == IMR);

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
        // Check if sha384(tls_public_key || account_public_key) matches the hash in
        // report_data. This check effectively proves that both tls_public_key and
        // account_public_key were included in the quote's report_data by an app running
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
            .filter(|event| event.event == COMPOSE_HASH_EVENT);

        let payload_is_correct = events.next().is_some_and(|event| {
            Self::validate_app_compose_config(&app_compose)
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
            .filter(|event| event.event == KEY_PROVIDER_EVENT);
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
            .filter(|event| event.event == MPC_IMAGE_HASH_EVENT);

        let digest_is_correct = mpc_image_hash_events.next().is_some_and(|event| {
            allowed_hashes
                .iter()
                .any(|hash| hash.as_hex() == *event.event_payload)
        });
        let single_repetition = mpc_image_hash_events.next().is_none();
        single_repetition && digest_is_correct
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
