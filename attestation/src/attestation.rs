use crate::{
    app_compose::AppCompose, collateral::Collateral, measurements::ExpectedMeasurements,
    quote::Quote, report_data::ReportData, tcbinfo::TcbInfo,
};
use dcap_qvl::verify::VerifiedReport;
use derive_more::Constructor;
use dstack_sdk::dstack_client::EventLog;
use k256::sha2::{Digest as _, Sha384};
use mpc_primitives::hash::MpcDockerImageHash;
use near_sdk::env::sha256;

/// Expected TCB status for a successfully verified TEE quote.
const EXPECTED_QUOTE_STATUS: &str = "UpToDate";

#[allow(clippy::large_enum_variant)]
pub enum Attestation {
    Dstack(DstackAttestation),
    Local(LocalAttestation),
}

#[allow(dead_code)]
#[derive(Constructor)]
pub struct DstackAttestation {
    quote: Quote,
    collateral: Collateral,
    tcb_info: TcbInfo,
    expected_measurements: ExpectedMeasurements,
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
        // && self.verify_app_compose(&attestation.tcb_info)
        // && self.verify_local_sgx_hash(&attestation.tcb_info, &attestation.expected_measurements)
        // && self.verify_mpc_hash(&attestation.tcb_info, allowed_docker_image_hashes)
    }

    /// Replays RTMR3 from the event log by hashing all relevant events together.
    fn replay_rtmr3(event_log: &[EventLog]) -> [u8; 48] {
        const IMR: u32 = 3;
        let mut digest = [0u8; 48];

        let filtered_events = event_log.iter().filter(|e| e.imr == IMR);

        for event in filtered_events {
            let mut hasher = Sha384::new();
            hasher.update(digest);
            match hex::decode(event.digest.as_str()) {
                Ok(decoded_bytes) => hasher.update(decoded_bytes.as_slice()),
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

        digest
    }

    fn validate_compose_hash(expected_hex: &str, app_compose: &str) -> bool {
        match hex::decode(expected_hex) {
            Ok(bytes) => match <[u8; 48]>::try_from(bytes.as_slice()) {
                Ok(expected_bytes) => Self::replay_app_compose(app_compose) == expected_bytes,
                Err(_) => {
                    tracing::error!(
                        "Failed to convert decoded hex to [u8; 48] for compose-hash event"
                    );
                    false
                }
            },
            Err(e) => {
                tracing::error!(
                    "Failed to decode hex string for compose-hash event: {:?}",
                    e
                );
                false
            }
        }
    }

    fn replay_app_compose(app_compose: &str) -> [u8; 48] {
        // sha256 of app_compose from TcbInfo
        let sha256_vec = sha256(app_compose.as_bytes());
        let mut sha256_bytes = [0u8; 32];
        sha256_bytes.copy_from_slice(&sha256_vec);

        // sha384 of custom encoding: [phala_prefix]:[event_name]:[sha256_payload]
        let mut hasher = Sha384::new();
        hasher.update([0x01, 0x00, 0x00, 0x08]);
        hasher.update(b":");
        hasher.update("compose-hash".as_bytes());
        hasher.update(b":");
        hasher.update(sha256_bytes);
        hasher.finalize().into()
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
            && report_data.rt_mr3 == Self::replay_rtmr3(&tcb_info.event_log)
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

        let docker_compose = match serde_yaml::to_string(&app_compose.docker_compose_file) {
            Ok(yaml_string) => yaml_string,
            Err(_) => return false,
        };

        tcb_info
            .event_log
            .iter()
            .find(|event| event.event == "compose-hash")
            .is_some_and(|event| {
                Self::validate_app_compose_config(&app_compose)
                    && Self::validate_compose_hash(&event.digest, &docker_compose)
            })
    }

    /// Validates app compose configuration against expected security requirements.
    fn validate_app_compose_config(app_compose: &AppCompose) -> bool {
        app_compose.manifest_version == 2
            && app_compose.runner == "docker-compose"
            && app_compose.docker_config == serde_json::json!({})
            && !app_compose.kms_enabled
            && app_compose.gateway_enabled == Some(false)
            && app_compose.public_logs
            && app_compose.public_sysinfo
            && app_compose.local_key_provider_enabled
            && app_compose.allowed_envs.is_empty()
            && app_compose.no_instance_id
            && app_compose.secure_time == Some(false)
            && app_compose.pre_launch_script.is_none()
    }

    /// Verifies local key-provider hash matches expected value.
    fn verify_local_sgx_hash(
        &self,
        tcb_info: &TcbInfo,
        expected_measurements: &ExpectedMeasurements,
    ) -> bool {
        tcb_info
            .event_log
            .iter()
            .find(|event| event.event == "key-provider")
            .map(|event| &event.digest)
            .is_some_and(|hash| *hash == hex::encode(expected_measurements.local_sgx_hash))
    }

    /// Verifies MPC node image hash is in allowed list.
    fn verify_mpc_hash(&self, tcb_info: &TcbInfo, allowed_hashes: &[MpcDockerImageHash]) -> bool {
        tcb_info
            .event_log
            .iter()
            .find(|e| e.event == "mpc-image-digest")
            .map(|e| &e.digest)
            .is_some_and(|digest| allowed_hashes.iter().any(|hash| hash.as_hex() == *digest))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        measurements::Measurements,
        report_data::{ReportDataV1, ReportDataVersion},
    };

    use super::*;
    use dstack_sdk::dstack_client::TcbInfo as DstackTcbInfo;
    use near_crypto::PublicKey;
    use rstest::rstest;
    use serde_json::{Value, json};

    fn mock_local_attestation(quote_verification_result: bool) -> Attestation {
        Attestation::Local(LocalAttestation {
            verification_result: quote_verification_result,
        })
    }

    fn create_test_collateral_json() -> Value {
        json!({"tcb_info_issuer_chain":"-----BEGIN CERTIFICATE-----\nMIICjTCCAjKgAwIBAgIUfjiC1ftVKUpASY5FhAPpFJG99FUwCgYIKoZIzj0EAwIw\naDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv\ncnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ\nBgNVBAYTAlVTMB4XDTI1MDUwNjA5MjUwMFoXDTMyMDUwNjA5MjUwMFowbDEeMBwG\nA1UEAwwVSW50ZWwgU0dYIFRDQiBTaWduaW5nMRowGAYDVQQKDBFJbnRlbCBDb3Jw\nb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMQswCQYD\nVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABENFG8xzydWRfK92bmGv\nP+mAh91PEyV7Jh6FGJd5ndE9aBH7R3E4A7ubrlh/zN3C4xvpoouGlirMba+W2lju\nypajgbUwgbIwHwYDVR0jBBgwFoAUImUM1lqdNInzg7SVUr9QGzknBqwwUgYDVR0f\nBEswSTBHoEWgQ4ZBaHR0cHM6Ly9jZXJ0aWZpY2F0ZXMudHJ1c3RlZHNlcnZpY2Vz\nLmludGVsLmNvbS9JbnRlbFNHWFJvb3RDQS5kZXIwHQYDVR0OBBYEFH44gtX7VSlK\nQEmORYQD6RSRvfRVMA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMAoGCCqG\nSM49BAMCA0kAMEYCIQDdmmRuAo3qCO8TC1IoJMITAoOEw4dlgEBHzSz1TuMSTAIh\nAKVTqOkt59+co0O3m3hC+v5Fb00FjYWcgeu3EijOULo5\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw\naDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv\ncnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ\nBgNVBAYTAlVTMB4XDTE4MDUyMTEwNDUxMFoXDTQ5MTIzMTIzNTk1OVowaDEaMBgG\nA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0\naW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT\nAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7\n1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB\nuzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ\nMEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50\nZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUImUM1lqdNInzg7SV\nUr9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI\nKoZIzj0EAwIDSQAwRgIhAOW/5QkR+S9CiSDcNoowLuPRLsWGf/Yi7GSX94BgwTwg\nAiEA4J0lrHoMs+Xo5o/sX6O9QWxHRAvZUGOdRQ7cvqRXaqI=\n-----END CERTIFICATE-----\n","tcb_info":"{\"id\":\"TDX\",\"version\":3,\"issueDate\":\"2025-08-05T10:50:09Z\",\"nextUpdate\":\"2025-09-04T10:50:09Z\",\"fmspc\":\"b0c06f000000\",\"pceId\":\"0000\",\"tcbType\":0,\"tcbEvaluationDataNumber\":17,\"tdxModule\":{\"mrsigner\":\"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"attributes\":\"0000000000000000\",\"attributesMask\":\"FFFFFFFFFFFFFFFF\"},\"tdxModuleIdentities\":[{\"id\":\"TDX_03\",\"mrsigner\":\"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"attributes\":\"0000000000000000\",\"attributesMask\":\"FFFFFFFFFFFFFFFF\",\"tcbLevels\":[{\"tcb\":{\"isvsvn\":3},\"tcbDate\":\"2024-03-13T00:00:00Z\",\"tcbStatus\":\"UpToDate\"}]},{\"id\":\"TDX_01\",\"mrsigner\":\"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"attributes\":\"0000000000000000\",\"attributesMask\":\"FFFFFFFFFFFFFFFF\",\"tcbLevels\":[{\"tcb\":{\"isvsvn\":4},\"tcbDate\":\"2024-03-13T00:00:00Z\",\"tcbStatus\":\"UpToDate\"},{\"tcb\":{\"isvsvn\":2},\"tcbDate\":\"2023-08-09T00:00:00Z\",\"tcbStatus\":\"OutOfDate\"}]}],\"tcbLevels\":[{\"tcb\":{\"sgxtcbcomponents\":[{\"svn\":2,\"category\":\"BIOS\",\"type\":\"Early Microcode Update\"},{\"svn\":2,\"category\":\"OS/VMM\",\"type\":\"SGX Late Microcode Update\"},{\"svn\":2,\"category\":\"OS/VMM\",\"type\":\"TXT SINIT\"},{\"svn\":2,\"category\":\"BIOS\"},{\"svn\":3,\"category\":\"BIOS\"},{\"svn\":1,\"category\":\"BIOS\"},{\"svn\":0},{\"svn\":5,\"category\":\"OS/VMM\",\"type\":\"SEAMLDR ACM\"},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0}],\"pcesvn\":11,\"tdxtcbcomponents\":[{\"svn\":5,\"category\":\"OS/VMM\",\"type\":\"TDX Module\"},{\"svn\":0,\"category\":\"OS/VMM\",\"type\":\"TDX Module\"},{\"svn\":2,\"category\":\"OS/VMM\",\"type\":\"TDX Late Microcode Update\"},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0}]},\"tcbDate\":\"2024-03-13T00:00:00Z\",\"tcbStatus\":\"UpToDate\"},{\"tcb\":{\"sgxtcbcomponents\":[{\"svn\":2,\"category\":\"BIOS\",\"type\":\"Early Microcode Update\"},{\"svn\":2,\"category\":\"OS/VMM\",\"type\":\"SGX Late Microcode Update\"},{\"svn\":2,\"category\":\"OS/VMM\",\"type\":\"TXT SINIT\"},{\"svn\":2,\"category\":\"BIOS\"},{\"svn\":3,\"category\":\"BIOS\"},{\"svn\":1,\"category\":\"BIOS\"},{\"svn\":0},{\"svn\":5,\"category\":\"OS/VMM\",\"type\":\"SEAMLDR ACM\"},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0}],\"pcesvn\":5,\"tdxtcbcomponents\":[{\"svn\":5,\"category\":\"OS/VMM\",\"type\":\"TDX Module\"},{\"svn\":0,\"category\":\"OS/VMM\",\"type\":\"TDX Module\"},{\"svn\":2,\"category\":\"OS/VMM\",\"type\":\"TDX Late Microcode Update\"},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0}]},\"tcbDate\":\"2018-01-04T00:00:00Z\",\"tcbStatus\":\"OutOfDate\",\"advisoryIDs\":[\"INTEL-SA-00106\",\"INTEL-SA-00115\",\"INTEL-SA-00135\",\"INTEL-SA-00203\",\"INTEL-SA-00220\",\"INTEL-SA-00233\",\"INTEL-SA-00270\",\"INTEL-SA-00293\",\"INTEL-SA-00320\",\"INTEL-SA-00329\",\"INTEL-SA-00381\",\"INTEL-SA-00389\",\"INTEL-SA-00477\",\"INTEL-SA-00837\"]}]}","tcb_info_signature":"9a3ed7e1cbf5b3f022fc51573c9e890728ba0db129be30fa8bea90ad79464ede1dcf7f43558d107cdc770571f4430310f7d6f0be2a62f1211ca1efc64d166cb3","qe_identity_issuer_chain":"-----BEGIN CERTIFICATE-----\nMIICjTCCAjKgAwIBAgIUfjiC1ftVKUpASY5FhAPpFJG99FUwCgYIKoZIzj0EAwIw\naDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv\ncnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ\nBgNVBAYTAlVTMB4XDTI1MDUwNjA5MjUwMFoXDTMyMDUwNjA5MjUwMFowbDEeMBwG\nA1UEAwwVSW50ZWwgU0dYIFRDQiBTaWduaW5nMRowGAYDVQQKDBFJbnRlbCBDb3Jw\nb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMQswCQYD\nVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABENFG8xzydWRfK92bmGv\nP+mAh91PEyV7Jh6FGJd5ndE9aBH7R3E4A7ubrlh/zN3C4xvpoouGlirMba+W2lju\nypajgbUwgbIwHwYDVR0jBBgwFoAUImUM1lqdNInzg7SVUr9QGzknBqwwUgYDVR0f\nBEswSTBHoEWgQ4ZBaHR0cHM6Ly9jZXJ0aWZpY2F0ZXMudHJ1c3RlZHNlcnZpY2Vz\nLmludGVsLmNvbS9JbnRlbFNHWFJvb3RDQS5kZXIwHQYDVR0OBBYEFH44gtX7VSlK\nQEmORYQD6RSRvfRVMA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMAoGCCqG\nSM49BAMCA0kAMEYCIQDdmmRuAo3qCO8TC1IoJMITAoOEw4dlgEBHzSz1TuMSTAIh\nAKVTqOkt59+co0O3m3hC+v5Fb00FjYWcgeu3EijOULo5\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw\naDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv\ncnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ\nBgNVBAYTAlVTMB4XDTE4MDUyMTEwNDUxMFoXDTQ5MTIzMTIzNTk1OVowaDEaMBgG\nA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0\naW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT\nAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7\n1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB\nuzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ\nMEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50\nZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUImUM1lqdNInzg7SV\nUr9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI\nKoZIzj0EAwIDSQAwRgIhAOW/5QkR+S9CiSDcNoowLuPRLsWGf/Yi7GSX94BgwTwg\nAiEA4J0lrHoMs+Xo5o/sX6O9QWxHRAvZUGOdRQ7cvqRXaqI=\n-----END CERTIFICATE-----\n","qe_identity":"{\"id\":\"TD_QE\",\"version\":2,\"issueDate\":\"2025-08-05T11:27:26Z\",\"nextUpdate\":\"2025-09-04T11:27:26Z\",\"tcbEvaluationDataNumber\":17,\"miscselect\":\"00000000\",\"miscselectMask\":\"FFFFFFFF\",\"attributes\":\"11000000000000000000000000000000\",\"attributesMask\":\"FBFFFFFFFFFFFFFF0000000000000000\",\"mrsigner\":\"DC9E2A7C6F948F17474E34A7FC43ED030F7C1563F1BABDDF6340C82E0E54A8C5\",\"isvprodid\":2,\"tcbLevels\":[{\"tcb\":{\"isvsvn\":4},\"tcbDate\":\"2024-03-13T00:00:00Z\",\"tcbStatus\":\"UpToDate\"}]}","qe_identity_signature":"537a22f7e34b9c8f573cd0b791b040142c27702705a5ea15933ba2a14a324e33a8b694c71a5afb8cb60c3556fa698f4cd17066292616546728007385f18838cb"})
    }

    fn mock_dstack_attestation() -> Attestation {
        const VALID_QUOTE_HEX: &str = "040002008100000000000000939a7233f79c4ca9940a0db3957f06078034f4c3963ec6129de9141e92764277000000000701030000000000000000000000000049b66faa451d19ebbdbe89371b8daf2b65aa3984ec90110343e9e2eec116af08850fa20e3b1aa9a874d77a65380ee7e600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000e702060000000000c68518a0ebb42136c12b2275164f8c72f25fa9a34392228687ed6e9caeb9c0f1dbd895e9cf475121c029dc47e70e91fd017e06d8e38e4cd81b01d99ad3138517f8f2d5d989fd7b705fa4ac9b15b58149a90000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003744b154069500a466f514253b49858299b2e1bdc44e3d557337d81e828bedf6a0410f27d3a18c932e5e49e1c42157374b66e888c8dfa7a504fc7ca060ab9e2d051233f115d71304085570c7ac71f5a190a3e237d15f0965967a78539ba0d7875a41c9f71ce5655b6ba605fe0d00a0a05add7471acaaa6aa155bce1e04b8204f0fffaec2e6c95ffc1442b37e141127d947e591f8ee447150812067f7a6458451f9c74a995830815f93146a6d6fdeb7dafd0989eaa63df9b66c78aa1b3ee3a3b000010d6bbc3fea6875f640bf334454ef179ac0db53eecf4e9a40bce3d782a21322b8374bb44681d48d26510e9cca99a57cd10000000000000000000000000000cc10000088cd26cfe9bde28ef92d92640dad8a7da6aa2500809f92d20d84d67576394e839d5ded7797b3ab5336b589fe5d3632e75c0b37fa73b345a34e0d947149f855e426496bd4c37d07cf006594b7d411570252446d99ac9c81bc6e60e351edf0d2310e3e7b99d50274104a4378fae1f9b6d64a1a8f506a856f732c45d770802038df0600461000000303191b04ff0006000000000000000000000000000000000000000000000000000000000000000000000000000000001500000000000000e700000000000000e5a3a7b5d830c2953b98534c6c59a3a34fdc34e933f7f5898f0a85cf08846bca0000000000000000000000000000000000000000000000000000000000000000dc9e2a7c6f948f17474e34a7fc43ed030f7c1563f1babddf6340c82e0e54a8c5000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020006000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005abcb6edd8f72b258ded15ece343f5add4ea3d68b82b74b2dc2c64ab2ad13bb90000000000000000000000000000000000000000000000000000000000000000131ebf4810ca59a01e6a444b8d30089b49c42ac32cb4422d60608ad93c6a7f631feb994066c051f9620d1b769812f10cf455e2739bede5453ccfc95c9d486f6e2000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f05005e0e00002d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d49494538444343424a656741774942416749564150434f50736f446a625237724636475a364d2b4a6e516d4d5734754d416f4743437147534d343942414d430a4d484178496a416742674e5642414d4d47556c756447567349464e4857434251513073675547786864475a76636d306751304578476a415942674e5642416f4d0a45556c756447567349454e76636e4276636d4630615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b47413155450a4341774351304578437a414a42674e5642415954416c56544d423458445449314d4459774f5445784d6a55794e466f5844544d794d4459774f5445784d6a55790a4e466f77634445694d434147413155454177775a535735305a5777675530645949464244537942445a584a3061575a70593246305a5445614d426747413155450a43677752535735305a577767513239796347397959585270623234784644415342674e564241634d43314e68626e526849454e7359584a684d517377435159440a5651514944414a445154454c4d416b474131554542684d4356564d775754415442676371686b6a4f5051494242676771686b6a4f50514d4242774e43414154610a422b585047564e76734a7344354f497876374c433773524e4d6c2f336a414a445450497239725475325246447750374a724d784b4158675262456541644f674c0a4555745a4a6b6a496a38695351724643595247396f3449444444434341776777487759445652306a42426777466f41556c5739647a62306234656c4153636e550a3944504f4156634c336c5177617759445652306642475177596a42676f46366758495a616148523063484d364c79396863476b7564484a316333526c5a484e6c0a636e5a705932567a4c6d6c75644756734c6d4e766253397a5a3367765932567964476c6d61574e6864476c76626939324e4339775932746a636d772f593245390a6347786864475a76636d306d5a57356a62325270626d63395a4756794d4230474131556444675157424253437974663263636e513878764631383348445836350a79732b657144414f42674e56485138424166384542414d434273417744415944565230544151482f4241497741444343416a6b4743537147534962345451454e0a4151534341696f776767496d4d42344743697147534962345451454e41514545455030486b327a7541744b5543576c5870346f706d7738776767466a42676f710a686b69472b453042445145434d494942557a415142677371686b69472b4530424451454341514942417a415142677371686b69472b45304244514543416749420a417a415142677371686b69472b4530424451454341774942416a415142677371686b69472b4530424451454342414942416a415142677371686b69472b4530420a44514543425149424244415142677371686b69472b45304244514543426749424154415142677371686b69472b453042445145434277494241444151426773710a686b69472b45304244514543434149424254415142677371686b69472b45304244514543435149424144415142677371686b69472b45304244514543436749420a4144415142677371686b69472b45304244514543437749424144415142677371686b69472b45304244514543444149424144415142677371686b69472b4530420a44514543445149424144415142677371686b69472b45304244514543446749424144415142677371686b69472b453042445145434477494241444151426773710a686b69472b45304244514543454149424144415142677371686b69472b4530424451454345514942437a416642677371686b69472b45304244514543456751510a41774d43416751424141554141414141414141414144415142676f71686b69472b45304244514544424149414144415542676f71686b69472b453042445145450a4241617777473841414141774477594b4b6f5a496876684e4151304242516f424154416542676f71686b69472b45304244514547424241694e4855646f35462b0a382f45444873325767657a434d45514743697147534962345451454e415163774e6a415142677371686b69472b45304244514548415145422f7a4151426773710a686b69472b45304244514548416745422f7a415142677371686b69472b45304244514548417745422f7a414b42676771686b6a4f5051514441674e48414442450a41694246706b6175756e4f525a336771666e522b4b4a4141367373546d4f487a6b354b6a2f6d3774425875367577496749487353394136577846306a492f51790a62526c6c642f37363651355052464f6c594b414f475369426f44673d0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a2d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d4949436c6a4343416a32674177494241674956414a567658633239472b487051456e4a3150517a7a674658433935554d416f4743437147534d343942414d430a4d476778476a415942674e5642414d4d45556c756447567349464e48574342536232393049454e424d526f77474159445651514b4442464a626e526c624342440a62334a7762334a6864476c76626a45554d424947413155454277774c553246756447456751327868636d4578437a414a42674e564241674d416b4e424d5173770a435159445651514745774a56557a4165467730784f4441314d6a45784d4455774d5442614677307a4d7a41314d6a45784d4455774d5442614d484178496a41670a42674e5642414d4d47556c756447567349464e4857434251513073675547786864475a76636d306751304578476a415942674e5642416f4d45556c75644756730a49454e76636e4276636d4630615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b474131554543417743513045780a437a414a42674e5642415954416c56544d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a304441516344516741454e53422f377432316c58534f0a3243757a7078773734654a423732457944476757357258437478327456544c7136684b6b367a2b5569525a436e71523770734f766771466553786c6d546c4a6c0a65546d693257597a33714f42757a43427544416642674e5648534d4547444157674251695a517a575770303069664f44744a5653763141624f536347724442530a42674e5648523845537a424a4d45656752614244686b466f64485277637a6f764c324e6c636e52705a6d6c6a5958526c63793530636e567a6447566b633256790a646d6c6a5a584d75615735305a577775593239744c306c756447567355306459556d397664454e424c6d526c636a416442674e5648513445466751556c5739640a7a62306234656c4153636e553944504f4156634c336c517744675944565230504151482f42415144416745474d42494741315564457745422f7751494d4159420a4166384341514177436759494b6f5a497a6a30454177494452774177524149675873566b6930772b6936565947573355462f32327561586530594a446a3155650a6e412b546a44316169356343494359623153416d4435786b66545670766f34556f79695359787244574c6d5552344349394e4b7966504e2b0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a2d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d4949436a7a4343416a53674177494241674955496d554d316c71644e496e7a6737535655723951477a6b6e42717777436759494b6f5a497a6a3045417749770a614445614d4267474131554541777752535735305a5777675530645949464a766233516751304578476a415942674e5642416f4d45556c756447567349454e760a636e4276636d4630615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b47413155454341774351304578437a414a0a42674e5642415954416c56544d423458445445344d4455794d5445774e4455784d466f58445451354d54497a4d54497a4e546b314f566f77614445614d4267470a4131554541777752535735305a5777675530645949464a766233516751304578476a415942674e5642416f4d45556c756447567349454e76636e4276636d46300a615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b47413155454341774351304578437a414a42674e56424159540a416c56544d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a3044415163445167414543366e45774d4449595a4f6a2f69505773437a61454b69370a314f694f534c52466857476a626e42564a66566e6b59347533496a6b4459594c304d784f346d717379596a6c42616c54565978465032734a424b357a6c4b4f420a757a43427544416642674e5648534d4547444157674251695a517a575770303069664f44744a5653763141624f5363477244425342674e5648523845537a424a0a4d45656752614244686b466f64485277637a6f764c324e6c636e52705a6d6c6a5958526c63793530636e567a6447566b63325679646d6c6a5a584d75615735300a5a577775593239744c306c756447567355306459556d397664454e424c6d526c636a416442674e564851344546675155496d554d316c71644e496e7a673753560a55723951477a6b6e4271777744675944565230504151482f42415144416745474d42494741315564457745422f7751494d4159424166384341514577436759490a4b6f5a497a6a3045417749445351417752674968414f572f35516b522b533943695344634e6f6f774c7550524c735747662f59693747535839344267775477670a41694541344a306c72486f4d732b586f356f2f7358364f39515778485241765a55474f6452513763767152586171493d0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        let quote: Quote = VALID_QUOTE_HEX.parse().unwrap();
        let collateral = Collateral::try_from_json(create_test_collateral_json()).unwrap();
        let tcb_info = json!(
        {
            "mrtd": "c68518a0ebb42136c12b2275164f8c72f25fa9a34392228687ed6e9caeb9c0f1dbd895e9cf475121c029dc47e70e91fd",
            "rtmr0": "3744b154069500a466f514253b49858299b2e1bdc44e3d557337d81e828bedf6a0410f27d3a18c932e5e49e1c4215737",
            "rtmr1": "4b66e888c8dfa7a504fc7ca060ab9e2d051233f115d71304085570c7ac71f5a190a3e237d15f0965967a78539ba0d787",
            "rtmr2": "5a41c9f71ce5655b6ba605fe0d00a0a05add7471acaaa6aa155bce1e04b8204f0fffaec2e6c95ffc1442b37e141127d9",
            "rtmr3": "47e591f8ee447150812067f7a6458451f9c74a995830815f93146a6d6fdeb7dafd0989eaa63df9b66c78aa1b3ee3a3b0",
            "os_image_hash": "",
            "compose_hash": "7e06d8e38e4cd81b01d99ad3138517f8f2d5d989fd7b705fa4ac9b15b58149a9",
            "device_id": "f61bdbd417b4a1b6519e698e2ea90420c21140702b608c08c72fb51ec52a5fea",
            "app_compose": "{\"manifest_version\":2,\"name\":\"launcher_test_app\",\"runner\":\"docker-compose\",\"docker_compose_file\":\"version: '3.8'\\n\\nservices:\\n  launcher:\\n    image: barakeinavnear/launcher@sha256:1ea7571baf18bd052359abd2a1f269e7836f9bad2270eb55fc9475aa327f8d96\\n\\n # isuse #531: TODO (security): Replace with a specific image digest\\n    container_name: launcher\\n\\n    environment:\\n      - DOCKER_CONTENT_TRUST=1\\n      - DEFAULT_IMAGE_DIGEST=sha256:a87f7eb6882446dd714e6d47d9d1b9331cb333f36d3905f172c68adbd06e461f  # nearone/mpc-node-gcp:testnet-release\\n\\n    volumes:\\n      - /var/run/docker.sock:/var/run/docker.sock\\n      - /var/run/dstack.sock:/var/run/dstack.sock\\n      - /tapp:/tapp:ro\\n      - shared-volume:/mnt/shared:ro\\n\\n    security_opt:\\n      - no-new-privileges:true\\n\\n    read_only: true\\n\\n    tmpfs:\\n      - /tmp  # Required for many apps to function correctly when root FS is read-only\\n\\nvolumes:\\n  shared-volume:\\n    name: shared-volume\",\"kms_enabled\":false,\"gateway_enabled\":false,\"local_key_provider_enabled\":true,\"key_provider_id\":\"\",\"public_logs\":true,\"public_sysinfo\":true,\"allowed_envs\":[],\"no_instance_id\":true,\"secure_time\":true}",
            "event_log": [
                {
                    "imr": 0,
                    "event_type": 2147483659_u64,
                    "digest": "519245d8b6b54b48b57143e6647d41e5e6f3b4ef10a73c95be4d9a9c0f54115b707e7af5e38f7be6852229b18573690d",
                    "event": "",
                    "event_payload": "095464785461626c65000100000000000000af96bb93f2b9b84e9462e0ba745642360090800000000000"
                },
                {
                    "imr": 0,
                    "event_type": 2147483658_u64,
                    "digest": "344bc51c980ba621aaa00da3ed7436f7d6e549197dfe699515dfa2c6583d95e6412af21c097d473155875ffd561d6790",
                    "event": "",
                    "event_payload": "2946762858585858585858582d585858582d585858582d585858582d58585858585858585858585829000000c0ff000000000040080000000000"
                },
                {
                    "imr": 0,
                    "event_type": 2147483649_u64,
                    "digest": "9dc3a1f80bcec915391dcda5ffbb15e7419f77eab462bbf72b42166fb70d50325e37b36f93537a863769bcf9bedae6fb",
                    "event": "",
                    "event_payload": "61dfe48bca93d211aa0d00e098032b8c0a00000000000000000000000000000053006500630075007200650042006f006f007400"
                },
                {
                    "imr": 0,
                    "event_type": 2147483649_u64,
                    "digest": "6f2e3cbc14f9def86980f5f66fd85e99d63e69a73014ed8a5633ce56eca5b64b692108c56110e22acadcef58c3250f1b",
                    "event": "",
                    "event_payload": "61dfe48bca93d211aa0d00e098032b8c0200000000000000000000000000000050004b00"
                },
                {
                    "imr": 0,
                    "event_type": 2147483649_u64,
                    "digest": "d607c0efb41c0d757d69bca0615c3a9ac0b1db06c557d992e906c6b7dee40e0e031640c7bfd7bcd35844ef9edeadc6f9",
                    "event": "",
                    "event_payload": "61dfe48bca93d211aa0d00e098032b8c030000000000000000000000000000004b0045004b00"
                },
                {
                    "imr": 0,
                    "event_type": 2147483649_u64,
                    "digest": "08a74f8963b337acb6c93682f934496373679dd26af1089cb4eaf0c30cf260a12e814856385ab8843e56a9acea19e127",
                    "event": "",
                    "event_payload": "cbb219d73a3d9645a3bcdad00e67656f0200000000000000000000000000000064006200"
                },
                {
                    "imr": 0,
                    "event_type": 2147483649_u64,
                    "digest": "18cc6e01f0c6ea99aa23f8a280423e94ad81d96d0aeb5180504fc0f7a40cb3619dd39bd6a95ec1680a86ed6ab0f9828d",
                    "event": "",
                    "event_payload": "cbb219d73a3d9645a3bcdad00e67656f03000000000000000000000000000000640062007800"
                },
                {
                    "imr": 0,
                    "event_type": 4_u64,
                    "digest": "394341b7182cd227c5c6b07ef8000cdfd86136c4292b8e576573ad7ed9ae41019f5818b4b971c9effc60e1ad9f1289f0",
                    "event": "",
                    "event_payload": "00000000"
                },
                {
                    "imr": 0,
                    "event_type": 10_u64,
                    "digest": "6dae15170c9fea6455681e3f838941a642ff9001a02a333e9ca8549af1db4ba47f01403e31dabe6e8a0b41ddd38b6d99",
                    "event": "",
                    "event_payload": "414350492044415441"
                },
                {
                    "imr": 0,
                    "event_type": 10_u64,
                    "digest": "b3a62232ef6be064cce25a8b92cf55d4a6c099ee7a9c0852ce0c7d572393dae84895c0f59a9db5000f0b34a90c1b1bec",
                    "event": "",
                    "event_payload": "414350492044415441"
                },
                {
                    "imr": 0,
                    "event_type": 10_u64,
                    "digest": "b6ed8ff3fca3c308f3f1ec7889054cc900b1c6dad9b14aedd0144d046626c81a5dbae47937f4949bb2d674a0bd699a7b",
                    "event": "",
                    "event_payload": "414350492044415441"
                },
                {
                    "imr": 1,
                    "event_type": 2147483651_u64,
                    "digest": "8cc63f85b7793b5c25bd02b8f68508b99fd4a1d59b477e4053dfd91768dfa62822be5ab001b353cbde25eb173a228723",
                    "event": "",
                    "event_payload": "18804e7c000000000094b4000000000000000000000000002a000000000000000403140072f728144ab61e44b8c39ebdd7f893c7040412006b00650072006e0065006c0000007fff0400"
                },
                {
                    "imr": 0,
                    "event_type": 2147483650_u64,
                    "digest": "1dd6f7b457ad880d840d41c961283bab688e94e4b59359ea45686581e90feccea3c624b1226113f824f315eb60ae0a7c",
                    "event": "",
                    "event_payload": "61dfe48bca93d211aa0d00e098032b8c0900000000000000020000000000000042006f006f0074004f0072006400650072000000"
                },
                {
                    "imr": 0,
                    "event_type": 2147483650_u64,
                    "digest": "23ada07f5261f12f34a0bd8e46760962d6b4d576a416f1fea1c64bc656b1d28eacf7047ae6e967c58fd2a98bfa74c298",
                    "event": "",
                    "event_payload": "61dfe48bca93d211aa0d00e098032b8c08000000000000003e0000000000000042006f006f0074003000300030003000090100002c0055006900410070007000000004071400c9bdb87cebf8344faaea3ee4af6516a10406140021aa2c4614760345836e8ab6f46623317fff0400"
                },
                {
                    "imr": 1,
                    "event_type": 2147483655_u64,
                    "digest": "77a0dab2312b4e1e57a84d865a21e5b2ee8d677a21012ada819d0a98988078d3d740f6346bfe0abaa938ca20439a8d71",
                    "event": "",
                    "event_payload": "43616c6c696e6720454649204170706c69636174696f6e2066726f6d20426f6f74204f7074696f6e"
                },
                {
                    "imr": 1,
                    "event_type": 4_u64,
                    "digest": "394341b7182cd227c5c6b07ef8000cdfd86136c4292b8e576573ad7ed9ae41019f5818b4b971c9effc60e1ad9f1289f0",
                    "event": "",
                    "event_payload": "00000000"
                },
                {
                    "imr": 2,
                    "event_type": 6_u64,
                    "digest": "3a39dd006e06b2e52764221aee49c94bd4ef798317f27968140e6d0823f52b4ee87b2788960e5d119d287d9b62885a10",
                    "event": "",
                    "event_payload": "ed223b8f1a0000004c4f414445445f494d4147453a3a4c6f61644f7074696f6e7300"
                },
                {
                    "imr": 2,
                    "event_type": 6_u64,
                    "digest": "f82aa3cc8b76d7bb525184c89c5928fb67fcd8b508c55e3eec4a5e3f6f9d78b2427ae66f1689edeef0e6614e8aa3fe54",
                    "event": "",
                    "event_payload": "ec223b8f0d0000004c696e757820696e6974726400"
                },
                {
                    "imr": 1,
                    "event_type": 2147483655_u64,
                    "digest": "214b0bef1379756011344877743fdc2a5382bac6e70362d624ccf3f654407c1b4badf7d8f9295dd3dabdef65b27677e0",
                    "event": "",
                    "event_payload": "4578697420426f6f7420536572766963657320496e766f636174696f6e"
                },
                {
                    "imr": 1,
                    "event_type": 2147483655_u64,
                    "digest": "0a2e01c85deae718a530ad8c6d20a84009babe6c8989269e950d8cf440c6e997695e64d455c4174a652cd080f6230b74",
                    "event": "",
                    "event_payload": "4578697420426f6f742053657276696365732052657475726e656420776974682053756363657373"
                },
                {
                    "imr": 3,
                    "event_type": 134217729_u64,
                    "digest": "f9974020ef507068183313d0ca808e0d1ca9b2d1ad0c61f5784e7157c362c06536f5ddacdad4451693f48fcc72fff624",
                    "event": "system-preparing",
                    "event_payload": ""
                },
                {
                    "imr": 3,
                    "event_type": 134217729_u64,
                    "digest": "507d068c19afb9b4bedf2a4a8854b99f67b57ead2cdfde2008124dfff70701c5d1cf8119048e69529b5547c5f69167b7",
                    "event": "app-id",
                    "event_payload": "7e06d8e38e4cd81b01d99ad3138517f8f2d5d989"
                },
                {
                    "imr": 3,
                    "event_type": 134217729_u64,
                    "digest": "1487d60c8aba4acf71730bf970fb4c6a77823f84d9ec60c56d587a922bab7c96830b154ccd927e3ef388e38c3ed5890b",
                    "event": "compose-hash",
                    "event_payload": "7e06d8e38e4cd81b01d99ad3138517f8f2d5d989fd7b705fa4ac9b15b58149a9"
                },
                {
                    "imr": 3,
                    "event_type": 134217729_u64,
                    "digest": "305a62e30e8f4ca791946c3ede6755cfacebe02be9101f0bccf2591509a0c8e8095bc83b3d53bfc5d70d6c7cf7813fc5",
                    "event": "instance-id",
                    "event_payload": ""
                },
                {
                    "imr": 3,
                    "event_type": 134217729_u64,
                    "digest": "98bd7e6bd3952720b65027fd494834045d06b4a714bf737a06b874638b3ea00ff402f7f583e3e3b05e921c8570433ac6",
                    "event": "boot-mr-done",
                    "event_payload": ""
                },
                {
                    "imr": 3,
                    "event_type": 134217729_u64,
                    "digest": "74ca939b8c3c74aab3c30966a788f7743951d54a936a711dd01422f003ff9df6666f3cc54975d2e4f35c829865583f0f",
                    "event": "key-provider",
                    "event_payload": "7b226e616d65223a226c6f63616c2d736778222c226964223a2231623761343933373834303332343962363938366139303738343463616230393231656361333264643437653635376633633130333131636361656363663862227d"
                },
                {
                    "imr": 3,
                    "event_type": 134217729,
                    "digest": "1a76b2a80a0be71eae59f80945d876351a7a3fb8e9fd1ff1cede5734aa84ea11fd72b4edfbb6f04e5a85edd114c751bd",
                    "event": "system-ready",
                    "event_payload": ""
                },
                {
                    "imr": 3,
                    "event_type": 134217729,
                    "digest": "bcb7a884a6ba0970997335c548b61e2486be6065860219c5f436291d57ce62a8feb2405a63dfbbfca63be8ab6cd9e72a",
                    "event": "mpc-image-digest",
                    "event_payload": "a87f7eb6882446dd714e6d47d9d1b9331cb333f36d3905f172c68adbd06e461f"
                }
            ]
        });
        let tcb_info: DstackTcbInfo = serde_json::from_value(tcb_info).unwrap();
        let expected_measurements = ExpectedMeasurements {
            rtmrs: Measurements {
                rtmr0: [
                    0x37, 0x44, 0xb1, 0x54, 0x06, 0x95, 0x00, 0xa4, 0x66, 0xf5, 0x14, 0x25, 0x3b,
                    0x49, 0x85, 0x82, 0x99, 0xb2, 0xe1, 0xbd, 0xc4, 0x4e, 0x3d, 0x55, 0x73, 0x37,
                    0xd8, 0x1e, 0x82, 0x8b, 0xed, 0xf6, 0xa0, 0x41, 0x0f, 0x27, 0xd3, 0xa1, 0x8c,
                    0x93, 0x2e, 0x5e, 0x49, 0xe1, 0xc4, 0x21, 0x57, 0x37,
                ],
                rtmr1: [
                    0x4b, 0x66, 0xe8, 0x88, 0xc8, 0xdf, 0xa7, 0xa5, 0x04, 0xfc, 0x7c, 0xa0, 0x60,
                    0xab, 0x9e, 0x2d, 0x05, 0x12, 0x33, 0xf1, 0x15, 0xd7, 0x13, 0x04, 0x08, 0x55,
                    0x70, 0xc7, 0xac, 0x71, 0xf5, 0xa1, 0x90, 0xa3, 0xe2, 0x37, 0xd1, 0x5f, 0x09,
                    0x65, 0x96, 0x7a, 0x78, 0x53, 0x9b, 0xa0, 0xd7, 0x87,
                ],
                rtmr2: [
                    0x5a, 0x41, 0xc9, 0xf7, 0x1c, 0xe5, 0x65, 0x5b, 0x6b, 0xa6, 0x05, 0xfe, 0x0d,
                    0x00, 0xa0, 0xa0, 0x5a, 0xdd, 0x74, 0x71, 0xac, 0xaa, 0xa6, 0xaa, 0x15, 0x5b,
                    0xce, 0x1e, 0x04, 0xb8, 0x20, 0x4f, 0x0f, 0xff, 0xae, 0xc2, 0xe6, 0xc9, 0x5f,
                    0xfc, 0x14, 0x42, 0xb3, 0x7e, 0x14, 0x11, 0x27, 0xd9,
                ],
                mrtd: [
                    0xc6, 0x85, 0x18, 0xa0, 0xeb, 0xb4, 0x21, 0x36, 0xc1, 0x2b, 0x22, 0x75, 0x16,
                    0x4f, 0x8c, 0x72, 0xf2, 0x5f, 0xa9, 0xa3, 0x43, 0x92, 0x22, 0x86, 0x87, 0xed,
                    0x6e, 0x9c, 0xae, 0xb9, 0xc0, 0xf1, 0xdb, 0xd8, 0x95, 0xe9, 0xcf, 0x47, 0x51,
                    0x21, 0xc0, 0x29, 0xdc, 0x47, 0xe7, 0x0e, 0x91, 0xfd,
                ],
            },
            local_sgx_hash: [
                0x74, 0xca, 0x93, 0x9b, 0x8c, 0x3c, 0x74, 0xaa, 0xb3, 0xc3, 0x09, 0x66, 0xa7, 0x88,
                0xf7, 0x74, 0x39, 0x51, 0xd5, 0x4a, 0x93, 0x6a, 0x71, 0x1d, 0xd0, 0x14, 0x22, 0xf0,
                0x03, 0xff, 0x9d, 0xf6, 0x66, 0x6f, 0x3c, 0xc5, 0x49, 0x75, 0xd2, 0xe4, 0xf3, 0x5c,
                0x82, 0x98, 0x65, 0x58, 0x3f, 0x0f,
            ],
            report_data_version: ReportDataVersion::V1,
        };
        Attestation::Dstack(DstackAttestation::new(
            quote,
            collateral,
            tcb_info.into(),
            expected_measurements,
        ))
    }

    #[rstest]
    #[case(false, false)]
    #[case(true, true)]
    fn test_mock_attestation_verify(
        #[case] quote_verification_result: bool,
        #[case] expected_quote_verification_result: bool,
    ) {
        let timestamp_s = 0u64;
        let tls_key = "ed25519:DcA2MzgpJbrUATQLLceocVckhhAqrkingax4oJ9kZ847"
            .parse()
            .unwrap();
        let account_key = "ed25519:H9k5eiU4xXyb8F7cUDjZYNuH1zGAx5BBNrYwLPNhq6Zx"
            .parse()
            .unwrap();
        let report_data = ReportData::V1(ReportDataV1::new(tls_key, account_key));

        assert_eq!(
            mock_local_attestation(quote_verification_result)
                .verify(report_data, timestamp_s, &[],),
            expected_quote_verification_result
        );
    }

    #[test]
    fn test_verify_method_signature() {
        let attestation = mock_dstack_attestation();
        let tls_key: PublicKey = "ed25519:5SiS1SJiABiM79Yt6uEjMabAT9UguQY9hSyF7xfHLGYt"
            .parse()
            .unwrap();
        let account_key: PublicKey = "ed25519:B2JvaYmgzfXsvCxrqd4nBrBt8jo9ReqUZatG3dAZEBv5"
            .parse()
            .unwrap();
        let report_data = ReportData::V1(ReportDataV1::new(tls_key, account_key));
        let timestamp_s = 1754405596_u64;
        let allowed_hashes = &[];
        let verification_result = attestation.verify(report_data, timestamp_s, allowed_hashes);
        assert!(verification_result);
    }
}
