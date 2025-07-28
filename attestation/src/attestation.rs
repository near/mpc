use crate::{
    app_compose::AppCompose, collateral::Collateral, quote::Quote, report_data::ReportData,
    tcbinfo::TcbInfo,
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
}

#[derive(Constructor)]
pub struct LocalAttestation {
    quote_verification_result: bool,
    #[allow(dead_code)]
    docker_image_verification_result: bool,
}

impl Attestation {
    // TODO: Define a process for updating the static RTMRs below going forward, since they are
    // probably already outdated.
    //
    // $ git rev-parse HEAD
    // fbdf2e76fb6bd9142277fdd84809de87d86548ef
    //
    // See also: https://github.com/Dstack-TEE/meta-dstack?tab=readme-ov-file#reproducible-build-the-guest-image

    const MRTD: [u8; 48] = [
        0xc6, 0x85, 0x18, 0xa0, 0xeb, 0xb4, 0x21, 0x36, 0xc1, 0x2b, 0x22, 0x75, 0x16, 0x4f, 0x8c,
        0x72, 0xf2, 0x5f, 0xa9, 0xa3, 0x43, 0x92, 0x22, 0x86, 0x87, 0xed, 0x6e, 0x9c, 0xae, 0xb9,
        0xc0, 0xf1, 0xdb, 0xd8, 0x95, 0xe9, 0xcf, 0x47, 0x51, 0x21, 0xc0, 0x29, 0xdc, 0x47, 0xe7,
        0x0e, 0x91, 0xfd,
    ];

    const RTMR0: [u8; 48] = [
        0x7a, 0xe1, 0xc6, 0xbc, 0x16, 0x53, 0xc4, 0xcf, 0x03, 0x7b, 0x0e, 0xe6, 0x02, 0x94, 0x57,
        0xee, 0x67, 0xc4, 0x75, 0x28, 0x5b, 0xcf, 0x47, 0x2a, 0x92, 0xf5, 0x18, 0x43, 0x14, 0x8e,
        0x47, 0x7f, 0x31, 0x26, 0x18, 0x4d, 0xd6, 0x92, 0x82, 0x27, 0x9d, 0x27, 0x8a, 0x74, 0x66,
        0xb6, 0x6c, 0xae,
    ];

    const RTMR1: [u8; 48] = [
        0xa7, 0x07, 0xa3, 0x36, 0x70, 0x0c, 0x7d, 0xf3, 0x08, 0x52, 0x1f, 0x70, 0x44, 0xd0, 0xcd,
        0x46, 0xe1, 0x62, 0xb7, 0xea, 0xeb, 0x6c, 0x1a, 0x91, 0xa0, 0x8e, 0x32, 0xe3, 0xd8, 0xd4,
        0xb0, 0xad, 0x01, 0xfe, 0x8f, 0xbc, 0x2b, 0x91, 0x30, 0x20, 0x26, 0x2a, 0x45, 0x5f, 0xa6,
        0xb1, 0xa5, 0xc4,
    ];

    const RTMR2: [u8; 48] = [
        0x2e, 0x36, 0xd0, 0xb6, 0x1a, 0x3a, 0x20, 0xc2, 0xdf, 0xbf, 0xf7, 0x0c, 0x96, 0x00, 0x5f,
        0xf3, 0xe1, 0xc7, 0x81, 0x3b, 0x4a, 0xba, 0xb4, 0x52, 0x57, 0x03, 0x30, 0xdd, 0xeb, 0xab,
        0xf9, 0x39, 0x39, 0x30, 0x99, 0x23, 0x4a, 0xbc, 0x03, 0x09, 0xf0, 0x39, 0x36, 0xed, 0xeb,
        0xf7, 0x4b, 0x1f,
    ];

    const EXPECTED_LOCAL_SGX_HASH: &str =
        "1b7a49378403249b6986a907844cab0921eca32dd47e657f3c10311ccaeccf8b";

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
            Self::Local(config) => config.quote_verification_result,
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
        match dcap_qvl::verify::verify(quote_bytes, &attestation.collateral, timestamp_s) {
            Ok(verification_result) => {
                // The "UpToDate" TCB status indicates that the measured platform components (CPU
                // microcode, firmware, etc.) match the latest known good values published by Intel
                // and do not require any updates or mitigations.
                let status_is_up_to_date = verification_result.status == EXPECTED_QUOTE_STATUS;

                // Advisory IDs indicate known security vulnerabilities or issues with the TEE.
                // For a quote to be considered secure, there should be no outstanding advisories.
                let no_security_advisories = verification_result.advisory_ids.is_empty();

                if let Some(report_data) = verification_result.report.as_td10() {
                    // Check if sha384(tls_public_key || account_public_key) matches the hash in
                    // report_data. This check effectively proves that both tls_public_key and
                    // account_public_key were included in the quote's report_data by an app running
                    // inside a TDX enclave. The RTMR checks that follow this check ensure that the
                    // app was run in an environment measured by the RTMRs (which are also part of
                    // the quote). In particular, if the tls_public_key was generated inside the
                    // enclave, this effectively proves that its private counterpart never left the
                    // enclave.
                    let report_data_valid =
                        expected_report_data.to_bytes() == report_data.report_data;

                    // Check if the RTMRs match the expected values. To learn more about RTMRs and
                    // their significance, refer to the TDX documentation:
                    // - https://phala.network/posts/understanding-tdx-attestation-reports-a-developers-guide
                    // - https://www.kernel.org/doc/Documentation/x86/tdx.rst
                    let static_rtmrs_valid = report_data.rt_mr0 == Self::RTMR0
                        && report_data.rt_mr1 == Self::RTMR1
                        && report_data.rt_mr2 == Self::RTMR2
                        && report_data.mr_td == Self::MRTD
                        && attestation.tcb_info.rtmr0 == hex::encode(Self::RTMR0)
                        && attestation.tcb_info.rtmr1 == hex::encode(Self::RTMR1)
                        && attestation.tcb_info.rtmr2 == hex::encode(Self::RTMR2)
                        && attestation.tcb_info.mrtd == hex::encode(Self::MRTD);

                    // attestation.tcb_info.rtmr3
                    let rtmr3_valid = attestation.tcb_info.rtmr3 == hex::encode(report_data.rt_mr3)
                        && report_data.rt_mr3
                            == Self::replay_rtmr3(&attestation.tcb_info.event_log);

                    // TODO: Verifying the app compose file seems redundant since both the
                    // app_compose and the expected app_compose hash come from the same TCB info
                    // fetched from the /Info dstack endpoint.
                    let app_compose: AppCompose =
                        match serde_json::from_str(&attestation.tcb_info.app_compose) {
                            Ok(compose) => compose,
                            Err(e) => {
                                tracing::error!("Failed to parse app_compose JSON: {:?}", e);
                                return false;
                            }
                        };
                    let docker_compose =
                        match serde_yaml::to_string(&app_compose.docker_compose_file) {
                            Ok(yaml_string) => yaml_string,
                            Err(_) => return false,
                        };
                    let app_compose_valid = {
                        let expected_compose_hash = attestation
                            .tcb_info
                            .event_log
                            .iter()
                            .find(|event| event.event == "compose-hash")
                            .map(|event| &event.digest);

                        match expected_compose_hash {
                            Some(expected_hex) => {
                                let app_compose_fields_valid = app_compose.manifest_version == 2
                                    && app_compose.runner == "docker-compose"
                                    && app_compose.docker_config == serde_json::json!({})
                                    && app_compose.kms_enabled == false
                                    && app_compose.gateway_enabled == Some(false)
                                    && app_compose.public_logs == true
                                    && app_compose.public_sysinfo == true
                                    && app_compose.local_key_provider_enabled == true
                                    && app_compose.allowed_envs.is_empty()
                                    && app_compose.no_instance_id == true
                                    && app_compose.secure_time == Some(false)
                                    && app_compose.pre_launch_script.is_none();
                                app_compose_fields_valid
                                    && Self::validate_compose_hash(expected_hex, &docker_compose)
                            }
                            _ => false,
                        }
                    };

                    let local_sgx_hash_valid = {
                        let local_sgx_hash = attestation
                            .tcb_info
                            .event_log
                            .iter()
                            .find(|event| event.event == "local-sgx")
                            .map(|event| &event.digest);
                        match local_sgx_hash {
                            Some(hash) => hash == Self::EXPECTED_LOCAL_SGX_HASH,
                            None => false,
                        }
                    };

                    let mpc_hash_allowed = {
                        let mpc_node_image_digest = attestation
                            .tcb_info
                            .event_log
                            .iter()
                            .find(|e| e.event == "mpc-image-digest")
                            .and_then(|e| Some(e.digest.clone()));

                        match mpc_node_image_digest {
                            Some(digest) => allowed_docker_image_hashes
                                .iter()
                                .any(|hash| hash.as_hex() == digest),
                            None => false,
                        }
                    };

                    status_is_up_to_date
                        && no_security_advisories
                        && report_data_valid
                        && static_rtmrs_valid
                        && rtmr3_valid
                        && app_compose_valid
                        && local_sgx_hash_valid
                        && mpc_hash_allowed
                } else {
                    tracing::error!(
                        "Expected TD10 report data, but got: {:?}",
                        verification_result.report
                    );
                    false
                }
            }
            Err(err) => {
                tracing::error!("TEE quote verification failed: {:?}", err);
                false
            }
        }
    }

    /// Replays RTMR3 from the event log by hashing all relevant events together.
    fn replay_rtmr3(event_log: &[EventLog]) -> [u8; 48] {
        const IMR: u32 = 3;
        let mut digest = [0u8; 48];

        let filtered_events = event_log.iter().filter(|e| e.imr == IMR);

        for event in filtered_events {
            let mut hasher = Sha384::new();
            hasher.update(digest);
            hasher.update(hex::decode(event.digest.as_str()).unwrap().as_slice());
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
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub struct Measurements {
    rt_mr0: [u8; 48],
    rt_mr1: [u8; 48],
    rt_mr2: [u8; 48],
    rt_td: [u8; 48],
}

#[derive(Debug)]
pub enum MeasurementsError {
    NoTd10Report,
}

impl TryFrom<VerifiedReport> for Measurements {
    type Error = MeasurementsError;

    fn try_from(verified_report: VerifiedReport) -> Result<Self, Self::Error> {
        let td10 = verified_report
            .report
            .as_td10()
            .ok_or(MeasurementsError::NoTd10Report)?;
        Ok(Self {
            rt_mr0: td10.rt_mr0,
            rt_mr1: td10.rt_mr1,
            rt_mr2: td10.rt_mr2,
            rt_td: td10.mr_td,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::report_data::ReportDataV1;

    use super::*;
    use rstest::rstest;

    fn mock_attestation(
        quote_verification_result: bool,
        docker_image_verification_result: bool,
    ) -> Attestation {
        Attestation::Local(LocalAttestation {
            quote_verification_result,
            docker_image_verification_result,
        })
    }

    #[rstest]
    #[case(false, false, false)]
    #[case(false, true, false)]
    #[case(true, false, true)]
    #[case(true, true, true)]
    fn test_mock_attestation_verify(
        #[case] quote_verification_result: bool,
        #[case] docker_image_verification_result: bool,
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
            mock_attestation(quote_verification_result, docker_image_verification_result).verify(
                report_data,
                timestamp_s,
                &[],
            ),
            expected_quote_verification_result
        );
    }
}
