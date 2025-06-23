use crate::{
    errors::{Error, InvalidCandidateSet},
    get_collateral,
    tee::{
        proposal::MpcDockerImageHash,
        quote::{replay_app_compose, replay_rtmr},
    },
};
use dcap_qvl::{
    quote::Quote,
    verify::{self, VerifiedReport},
};
use k256::sha2::{Digest, Sha384};
use near_sdk::{
    env::{self, sha256},
    near, PublicKey,
};
use serde::Deserialize;
use serde_json::Value;

use serde_yaml::Value as YamlValue;

//git rev-parse HEAD
//fbdf2e76fb6bd9142277fdd84809de87d86548ef
// https://github.com/Dstack-TEE/meta-dstack?tab=readme-ov-file#reproducible-build-the-guest-image

const MRTD: [u8; 48] = [
    0xc6, 0x85, 0x18, 0xa0, 0xeb, 0xb4, 0x21, 0x36, 0xc1, 0x2b, 0x22, 0x75, 0x16, 0x4f, 0x8c, 0x72,
    0xf2, 0x5f, 0xa9, 0xa3, 0x43, 0x92, 0x22, 0x86, 0x87, 0xed, 0x6e, 0x9c, 0xae, 0xb9, 0xc0, 0xf1,
    0xdb, 0xd8, 0x95, 0xe9, 0xcf, 0x47, 0x51, 0x21, 0xc0, 0x29, 0xdc, 0x47, 0xe7, 0x0e, 0x91, 0xfd,
];

const RTMR0: [u8; 48] = [
    0x7a, 0xe1, 0xc6, 0xbc, 0x16, 0x53, 0xc4, 0xcf, 0x03, 0x7b, 0x0e, 0xe6, 0x02, 0x94, 0x57, 0xee,
    0x67, 0xc4, 0x75, 0x28, 0x5b, 0xcf, 0x47, 0x2a, 0x92, 0xf5, 0x18, 0x43, 0x14, 0x8e, 0x47, 0x7f,
    0x31, 0x26, 0x18, 0x4d, 0xd6, 0x92, 0x82, 0x27, 0x9d, 0x27, 0x8a, 0x74, 0x66, 0xb6, 0x6c, 0xae,
];

const RTMR1: [u8; 48] = [
    0xa7, 0x07, 0xa3, 0x36, 0x70, 0x0c, 0x7d, 0xf3, 0x08, 0x52, 0x1f, 0x70, 0x44, 0xd0, 0xcd, 0x46,
    0xe1, 0x62, 0xb7, 0xea, 0xeb, 0x6c, 0x1a, 0x91, 0xa0, 0x8e, 0x32, 0xe3, 0xd8, 0xd4, 0xb0, 0xad,
    0x01, 0xfe, 0x8f, 0xbc, 0x2b, 0x91, 0x30, 0x20, 0x26, 0x2a, 0x45, 0x5f, 0xa6, 0xb1, 0xa5, 0xc4,
];

const RTMR2: [u8; 48] = [
    0x2e, 0x36, 0xd0, 0xb6, 0x1a, 0x3a, 0x20, 0xc2, 0xdf, 0xbf, 0xf7, 0x0c, 0x96, 0x00, 0x5f, 0xf3,
    0xe1, 0xc7, 0x81, 0x3b, 0x4a, 0xba, 0xb4, 0x52, 0x57, 0x03, 0x30, 0xdd, 0xeb, 0xab, 0xf9, 0x39,
    0x39, 0x30, 0x99, 0x23, 0x4a, 0xbc, 0x03, 0x09, 0xf0, 0x39, 0x36, 0xed, 0xeb, 0xf7, 0x4b, 0x1f,
];

const EXPECTED_LOCAL_SGX_HASH: &str =
    "1b7a49378403249b6986a907844cab0921eca32dd47e657f3c10311ccaeccf8b";
const EXPECTED_REPORT_DATA_VERSION: u16 = 1;

#[derive(Deserialize, Debug)]
struct Config {
    manifest_version: u8,
    #[allow(dead_code)]
    name: String,
    runner: String,
    #[allow(dead_code)]
    docker_compose_file: String,
    docker_config: serde_json::Value,
    kms_enabled: bool,
    gateway_enabled: bool,
    public_logs: bool,
    public_sysinfo: bool,
    local_key_provider_enabled: bool,
    allowed_envs: Vec<String>,
    no_instance_id: bool,
    secure_time: bool,
    pre_launch_script: String,
}

#[near(serializers=[borsh, json])]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Default)]
pub struct TeeParticipantInfo {
    /// TEE Remote Attestation Quote that proves the participant's identity.
    pub tee_quote: Vec<u8>,
    /// Supplemental data for the TEE quote, including Intel certificates to verify it came from
    /// genuine Intel hardware, along with details about the Trusted Computing Base (TCB)
    /// versioning, status, and other relevant info.
    pub quote_collateral: String,
    /// Dstack event log.
    pub raw_tcb_info: String,
}

impl TeeParticipantInfo {
    /// Verifies the TEE quote against the provided collateral.
    pub fn verify_quote(&self, timestamp_s: u64) -> Result<VerifiedReport, Error> {
        let tee_collateral = get_collateral(self.quote_collateral.clone())
            .map_err(|_| Into::<Error>::into(InvalidCandidateSet::InvalidParticipantsTeeQuote))?;
        let verification_result = verify::verify(&self.tee_quote, &tee_collateral, timestamp_s);
        verification_result.map_err(|_| InvalidCandidateSet::InvalidParticipantsTeeQuote.into())
    }

    /// Checks whether the node is running the expected Docker images (launcher and MPC node) by
    /// verifying report_data, replaying RTMR3, and comparing the relevant event values to the
    /// expected values.
    pub fn verify_docker_image(
        &self,
        allowed_docker_image_hashes: &[MpcDockerImageHash],
        historical_docker_image_hashes: &[MpcDockerImageHash],
        report: VerifiedReport,
        public_key: PublicKey,
    ) -> Result<bool, Error> {
        let quote = Quote::parse(&self.tee_quote)
            .map_err(|_| Into::<Error>::into(InvalidCandidateSet::InvalidParticipantsTeeQuote))?;
        let tcb_info: Value = serde_json::from_str(&self.raw_tcb_info)
            .map_err(|_| Into::<Error>::into(InvalidCandidateSet::InvalidParticipantsTeeQuote))?;

        let event_log = match tcb_info["event_log"].as_array() {
            Some(log) => log,
            None => return Err(InvalidCandidateSet::InvalidParticipantsTeeQuote.into()),
        };

        if Self::verify_static_rtmrs(report) {
            return Ok(false);
        }
        if self.verify_report_data(&quote, public_key) {
            return Ok(false);
        }
        if !Self::check_rtmr3_vs_actual(&quote, event_log) {
            return Ok(false);
        }
        if !Self::check_app_compose(event_log, &tcb_info) {
            return Ok(false);
        }
        if !Self::check_app_compose_fields(&tcb_info) {
            return Ok(false);
        }
        if !Self::check_docker_compose_hash(
            &tcb_info,
            allowed_docker_image_hashes,
            historical_docker_image_hashes,
        ) {
            return Ok(false);
        }
        if !Self::check_local_sgx(event_log) {
            return Ok(false);
        }
        if !Self::check_mpc_hash(event_log, allowed_docker_image_hashes) {
            return Ok(false);
        }

        Ok(true)
    }

    fn verify_static_rtmrs(verified_report: VerifiedReport) -> bool {
        if let Some(td10) = verified_report.report.as_td10() {
            td10.rt_mr0 == RTMR0
                && td10.rt_mr1 == RTMR1
                && td10.rt_mr2 == RTMR2
                && td10.mr_td == MRTD
        } else {
            false
        }
    }

    fn verify_report_data(&self, quote: &Quote, node_signing_public_key: PublicKey) -> bool {
        let report_data = match quote.report.as_td10() {
            Some(r) => r.report_data,
            None => return false,
        };
        let binary_version = u16::from_be_bytes([report_data[0], report_data[1]]);
        let expected_hash = &report_data[4..52]; // 48 bytes for SHA3-384

        let mut hasher = Sha384::new();
        hasher.update(node_signing_public_key.as_bytes());
        hasher.update(env::signer_account_pk().as_bytes());
        let actual_hash = hasher.finalize();

        binary_version == EXPECTED_REPORT_DATA_VERSION && actual_hash.as_slice() == expected_hash
    }

    fn check_rtmr3_vs_actual(quote: &Quote, event_log: &[Value]) -> bool {
        let expected_rtmr3 = match quote.report.as_td10() {
            Some(r) => hex::encode(r.rt_mr3),
            None => return false,
        };
        let replayed_rtmr3 = replay_rtmr(event_log.to_owned(), 3);
        expected_rtmr3 == replayed_rtmr3
    }

    fn check_app_compose(event_log: &[Value], tcb_info: &Value) -> bool {
        let expected_compose_hash = event_log
            .iter()
            .find(|e| e["event"].as_str() == Some("compose-hash"))
            .and_then(|e| e["digest"].as_str());
        let app_compose = tcb_info["app_compose"].as_str();
        match (expected_compose_hash, app_compose) {
            (Some(expected), Some(app)) => replay_app_compose(app) == expected,
            _ => false,
        }
    }

    fn check_app_compose_fields(tcb_info: &Value) -> bool {
        let compose_str = match tcb_info.get("docker_compose_file").and_then(|v| v.as_str()) {
            Some(compose) => compose,
            None => return false,
        };

        let parsed: Config = match serde_json::from_str(compose_str) {
            Ok(cfg) => cfg,
            Err(_) => return false,
        };

        // Construct expected Config baseline
        let expected = Config {
            manifest_version: 2,
            name: "".to_string(), // Not validated
            runner: "docker-compose".to_string(),
            docker_compose_file: "".to_string(), // Not validated
            docker_config: serde_json::json!({}),
            kms_enabled: false,
            gateway_enabled: false,
            public_logs: true,
            public_sysinfo: true,
            local_key_provider_enabled: true,
            allowed_envs: vec![],
            no_instance_id: true,
            secure_time: false,
            pre_launch_script: "".to_string(),
        };

        // Return false on any mismatch
        parsed.manifest_version == expected.manifest_version
            && parsed.runner == expected.runner
            && parsed.docker_config == expected.docker_config
            && parsed.kms_enabled == expected.kms_enabled
            && parsed.gateway_enabled == expected.gateway_enabled
            && parsed.public_logs == expected.public_logs
            && parsed.public_sysinfo == expected.public_sysinfo
            && parsed.local_key_provider_enabled == expected.local_key_provider_enabled
            && parsed.allowed_envs == expected.allowed_envs
            && parsed.no_instance_id == expected.no_instance_id
            && parsed.secure_time == expected.secure_time
            && parsed.pre_launch_script == expected.pre_launch_script
    }

    fn check_docker_compose_hash(
        tcb_info: &Value,
        allowed_docker_image_hashes: &[MpcDockerImageHash],
        historical_docker_image_hashes: &[MpcDockerImageHash],
    ) -> bool {
        let compose_yaml = match tcb_info.get("docker_compose_file").and_then(|v| v.as_str()) {
            Some(yaml) => yaml,
            None => return false,
        };

        if serde_yaml::from_str::<YamlValue>(compose_yaml).is_err() {
            return false;
        }

        let compose_yaml_hash = sha256(compose_yaml.as_bytes());
        let mut compose_yaml_hash_arr = [0u8; 32];
        compose_yaml_hash_arr.copy_from_slice(&compose_yaml_hash);

        allowed_docker_image_hashes
            .iter()
            .chain(historical_docker_image_hashes)
            .any(|hash| hash.as_hex() == hex::encode(compose_yaml_hash_arr))
    }

    fn check_local_sgx(event_log: &[Value]) -> bool {
        let local_sgx_hash = event_log
            .iter()
            .find(|e| e["event"].as_str() == Some("local-sgx"))
            .and_then(|e| e["digest"].as_str());
        match local_sgx_hash {
            Some(hash) => hash == EXPECTED_LOCAL_SGX_HASH,
            None => false,
        }
    }

    fn check_mpc_hash(
        event_log: &[Value],
        allowed_docker_image_hashes: &[MpcDockerImageHash],
    ) -> bool {
        let mpc_node_image_digest = event_log
            .iter()
            .find(|e| e["event"].as_str() == Some("mpc-image-digest"))
            .and_then(|e| e["digest"].as_str());

        match mpc_node_image_digest {
            Some(digest) => allowed_docker_image_hashes
                .iter()
                .any(|hash| hash.as_hex() == *digest),
            None => false,
        }
    }
}
