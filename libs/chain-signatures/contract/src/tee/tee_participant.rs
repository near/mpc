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
use near_sdk::{env::sha256, near};
use serde_json::Value;
use serde_yaml::Value as YamlValue;

const RTMR0: [u8; 48] = [0u8; 48];
const RTMR1: [u8; 48] = [0u8; 48];
const RTMR2: [u8; 48] = [0u8; 48];
const MRTD: [u8; 48] = [0u8; 48];
const EXPECTED_LOCAL_SGX_HASH: &str =
    "1b7a49378403249b6986a907844cab0921eca32dd47e657f3c10311ccaeccf8b";

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

    pub fn verify_static_rtmrs(verified_report: VerifiedReport) -> bool {
        if let Some(td10) = verified_report.report.as_td10() {
            td10.rt_mr0 == RTMR0
                && td10.rt_mr1 == RTMR1
                && td10.rt_mr2 == RTMR2
                && td10.mr_td == MRTD
        } else {
            false
        }
    }

    /// Checks if the node is running the expected Docker images (launcher and MPC node) by
    /// replaying RTMR3 and comparing the relevant event values to the expected values.
    pub fn verify_docker_images_via_rtmr3(
        &self,
        allowed_docker_image_hashes: &[MpcDockerImageHash],
    ) -> Result<bool, Error> {
        let quote = Quote::parse(&self.tee_quote)
            .map_err(|_| Into::<Error>::into(InvalidCandidateSet::InvalidParticipantsTeeQuote))?;
        let tcb_info: Value = serde_json::from_str(&self.raw_tcb_info)
            .map_err(|_| Into::<Error>::into(InvalidCandidateSet::InvalidParticipantsTeeQuote))?;

        let event_log = match tcb_info["event_log"].as_array() {
            Some(log) => log,
            None => return Err(InvalidCandidateSet::InvalidParticipantsTeeQuote.into()),
        };

        if !Self::check_rtmr3_vs_actual(&quote, event_log) {
            return Ok(false);
        }
        if !Self::check_app_compose(event_log, &tcb_info) {
            return Ok(false);
        }
        if !Self::check_docker_compose_hash(&tcb_info, allowed_docker_image_hashes) {
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

    fn check_docker_compose_hash(
        tcb_info: &Value,
        allowed_docker_image_hashes: &[MpcDockerImageHash],
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
