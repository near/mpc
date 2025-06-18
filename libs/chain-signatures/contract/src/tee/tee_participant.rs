use crate::{
    errors::{Error, InvalidCandidateSet},
    get_collateral,
    tee::{
        quote::{replay_app_compose, replay_rtmr},
        tee_state::TeeState,
    },
};
use dcap_qvl::{
    quote::Quote,
    verify::{self, VerifiedReport},
};
use near_sdk::{env, near};
use serde_json::Value;

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
    pub fn verify_docker_images_via_rtmr3(&self, tee_state: &mut TeeState) -> Result<bool, Error> {
        let quote = Quote::parse(&self.tee_quote)
            .map_err(|_| Into::<Error>::into(InvalidCandidateSet::InvalidParticipantsTeeQuote))?;
        let tcb_info: Value = serde_json::from_str(&self.raw_tcb_info)
            .map_err(|_| Into::<Error>::into(InvalidCandidateSet::InvalidParticipantsTeeQuote))?;

        // Replay RTMR3 from dstack's event log (a.k.a. TCB info)

        let expected_rtmr3 = {
            let report = match quote.report.as_td10() {
                Some(r) => r,
                None => return Err(InvalidCandidateSet::InvalidParticipantsTeeQuote.into()),
            };
            hex::encode(report.rt_mr3)
        };
        let event_log = match tcb_info["event_log"].as_array() {
            Some(log) => log,
            None => return Err(InvalidCandidateSet::InvalidParticipantsTeeQuote.into()),
        };
        let replayed_rtmr3 = replay_rtmr(event_log.to_owned(), 3);
        if expected_rtmr3 != replayed_rtmr3 {
            return Ok(false);
        }

        // Check if the expected app_compose hash from tcb_info matches the hash of the replayed app_compose

        let expected_compose_hash = match event_log
            .iter()
            .find(|e| e["event"].as_str() == Some("compose-hash"))
        {
            Some(e) => match e["digest"].as_str() {
                Some(d) => d,
                None => return Err(InvalidCandidateSet::InvalidParticipantsTeeQuote.into()),
            },
            None => return Err(InvalidCandidateSet::InvalidParticipantsTeeQuote.into()),
        };
        let app_compose = match tcb_info["app_compose"].as_str() {
            Some(a) => a,
            None => return Err(InvalidCandidateSet::InvalidParticipantsTeeQuote.into()),
        };
        let replayed_compose_hash = replay_app_compose(app_compose);
        if expected_compose_hash != replayed_compose_hash {
            return Ok(false);
        }

        // Check if the local-sgx hash is the expected one

        let local_sgx_hash = match event_log
            .iter()
            .find(|e| e["event"].as_str() == Some("local-sgx"))
        {
            Some(e) => match e["digest"].as_str() {
                Some(d) => d,
                None => return Ok(false),
            },
            None => return Ok(false),
        };

        if local_sgx_hash != EXPECTED_LOCAL_SGX_HASH {
            return Ok(false);
        }

        // Check if the node is running the expected MPC node version

        let mpc_node_image_digest = match event_log
            .iter()
            .find(|e| e["event"].as_str() == Some("image-digest"))
        {
            Some(e) => match e["digest"].as_str() {
                Some(d) => d,
                None => return Err(InvalidCandidateSet::InvalidParticipantsTeeQuote.into()),
            },
            None => return Err(InvalidCandidateSet::InvalidParticipantsTeeQuote.into()),
        };

        if !tee_state
            .allowed_docker_image_hashes
            .is_code_hash_allowed(mpc_node_image_digest.to_owned(), env::block_height())
        {
            return Ok(false);
        }

        Ok(true)
    }

    pub fn verify_report_data(&self) -> Result<(), Error> {
        Ok(())
    }
}
