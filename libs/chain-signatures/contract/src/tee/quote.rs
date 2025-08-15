use anyhow::{Error, Result};
use dcap_qvl::{quote::Quote, verify::VerifiedReport, QuoteCollateralV3};
use hex::{decode, encode, FromHexError};
use k256::sha2::{Digest as _, Sha384};
use near_sdk::{env::sha256, near, require};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TeeQuoteStatus {
    /// No TEE information was found for this participant.
    /// This indicates the participant is not running in a TEE environment
    /// or has not provided TEE attestation data.
    None,

    /// TEE quote and Docker image verification both passed successfully.
    /// The participant is considered to have a valid, verified TEE status.
    Valid,

    /// TEE verification failed - either the quote verification failed,
    /// the Docker image verification failed, or both validations failed.
    /// The participant should not be trusted for TEE-dependent operations.
    Invalid,
}

impl From<Result<VerifiedReport, crate::Error>> for TeeQuoteStatus {
    fn from(result: Result<VerifiedReport, crate::Error>) -> Self {
        match result {
            Ok(_) => TeeQuoteStatus::Valid,
            Err(_) => TeeQuoteStatus::Invalid,
        }
    }
}

/// Remote Attestation TDX quote.
#[near(serializers=[borsh, json])]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct TeeQuote(pub(crate) Vec<u8>);

impl TeeQuote {
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }

    pub fn get_rtmr3(&self) -> Result<[u8; 48]> {
        let quote = Quote::parse(&self.0)?;
        Ok(quote.report.as_td10().unwrap().rt_mr3)
    }
}

/// Parses the raw JSON string into a QuoteCollateralV3 structure.
pub fn get_collateral(raw: String) -> Result<QuoteCollateralV3, Error> {
    fn get_str(v: &Value, key: &str) -> String {
        v.get(key)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .unwrap_or_else(|| panic!("Missing or invalid field: {}", key))
    }

    fn get_hex(v: &Value, key: &str) -> Result<Vec<u8>, FromHexError> {
        hex::decode(get_str(v, key))
    }

    let v: Value = serde_json::from_str(&raw).expect("Invalid quote collateral JSON");

    Ok(QuoteCollateralV3 {
        tcb_info_issuer_chain: get_str(&v, "tcb_info_issuer_chain"),
        tcb_info: get_str(&v, "tcb_info"),
        tcb_info_signature: get_hex(&v, "tcb_info_signature")?,
        qe_identity_issuer_chain: get_str(&v, "qe_identity_issuer_chain"),
        qe_identity: get_str(&v, "qe_identity"),
        qe_identity_signature: get_hex(&v, "qe_identity_signature")?,
        pck_crl_issuer_chain: get_str(&v, "pck_crl_issuer_chain"),
        root_ca_crl: get_hex(&v, "root_ca_crl")?,
        pck_crl: get_hex(&v, "pck_crl")?,
    })
}

pub fn verify_codehash(raw_tcb_info: String, rtmr3: String) -> String {
    let tcb_info: Value =
        serde_json::from_str(&raw_tcb_info).expect("TCB Info should be valid JSON");
    let event_log = tcb_info["event_log"].as_array().unwrap();
    // get compose hash from events
    let expected_compose_hash = event_log
        .iter()
        .find(|e| e["event"].as_str().unwrap() == "compose-hash")
        .unwrap()["digest"]
        .as_str()
        .unwrap();

    // replay the rtmr3 and compose hash
    let replayed_rtmr3 = replay_rtmr(event_log.to_owned(), 3);
    let app_compose = tcb_info["app_compose"].as_str().unwrap();
    let replayed_compose_hash = replay_app_compose(app_compose);

    // compose hash match expected
    require!(replayed_compose_hash == expected_compose_hash);
    // event with compose hash matches report rtmr3
    require!(replayed_rtmr3 == rtmr3);

    let (_, right) = app_compose.split_once("\\n    image:").unwrap();
    let (left, _) = right.split_once("\\n").unwrap();
    let (_, codehash) = left.split_once("@sha256:").unwrap();

    codehash.to_owned()
}

pub fn replay_rtmr(event_log: Vec<Value>, imr: u8) -> String {
    let mut digest = [0u8; 48];

    // filter by imr
    let filtered_events = event_log
        .iter()
        .filter(|e| e["imr"].as_u64().unwrap() as u8 == imr);

    // hash all digests together
    for event in filtered_events {
        let mut hasher = Sha384::new();
        hasher.update(digest);
        hasher.update(
            decode(event["digest"].as_str().unwrap())
                .unwrap()
                .as_slice(),
        );
        digest = hasher.finalize().into();
    }

    // return hex encoded digest (rtmr[imr])
    encode(digest)
}

pub fn replay_app_compose(app_compose: &str) -> String {
    // sha256 of app_compose from TcbInfo
    let sha256_vec = sha256(app_compose.as_bytes());
    let mut sha256_bytes = [0u8; 32];
    sha256_bytes.copy_from_slice(&sha256_vec);

    // sha384 of custom encoding: [phala_prefix]:[event_name]:[sha256_payload]
    let mut hasher = Sha384::new();
    hasher.update(vec![0x01, 0x00, 0x00, 0x08]);
    hasher.update(b":");
    hasher.update("compose-hash".as_bytes());
    hasher.update(b":");
    hasher.update(sha256_bytes);
    let digest: [u8; 48] = hasher.finalize().into();

    encode(digest)
}

#[cfg(test)]
mod tests {
    use super::{get_collateral, replay_app_compose, replay_rtmr, verify_codehash};

    use dcap_qvl::verify;
    use hex::encode;

    #[test]
    fn test_verify_quote_and_codehash() {
        let tcb_info_string = include_str!("../../../../../attestation/tests/assets/tcb_info.json");
        let tcb_info: serde_json::Value = serde_json::from_str(tcb_info_string).unwrap();

        let event_log = tcb_info["event_log"].as_array().unwrap();

        let raw_quote_collateral =
            include_str!("../../../../../attestation/tests/assets/collateral.json");
        let collateral = get_collateral(raw_quote_collateral.to_string()).unwrap();

        let quote_string = include_str!("../../../../../attestation/tests/assets/quote.json");
        let quote: Vec<u8> = serde_json::from_str(&quote_string).unwrap();

        let now = 1755251397; // Fri, 15 Aug 2025 09:49:57 UTC

        // get compose hash from events
        let expected_compose_hash = event_log
            .iter()
            .find(|e| e["event"].as_str().unwrap() == "compose-hash")
            .unwrap()["digest"]
            .as_str()
            .unwrap();

        // verified report with rtmrs
        let result = verify::verify(&quote, &collateral, now).unwrap();
        let rtmr3 = encode(result.report.as_td10().unwrap().rt_mr3);

        // replay the rtmr3 and compose hash
        let replayed_rtmr3 = replay_rtmr(event_log.to_owned(), 3);
        let replayed_compose_hash: String =
            replay_app_compose(tcb_info["app_compose"].as_str().unwrap());

        // compose hash match expected
        assert!(replayed_compose_hash == expected_compose_hash);
        // event with compose hash matches report rtmr3
        assert!(replayed_rtmr3 == rtmr3);

        println!("replayed_rtmr3 {:?}", replayed_rtmr3);
        println!("replayed_compose_hash {:?}", replayed_compose_hash);

        let codehash = verify_codehash(tcb_info.to_string(), rtmr3);

        println!("codehash {:?}", codehash);
    }
}
