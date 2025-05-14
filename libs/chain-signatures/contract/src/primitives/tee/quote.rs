use anyhow::Result;
use dcap_qvl::{quote::Quote, QuoteCollateralV3};
use near_sdk::near;
use serde_json::Value;

/// Remote Attestation TDX quote.
#[near(serializers=[borsh, json])]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct TeeQuote(Vec<u8>);

impl TeeQuote {
    pub fn new(data: Vec<u8>) -> Self {
        TeeQuote(data)
    }

    pub fn get_quote(&self) -> Result<Quote> {
        Quote::parse(&self.0)
    }

    pub fn get_rtmr3(&self) -> Result<[u8; 48]> {
        let quote = self.get_quote()?;
        Ok(quote.report.as_td10().unwrap().rt_mr3)
    }
}

/// Parses the raw JSON string into a QuoteCollateralV3 structure.
pub fn get_collateral(raw: String) -> QuoteCollateralV3 {
    fn get_str(v: &Value, key: &str) -> String {
        v.get(key)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .unwrap_or_else(|| panic!("Missing or invalid field: {}", key))
    }

    fn get_hex(v: &Value, key: &str) -> Vec<u8> {
        hex::decode(get_str(v, key)).unwrap_or_else(|_| panic!("Failed to decode hex: {}", key))
    }

    let v: Value = serde_json::from_str(&raw).expect("Invalid quote collateral JSON");

    QuoteCollateralV3 {
        tcb_info_issuer_chain: get_str(&v, "tcb_info_issuer_chain"),
        tcb_info: get_str(&v, "tcb_info"),
        tcb_info_signature: get_hex(&v, "tcb_info_signature"),
        qe_identity_issuer_chain: get_str(&v, "qe_identity_issuer_chain"),
        qe_identity: get_str(&v, "qe_identity"),
        qe_identity_signature: get_hex(&v, "qe_identity_signature"),
    }
}
