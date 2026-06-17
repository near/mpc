//! Quote collateral (Intel certificates + TCB info) used to verify a quote.
//!
//! `Collateral` is re-exported from `tee-verifier-interface`, not redefined,
//! so it has a single canonical definition.
//!
//! The `test-utils` JSON parser below lives here, not in the wire crate:
//! `tee-verifier-interface` is Borsh-only on the cross-contract call, so
//! adding `serde_json` + `hex` there would bloat every consumer's WASM. The
//! only place collateral exists as JSON is off-chain test fixtures.
pub use tee_verifier_interface::Collateral;

#[cfg(feature = "test-utils")]
pub use parse::{CollateralError, collateral_from_json, collateral_from_str};

#[cfg(feature = "test-utils")]
mod parse {
    use super::Collateral;
    use alloc::{string::String, vec::Vec};
    use hex::FromHexError;
    use serde_json::Value;
    use thiserror::Error;

    pub fn collateral_from_json(v: Value) -> Result<Collateral, CollateralError> {
        fn get_str(v: &Value, key: &str) -> Result<String, CollateralError> {
            v.get(key)
                .and_then(Value::as_str)
                .map(String::from)
                .ok_or_else(|| CollateralError::MissingField(String::from(key)))
        }

        fn get_hex(v: &Value, key: &str) -> Result<Vec<u8>, CollateralError> {
            let hex_str = get_str(v, key)?;
            hex::decode(hex_str).map_err(|source| CollateralError::HexDecode {
                field: String::from(key),
                source,
            })
        }

        Ok(Collateral {
            pck_crl_issuer_chain: get_str(&v, "pck_crl_issuer_chain")?,
            root_ca_crl: get_hex(&v, "root_ca_crl")?,
            pck_crl: get_hex(&v, "pck_crl")?,
            tcb_info_issuer_chain: get_str(&v, "tcb_info_issuer_chain")?,
            tcb_info: get_str(&v, "tcb_info")?,
            tcb_info_signature: get_hex(&v, "tcb_info_signature")?,
            qe_identity_issuer_chain: get_str(&v, "qe_identity_issuer_chain")?,
            qe_identity: get_str(&v, "qe_identity")?,
            qe_identity_signature: get_hex(&v, "qe_identity_signature")?,
            pck_certificate_chain: get_str(&v, "pck_certificate_chain").ok(),
        })
    }

    pub fn collateral_from_str(s: &str) -> Result<Collateral, CollateralError> {
        let json_value: Value =
            serde_json::from_str(s).map_err(|_| CollateralError::InvalidJson)?;
        collateral_from_json(json_value)
    }

    #[derive(Debug, Error)]
    pub enum CollateralError {
        #[error("Missing or invalid field: {0}")]
        MissingField(String),
        #[error("Failed to decode hex field '{field}': {source}")]
        HexDecode {
            field: String,
            #[source]
            source: FromHexError,
        },
        #[error("Invalid JSON format")]
        InvalidJson,
    }
}
