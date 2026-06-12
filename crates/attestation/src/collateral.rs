//! Quote collateral (Intel certificates + TCB info) used to verify a quote.
//!
//! Re-exported from `tee-verifier-interface` so the collateral type has a
//! single definition shared by the verifier wire, this crate's post-DCAP
//! logic, and every consumer. This crate does not define its own collateral
//! type; the `test-utils` JSON parser below produces the re-exported type.
pub use tee_verifier_interface::Collateral;

#[cfg(feature = "test-utils")]
pub use parse::{CollateralError, collateral_from_json, collateral_from_str};

#[cfg(feature = "test-utils")]
mod parse {
    use super::Collateral;
    use alloc::string::String;
    use alloc::vec::Vec;
    use hex::FromHexError;
    use serde_json::Value;
    use thiserror::Error;

    /// Parses a JSON value (hex-encoded byte fields) into a [`Collateral`].
    ///
    /// The verifier wire [`Collateral`] holds plain `Vec<u8>` fields, so this
    /// off-chain helper hex-decodes the byte fields explicitly rather than
    /// relying on a serde derive — keeping `tee-verifier-interface` serde-free.
    ///
    /// # Errors
    ///
    /// Returns a [`CollateralError`] if a required field is missing, has the
    /// wrong type, or a hex field cannot be decoded.
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

    /// Parses a JSON string into a [`Collateral`].
    ///
    /// # Errors
    ///
    /// Returns a [`CollateralError`] if the string is not valid JSON, a
    /// required field is missing, or a hex field cannot be decoded.
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
