use alloc::{string::String, vec::Vec};
use borsh::{BorshDeserialize, BorshSerialize};
use core::str::FromStr;
use derive_more::{Deref, From, Into};
use hex::FromHexError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

pub use dcap_qvl::QuoteCollateralV3;

/// Supplemental data for the TEE quote, including Intel certificates to verify it came from genuine
/// Intel hardware, along with details about the Trusted Computing Base (TCB) versioning, status,
/// and other relevant info.
#[derive(
    Clone, From, Deref, Into, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
#[serde(try_from = "Value")]
pub struct Collateral(QuoteCollateralV3);

impl Collateral {
    /// Attempts to create a [`Collateral`] from a JSON value containing quote collateral data.
    ///
    /// # Errors
    ///
    /// Returns a [`CollateralError`] if:
    /// - Any required field is missing or has an invalid type
    /// - Hex fields cannot be decoded
    pub fn try_from_json(v: Value) -> Result<Self, CollateralError> {
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

        let quote_collateral = QuoteCollateralV3 {
            tcb_info_issuer_chain: get_str(&v, "tcb_info_issuer_chain")?,
            tcb_info: get_str(&v, "tcb_info")?,
            tcb_info_signature: get_hex(&v, "tcb_info_signature")?,
            qe_identity_issuer_chain: get_str(&v, "qe_identity_issuer_chain")?,
            qe_identity: get_str(&v, "qe_identity")?,
            qe_identity_signature: get_hex(&v, "qe_identity_signature")?,
            pck_crl_issuer_chain: get_str(&v, "pck_crl_issuer_chain")?,
            root_ca_crl: get_hex(&v, "root_ca_crl")?,
            pck_crl: get_hex(&v, "pck_crl")?,
        };
        Ok(Self(quote_collateral))
    }
}

impl FromStr for Collateral {
    type Err = CollateralError;

    /// Attempts to parse a JSON string into a [`Collateral`].
    ///
    /// This is a convenience method that first parses the string as JSON, then attempts to convert
    /// it to a [`Collateral`].
    ///
    /// # Errors
    ///
    /// Returns a [`CollateralError`] if:
    /// - The string is not valid JSON
    /// - The JSON doesn't contain the required collateral fields
    /// - Hex fields cannot be decoded
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let json_value: Value =
            serde_json::from_str(s).map_err(|_| CollateralError::InvalidJson)?;
        Self::try_from_json(json_value)
    }
}

impl TryFrom<Value> for Collateral {
    type Error = CollateralError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        Self::try_from_json(value)
    }
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
