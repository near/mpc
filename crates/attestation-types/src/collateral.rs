//! `Collateral` — Borsh-stable mirror of `dcap_qvl::QuoteCollateralV3`.
//!
//! Field-for-field copy. Borsh wire layout matches the upstream type when
//! `dcap-qvl` is built with its `borsh` feature, so on-chain state that
//! previously stored an `attestation::collateral::Collateral` (newtype
//! wrapping `dcap_qvl::QuoteCollateralV3`) decodes into this type with no
//! migration.
//!
//! The conversion to/from `dcap_qvl::QuoteCollateralV3` lives in the
//! `attestation` crate (it depends on `dcap-qvl`); this crate does not.

use alloc::{string::String, vec::Vec};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

// `BorshSchema` derive expands to `T::declaration().to_string()`, which is
// only in scope under no_std when `alloc::string::ToString` is imported.
#[cfg(feature = "borsh-schema")]
use alloc::string::ToString as _;

#[cfg(feature = "test-utils")]
use {core::str::FromStr, hex::FromHexError, serde_json::Value, thiserror::Error};

/// Supplemental data for the TEE quote, including Intel certificates to verify it came from genuine
/// Intel hardware, along with details about the Trusted Computing Base (TCB) versioning, status,
/// and other relevant info.
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
#[cfg_attr(feature = "borsh-schema", derive(borsh::BorshSchema))]
#[cfg_attr(feature = "test-utils", serde(try_from = "Value"))]
pub struct Collateral {
    pub pck_crl_issuer_chain: String,
    pub root_ca_crl: Vec<u8>,
    pub pck_crl: Vec<u8>,
    pub tcb_info_issuer_chain: String,
    pub tcb_info: String,
    pub tcb_info_signature: Vec<u8>,
    pub qe_identity_issuer_chain: String,
    pub qe_identity: String,
    pub qe_identity_signature: Vec<u8>,
    pub pck_certificate_chain: Option<String>,
}

#[cfg(feature = "test-utils")]
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

        Ok(Self {
            tcb_info_issuer_chain: get_str(&v, "tcb_info_issuer_chain")?,
            tcb_info: get_str(&v, "tcb_info")?,
            tcb_info_signature: get_hex(&v, "tcb_info_signature")?,
            qe_identity_issuer_chain: get_str(&v, "qe_identity_issuer_chain")?,
            qe_identity: get_str(&v, "qe_identity")?,
            qe_identity_signature: get_hex(&v, "qe_identity_signature")?,
            pck_crl_issuer_chain: get_str(&v, "pck_crl_issuer_chain")?,
            root_ca_crl: get_hex(&v, "root_ca_crl")?,
            pck_crl: get_hex(&v, "pck_crl")?,
            pck_certificate_chain: get_str(&v, "pck_certificate_chain").ok(),
        })
    }
}

#[cfg(feature = "test-utils")]
impl FromStr for Collateral {
    type Err = CollateralError;

    /// Attempts to parse a JSON string into a [`Collateral`].
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let json_value: Value =
            serde_json::from_str(s).map_err(|_| CollateralError::InvalidJson)?;
        Self::try_from_json(json_value)
    }
}

#[cfg(feature = "test-utils")]
impl TryFrom<Value> for Collateral {
    type Error = CollateralError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        Self::try_from_json(value)
    }
}

#[cfg(feature = "test-utils")]
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
