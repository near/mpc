//! Backward-compatible types for deserializing legacy chain calls.
//!
//! These types handle the transition from deprecated field names
//! (payload, key_version) to their current counterparts (payload_v2, domain_id).

use serde::{Deserialize, Serialize};
use std::fmt;

use crate::Payload;
use mpc_primitives::domain::DomainId;

/// Backward-compatible sign request args. Accepts both old field names
/// (payload, key_version) and new (payload_v2, domain_id).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LegacySignRequestArgs {
    pub path: String,

    // Either one of the following two must be present.
    pub payload_v2: Option<Payload>,
    #[serde(rename = "payload")]
    pub deprecated_payload: Option<[u8; 32]>,

    // Either one of the following two must be present.
    pub domain_id: Option<DomainId>,
    #[serde(rename = "key_version")]
    pub deprecated_key_version: Option<u32>,
}

/// Canonical sign request with resolved fields.
#[derive(Debug, Clone)]
pub struct SignRequest {
    pub payload: Payload,
    pub path: String,
    pub domain_id: DomainId,
}

/// Error when converting backward-compat args to canonical form.
#[derive(Debug)]
pub enum SignRequestError {
    MalformedPayload,
    InvalidDomainId,
}

impl fmt::Display for SignRequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignRequestError::MalformedPayload => {
                write!(
                    f,
                    "expected exactly one of payload_v2 or deprecated_payload"
                )
            }
            SignRequestError::InvalidDomainId => {
                write!(f, "expected exactly one of domain_id or key_version")
            }
        }
    }
}

impl TryFrom<LegacySignRequestArgs> for SignRequest {
    type Error = SignRequestError;

    fn try_from(args: LegacySignRequestArgs) -> Result<Self, Self::Error> {
        let payload = match (args.payload_v2, args.deprecated_payload) {
            (Some(payload), None) => payload,
            (None, Some(payload)) => Payload::from_legacy_ecdsa(payload),
            _ => return Err(SignRequestError::MalformedPayload),
        };
        let domain_id = match (args.domain_id, args.deprecated_key_version) {
            (Some(domain_id), None) => domain_id,
            (None, Some(key_version)) => DomainId(key_version.into()),
            _ => return Err(SignRequestError::InvalidDomainId),
        };
        Ok(SignRequest {
            payload,
            path: args.path,
            domain_id,
        })
    }
}
