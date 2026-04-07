use borsh::{BorshDeserialize, BorshSerialize};
use near_mpc_bounded_collections::{BoundedVec, hex_serde};
use serde::{Deserialize, Serialize};

use crate::types::DomainId;

pub const ECDSA_PAYLOAD_SIZE_BYTES: usize = 32;

pub const EDDSA_PAYLOAD_SIZE_LOWER_BOUND_BYTES: usize = 32;
// Transaction signatures for Solana is over the whole transaction payload,
// not the transaction hash. The max size for a solana transaction is 1232 bytes,
// to fit in a single UDP packet, hence the 1232 byte upper bounds.
pub const EDDSA_PAYLOAD_SIZE_UPPER_BOUND_BYTES: usize = 1232;

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct SignRequestArgs {
    pub path: String,
    pub payload_v2: Payload,
    pub domain_id: DomainId,
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub enum Payload {
    Ecdsa(
        #[serde(with = "hex_serde")]
        BoundedVec<u8, ECDSA_PAYLOAD_SIZE_BYTES, ECDSA_PAYLOAD_SIZE_BYTES>,
    ),
    Eddsa(
        #[serde(with = "hex_serde")]
        BoundedVec<u8, EDDSA_PAYLOAD_SIZE_LOWER_BOUND_BYTES, EDDSA_PAYLOAD_SIZE_UPPER_BOUND_BYTES>,
    ),
}

impl Payload {
    /// Create an ECDSA payload from a legacy 32-byte array.
    pub fn from_legacy_ecdsa(bytes: [u8; 32]) -> Self {
        Payload::Ecdsa(bytes.into())
    }

    /// If this is an ECDSA payload, return the 32 bytes.
    pub fn as_ecdsa(&self) -> Option<&[u8; ECDSA_PAYLOAD_SIZE_BYTES]> {
        match self {
            Payload::Ecdsa(bytes) => Some(bytes.as_ref()),
            _ => None,
        }
    }

    /// If this is an EdDSA payload, return the bytes.
    pub fn as_eddsa(&self) -> Option<&[u8]> {
        match self {
            Payload::Eddsa(bytes) => Some(bytes.as_ref()),
            _ => None,
        }
    }
}

/// A validated sign request (parsed from [`SignRequestArgs`] with backward compat).
#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct SignRequest {
    pub payload: Payload,
    pub path: String,
    pub domain_id: DomainId,
}

/// Legacy sign request args that support both old and new payload/domain formats.
/// Used for deserializing on-chain function call arguments.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LegacySignRequestArgs {
    pub path: String,
    pub payload_v2: Option<Payload>,
    #[serde(rename = "payload")]
    pub deprecated_payload: Option<[u8; 32]>,
    pub domain_id: Option<DomainId>,
    #[serde(rename = "key_version")]
    pub deprecated_key_version: Option<u32>,
}

/// The index into calling the YieldResume feature of NEAR. This will allow to resume
/// a yield call after the contract has been called back via this index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YieldIndex {
    pub data_id: [u8; 32],
}

impl TryFrom<LegacySignRequestArgs> for SignRequest {
    type Error = String;

    fn try_from(args: LegacySignRequestArgs) -> Result<Self, Self::Error> {
        let payload = match (args.payload_v2, args.deprecated_payload) {
            (Some(payload), None) => payload,
            (None, Some(payload)) => Payload::from_legacy_ecdsa(payload),
            _ => {
                return Err(
                    "Malformed payload: exactly one of payload_v2 or payload must be present"
                        .to_string(),
                );
            }
        };
        let domain_id =
            match (args.domain_id, args.deprecated_key_version) {
                (Some(domain_id), None) => domain_id,
                (None, Some(key_version)) => DomainId(key_version.into()),
                _ => return Err(
                    "Invalid domain_id: exactly one of domain_id or key_version must be present"
                        .to_string(),
                ),
            };
        Ok(SignRequest {
            payload,
            path: args.path,
            domain_id,
        })
    }
}
