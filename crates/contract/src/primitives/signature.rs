use crate::crypto_shared;
use crate::errors::{Error, InvalidParameters};
use crate::DomainId;
use bounded_collections::{hex_serde, BoundedVec};
use crypto_shared::derive_tweak;
use near_account_id::AccountId;
use near_sdk::{near, CryptoHash};
use std::fmt::Debug;

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
#[near(serializers=[borsh, json])]
pub struct Tweak([u8; 32]);

impl Tweak {
    pub fn as_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// A signature payload; the right payload must be passed in for the curve.
/// The json encoding for this payload converts the bytes to hex string.
#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
#[near(serializers=[borsh, json])]
pub enum Payload {
    Ecdsa(
        #[serde(with = "hex_serde")]
        #[cfg_attr(
            all(feature = "abi", not(target_arch = "wasm32")),
            schemars(with = "hex_serde::HexString<32, 32>")
        )]
        BoundedVec<u8, 32, 32>,
    ),
    Eddsa(
        #[serde(with = "hex_serde")]
        #[cfg_attr(
            all(feature = "abi", not(target_arch = "wasm32")),
            schemars(with = "hex_serde::HexString<32, 1232>")
        )]
        BoundedVec<u8, 32, 1232>,
    ),
}

impl Payload {
    pub fn from_legacy_ecdsa(bytes: [u8; 32]) -> Self {
        Payload::Ecdsa(bytes.into())
    }

    pub fn as_ecdsa(&self) -> Option<&[u8; 32]> {
        match self {
            Payload::Ecdsa(bytes) => Some(bytes.as_ref()),
            _ => None,
        }
    }

    pub fn as_eddsa(&self) -> Option<&[u8]> {
        match self {
            Payload::Eddsa(bytes) => Some(bytes.as_slice()),
            _ => None,
        }
    }
}

/// The index into calling the YieldResume feature of NEAR. This will allow to resume
/// a yield call after the contract has been called back via this index.
#[derive(Debug, Clone)]
#[near(serializers=[borsh, json])]
pub struct YieldIndex {
    pub data_id: CryptoHash,
}
#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
#[near(serializers=[borsh, json])]
pub struct SignatureRequest {
    pub tweak: Tweak,
    pub payload: Payload,
    pub domain_id: DomainId,
}

impl SignatureRequest {
    pub fn new(domain: DomainId, payload: Payload, predecessor_id: &AccountId, path: &str) -> Self {
        let tweak = derive_tweak(predecessor_id, path);
        SignatureRequest {
            domain_id: domain,
            tweak,
            payload,
        }
    }
}

#[derive(Clone, Debug, Default)]
#[near(serializers=[json])]
pub struct SignRequestArgs {
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

#[derive(Debug, Clone)]
#[near(serializers=[borsh])]
pub struct SignRequest {
    pub payload: Payload,
    pub path: String,
    pub domain_id: DomainId,
}

impl TryFrom<SignRequestArgs> for SignRequest {
    type Error = Error;

    fn try_from(args: SignRequestArgs) -> Result<Self, Self::Error> {
        let payload = match (args.payload_v2, args.deprecated_payload) {
            (Some(payload), None) => payload,
            (None, Some(payload)) => Payload::from_legacy_ecdsa(payload),
            _ => return Err(InvalidParameters::MalformedPayload.into()),
        };
        let domain_id = match (args.domain_id, args.deprecated_key_version) {
            (Some(domain_id), None) => domain_id,
            (None, Some(key_version)) => DomainId(key_version.into()),
            _ => return Err(InvalidParameters::InvalidDomainId.into()),
        };
        Ok(SignRequest {
            payload,
            path: args.path,
            domain_id,
        })
    }
}

#[derive(Clone, Debug)]
#[near(serializers=[borsh])]
pub enum SignatureResult<T, E> {
    Ok(T),
    Err(E),
}
