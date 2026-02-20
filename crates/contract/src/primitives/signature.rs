use crate::crypto_shared;
use crate::errors::{Error, InvalidParameters};
use crate::DomainId;
use bounded_collections::BoundedVec;
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
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
#[near(serializers=[borsh])]
pub enum Payload {
    Ecdsa(BoundedVec<u8, 32, 32>),
    Eddsa(BoundedVec<u8, 32, 1232>),
}

/// Custom JSON serialization preserving the hex-encoded string format
/// used by the original `Bytes` type, so the on-chain API stays backwards-compatible.
impl near_sdk::serde::Serialize for Payload {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: near_sdk::serde::Serializer,
    {
        #[derive(near_sdk::serde::Serialize)]
        #[serde(crate = "near_sdk::serde")]
        enum Helper<'a> {
            Ecdsa(&'a str),
            Eddsa(&'a str),
        }
        match self {
            Payload::Ecdsa(bytes) => {
                let hex = hex::encode(bytes.as_slice());
                Helper::Ecdsa(&hex).serialize(serializer)
            }
            Payload::Eddsa(bytes) => {
                let hex = hex::encode(bytes.as_slice());
                Helper::Eddsa(&hex).serialize(serializer)
            }
        }
    }
}

impl<'de> near_sdk::serde::Deserialize<'de> for Payload {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: near_sdk::serde::Deserializer<'de>,
    {
        #[derive(near_sdk::serde::Deserialize)]
        #[serde(crate = "near_sdk::serde")]
        enum Helper {
            Ecdsa(String),
            Eddsa(String),
        }
        match Helper::deserialize(deserializer)? {
            Helper::Ecdsa(hex) => {
                let bytes = hex::decode(&hex).map_err(near_sdk::serde::de::Error::custom)?;
                let bounded: BoundedVec<u8, 32, 32> = bytes
                    .try_into()
                    .map_err(near_sdk::serde::de::Error::custom)?;
                Ok(Payload::Ecdsa(bounded))
            }
            Helper::Eddsa(hex) => {
                let bytes = hex::decode(&hex).map_err(near_sdk::serde::de::Error::custom)?;
                let bounded: BoundedVec<u8, 32, 1232> = bytes
                    .try_into()
                    .map_err(near_sdk::serde::de::Error::custom)?;
                Ok(Payload::Eddsa(bounded))
            }
        }
    }
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
