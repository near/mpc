use crate::crypto_shared;
use crate::errors::{Error, InvalidParameters};
use crate::DomainId;
use crypto_shared::derive_tweak;
use near_sdk::{near, AccountId, CryptoHash};
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
        #[cfg_attr(
            all(feature = "abi", not(target_arch = "wasm32")),
            schemars(with = "[u8; 32]"),
            borsh(schema(with_funcs(
                declaration = "<[u8; 32] as ::borsh::BorshSchema>::declaration",
                definitions = "<[u8; 32] as ::borsh::BorshSchema>::add_definitions_recursively"
            ),))
        )]
        Bytes<32, 32>,
    ),
    Eddsa(
        #[cfg_attr(
            all(feature = "abi", not(target_arch = "wasm32")),
            schemars(with = "Vec<u8>"),
            borsh(schema(with_funcs(
                declaration = "<Vec<u8> as ::borsh::BorshSchema>::declaration",
                definitions = "<Vec<u8> as ::borsh::BorshSchema>::add_definitions_recursively"
            ),))
        )]
        Bytes<32, 1232>,
    ),
}

impl Payload {
    pub fn from_legacy_ecdsa(bytes: [u8; 32]) -> Self {
        Payload::Ecdsa(Bytes::new(bytes.to_vec()).unwrap())
    }

    pub fn as_ecdsa(&self) -> Option<&[u8; 32]> {
        match self {
            Payload::Ecdsa(bytes) => Some(bytes.as_fixed_bytes()),
            _ => None,
        }
    }

    pub fn as_eddsa(&self) -> Option<&[u8]> {
        match self {
            Payload::Eddsa(bytes) => Some(bytes.as_bytes()),
            _ => None,
        }
    }
}

/// A byte array with a statically encoded minimum and maximum length.
/// The `new` function as well as json deserialization checks that the length is within bounds.
/// The borsh deserialization does not perform such checks, as the borsh serialization is only
/// used for internal contract storage.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
#[near(serializers=[borsh])]
pub struct Bytes<const MIN_LEN: usize, const MAX_LEN: usize>(Vec<u8>);

impl<const MIN_LEN: usize, const MAX_LEN: usize> Bytes<MIN_LEN, MAX_LEN> {
    pub fn new(bytes: Vec<u8>) -> Result<Self, Error> {
        if bytes.len() < MIN_LEN || bytes.len() > MAX_LEN {
            return Err(InvalidParameters::MalformedPayload.into());
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> Bytes<N, N> {
    pub fn as_fixed_bytes(&self) -> &[u8; N] {
        self.0.as_slice().try_into().unwrap()
    }
}

impl<const MIN_LEN: usize, const MAX_LEN: usize> Debug for Bytes<MIN_LEN, MAX_LEN> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Bytes").field(&hex::encode(&self.0)).finish()
    }
}

impl<const MIN_LEN: usize, const MAX_LEN: usize> near_sdk::serde::Serialize
    for Bytes<MIN_LEN, MAX_LEN>
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: near_sdk::serde::Serializer,
    {
        hex::encode(&self.0).serialize(serializer)
    }
}

impl<'de, const MIN_LEN: usize, const MAX_LEN: usize> near_sdk::serde::Deserialize<'de>
    for Bytes<MIN_LEN, MAX_LEN>
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: near_sdk::serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(near_sdk::serde::de::Error::custom)?;
        Self::new(bytes).map_err(near_sdk::serde::de::Error::custom)
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
