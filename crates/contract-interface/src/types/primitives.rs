use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

/// A Near AccountId
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct AccountId(pub String);

/// AppId for CKD
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    derive_more::Into,
    derive_more::From,
    derive_more::AsRef,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct CkdAppId(pub [u8; 32]);

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    derive_more::Into,
    derive_more::From,
    derive_more::AsRef,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct Tweak(pub [u8; 32]);

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    derive_more::Into,
    derive_more::From,
    derive_more::AsRef,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct DomainId(pub u64);

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
#[serde(tag = "scheme")]
pub enum SignatureResponse {
    Secp256k1(K256Signature),
    Ed25519 { signature: Ed25519Signature },
}

#[serde_as]
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct Ed25519Signature(
    #[cfg_attr(
            all(feature = "abi", not(target_arch = "wasm32")),
            schemars(with = "Vec<u8>") // Schemars doesn't support arrays of size greater than 32. 
        )]
    #[serde_as(as = "[_; 64]")]
    [u8; 64],
);

#[serde_as]
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct K256Signature {
    pub big_r: AffinePoint,
    pub s: K256Scalar,
    pub recovery_id: u8,
}

#[serde_as]
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct AffinePoint {
    // TODO: Figure out how to represent affine_point to be backwards compatible with
    // SerializableAffinePoint in contract::crypto_shared::SerializableAffinePoint
    pub affine_point: Vec<u8>,
}

#[serde_as]
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct K256Scalar(pub [u8; 32]);
