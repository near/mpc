use borsh::{BorshDeserialize, BorshSerialize};
use near_mpc_bounded_collections::{BoundedVec, hex_serde};
use serde::{Deserialize, Serialize};
use serde_with::{hex::Hex, serde_as};

use crate::Bls12381G1PublicKey;

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

impl Tweak {
    pub fn as_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

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

pub const ECDSA_PAYLOAD_SIZE_BYTES: usize = 32;

pub const EDDSA_PAYLOAD_SIZE_LOWER_BOUND_BYTES: usize = 32;
// Transaction signatures for Solana is over the whole transaction payload,
// not the transaction hash. The max size for a solana transaction is 1232 bytes,
// to fit in a single UDP packet, hence the 1232 byte upper bounds.
pub const EDDSA_PAYLOAD_SIZE_UPPER_BOUND_BYTES: usize = 1232;

/// A signature payload; the right payload must be passed in for the curve.
/// The json encoding for this payload converts the bytes to hex string.
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
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub enum Payload {
    Ecdsa(
        #[serde(with = "hex_serde")]
        #[cfg_attr(
            all(feature = "abi", not(target_arch = "wasm32")),
            schemars(
                with = "hex_serde::HexString<ECDSA_PAYLOAD_SIZE_BYTES, ECDSA_PAYLOAD_SIZE_BYTES>"
            )
        )]
        BoundedVec<u8, ECDSA_PAYLOAD_SIZE_BYTES, ECDSA_PAYLOAD_SIZE_BYTES>,
    ),
    Eddsa(
        #[serde(with = "hex_serde")]
        #[cfg_attr(
            all(feature = "abi", not(target_arch = "wasm32")),
            schemars(
                with = "hex_serde::HexString<EDDSA_PAYLOAD_SIZE_LOWER_BOUND_BYTES, EDDSA_PAYLOAD_SIZE_UPPER_BOUND_BYTES>"
            )
        )]
        BoundedVec<u8, EDDSA_PAYLOAD_SIZE_LOWER_BOUND_BYTES, EDDSA_PAYLOAD_SIZE_UPPER_BOUND_BYTES>,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct CKDResponse {
    pub big_y: Bls12381G1PublicKey,
    pub big_c: Bls12381G1PublicKey,
}

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
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
#[serde(tag = "scheme")]
pub enum SignatureResponse {
    Secp256k1(K256Signature),
    Ed25519 { signature: Ed25519Signature },
}

#[serde_as]
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
    derive_more::From,
    derive_more::Deref,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
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
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct K256Signature {
    pub big_r: K256AffinePoint,
    pub s: K256Scalar,
    pub recovery_id: u8,
}

#[serde_as]
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
    derive_more::From,
    derive_more::Into,
    derive_more::AsRef,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
/// AffinePoint on the Secp256k1 curve
pub struct K256AffinePoint {
    #[serde_as(as = "Hex")]
    pub affine_point: [u8; 33],
}

#[serde_as]
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
    derive_more::From,
    derive_more::Into,
    derive_more::AsRef,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct K256Scalar {
    #[serde_as(as = "Hex")]
    pub scalar: [u8; 32],
}
