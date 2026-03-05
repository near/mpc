#![deny(clippy::mod_module_files)]

pub mod conversions;
pub mod crypto;
pub mod primitives;

pub use conversions::CryptoConversionError;
pub use crypto::{
    Bls12381G1PublicKey, Bls12381G2PublicKey, Ed25519PublicKey, ParsePublicKeyError, PublicKey,
    PublicKeyExtended, Secp256k1PublicKey,
};
pub use primitives::{
    Ed25519Signature, K256AffinePoint, K256Scalar, K256Signature, SignatureResponse,
};

#[cfg(feature = "blstrs")]
pub use blstrs;

#[cfg(feature = "near")]
pub use near_sdk;

#[cfg(feature = "k256")]
pub use k256;

#[cfg(feature = "ed25519-dalek")]
pub use curve25519_dalek;
#[cfg(feature = "ed25519-dalek")]
pub use ed25519_dalek;
