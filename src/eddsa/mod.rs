//! This module serves as a wrapper for Frost protocol.
use frost_ed25519::Ed25519Sha512;
pub type KeygenOutput = crate::generic_dkg::KeygenOutput<Ed25519Sha512>;

pub mod dkg_ed25519;
pub mod sign;
#[cfg(test)]
mod test;
