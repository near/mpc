//! This module serves as a wrapper for Ed25519 scheme.
pub mod sign;

mod presign;
#[cfg(test)]
mod test;

pub use presign::{
    Ed25519Sha512, KeygenOutput, PresignArguments, PresignOutput, SignatureOption, presign,
};
