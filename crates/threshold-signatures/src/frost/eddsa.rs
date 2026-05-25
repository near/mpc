//! This module serves as a wrapper for Ed25519 scheme.
mod presign;
pub mod sign;
#[cfg(test)]
mod test;

pub use presign::{
    presign, Ed25519Sha512, KeygenOutput, PresignArguments, PresignOutput, SignatureOption,
};
