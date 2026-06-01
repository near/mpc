//! This module serves as a wrapper for Ed25519 scheme.
pub mod sign;
#[cfg(test)]
mod test;

use crate::{
    Ciphersuite,
    crypto::ciphersuite::{BytesOrder, ScalarSerializationFormat},
    errors::InitializationError,
    participants::Participant,
    protocol::Protocol,
};
use rand_core::CryptoRngCore;

pub use frost_ed25519::Ed25519Sha512;

impl ScalarSerializationFormat for Ed25519Sha512 {
    fn bytes_order() -> BytesOrder {
        BytesOrder::LittleEndian
    }
}

impl Ciphersuite for Ed25519Sha512 {}

/// Signature would be Some for coordinator and None for other participants
pub type SignatureOption = Option<frost_ed25519::Signature>;

pub type KeygenOutput = super::KeygenOutput<Ed25519Sha512>;
pub type PresignArguments = super::PresignArguments<Ed25519Sha512>;
pub type PresignOutput = super::PresignOutput<Ed25519Sha512>;

/// Ed25519 presigning function
pub fn presign<R>(
    participants: &[Participant],
    me: Participant,
    args: &PresignArguments,
    rng: R,
) -> Result<impl Protocol<Output = PresignOutput> + use<R>, InitializationError>
where
    R: CryptoRngCore + Send + 'static,
{
    super::presign(participants, me, args, rng)
}
