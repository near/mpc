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

pub type KeygenOutput = crate::KeygenOutput<Ed25519Sha512>;
pub type PresignArguments = crate::frost::PresignArguments<Ed25519Sha512>;
pub type PresignOutput = crate::frost::PresignOutput<Ed25519Sha512>;

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
    crate::frost::presign(participants, me, args, rng)
}
