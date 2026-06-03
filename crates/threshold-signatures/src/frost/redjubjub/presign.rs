use crate::{
    Ciphersuite,
    crypto::ciphersuite::{BytesOrder, ScalarSerializationFormat},
    errors::InitializationError,
    participants::Participant,
    protocol::Protocol,
};
use rand_core::CryptoRngCore;
use reddsa::frost::redjubjub::Signature;

// JubJub + Blake2b512 Ciphersuite
pub use reddsa::frost::redjubjub::JubjubBlake2b512;

impl ScalarSerializationFormat for JubjubBlake2b512 {
    fn bytes_order() -> BytesOrder {
        BytesOrder::LittleEndian
    }
}
impl Ciphersuite for JubjubBlake2b512 {}

pub type KeygenOutput = crate::KeygenOutput<JubjubBlake2b512>;
pub type PresignArguments = crate::frost::PresignArguments<JubjubBlake2b512>;
pub type PresignOutput = crate::frost::PresignOutput<JubjubBlake2b512>;

/// Signature would be Some for coordinator and None for other participants
pub type SignatureOption = Option<Signature>;

/// `RedJubJub` presigning function
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
