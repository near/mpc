use super::CheetahTip5;
use crate::{errors::InitializationError, participants::Participant, protocol::Protocol};
use rand_core::CryptoRngCore;

/// `Some` for the coordinator, `None` for other participants.
pub type SignatureOption = Option<frost_core::Signature<CheetahTip5>>;

pub type KeygenOutput = crate::KeygenOutput<CheetahTip5>;
pub type PresignArguments = crate::frost::PresignArguments<CheetahTip5>;
pub type PresignOutput = crate::frost::PresignOutput<CheetahTip5>;

/// Cheetah (SchnorrCheetah) presigning — generates a FROST presignature (round-1
/// nonces + commitments) for later one-round signing. Wraps the generic FROST presign.
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
