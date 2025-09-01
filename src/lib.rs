mod crypto;
mod generic_dkg;
mod participants;

pub mod protocol;

pub mod confidential_key_derivation;
pub mod ecdsa;
pub mod eddsa;

pub use frost_core;
pub use frost_ed25519;
pub use frost_secp256k1;
#[cfg(test)]
mod test;

#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq)]
/// Generic type of key pairs
pub struct KeygenOutput<C: Ciphersuite> {
    pub private_share: SigningShare<C>,
    pub public_key: VerifyingKey<C>,
}

/// Generic key generation function agnostic of the curve
pub fn keygen<C: Ciphersuite>(
    participants: &[Participant],
    me: Participant,
    threshold: usize,
) -> Result<impl Protocol<Output = KeygenOutput<C>>, InitializationError>
where
    frost_core::Element<C>: Send,
    frost_core::Scalar<C>: Send,
{
    let comms = Comms::new();
    let participants = assert_keygen_invariants(participants, me, threshold)?;
    let fut = do_keygen::<C>(comms.shared_channel(), participants, me, threshold);
    Ok(make_protocol(comms, fut))
}

/// Performs the key reshare protocol
pub fn reshare<C: Ciphersuite>(
    old_participants: &[Participant],
    old_threshold: usize,
    old_signing_key: Option<SigningShare<C>>,
    old_public_key: VerifyingKey<C>,
    new_participants: &[Participant],
    new_threshold: usize,
    me: Participant,
) -> Result<impl Protocol<Output = KeygenOutput<C>>, InitializationError>
where
    frost_core::Element<C>: Send,
    frost_core::Scalar<C>: Send,
{
    let comms = Comms::new();
    let threshold = new_threshold;
    let (participants, old_participants) = reshare_assertions::<C>(
        new_participants,
        me,
        threshold,
        old_signing_key,
        old_threshold,
        old_participants,
    )?;
    let fut = do_reshare(
        comms.shared_channel(),
        participants,
        me,
        threshold,
        old_signing_key,
        old_public_key,
        old_participants,
    );
    Ok(make_protocol(comms, fut))
}

/// Performs the refresh protocol
pub fn refresh<C: Ciphersuite>(
    old_signing_key: Option<SigningShare<C>>,
    old_public_key: VerifyingKey<C>,
    new_participants: &[Participant],
    new_threshold: usize,
    me: Participant,
) -> Result<impl Protocol<Output = KeygenOutput<C>>, InitializationError>
where
    frost_core::Element<C>: Send,
    frost_core::Scalar<C>: Send,
{
    if old_signing_key.is_none() {
        return Err(InitializationError::BadParameters(format!(
            "The participant {me:?} is running refresh without an old share",
        )));
    }
    let comms = Comms::new();
    let threshold = new_threshold;
    let (participants, old_participants) = reshare_assertions::<C>(
        new_participants,
        me,
        threshold,
        old_signing_key,
        threshold,
        new_participants,
    )?;
    let fut = do_reshare(
        comms.shared_channel(),
        participants,
        me,
        threshold,
        old_signing_key,
        old_public_key,
        old_participants,
    );
    Ok(make_protocol(comms, fut))
}

// Libraries calls
use crypto::ciphersuite::Ciphersuite;
use frost_core::{keys::SigningShare, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::marker::Send;

use crate::generic_dkg::*;
use crate::protocol::internal::{make_protocol, Comms};
use crate::protocol::{errors::InitializationError, Participant, Protocol};
