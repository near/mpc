/// Implements [`Debug`] for types containing secret cryptographic material,
/// ensuring secrets are never leaked through debug output.
///
/// # Fully redacted
/// When all fields are secret, outputs `TypeName(<redacted>)`:
/// ```ignore
/// impl_secret_debug!(ScalarWrapper);
/// ```
///
/// # Partially redacted
/// When some fields are public, shows public fields and redacts secret ones:
/// ```ignore
/// impl_secret_debug!(PresignOutput { show: [big_r], redact: [k, sigma] });
/// ```
macro_rules! impl_secret_debug {
    ($name:ident) => {
        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                write!(f, concat!(stringify!($name), "(<redacted>)"))
            }
        }
    };
    ($name:ident { show: [$($show:ident),* $(,)?], redact: [$($redact:ident),* $(,)?] }) => {
        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.debug_struct(stringify!($name))
                    $(.field(stringify!($show), &self.$show))*
                    $(.field(stringify!($redact), &"<redacted>"))*
                    .finish()
            }
        }
    };
}

mod crypto;
pub mod participants;

pub mod confidential_key_derivation;
pub mod ecdsa;
pub mod errors;
pub mod frost;

#[cfg(feature = "test-utils")]
pub mod test_utils;

// TODO: We should probably no expose the full modules, but only the types
// that make sense for our library
pub use blstrs;
pub use frost_core;
pub use frost_ed25519;
pub use frost_secp256k1;

pub use crypto::ciphersuite::Ciphersuite;
pub use participants::ParticipantList;
// For benchmark
pub use crypto::polynomials::{
    batch_compute_lagrange_coefficients, batch_invert, compute_lagrange_coefficient,
};
use zeroize::ZeroizeOnDrop;

mod dkg;
pub mod protocol;
mod thresholds;

use crate::dkg::{assert_key_invariants, assert_reshare_keys_invariants, do_keygen, do_reshare};
use crate::errors::InitializationError;
use crate::participants::Participant;
use crate::protocol::internal::{make_protocol, Comms};
use crate::protocol::Protocol;
pub use crate::thresholds::{MaxMalicious, ReconstructionLowerBound};
use rand_core::CryptoRngCore;
use std::fmt;
use std::marker::Send;

use frost_core::serialization::SerializableScalar;
use frost_core::{keys::SigningShare, Group, VerifyingKey};

use serde::{Deserialize, Serialize};

pub type Scalar<C> = frost_core::Scalar<C>;
pub type Element<C> = frost_core::Element<C>;

#[derive(Clone, Deserialize, Serialize, Eq, PartialEq, ZeroizeOnDrop)]
#[serde(bound = "C: Ciphersuite")]
/// Generic type of key pairs
pub struct KeygenOutput<C: Ciphersuite> {
    pub private_share: SigningShare<C>,
    #[zeroize[skip]]
    pub public_key: VerifyingKey<C>,
}

impl<C: Ciphersuite> fmt::Debug for KeygenOutput<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeygenOutput")
            .field("private_share", &"<redacted>")
            .field("public_key", &self.public_key)
            .finish()
    }
}

/// This is a necessary element to be able to derive different keys
/// from signing shares.
/// We do not bind the user with the way to compute the inner scalar of the tweak
#[derive(Copy, Clone, Deserialize, Serialize, Eq, PartialEq)]
#[serde(bound = "C: Ciphersuite")]
pub struct Tweak<C: Ciphersuite>(SerializableScalar<C>);

impl<C: Ciphersuite> Tweak<C> {
    pub fn new(tweak: Scalar<C>) -> Self {
        Self(SerializableScalar(tweak))
    }

    /// Outputs the inner value of the tweak
    pub fn value(&self) -> Scalar<C> {
        self.0 .0
    }

    /// Derives the signing share as x + tweak
    pub fn derive_signing_share(&self, private_share: &SigningShare<C>) -> SigningShare<C> {
        let derived_share = private_share.to_scalar() + self.value();
        SigningShare::new(derived_share)
    }

    /// Derives the verifying key as X + tweak . G
    pub fn derive_verifying_key(&self, public_key: &VerifyingKey<C>) -> VerifyingKey<C> {
        let derived_share = public_key.to_element() + C::Group::generator() * self.value();
        VerifyingKey::new(derived_share)
    }
}

/// Maximum incoming buffer entries for keygen, reshare, and refresh protocols.
pub(crate) const DKG_MAX_INCOMING_BUFFER_ENTRIES: usize = 5;

/// Generic key generation function agnostic of the curve
pub fn keygen<C: Ciphersuite>(
    participants: &[Participant],
    me: Participant,
    threshold: impl Into<ReconstructionLowerBound> + Send + Copy + 'static,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = KeygenOutput<C>>, InitializationError>
where
    Element<C>: Send,
    Scalar<C>: Send,
{
    let comms = Comms::with_buffer_capacity(DKG_MAX_INCOMING_BUFFER_ENTRIES);
    let participants = assert_key_invariants(participants, me, threshold)?;
    let fut = do_keygen::<C>(comms.shared_channel(), participants, me, threshold, rng);
    Ok(make_protocol(comms, fut))
}

/// Performs the key reshare protocol
#[allow(clippy::too_many_arguments)]
pub fn reshare<C: Ciphersuite>(
    old_participants: &[Participant],
    old_threshold: impl Into<ReconstructionLowerBound> + Send + 'static,
    old_signing_key: Option<SigningShare<C>>,
    old_public_key: VerifyingKey<C>,
    new_participants: &[Participant],
    new_threshold: impl Into<ReconstructionLowerBound> + Copy + Send + 'static,
    me: Participant,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = KeygenOutput<C>>, InitializationError>
where
    Element<C>: Send,
    Scalar<C>: Send,
{
    let comms = Comms::with_buffer_capacity(DKG_MAX_INCOMING_BUFFER_ENTRIES);
    let threshold = new_threshold;
    let (participants, old_participants) = assert_reshare_keys_invariants::<C>(
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
        rng,
    );
    Ok(make_protocol(comms, fut))
}

/// Performs the refresh protocol
pub fn refresh<C: Ciphersuite>(
    old_signing_key: Option<SigningShare<C>>,
    old_public_key: VerifyingKey<C>,
    old_participants: &[Participant],
    old_threshold: impl Into<ReconstructionLowerBound> + Copy + Send + 'static,
    me: Participant,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = KeygenOutput<C>>, InitializationError>
where
    Element<C>: Send,
    Scalar<C>: Send,
{
    if old_signing_key.is_none() {
        return Err(InitializationError::BadParameters(format!(
            "The participant {me:?} is running refresh without an old share",
        )));
    }
    let comms = Comms::with_buffer_capacity(DKG_MAX_INCOMING_BUFFER_ENTRIES);
    // NOTE: this equality must be kept, as changing the threshold during `key refresh`
    // might lead to insecure scenarios. For more information see https://github.com/ZcashFoundation/frost/security/advisories/GHSA-wgq8-vr6r-mqxm
    let threshold = old_threshold;
    let (participants, old_participants) = assert_reshare_keys_invariants::<C>(
        old_participants,
        me,
        threshold,
        old_signing_key,
        threshold,
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
        rng,
    );
    Ok(make_protocol(comms, fut))
}
