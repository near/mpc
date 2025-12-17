//! This module abstracts the Signature Schema,
//! i.e., we might want to use ECDSA over the Secp256k1 curve, EdDSA over Ed25519, or something else.
//! `SignatureProvider` exposes an interface for such add-ons. Alongside it, helper functions
//! (like `RegisterMpcTask`) are exposed, which somewhat guarantees that if the code compiles,
//! you don’t need to add anything more internally for it to work.
//!
//! As a reference, check the existing implementations.

pub mod ckd;
pub mod ecdsa;
pub mod eddsa;
pub mod robust_ecdsa;

use crate::config::ParticipantsConfig;
use crate::network::NetworkTaskChannel;
use crate::primitives::{MpcTaskId, ParticipantId};
use crate::types::SignatureId;
pub use ckd::CKDProvider;
pub use ecdsa::EcdsaSignatureProvider;
pub use ecdsa::EcdsaTaskId;
// TODO(#1640): remove as part of the provider integration
#[allow(unused)]
pub use robust_ecdsa::RobustEcdsaSignatureProvider;
use std::sync::Arc;

/// The interface that defines the requirements for a signing schema to be correctly used in the code.
pub trait SignatureProvider {
    type PublicKey;
    type SecretShare;
    type KeygenOutput;

    type Signature;

    /// Trait bound `Into<MpcTaskId>` serves as a way to see what logic needs to be added,
    /// when introducing new `TaskId`. Implementation of the trait should be trivial.
    type TaskId: Into<MpcTaskId>;

    /// Generates a signature.
    /// The implementation should handle the key derivation function (KDF) if needed.
    /// Only the leader should call this function.
    async fn make_signature(
        &self,
        id: SignatureId,
    ) -> anyhow::Result<(Self::Signature, Self::PublicKey)>;

    /// Executes the key generation protocol.
    /// Returns once key generation is complete or encounters an error.
    /// This should only succeed if all participants are online and running this function.
    ///
    /// Both leaders and followers call this function.
    ///
    /// It drains `channel_receiver` until the required task is found, meaning these clients must not be run in parallel.
    async fn run_key_generation_client(
        threshold: usize,
        channel: NetworkTaskChannel,
    ) -> anyhow::Result<Self::KeygenOutput>;

    /// Executes the key resharing protocol. This can only succeed if all new participants are online.
    /// Both leaders and followers call this function.
    /// It drains `channel_receiver` until the required task is found, meaning these clients must not be run in parallel.
    async fn run_key_resharing_client(
        new_threshold: usize,
        key_share: Option<Self::SecretShare>,
        public_key: Self::PublicKey,
        old_participants: &ParticipantsConfig,
        channel: NetworkTaskChannel,
    ) -> anyhow::Result<Self::KeygenOutput>;

    /// Expected to be called in a common loop that handles received channels and redirects them
    /// to the respective `SignatureProvider`.
    /// This function is called during the "normal MPC run",
    /// i.e., it should fail if it receives messages from the `KeyGeneration` or `KeyResharing` stage.
    async fn process_channel(&self, channel: NetworkTaskChannel) -> anyhow::Result<()>;

    /// Spawns any auxiliary logic that performs pre-computation (typically meant to optimize signature delay).
    async fn spawn_background_tasks(self: Arc<Self>) -> anyhow::Result<()>;
}

/// A resource might be generated with a set of some participants `A`.
/// This trait helps check whether the current set of participants contains `A`.
pub trait HasParticipants {
    fn is_subset_of_active_participants(&self, active_participants: &[ParticipantId]) -> bool;
}

/// Helper functions to convert back and forth public key types
pub trait PublicKeyConversion: Sized {
    #[cfg(test)]
    fn to_near_sdk_public_key(&self) -> anyhow::Result<near_sdk::PublicKey>;
    fn from_near_sdk_public_key(public_key: &near_sdk::PublicKey) -> anyhow::Result<Self>;
}
