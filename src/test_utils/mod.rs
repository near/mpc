#![allow(
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::unwrap_used,
    clippy::cast_possible_truncation
)]

mod dkg;
mod mockrng;
mod participants;
mod presign;
mod protocol;
mod sign;
mod snapshot;
pub mod test_generators;

use crate::errors::ProtocolError;
use crate::participants::Participant;
use crate::protocol::Protocol;
use crate::KeygenOutput;
use rand_core::CryptoRngCore;

/// Type representing DKG output keys
pub type GenOutput<C> = Vec<(Participant, KeygenOutput<C>)>;
/// Type representing DKG output protocols runs
pub type GenProtocol<C> = Vec<(Participant, Box<dyn Protocol<Output = C>>)>;
/// Type for a deterministic RNG
pub use mockrng::MockCryptoRng;

pub use dkg::{assert_public_key_invariant, run_keygen, run_refresh, run_reshare};
pub use mockrng::create_rngs;
pub use participants::{generate_participants, generate_participants_with_random_ids};
pub use presign::ecdsa_generate_rerandpresig_args;
pub use protocol::{run_protocol, run_protocol_and_take_snapshots, run_two_party_protocol};
pub use sign::{check_one_coordinator_output, run_sign};
pub use snapshot::ProtocolSnapshot;
pub use test_generators::*;

/// Checks that the list contains all None but one element
/// and verifies such element belongs to the coordinator
pub fn one_coordinator_output<ProtocolOutput: Clone>(
    all_sigs: Vec<(Participant, Option<ProtocolOutput>)>,
    coordinator: Participant,
) -> Result<ProtocolOutput, ProtocolError> {
    check_one_coordinator_output(all_sigs, coordinator)
}

pub fn random_32_bytes(rng: &mut impl CryptoRngCore) -> [u8; 32] {
    let mut bytes: [u8; 32] = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    bytes
}
