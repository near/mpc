#![allow(
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::unwrap_used,
    clippy::cast_possible_truncation,
    clippy::indexing_slicing
)]

mod ckd;
mod dkg;
mod mockrng;
mod participant_simulation;
mod participants;
mod presign;
mod protocol;
mod sign;
pub mod simulator_bench;
mod snapshot;

use crate::KeygenOutput;
use crate::participants::Participant;

/// Type representing DKG output keys
pub type GenOutput<C> = Vec<(Participant, KeygenOutput<C>)>;
/// Type representing DKG output protocols runs
pub type GenProtocol<C> = Vec<(Participant, Box<dyn crate::protocol::Protocol<Output = C>>)>;
/// Type for a deterministic RNG
pub use mockrng::MockCryptoRng;

pub use ckd::generate_ckd_app_package;
pub use dkg::{
    assert_public_key_invariant, build_frost_key_packages_with_dealer, generate_test_keys,
    make_keygen_output, run_keygen, run_refresh, run_reshare,
};
pub use participant_simulation::Simulator;
pub use participants::{generate_participants, generate_participants_with_random_ids};
pub use presign::{ecdsa_generate_rerandpresig_args, frost_run_presignature};
pub use protocol::{
    assert_buffer_capacity, build_buffer_test, expected_buffer_by_role,
    run_and_assert_buffer_entries,
};
pub use protocol::{
    run_protocol, run_protocol_and_take_snapshots, run_simulated_protocol, run_two_party_protocol,
};
pub use sign::{check_one_coordinator_output, run_sign};
pub use simulator_bench::{
    BenchConfig, LatencyModel, SimulationMetrics, bench_simulation, run_simulation,
};
pub use snapshot::ProtocolSnapshot;

// Taken from https://github.com/ZcashFoundation/frost/blob/3ffc19d8f473d5bc4e07ed41bc884bdb42d6c29f/frost-secp256k1/tests/common_traits_tests.rs#L9
#[allow(clippy::unnecessary_literal_unwrap)]
pub fn check_common_traits_for_type<T: Clone + Eq + PartialEq + std::fmt::Debug>(v: &T) {
    // Make sure can be debug-printed. This also catches if the Debug does not
    // have an endless recursion (a popular mistake).
    println!("{v:?}");
    // Test Clone and Eq
    assert_eq!(*v, v.clone());
    // Make sure it can be unwrapped in a Result (which requires Debug).
    let e: Result<T, ()> = Ok(v.clone());
    assert_eq!(*v, e.unwrap());
}
