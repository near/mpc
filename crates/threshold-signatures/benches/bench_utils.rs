#![allow(
    dead_code,
    unused_imports,
    clippy::missing_panics_doc,
    clippy::indexing_slicing
)]

#[path = "bench_utils/ckd.rs"]
mod ckd;
#[path = "bench_utils/dkg.rs"]
mod dkg;
#[path = "bench_utils/frost_eddsa.rs"]
mod frost_eddsa;
#[path = "bench_utils/ot_based_ecdsa.rs"]
mod ot_based_ecdsa;
#[path = "bench_utils/robust_ecdsa.rs"]
mod robust_ecdsa;

pub use ckd::*;
pub use dkg::*;
pub use frost_eddsa::*;
pub use ot_based_ecdsa::*;
pub use robust_ecdsa::*;

use k256::AffinePoint;
use std::{collections::HashMap, env, sync::LazyLock};

use rand_core::SeedableRng;
use threshold_signatures::{
    ReconstructionThreshold,
    ecdsa::{self, Scalar},
    participants::Participant,
    protocol::Protocol,
    test_utils::{MockCryptoRng, Simulator},
};

/// Rebuilds the RNG a participant's protocol was seeded with during snapshot
/// capture, so the simulated replay reproduces the exact recorded run.
pub fn participant_rng<S: std::hash::BuildHasher>(
    seeds: &HashMap<Participant, u64, S>,
    participant: Participant,
) -> MockCryptoRng {
    let seed = *seeds
        .get(&participant)
        .expect("participant must have a recorded seed");
    MockCryptoRng::seed_from_u64(seed)
}

// fix malicious number of participants
pub static MAX_MALICIOUS: LazyLock<usize> = std::sync::LazyLock::new(|| {
    env::var("MAX_MALICIOUS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(6)
});

// fix number of samples
pub static SAMPLE_SIZE: LazyLock<usize> = std::sync::LazyLock::new(|| {
    env::var("SAMPLE_SIZE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(15)
});

pub static RECONSTRUCTION_LOWER_BOUND: LazyLock<ReconstructionThreshold> =
    LazyLock::new(|| ReconstructionThreshold::from(*MAX_MALICIOUS + 1));

/// This helps defining a generic type for the benchmarks prepared outputs
pub struct PreparedOutputs<T> {
    pub participant: Participant,
    pub protocol: Box<dyn Protocol<Output = T>>,
    pub simulator: Simulator,
}
pub struct PreparedPresig<PresignOutput, KeygenOutput> {
    pub protocols: Vec<(Participant, Box<dyn Protocol<Output = PresignOutput>>)>,
    pub key_packages: Vec<(Participant, KeygenOutput)>,
    pub participants: Vec<Participant>,
    /// Per-participant RNG seed used to build each presign protocol; empty when
    /// the protocol is built from deterministic inputs.
    pub seeds: HashMap<Participant, u64>,
}

pub struct PreparedSig<RerandomizedPresignOutput> {
    pub protocols: Vec<(
        Participant,
        Box<dyn Protocol<Output = ecdsa::SignatureOption>>,
    )>,
    pub index: usize,
    pub presig: RerandomizedPresignOutput,
    pub derived_pk: AffinePoint,
    pub msg_hash: Scalar,
}
