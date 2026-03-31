#![allow(
    dead_code,
    unused_imports,
    clippy::missing_panics_doc,
    clippy::indexing_slicing
)]

#[path = "bench_utils/dkg.rs"]
mod dkg;
#[path = "bench_utils/frost_eddsa.rs"]
mod frost_eddsa;
#[path = "bench_utils/ot_based_ecdsa.rs"]
mod ot_based_ecdsa;
#[path = "bench_utils/robust_ecdsa.rs"]
mod robust_ecdsa;

pub use dkg::*;
pub use frost_eddsa::*;
pub use ot_based_ecdsa::*;
pub use robust_ecdsa::*;

use average::{Estimate, Quantile, Variance};
use k256::AffinePoint;
use std::{env, sync::LazyLock};

use threshold_signatures::{
    ecdsa::{self, Scalar},
    participants::Participant,
    protocol::Protocol,
    test_utils::Simulator,
    ReconstructionLowerBound,
};

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

pub static RECONSTRUCTION_LOWER_BOUND: LazyLock<ReconstructionLowerBound> =
    LazyLock::new(|| ReconstructionLowerBound::from(*MAX_MALICIOUS + 1));

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

#[allow(clippy::cast_precision_loss)]
/// Analyzes the size of the received data by a participant across the entire protocol
pub fn analyze_received_sizes(
    sizes: &[usize],
    is_print: bool,
) -> (usize, usize, f64, f64, f64, f64) {
    if sizes.len() <= 1 {
        return (0, 0, 0.0, 0.0, 0.0, 0.0);
    }
    let min = *sizes.iter().min().expect("Minimum should exist");
    let max = *sizes.iter().max().expect("Maximum should exist");
    let avg = sizes.iter().sum::<usize>() as f64 / sizes.len() as f64;

    let data = sizes.iter().map(|&x| x as f64).collect::<Vec<f64>>();

    // Median (0.5 quantile)
    let mut quantile = Quantile::new(0.5);
    // Variance + Std Dev
    let mut variance_est = Variance::new();

    for &x in &data {
        variance_est.add(x);
        quantile.add(x);
    }

    let median = quantile.quantile();
    let variance = variance_est.sample_variance();
    let std_dev = variance.sqrt();

    if is_print {
        println!("Analysis for received messages:");
        println!(
            "\
            min:{min}B\t\
            max:{max}B\t\
            average:{avg}B\t\
            median:{median}B\t\
            variance:{variance}B\t\
            standard deviation:{std_dev}B
        "
        );
    }

    (min, max, avg, median, variance, std_dev)
}
