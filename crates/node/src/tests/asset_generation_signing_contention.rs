//! Reproduction for issue #1175 — "asset generation impacts signing performance".
//!
//! Background asset generation (triples + presignatures) and signing both run on
//! the same `cores`-limited per-epoch MPC runtime (see
//! [`crate::coordinator::Coordinator`]'s `create_runtime_and_run`) with no priority
//! separation between them. The cait-sith poke loop in
//! [`crate::protocol::run_protocol`] is CPU-bound and does not yield between
//! network rounds, and the follower/passive side of generation
//! ([`crate::mpc_client`]'s `monitor_passive_channels_inner`) is unbounded. After a
//! resharing every node's triple/presignature stores are empty at once, so the
//! whole network refills simultaneously and each node is flooded with generation
//! work — which starves signing.
//!
//! This test reproduces that locally *without* nearcore, isolating the MPC-runtime
//! contention from the "nearcore lags" theory. It runs a 4-node in-process cluster
//! and compares signing latency in two states:
//!   - steady state — a small desired triple buffer that fills with a single batch
//!     and then idles;
//!   - post-resharing — the mainnet desired triple buffer (2^14), which starts
//!     empty and so triple generation runs flat out.
//!
//! Two knobs are not literal mainnet values, both because this in-process cluster
//! has near-instant networking (see `CORES_PER_NODE` and the `*_TRIPLE_CONCURRENCY`
//! constants): mainnet reaches CPU saturation because real cross-node latency
//! keeps many generations in flight at once, whereas here protocols finish too
//! fast to pile up that way. To recreate the same saturation cheaply we (a) give
//! MPC a single core, and (b) drive triple generation harder in the post-resharing
//! scenario (higher concurrency, no stagger) while leaving the steady scenario
//! with a gentle top-off concurrency. The buffer *size* that defines
//! "post-resharing" is the real mainnet 2^14.
//!
//! It is timing-sensitive, so it is `#[ignore]`d and excluded from CI. Run it
//! manually and read the printed report. `RUST_LOG=off` silences all `tracing`
//! output so the `[#1175]` summary lines aren't buried; the report goes through
//! `println!`, not tracing, so this only mutes the noise. Drop `RUST_LOG=off` if
//! you need the logs to diagnose a failure.
//! ```text
//! RUST_LOG=off cargo nextest run --cargo-profile=test-release -p mpc-node \
//!     signing_latency__should_degrade_under_concurrent_asset_generation \
//!     --run-ignored all --no-capture
//! ```
//! A handful of `panicked at crates/node/src/indexer/fake.rs … Result::unwrap()
//! on an Err value: Closed` lines may also appear on stderr at the end — these
//! are a pre-existing teardown race in the fake indexer's channels (the cluster
//! drops while background tasks are still using them) and don't affect the
//! result. The `[#1175]` summary still sits near the top of the test output.

use crate::indexer::participants::ContractState;
use crate::p2p::testing::PortSeed;
use crate::tests::{
    DEFAULT_BLOCK_TIME, DEFAULT_MAX_PROTOCOL_WAIT_TIME, IntegrationTestSetup,
    request_signature_and_await_response,
};
use crate::tracking::AutoAbortTask;
use average::{Estimate, Max, Mean, Quantile};
use mpc_node_config::{PresignatureConfig, TripleConfig};
use mpc_primitives::domain::DomainId;
use near_mpc_contract_interface::types::{
    DomainConfig, DomainPurpose, Protocol, ReconstructionThreshold,
};
use near_time::Clock;
use std::time::Duration;

const NUM_PARTICIPANTS: usize = 4;
const THRESHOLD: usize = 3;
const TXN_DELAY_BLOCKS: u64 = 1;

// The only knob that differs between the two scenarios is the desired triple
// buffer: the post-resharing run targets the mainnet size (2^14) and so generates
// continuously, while the steady run targets a tiny buffer that fills in a couple
// of batches and then leaves triple generation idle. Everything else is identical.
const CORES_PER_NODE: usize = 1;
/// Mainnet triple buffer (2^14): empty after a resharing, so a node refills toward
/// it continuously — the post-resharing state.
const REFILL_TRIPLES_TO_BUFFER: usize = 16_384;
/// Small enough to fill in a couple of batches and then idle — steady state, where
/// the buffer is already full.
const STEADY_TRIPLES_TO_BUFFER: usize = 128;
/// Triple generation is the heavy CPU op, so it is what we drive to recreate the
/// refill load. On mainnet (concurrency 2, 1s stagger) saturation builds because
/// real cross-node latency keeps many generations in flight at once; this
/// in-process cluster has near-instant networking, so to reach the same CPU
/// pressure within seconds we drop the stagger and raise concurrency in the
/// post-resharing scenario.
const REFILL_TRIPLE_CONCURRENCY: usize = 6;
/// Steady state only needs to top off as signing consumes presignatures — using
/// the post-resharing concurrency here would let the initial buffer fill spawn 6
/// concurrent CPU-heavy batches on the single MPC core, overshooting the small
/// target and producing a multi-second latency tail on early measured signatures.
/// One batch at a time is enough to refill the small steady buffer.
const STEADY_TRIPLE_CONCURRENCY: usize = 1;
const TRIPLE_STAGGER_SEC: u64 = 0;
/// Presignatures are buffered modestly and identically in both scenarios, so they
/// stay available for signing without themselves being the variable under test.
const PRESIGNATURE_CONCURRENCY: usize = 2;
const PRESIGNATURES_TO_BUFFER: usize = 64;

const WARMUP_SIGNATURES: usize = 2;
const MEASURED_SIGNATURES: usize = 8;
/// Generous relative to the observed steady-state tail so a loaded host doesn't
/// produce spurious timeouts in the steady-state scenario; the post-resharing
/// scenario blows past it regardless.
const PER_SIGNATURE_TIMEOUT: Duration = Duration::from_secs(15);

/// Summary statistics over a batch of signing attempts. Latency stats are computed
/// with the `average` crate (as in the threshold-signatures benches); timeouts are
/// counted separately since they have no finite latency.
struct LatencyReport {
    label: &'static str,
    n_ok: usize,
    timeouts: usize,
    mean: Duration,
    p50: Duration,
    p90: Duration,
    max: Duration,
}

impl LatencyReport {
    fn from_attempts(label: &'static str, attempts: &[Option<Duration>]) -> Self {
        let timeouts = attempts.iter().filter(|a| a.is_none()).count();
        let latencies: Vec<f64> = attempts
            .iter()
            .filter_map(|a| a.map(|d| d.as_secs_f64()))
            .collect();
        let n_ok = latencies.len();

        // Every request timed out: report the timeout bound as a sentinel so the
        // printed report and the comparison still reflect the degradation.
        if latencies.is_empty() {
            return Self {
                label,
                n_ok,
                timeouts,
                mean: PER_SIGNATURE_TIMEOUT,
                p50: PER_SIGNATURE_TIMEOUT,
                p90: PER_SIGNATURE_TIMEOUT,
                max: PER_SIGNATURE_TIMEOUT,
            };
        }

        let mut mean = Mean::new();
        let mut p50 = Quantile::new(0.5);
        let mut p90 = Quantile::new(0.9);
        let mut max = Max::new();
        for &seconds in &latencies {
            mean.add(seconds);
            p50.add(seconds);
            p90.add(seconds);
            max.add(seconds);
        }
        Self {
            label,
            n_ok,
            timeouts,
            mean: Duration::from_secs_f64(mean.mean()),
            p50: Duration::from_secs_f64(p50.quantile()),
            p90: Duration::from_secs_f64(p90.quantile()),
            max: Duration::from_secs_f64(max.max()),
        }
    }

    fn print(&self) {
        println!(
            "[#1175] {:<13} signing latency: n_ok={} timeouts={} \
             mean={:?} p50={:?} p90={:?} max={:?}",
            self.label, self.n_ok, self.timeouts, self.mean, self.p50, self.p90, self.max,
        );
    }
}

/// Brings up a 4-node cluster, completes keygen, then measures end-to-end signing
/// latency. When `buffers_empty` is true the nodes use the mainnet desired buffers
/// (so generation runs flat out — the post-resharing state); otherwise they use
/// small buffers that fill and idle (steady state).
async fn measure_signing_latency(buffers_empty: bool, case: u16) -> LatencyReport {
    let label = if buffers_empty {
        "post-resharing"
    } else {
        "steady-state"
    };
    let temp_dir = tempfile::tempdir().unwrap();
    let mut setup = IntegrationTestSetup::new(
        Clock::real(),
        temp_dir.path(),
        (0..NUM_PARTICIPANTS)
            .map(|i| format!("test{i}").parse().unwrap())
            .collect(),
        THRESHOLD,
        TXN_DELAY_BLOCKS,
        PortSeed::ASSET_GENERATION_SIGNING_CONTENTION_TEST.with_case(case),
        DEFAULT_BLOCK_TIME,
    );

    let ecdsa_domain = DomainConfig {
        id: DomainId(0),
        protocol: Protocol::CaitSith,
        reconstruction_threshold: ReconstructionThreshold::new(THRESHOLD as u64),
        purpose: DomainPurpose::Sign,
    };

    // Same config everywhere except triple generation: the desired buffer differs
    // (empty-and-refilling vs. already-full), and concurrency matches the load the
    // scenario is meant to model — aggressive refill vs. gentle top-off.
    for node in &mut setup.configs {
        node.config.cores = Some(CORES_PER_NODE);
        node.config.triple = TripleConfig {
            concurrency: if buffers_empty {
                REFILL_TRIPLE_CONCURRENCY
            } else {
                STEADY_TRIPLE_CONCURRENCY
            },
            desired_triples_to_buffer: if buffers_empty {
                REFILL_TRIPLES_TO_BUFFER
            } else {
                STEADY_TRIPLES_TO_BUFFER
            },
            parallel_triple_generation_stagger_time_sec: TRIPLE_STAGGER_SEC,
            timeout_sec: 60,
        };
        node.config.presignature = PresignatureConfig {
            concurrency: PRESIGNATURE_CONCURRENCY,
            desired_presignatures_to_buffer: PRESIGNATURES_TO_BUFFER,
            timeout_sec: 60,
        };
    }

    {
        let mut contract = setup.indexer.contract_mut().await;
        contract.initialize(setup.participants.clone());
        contract.add_domains(vec![ecdsa_domain.clone()]);
    }

    let _runs = setup
        .configs
        .into_iter()
        .map(|config| AutoAbortTask::from(tokio::spawn(config.run())))
        .collect::<Vec<_>>();

    setup
        .indexer
        .wait_for_contract_state(
            |state| matches!(state, ContractState::Running(_)),
            DEFAULT_MAX_PROTOCOL_WAIT_TIME,
        )
        .await
        .expect("timeout waiting for keygen to complete");

    // Warm up so presignatures are flowing before we start measuring. (User names
    // must be valid NEAR account IDs: lowercase alphanumeric.)
    for i in 0..WARMUP_SIGNATURES {
        let _ = request_signature_and_await_response(
            &mut setup.indexer,
            &format!("warmup{i}"),
            &ecdsa_domain,
            PER_SIGNATURE_TIMEOUT,
        )
        .await;
    }

    let mut attempts = Vec::with_capacity(MEASURED_SIGNATURES);
    for i in 0..MEASURED_SIGNATURES {
        let latency = request_signature_and_await_response(
            &mut setup.indexer,
            &format!("user{i}"),
            &ecdsa_domain,
            PER_SIGNATURE_TIMEOUT,
        )
        .await;
        attempts.push(latency);
    }

    LatencyReport::from_attempts(label, &attempts)
}

#[test_log::test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
#[ignore = "timing-sensitive reproduction for #1175; run manually with --run-ignored"]
#[expect(non_snake_case)]
async fn signing_latency__should_degrade_under_concurrent_asset_generation() {
    // Given a 4-node cluster signing in steady state (asset buffers already full),
    let steady = measure_signing_latency(false, 0).await;

    // When the same cluster signs just after a resharing (buffers empty, so every
    // node refills toward the mainnet target while signing),
    let post_resharing = measure_signing_latency(true, 1).await;

    steady.print();
    post_resharing.print();

    // Then signing latency degrades sharply during the refill: either signing
    // requests start timing out, or the median latency inflates well beyond the
    // steady-state baseline. (The steady-state baseline itself must stay healthy.)
    assert_eq!(
        steady.timeouts, 0,
        "steady-state baseline should not time out; harness is unhealthy"
    );
    assert!(
        post_resharing.timeouts > 0 || post_resharing.p50 >= steady.p50 * 2,
        "expected post-resharing refill to degrade signing: \
         steady p50 {:?}, post-resharing p50 {:?}, post-resharing timeouts {}",
        steady.p50,
        post_resharing.p50,
        post_resharing.timeouts,
    );
}
