//! Wall-clock benchmarks for the [`Participants`] struct.
//!
//! These benchmarks measure the performance of participant-related operations
//! (lookups, iteration, validation) at various participant counts to guide
//! future optimization decisions.
//!
//! Run with: `cargo bench -p mpc-contract --features test-utils --bench participants_bench`

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use mpc_contract::primitives::{
    participants::{ParticipantInfo, Participants},
    test_utils::{bogus_ed25519_near_public_key, gen_account_id, gen_participants},
};
use near_account_id::AccountId;

/// Participant counts to benchmark.
///
/// These are pure Rust benchmarks with no blockchain/sandbox overhead,
/// allowing us to test at scale to understand scaling behavior
const PARTICIPANT_COUNTS: &[usize] = &[100_000, 1_000_000, 10_000_000];

/// Generate a non-existent account ID for worst-case lookup testing.
fn gen_nonexistent_account() -> AccountId {
    "nonexistent.testnet".parse().unwrap()
}

/// Test data for benchmarking participant lookups.
struct LookupTestData {
    /// The participant set to benchmark against.
    participants: Participants,
    /// First participant in the list (best-case for linear scan).
    first: AccountId,
    /// Middle participant in the list (average-case for linear scan).
    middle: AccountId,
    /// Last participant in the list (worst-case for linear scan).
    last: AccountId,
    /// Non-existent account (worst-case: full scan with no match).
    missing: AccountId,
}

impl LookupTestData {
    fn new(n: usize) -> Self {
        let participants = gen_participants(n);
        let accounts: Vec<_> = participants
            .participants()
            .iter()
            .map(|(a, _, _)| a.clone())
            .collect();
        Self {
            participants,
            first: accounts[0].clone(),
            middle: accounts[n / 2].clone(),
            last: accounts[n - 1].clone(),
            missing: gen_nonexistent_account(),
        }
    }
}

/// Benchmark a lookup operation with first/middle/last/missing variants.
fn bench_lookup<F>(c: &mut Criterion, group_name: &str, lookup_fn: F)
where
    F: Fn(&Participants, &AccountId) + Copy,
{
    let mut group = c.benchmark_group(group_name);

    for &n in PARTICIPANT_COUNTS {
        group.throughput(Throughput::Elements(1));
        let data = LookupTestData::new(n);

        for (label, account) in [
            ("first", &data.first),
            ("middle", &data.middle),
            ("last", &data.last),
            ("missing", &data.missing),
        ] {
            group.bench_with_input(BenchmarkId::new(label, n), &n, |b, _| {
                b.iter(|| {
                    lookup_fn(
                        std::hint::black_box(&data.participants),
                        std::hint::black_box(account),
                    )
                })
            });
        }
    }

    group.finish();
}

/// Benchmark `is_participant()` method - checks if an account is a participant.
fn bench_is_participant(c: &mut Criterion) {
    bench_lookup(c, "is_participant", |p, a| {
        std::hint::black_box(p.is_participant(a));
    });
}

/// Benchmark `info()` method - retrieves ParticipantInfo for an account.
fn bench_info(c: &mut Criterion) {
    bench_lookup(c, "info", |p, a| {
        std::hint::black_box(p.info(a));
    });
}

/// Benchmark `validate()` method - validates coherence of participant fields.
fn bench_validate(c: &mut Criterion) {
    let mut group = c.benchmark_group("validate");

    for &n in PARTICIPANT_COUNTS {
        group.throughput(Throughput::Elements(n as u64));
        let participants = gen_participants(n);

        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| std::hint::black_box(participants.validate()))
        });
    }

    group.finish();
}

/// Benchmark `insert()` method - adds a new participant.
fn bench_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("insert");

    for &n in PARTICIPANT_COUNTS {
        group.throughput(Throughput::Elements(1));

        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter_batched(
                || {
                    (
                        gen_participants(n.saturating_sub(1)),
                        gen_account_id(),
                        ParticipantInfo {
                            url: "https://new.participant.com".to_string(),
                            sign_pk: bogus_ed25519_near_public_key(),
                        },
                    )
                },
                |(mut participants, account, info)| {
                    std::hint::black_box(
                        participants
                            .insert(std::hint::black_box(account), std::hint::black_box(info)),
                    )
                },
                criterion::BatchSize::SmallInput,
            )
        });
    }

    group.finish();
}

/// Benchmark Borsh serialization/deserialization.
fn bench_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("serialization");

    for &n in PARTICIPANT_COUNTS {
        let participants = gen_participants(n);
        let serialized = borsh::to_vec(&participants).unwrap();

        group.throughput(Throughput::Bytes(serialized.len() as u64));

        group.bench_with_input(BenchmarkId::new("serialize", n), &n, |b, _| {
            b.iter(|| {
                std::hint::black_box(borsh::to_vec(std::hint::black_box(&participants)).unwrap())
            })
        });

        group.bench_with_input(BenchmarkId::new("deserialize", n), &n, |b, _| {
            b.iter(|| {
                std::hint::black_box(
                    borsh::from_slice::<Participants>(std::hint::black_box(&serialized)).unwrap(),
                )
            })
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_is_participant,
    bench_info,
    bench_validate,
    bench_insert,
    bench_serialization,
);

criterion_main!(benches);
