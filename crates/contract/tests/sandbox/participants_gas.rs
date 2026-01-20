//! Gas regression tests for the [`Participants`] struct using sandbox tests.
//!
//! These tests measure actual on-chain gas consumption for contract operations
//! that involve [`Participants`] and assert they stay within expected bounds.
//!
//! Run with: `cargo test -p mpc-contract --features test-utils participants_gas -- --nocapture`
//!
//! [`Participants`]: mpc_contract::primitives::participants::Participants

use crate::sandbox::{
    common::{gen_accounts, init},
    utils::interface::IntoInterfaceType,
};
use contract_interface::types::{Attestation, MockAttestation};
use futures::future::join_all;
use mpc_contract::primitives::{
    participants::Participants,
    thresholds::{Threshold, ThresholdParameters},
};
use near_sdk::Gas;
use near_workspaces::{Account, Contract};
use serde_json::json;

/// Participant counts to test against
const PARTICIPANT_COUNTS: &[usize] = &[10, 30, 40];

/// Gas regression thresholds (in GGas).
///
/// Thresholds are minimal values that pass tests.
/// Update after running `cargo test -p mpc-contract --features test-utils measure_gas_baselines -- --nocapture`
///
/// Format: (n_participants, ggas_for_operation).
struct GasThresholds {
    /// Gas cost for calling [`Participants::len`].
    len: Gas,
    /// Gas cost for calling [`Participants::is_participant`].
    is_participant: Gas,
    /// Gas cost for calling [`Participants::info`].
    info: Gas,
    /// Gas cost for calling [`Participants::id`].
    id: Gas,
    /// Gas cost for calling [`Participants::validate`].
    validate: Gas,
    /// Gas cost for iterating over [`Participants::participants`] with `.iter().count()`.
    iter_count: Gas,
    /// Gas cost for collecting all account IDs from [`Participants::participants`].
    get_all_accounts: Gas,
    /// Gas cost for borsh-serializing [`Participants`].
    serialization: Gas,
}

fn get_thresholds(n: usize) -> GasThresholds {
    // Per-count thresholds based on measured values
    match n {
        10 => GasThresholds {
            len: Gas::from_ggas(3047),
            is_participant: Gas::from_ggas(3069),
            info: Gas::from_ggas(3069),
            id: Gas::from_ggas(1424),
            validate: Gas::from_ggas(3079),
            iter_count: Gas::from_ggas(1421),
            get_all_accounts: Gas::from_ggas(1421),
            serialization: Gas::from_ggas(3063),
        },
        30 => GasThresholds {
            len: Gas::from_ggas(3440),
            is_participant: Gas::from_ggas(3471),
            info: Gas::from_ggas(3471),
            id: Gas::from_ggas(1424),
            validate: Gas::from_ggas(3578),
            iter_count: Gas::from_ggas(1421),
            get_all_accounts: Gas::from_ggas(1421),
            serialization: Gas::from_ggas(3498),
        },
        40 => GasThresholds {
            len: Gas::from_ggas(3655),
            is_participant: Gas::from_ggas(3689),
            info: Gas::from_ggas(3689),
            id: Gas::from_ggas(1424),
            validate: Gas::from_ggas(3832),
            iter_count: Gas::from_ggas(1421),
            get_all_accounts: Gas::from_ggas(1421),
            serialization: Gas::from_ggas(3727),
        },
        _ => panic!("No thresholds defined for n={}", n),
    }
}

/// Test environment for a specific participant count.
struct TestEnv {
    contract: Contract,
    accounts: Vec<Account>,
    n_participants: usize,
}

impl TestEnv {
    fn first_account(&self) -> String {
        self.accounts[0].id().to_string()
    }

    fn middle_account(&self) -> String {
        self.accounts[self.n_participants / 2].id().to_string()
    }

    fn last_account(&self) -> String {
        self.accounts[self.n_participants - 1].id().to_string()
    }
}

async fn setup_test_env(n_participants: usize) -> TestEnv {
    let (worker, contract) = init().await;
    let (accounts, participants) = gen_accounts(&worker, n_participants).await;

    let threshold_params = make_threshold_params(&participants);
    init_contract(&contract, threshold_params).await;
    submit_attestations(&contract, &accounts, &participants).await;

    TestEnv {
        contract,
        accounts,
        n_participants,
    }
}

fn make_threshold_params(participants: &Participants) -> ThresholdParameters {
    let threshold = Threshold::new(((participants.len() as f64) * 0.6).ceil() as u64);
    ThresholdParameters::new(participants.clone(), threshold).unwrap()
}

async fn init_contract(contract: &Contract, params: ThresholdParameters) {
    let result = contract
        .call("init")
        .args_json(json!({ "parameters": params }))
        .gas(Gas::from_tgas(300))
        .transact()
        .await
        .unwrap();
    assert!(result.is_success(), "init failed: {:?}", result);
}

async fn submit_attestations(
    contract: &Contract,
    accounts: &[Account],
    participants: &Participants,
) {
    let futures: Vec<_> = participants
        .participants()
        .iter()
        .zip(accounts)
        .map(|((_, _, participant), account)| {
            let attestation = Attestation::Mock(MockAttestation::Valid);
            let tls_key = (&participant.sign_pk).into_interface_type();
            account
                .call(contract.id(), "submit_participant_info")
                .args_json((attestation, tls_key))
                .max_gas()
                .transact()
        })
        .collect();

    let results = join_all(futures).await;
    for (i, result) in results.into_iter().enumerate() {
        assert!(
            result.unwrap().is_success(),
            "submit_participant_info failed for participant {}",
            i
        );
    }
}

fn assert_gas_within_threshold(operation: &str, gas_burnt: Gas, max_gas: Gas) {
    let gas_ggas = gas_burnt.as_gas() as f64 / 1_000_000_000.0;
    let max_ggas = max_gas.as_gas() as f64 / 1_000_000_000.0;
    assert!(
        gas_burnt <= max_gas,
        "GAS REGRESSION: {} used {:.2} GGas but threshold is {:.2} GGas ({:.1}% over)",
        operation,
        gas_ggas,
        max_ggas,
        (gas_ggas / max_ggas - 1.0) * 100.0
    );
    println!(
        "  ✓ {}: {:.2} GGas (limit: {:.2} GGas)",
        operation, gas_ggas, max_ggas
    );
}

/// Run a benchmark contract method and assert gas is within threshold.
async fn run_bench(env: &TestEnv, method: &str, args: Option<serde_json::Value>, max_gas: Gas) {
    let mut call = env.accounts[0].call(env.contract.id(), method);
    if let Some(a) = args {
        call = call.args_json(a);
    }
    let result = call.max_gas().transact().await.unwrap();
    let gas_burnt = Gas::from_gas(result.total_gas_burnt.as_gas());
    assert_gas_within_threshold(method, gas_burnt, max_gas);
}

/// Run a benchmark for account lookups (first, middle, last, missing).
async fn run_bench_lookups(env: &TestEnv, method: &str, max_gas: Gas) {
    let first = env.first_account();
    let middle = env.middle_account();
    let last = env.last_account();
    let missing = "missing.account.near".to_string();

    for (label, account_id) in [
        ("first", first),
        ("middle", middle),
        ("last", last),
        ("missing", missing),
    ] {
        let result = env.accounts[0]
            .call(env.contract.id(), method)
            .args_json(json!({ "account_id": account_id }))
            .max_gas()
            .transact()
            .await
            .unwrap();
        let gas_burnt = Gas::from_gas(result.total_gas_burnt.as_gas());
        assert_gas_within_threshold(&format!("{}[{}]", method, label), gas_burnt, max_gas);
    }
}

/// Runs a gas regression test across all participant counts.
async fn run_gas_regression<F>(method: &str, get_threshold: F, use_lookups: bool)
where
    F: Fn(&GasThresholds) -> Gas,
{
    for &n in PARTICIPANT_COUNTS {
        println!("\n  Testing with {} participants...", n);
        let env = setup_test_env(n).await;
        let threshold = get_threshold(&get_thresholds(n));
        if use_lookups {
            run_bench_lookups(&env, method, threshold).await;
        } else {
            run_bench(&env, method, None, threshold).await;
        }
    }
}

#[tokio::test]
async fn gas_regression_participants_len() {
    run_gas_regression("bench_participants_len", |t| t.len, false).await;
}

#[tokio::test]
async fn gas_regression_is_participant() {
    run_gas_regression("bench_is_participant", |t| t.is_participant, true).await;
}

#[tokio::test]
async fn gas_regression_participant_info() {
    run_gas_regression("bench_participant_info", |t| t.info, true).await;
}

#[tokio::test]
async fn gas_regression_participant_id() {
    run_gas_regression("bench_participant_id", |t| t.id, true).await;
}

#[tokio::test]
async fn gas_regression_participants_validate() {
    run_gas_regression("bench_participants_validate", |t| t.validate, false).await;
}

#[tokio::test]
async fn gas_regression_participants_iter_count() {
    run_gas_regression("bench_participants_iter_count", |t| t.iter_count, false).await;
}

#[tokio::test]
async fn gas_regression_get_all_participant_accounts() {
    run_gas_regression(
        "bench_get_all_participant_accounts",
        |t| t.get_all_accounts,
        false,
    )
    .await;
}

#[tokio::test]
async fn gas_regression_participants_serialization() {
    run_gas_regression(
        "bench_participants_serialization_size",
        |t| t.serialization,
        false,
    )
    .await;
}
