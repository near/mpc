//! Gas regression tests for the [`Participants`] struct using sandbox tests.
//!
//! These tests measure actual on-chain gas consumption for contract operations
//! that involve [`Participants`] and assert they stay within expected bounds.
//!
//! Run with:
//! ```sh
//! cargo test -p mpc-contract --features test-utils,bench-utils participants_gas
//! ```
//!
//! [`Participants`]: mpc_contract::primitives::participants::Participants

use crate::sandbox::{
    common::{gen_accounts, init},
    utils::{
        interface::IntoInterfaceType, mpc_contract::submit_participant_info,
        shared_key_utils::new_secp256k1,
    },
};
use contract_interface::types::{Attestation, MockAttestation};
use mpc_contract::{
    crypto_shared::types::PublicKeyExtended,
    primitives::{
        domain::{DomainConfig, DomainId, SignatureScheme},
        key_state::{AttemptId, EpochId, KeyForDomain, Keyset},
        participants::Participants,
        thresholds::{Threshold, ThresholdParameters},
    },
};
use near_sdk::Gas;
use near_workspaces::{Account, Contract};
use serde_json::json;

/// Participant counts to test against
const PARTICIPANT_COUNTS: &[usize] = &[10, 30, 40, 100, 400];

/// Percentage buffer added to measured gas values to account for variability.
/// Gas measurements can fluctuate between runs (observed up to ~20%).
///
/// TODO(#1821): Investigate and reduce gas cost variability.
const GAS_BUFFER_PERCENT: f64 = 25.0;

/// Gas regression thresholds.
struct GasThresholds {
    /// Gas cost for calling [`Participants::len`].
    len: Gas,
    /// Gas cost for calling [`Participants::is_participant`].
    is_participant: Gas,
    /// Gas cost for calling [`Participants::info`].
    info: Gas,
    /// Gas cost for calling [`Participants::validate`].
    validate: Gas,
    /// Gas cost for borsh-serializing [`Participants`].
    serialization: Gas,
    /// Gas cost for calling [`Participants::insert`].
    insert: Gas,
    /// Gas cost for calling [`Participants::update_info`].
    update_info: Gas,
}

impl GasThresholds {
    /// Creates thresholds with buffer applied to all values.
    fn with_buffer(self) -> Self {
        Self {
            len: apply_buffer(self.len),
            is_participant: apply_buffer(self.is_participant),
            info: apply_buffer(self.info),
            validate: apply_buffer(self.validate),
            serialization: apply_buffer(self.serialization),
            insert: apply_buffer(self.insert),
            update_info: apply_buffer(self.update_info),
        }
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
async fn gas_regression_participants_validate() {
    run_gas_regression("bench_participants_validate", |t| t.validate, false).await;
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

#[tokio::test]
async fn gas_regression_participants_insert() {
    run_gas_regression_running("bench_participants_insert", |t| t.insert, false).await;
}

#[tokio::test]
async fn gas_regression_participants_update_info() {
    run_gas_regression_running("bench_participants_update_info", |t| t.update_info, true).await;
}

/// Runs a gas regression test across all participant counts.
async fn run_gas_regression<F>(method: &str, get_threshold: F, use_lookups: bool)
where
    F: Fn(&GasThresholds) -> Gas,
{
    run_gas_regression_with_setup(method, get_threshold, use_lookups, false).await;
}

/// Runs a gas regression test with Running state (for mutation operations).
async fn run_gas_regression_running<F>(method: &str, get_threshold: F, use_lookups: bool)
where
    F: Fn(&GasThresholds) -> Gas,
{
    for &n in PARTICIPANT_COUNTS {
        println!("\n  Testing with {} participants...", n);
        let env = setup_test_env_running(n).await;
        let threshold = get_threshold(&get_thresholds(n));
        if use_lookups {
            run_bench_lookups(&env, method, threshold).await;
        } else {
            run_bench(&env, method, None, threshold).await;
        }
    }
}

async fn run_gas_regression_with_setup<F>(
    method: &str,
    get_threshold: F,
    use_lookups: bool,
    running_state: bool,
) where
    F: Fn(&GasThresholds) -> Gas,
{
    for &n in PARTICIPANT_COUNTS {
        println!("\n  Testing with {} participants...", n);
        let env = if running_state {
            setup_test_env_running(n).await
        } else {
            setup_test_env(n).await
        };
        let threshold = get_threshold(&get_thresholds(n));
        if use_lookups {
            run_bench_lookups(&env, method, threshold).await;
        } else {
            run_bench(&env, method, None, threshold).await;
        }
    }
}

/// Returns gas thresholds for the given participant count (with buffer applied).
///
/// Base values are measured from actual test runs (in GGas, rounded up to nearest integer).
/// For lookups (is_participant, info, update_info), we use the worst-case (last element).
///
/// To update thresholds: run tests, observe actual gas usage, round up, and update values below.
/// The 25% buffer is applied automatically via `with_buffer()`.
fn get_thresholds(n: usize) -> GasThresholds {
    let base = match n {
        10 => GasThresholds {
            len: Gas::from_ggas(3052),
            is_participant: Gas::from_ggas(3074),
            info: Gas::from_ggas(3074),
            validate: Gas::from_ggas(3083),
            serialization: Gas::from_ggas(3067),
            insert: Gas::from_ggas(3477),
            update_info: Gas::from_ggas(3495),
        },
        30 => GasThresholds {
            len: Gas::from_ggas(3445),
            is_participant: Gas::from_ggas(3475),
            info: Gas::from_ggas(3475),
            validate: Gas::from_ggas(3576),
            serialization: Gas::from_ggas(3500),
            insert: Gas::from_ggas(4356),
            update_info: Gas::from_ggas(4384),
        },
        40 => GasThresholds {
            len: Gas::from_ggas(3659),
            is_participant: Gas::from_ggas(3475),
            info: Gas::from_ggas(3475),
            validate: Gas::from_ggas(3858),
            serialization: Gas::from_ggas(3728),
            insert: Gas::from_ggas(4793),
            update_info: Gas::from_ggas(4384),
        },
        100 => GasThresholds {
            len: Gas::from_ggas(4865),
            is_participant: Gas::from_ggas(4924),
            info: Gas::from_ggas(4924),
            validate: Gas::from_ggas(5444),
            serialization: Gas::from_ggas(5060),
            insert: Gas::from_ggas(7386),
            update_info: Gas::from_ggas(7448),
        },
        400 => GasThresholds {
            len: Gas::from_ggas(10898),
            is_participant: Gas::from_ggas(11078),
            info: Gas::from_ggas(11078),
            validate: Gas::from_ggas(13701),
            serialization: Gas::from_ggas(11676),
            insert: Gas::from_ggas(20449),
            update_info: Gas::from_ggas(20612),
        },
        _ => panic!("No gas thresholds defined for n={}", n),
    };
    base.with_buffer()
}

/// Applies buffer percentage to a gas value.
fn apply_buffer(base: Gas) -> Gas {
    let buffered = (base.as_gas() as f64 * (1.0 + GAS_BUFFER_PERCENT / 100.0)).ceil() as u64;
    Gas::from_gas(buffered)
}

/// Run a benchmark contract method and assert gas is within threshold.
async fn run_bench(env: &TestEnv, method: &str, args: Option<serde_json::Value>, max_gas: Gas) {
    let mut call = env.accounts[0].call(env.contract.id(), method);
    if let Some(a) = args {
        call = call.args_json(a);
    }
    let result = call.max_gas().transact().await.unwrap();
    assert!(
        result.is_success(),
        "Contract call to '{}' failed. Method may not exist. \
         Ensure contract was built with --features=bench-utils. \
         Failures: {:?}",
        method,
        result.failures()
    );
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
        assert!(
            result.is_success(),
            "Contract call to '{}' with account '{}' failed. Method may not exist. \
             Ensure contract was built with --features=bench-utils. \
             Failures: {:?}",
            method,
            account_id,
            result.failures()
        );
        let gas_burnt = Gas::from_gas(result.total_gas_burnt.as_gas());
        assert_gas_within_threshold(&format!("{}[{}]", method, label), gas_burnt, max_gas);
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

async fn setup_test_env(n_participants: usize) -> TestEnv {
    setup_test_env_with_state(n_participants, false).await
}

/// Setup for tests that need Running state (mutation operations).
async fn setup_test_env_running(n_participants: usize) -> TestEnv {
    setup_test_env_with_state(n_participants, true).await
}

async fn setup_test_env_with_state(n_participants: usize, running_state: bool) -> TestEnv {
    let (worker, contract) = init().await;
    let (accounts, participants) = gen_accounts(&worker, n_participants).await;

    let threshold_params = make_threshold_params(&participants);
    if running_state {
        init_contract_running(&contract, threshold_params).await;
    } else {
        init_contract(&contract, threshold_params).await;
    }
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

/// Initialize contract in Running state (required for mutation benchmarks).
async fn init_contract_running(contract: &Contract, params: ThresholdParameters) {
    // Create a dummy domain and keyset for running state
    let domain_id = DomainId(0);
    let domain = DomainConfig {
        id: domain_id,
        scheme: SignatureScheme::Secp256k1,
    };

    // Create a valid secp256k1 public key using test utilities
    let (dto_pk, _) = new_secp256k1();
    let public_key: PublicKeyExtended = dto_pk.try_into().unwrap();

    let key = KeyForDomain {
        attempt: AttemptId::new(),
        domain_id,
        key: public_key,
    };
    let keyset = Keyset::new(EpochId::new(1), vec![key]);

    let result = contract
        .call("init_running")
        .args_json(json!({
            "domains": vec![domain],
            "next_domain_id": 2u64,
            "keyset": keyset,
            "parameters": params,
        }))
        .gas(Gas::from_tgas(300))
        .transact()
        .await
        .unwrap();
    assert!(result.is_success(), "init_running failed: {:?}", result);
}

async fn submit_attestations(
    contract: &Contract,
    accounts: &[Account],
    participants: &Participants,
) {
    // Submit attestations sequentially to avoid nonce conflicts when testing
    // with large participant counts (100+). Parallel submission with join_all
    // causes `InvalidNonce` errors due to race conditions in nonce management.
    for (i, ((_, _, participant), account)) in
        participants.participants().iter().zip(accounts).enumerate()
    {
        let attestation = Attestation::Mock(MockAttestation::Valid);
        let tls_key = (&participant.sign_pk).into_interface_type();
        let success = submit_participant_info(account, contract, &attestation, &tls_key)
            .await
            .expect("submit_participant_info should not error");
        assert!(
            success,
            "submit_participant_info failed for participant {}",
            i
        );
    }
}
