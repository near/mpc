//! Gas regression tests for the [`Participants`] struct using sandbox tests.
//!
//! These tests measure actual on-chain gas consumption for contract operations
//! that involve [`Participants`] and assert they stay within expected bounds.
//!
//! Run with:
//! ```sh
//! cargo test -p mpc-contract participants_gas
//! ```
//!
//! [`Participants`]: mpc_contract::primitives::participants::Participants

use crate::sandbox::{
    common::{
        gen_accounts, init_contract, init_contract_running, make_threshold_params,
        submit_attestations,
    },
    utils::{contract_build::current_contract_with_bench_methods, shared_key_utils::new_secp256k1},
};
use mpc_contract::{
    crypto_shared::types::PublicKeyExtended,
    primitives::{
        domain::{DomainConfig, DomainId, SignatureScheme},
        key_state::{AttemptId, EpochId, KeyForDomain, Keyset},
    },
};
use near_sdk::Gas;
use near_workspaces::{Account, Contract};
use rstest::rstest;
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeMap;

/// Path to gas thresholds configuration file.
const GAS_THRESHOLDS_FILE: &str = "gas_thresholds.json";

/// Gas thresholds configuration loaded from [`GAS_THRESHOLDS_FILE`].
#[derive(Debug, Deserialize)]
struct GasThresholdsConfig {
    /// Percentage added to thresholds to account for gas fluctuations.
    /// TODO(#1821): Investigate and reduce gas cost variability.
    buffer_percent: f64,
    /// Gas thresholds keyed by participant count.
    thresholds: BTreeMap<usize, GasThresholds>,
}

/// Gas threshold values for [`Participants`] operations.
/// Note: JSON stores values in GGas, converted to Gas on load.
#[derive(Debug, Deserialize)]
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

impl GasThresholdsConfig {
    fn load() -> Self {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/sandbox")
            .join(GAS_THRESHOLDS_FILE);
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
    }

    fn participant_counts(&self) -> Vec<usize> {
        self.thresholds.keys().copied().collect()
    }

    fn get(&self, n: usize) -> GasThresholds {
        let t = self.thresholds.get(&n).unwrap();
        GasThresholds {
            len: self.apply_buffer(t.len),
            is_participant: self.apply_buffer(t.is_participant),
            info: self.apply_buffer(t.info),
            validate: self.apply_buffer(t.validate),
            serialization: self.apply_buffer(t.serialization),
            insert: self.apply_buffer(t.insert),
            update_info: self.apply_buffer(t.update_info),
        }
    }

    fn apply_buffer(&self, ggas_from_json: Gas) -> Gas {
        let ggas = ggas_from_json.as_gas(); // JSON value is in GGas, parsed as raw gas
        let buffered = (ggas as f64 * (1.0 + self.buffer_percent / 100.0)).ceil() as u64;
        const GGAS: u64 = 1_000_000_000;
        Gas::from_gas(buffered * GGAS)
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

/// Gas regression test cases parametrized by method.
///
/// Each case tests a specific [`Participants`](mpc_contract::primitives::participants::Participants)
/// operation across all participant counts defined in [`GAS_THRESHOLDS_FILE`],
/// asserting gas consumption stays within thresholds.
#[rstest]
#[case::len("bench_participants_len", |t: &GasThresholds| t.len, false, false)]
#[case::is_participant("bench_is_participant", |t: &GasThresholds| t.is_participant, true, false)]
#[case::info("bench_participant_info", |t: &GasThresholds| t.info, true, false)]
#[case::validate("bench_participants_validate", |t: &GasThresholds| t.validate, false, false)]
#[case::serialization("bench_participants_serialization_size", |t: &GasThresholds| t.serialization, false, false)]
#[case::insert("bench_participants_insert", |t: &GasThresholds| t.insert, false, true)]
#[case::update_info("bench_participants_update_info", |t: &GasThresholds| t.update_info, true, true)]
#[tokio::test]
async fn gas_regression(
    #[case] method: &str,
    #[case] get_threshold: fn(&GasThresholds) -> Gas,
    #[case] use_lookups: bool,
    #[case] running_state: bool,
) {
    run_gas_regression(method, get_threshold, use_lookups, running_state).await;
}

/// Runs a gas regression test across all participant counts defined in the config.
///
/// For each participant count (as defined in [`GAS_THRESHOLDS_FILE`]), this function:
/// 1. Sets up a test environment with that many participants
/// 2. Calls the specified benchmark method on the contract
/// 3. Asserts that gas consumption stays within the configured threshold
///
/// The `use_lookups` flag runs the benchmark against first/middle/last/missing accounts
/// to test lookup performance at different positions. The `running_state` flag determines
/// whether the contract is initialized in [`Running`](mpc_contract::state::ProtocolContractState::Running)
/// state (required for mutation operations).
async fn run_gas_regression<F>(
    method: &str,
    get_threshold: F,
    use_lookups: bool,
    running_state: bool,
) where
    F: Fn(&GasThresholds) -> Gas,
{
    let config = GasThresholdsConfig::load();

    for n in config.participant_counts() {
        println!("\n  Testing with {} participants...", n);
        let env = if running_state {
            setup_test_env_running(n).await
        } else {
            setup_test_env(n).await
        };
        let threshold = get_threshold(&config.get(n));
        if use_lookups {
            run_bench_lookups(&env, method, threshold).await;
        } else {
            run_bench(&env, method, None, threshold).await;
        }
    }
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
         Ensure contract was built with --features=test-utils. \
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
             Ensure contract was built with --features=test-utils. \
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
    let worker = near_workspaces::sandbox().await.unwrap();
    let wasm = current_contract_with_bench_methods();
    let contract = worker.dev_deploy(wasm).await.unwrap();
    let (accounts, participants) = gen_accounts(&worker, n_participants).await;

    let threshold_params = make_threshold_params(&participants);
    if running_state {
        // Create a dummy domain and keyset for running state
        let domain_id = DomainId(0);
        let domain = DomainConfig {
            id: domain_id,
            scheme: SignatureScheme::Secp256k1,
        };
        let (dto_pk, _) = new_secp256k1();
        let public_key: PublicKeyExtended = dto_pk.try_into().unwrap();
        let key = KeyForDomain {
            attempt: AttemptId::new(),
            domain_id,
            key: public_key,
        };
        let keyset = Keyset::new(EpochId::new(1), vec![key]);
        let domains = vec![domain];
        let next_domain_id = domains.len() as u64 + 1;
        init_contract_running(&contract, domains, next_domain_id, keyset, threshold_params).await;
    } else {
        init_contract(&contract, threshold_params, None).await;
    }
    submit_attestations(&contract, &accounts, &participants).await;

    TestEnv {
        contract,
        accounts,
        n_participants,
    }
}
