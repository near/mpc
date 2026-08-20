//! Sandbox tests for the attestation flow against a real deployed `tee-verifier`.
//!
//! The Verified path needs a verifier build whose clock is pinned inside the
//! fixture collateral's validity window, the fixture's compose hash patched into
//! contract state (no vote can derive it), and signing as the fixture account,
//! whose key the quote's report_data binds.
#![allow(non_snake_case)]

use crate::sandbox::{
    common::SandboxTestSetup,
    utils::{
        consts::ALL_PROTOCOLS,
        contract_build::{tee_verifier_contract, tee_verifier_contract_with_sandbox_test_hooks},
        mpc_contract::{
            available_attestation_grants, get_config, get_participant_attestation,
            get_tee_accounts, prepay_attestation_grants, submit_participant_info,
            tee_verifier_account_id, total_gas_fee,
        },
        transactions::execute_async_handle_calls,
    },
};
use attestation::measurements::Measurements;
use mpc_attestation::attestation::{DEFAULT_EXPIRATION_DURATION_SECONDS, default_measurements};
use mpc_contract::{
    errors::TeeError,
    tee::{tee_state::AttestationSubmissionError, test_utils::whitelist_dstack_in_state},
};
use mpc_primitives::hash::{LauncherDockerComposeHash, TeeVerifierCodeHash};
use near_mpc_contract_interface::types as dtos;
use near_workspaces::{
    Account, AccountId, Contract, Worker,
    network::Sandbox,
    result::ExecutionFinalResult,
    types::{Gas, NearToken, SecretKey},
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tee_verifier_interface::SANDBOX_TEST_PINNED_NOW_STORAGE_KEY;
use test_utils::attestation::{
    VALID_ATTESTATION_TIMESTAMP, account_secret_key, image_digest, launcher_compose_digest,
    launcher_image_hash, mock_dto_dstack_attestation, p2p_tls_key, verified_report,
};
use tokio_util::time::FutureExt as _;

struct VerifiedFixture {
    setup: SandboxTestSetup,
    verifier: Contract,
    submitter: Account,
}

async fn setup() -> SandboxTestSetup {
    SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .build()
        .await
}

async fn trust_verifier(setup: &SandboxTestSetup, verifier: &AccountId) {
    // Arbitrary: the hash only buckets votes (voters must commit to the same
    // value), the contract never compares it to the deployed verifier code.
    let expected_code_hash = TeeVerifierCodeHash::new([7u8; 32]);
    execute_async_handle_calls(&setup.mpc_signer_accounts, &setup.contract, |handle| {
        let verifier = verifier.clone();
        async move {
            handle
                .vote_tee_verifier_change(verifier, expected_code_hash)
                .await
        }
    })
    .await
    .unwrap();
}

async fn deploy_and_trust(setup: &SandboxTestSetup, wasm: &[u8]) -> Contract {
    let verifier = setup.worker.dev_deploy(wasm).await.unwrap();
    trust_verifier(setup, verifier.id()).await;
    verifier
}

async fn deploy_and_trust_pinned_verifier(setup: &SandboxTestSetup) -> Contract {
    let verifier = deploy_and_trust(setup, tee_verifier_contract_with_sandbox_test_hooks()).await;
    setup
        .worker
        .patch_state(
            verifier.id(),
            SANDBOX_TEST_PINNED_NOW_STORAGE_KEY,
            &VALID_ATTESTATION_TIMESTAMP.to_le_bytes(),
        )
        .await
        .unwrap();
    verifier
}

async fn whitelist_fixture_dstack_hashes(
    setup: &SandboxTestSetup,
    compose_hash: Option<LauncherDockerComposeHash>,
) {
    let state = setup
        .worker
        .view_state(setup.contract.id())
        .prefix(b"STATE")
        .await
        .unwrap()
        .remove(b"STATE".as_slice())
        .expect("the contract must have a STATE entry");
    let patched =
        whitelist_dstack_in_state(&state, image_digest(), launcher_image_hash(), compose_hash);
    setup
        .worker
        .patch_state(setup.contract.id(), b"STATE", &patched)
        .await
        .unwrap();
}

async fn create_fixture_account(worker: &Worker<Sandbox>, account_id: &str) -> Account {
    let secret_key: SecretKey = account_secret_key()
        .parse()
        .expect("near_account_secret_key asset holds a valid ed25519 secret key");
    worker
        .create_root_account_subaccount(account_id.parse().unwrap(), secret_key)
        .await
        .unwrap()
        .into_result()
        .unwrap()
}

/// A separate payer leaves the beneficiary's balance untouched, so tests can assert it
/// spent only gas. Returns the beneficiary's balance after the prepayment.
async fn prepay_grant_from_separate_payer(
    setup: &SandboxTestSetup,
    beneficiary: &Account,
) -> NearToken {
    let payer = setup.worker.dev_create_account().await.unwrap();
    let prepayment = prepay_attestation_grants(&payer, &setup.contract, beneficiary.id(), 1)
        .await
        .unwrap();
    assert!(prepayment.is_success(), "prepayment failed: {prepayment:?}");
    beneficiary.view_account().await.unwrap().balance
}

async fn setup_verified_fixture() -> VerifiedFixture {
    setup_fixture(Some(launcher_compose_digest())).await
}

async fn setup_fixture(allowed_compose_hash: Option<LauncherDockerComposeHash>) -> VerifiedFixture {
    let setup = setup().await;
    let verifier = deploy_and_trust_pinned_verifier(&setup).await;
    whitelist_fixture_dstack_hashes(&setup, allowed_compose_hash).await;
    let submitter = create_fixture_account(&setup.worker, "fixture-node-a").await;
    prepay_grant_from_separate_payer(&setup, &submitter).await;
    VerifiedFixture {
        setup,
        verifier,
        submitter,
    }
}

async fn submit_dstack(submitter: &Account, contract: &Contract) -> ExecutionFinalResult {
    submit_participant_info(
        submitter,
        contract,
        &mock_dto_dstack_attestation(),
        &p2p_tls_key().into(),
    )
    .await
    .unwrap()
}

/// Full success pins that the verdict was Verified, so the whole DCAP path ran;
/// a Rejected verdict or a failed promise fails the transaction.
async fn submit_dstack_verified(
    submitter: &Account,
    contract: &Contract,
) -> (ExecutionFinalResult, dtos::VerifiedAttestation) {
    let result = submit_dstack(submitter, contract).await;
    assert!(
        result.failures().is_empty(),
        "expected every receipt to succeed, got: {result:#?}"
    );
    let stored = stored_fixture_attestation(contract)
        .await
        .expect("a Verified submission must store an attestation");
    (result, stored)
}

async fn stored_fixture_attestation(contract: &Contract) -> Option<dtos::VerifiedAttestation> {
    get_participant_attestation(contract, &p2p_tls_key().into())
        .await
        .unwrap()
}

fn assert_failure_contains(result: &ExecutionFinalResult, expected_errors: &[&str]) {
    let failures = result.failures();
    assert!(
        !failures.is_empty(),
        "expected the promise chain to fail on a receipt, got: {result:#?}"
    );
    // Substring-match: near-workspaces keeps `ExecutionOutcome.status`
    // `pub(crate)`, so the error is only reachable via the Debug dump.
    let rendered = format!("{failures:?}");
    for expected in expected_errors {
        assert!(
            rendered.contains(expected),
            "expected a receipt failure containing {expected:?}, got: {rendered}"
        );
    }
}

async fn assert_submission_failed_cleanly(
    result: &ExecutionFinalResult,
    contract: &Contract,
    submitter: &Account,
    balance_before: NearToken,
    expected_errors: &[&str],
) {
    assert_failure_contains(result, expected_errors);
    let stored = stored_fixture_attestation(contract).await;
    assert!(stored.is_none(), "nothing should be stored on failure");
    let remaining = available_attestation_grants(contract, submitter.id())
        .await
        .unwrap();
    assert_eq!(
        remaining, 1,
        "a failed submission must not consume the prepaid grant"
    );
    assert_only_gas_spent(submitter, balance_before, result).await;
}

/// The unspent-gas refund lands a block or two after the transaction, so the
/// balance is polled until it settles rather than read once.
async fn assert_only_gas_spent(
    account: &Account,
    balance_before: NearToken,
    result: &ExecutionFinalResult,
) {
    const TIMEOUT: Duration = Duration::from_secs(10);
    const POLL_INTERVAL: Duration = Duration::from_millis(500);

    let expected = total_gas_fee(result);
    let mut net_spent = balance_before;
    let settled = async {
        loop {
            let balance_after = account.view_account().await.unwrap().balance;
            net_spent = balance_before.saturating_sub(balance_after);
            if net_spent == expected {
                return;
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }
    .timeout(TIMEOUT)
    .await;
    assert!(
        settled.is_ok(),
        "balance never settled at the gas fee: spent {net_spent}, expected {expected}"
    );
}

#[tokio::test]
async fn submit_participant_info__should_reject_dstack_when_verifier_not_configured() {
    // Given
    let setup = setup().await;
    let submitter = &setup.mpc_signer_accounts[0];
    prepay_grant_from_separate_payer(&setup, submitter).await;

    // When
    let result = submit_dstack(submitter, &setup.contract).await;

    // Then: it fails synchronously (before any cross-contract call), so the error
    // is on the top-level tx result, not a later receipt.
    let err = result
        .into_result()
        .expect_err("Dstack submit must fail when no verifier is configured")
        .to_string();
    let expected_panic = format!(
        "Smart contract panicked: {}",
        TeeError::VerifierNotConfigured
    );
    assert!(
        err.contains(&expected_panic),
        "expected {expected_panic:?}, got: {err}"
    );
    let stored = stored_fixture_attestation(&setup.contract).await;
    assert!(stored.is_none(), "no attestation should be stored");
}

#[tokio::test]
async fn tee_verifier_account_id__should_return_none_until_a_verifier_is_voted_in() {
    // Given
    let setup = setup().await;
    assert_eq!(tee_verifier_account_id(&setup.contract).await, None);

    // When
    let verifier: AccountId = "verifier.near".parse().unwrap();
    trust_verifier(&setup, &verifier).await;

    // Then
    assert_eq!(
        tee_verifier_account_id(&setup.contract).await,
        Some(verifier)
    );
}

#[tokio::test]
async fn submit_participant_info__should_store_nothing_on_verifier_rejection() {
    // Given
    let setup = setup().await;
    deploy_and_trust(&setup, tee_verifier_contract()).await;
    let submitter = &setup.mpc_signer_accounts[0];
    let balance_before = prepay_grant_from_separate_payer(&setup, submitter).await;
    let mut attestation = mock_dto_dstack_attestation();
    let dtos::Attestation::Dstack(dstack) = &mut attestation else {
        panic!("fixture must be a Dstack attestation");
    };
    dstack.quote = dtos::HexVec(vec![0u8; 16]);

    // When
    let result = submit_participant_info(
        submitter,
        &setup.contract,
        &attestation,
        &p2p_tls_key().into(),
    )
    .await
    .unwrap();

    // Then
    assert_submission_failed_cleanly(
        &result,
        &setup.contract,
        submitter,
        balance_before,
        &[&TeeError::QuoteRejected {
            reason: String::new(),
        }
        .to_string()],
    )
    .await;
}

#[tokio::test]
async fn submit_participant_info__should_fail_and_store_nothing_when_verifier_unreachable() {
    // Given: a verifier account that was never deployed, so the verify_quote promise fails.
    let setup = setup().await;
    let missing_verifier: AccountId = "nonexistent-verifier.near".parse().unwrap();
    trust_verifier(&setup, &missing_verifier).await;
    let submitter = &setup.mpc_signer_accounts[0];
    let balance_before = prepay_grant_from_separate_payer(&setup, submitter).await;

    // When
    let result = submit_dstack(submitter, &setup.contract).await;

    // Then
    assert_submission_failed_cleanly(
        &result,
        &setup.contract,
        submitter,
        balance_before,
        &[&TeeError::VerifierUnavailable.to_string()],
    )
    .await;
}

#[tokio::test]
async fn submit_participant_info__should_run_dcap_within_verifier_gas_budget() {
    // Given
    let fx = setup_verified_fixture().await;

    // When
    let (result, _) = submit_dstack_verified(&fx.submitter, &fx.setup.contract).await;

    // Then
    let outcomes = result.outcomes();
    let verify_quote_outcome = outcomes
        .iter()
        .find(|outcome| outcome.executor_id == *fx.verifier.id())
        .expect("the verify_quote receipt must have executed on the verifier");
    // The receipt gets exactly `verifier_tera_gas` of static gas, so success already
    // proves it fit. Assert headroom instead: the regression that matters is
    // `dcap-qvl` growing until it OOGs in production.
    const HEADROOM_PERCENT: u64 = 10;
    let budget = Gas::from_tgas(
        get_config(&fx.setup.contract)
            .await
            .unwrap()
            .verifier_tera_gas,
    );
    let max_allowed = Gas::from_gas(budget.as_gas() * (100 - HEADROOM_PERCENT) / 100);
    assert!(
        verify_quote_outcome.gas_burnt <= max_allowed,
        "verify_quote burnt {} of the {budget} budget, leaving less than {HEADROOM_PERCENT}% \
         headroom. Find what grew (gas schedule or `dcap-qvl`) before raising \
         DEFAULT_VERIFIER_TERA_GAS, or the OOG this guards against reaches mainnet",
        verify_quote_outcome.gas_burnt,
    );
}

#[tokio::test]
async fn submit_participant_info__should_fail_cleanly_when_verifier_gas_budget_too_low() {
    // Given: a verifier gas budget far below `DEFAULT_VERIFIER_TERA_GAS`, so the
    // verify_quote receipt runs out of gas mid-DCAP.
    const INSUFFICIENT_VERIFIER_TERA_GAS: u64 = 10;
    let setup = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .with_init_config(dtos::InitConfig {
            verifier_tera_gas: Some(INSUFFICIENT_VERIFIER_TERA_GAS),
            ..Default::default()
        })
        .build()
        .await;
    deploy_and_trust(&setup, tee_verifier_contract()).await;
    let submitter = &setup.mpc_signer_accounts[0];
    let balance_before = prepay_grant_from_separate_payer(&setup, submitter).await;

    // When
    let result = submit_dstack(submitter, &setup.contract).await;

    // Then: the failed promise is indistinguishable from a crashed verifier.
    assert_submission_failed_cleanly(
        &result,
        &setup.contract,
        submitter,
        balance_before,
        &[&TeeError::VerifierUnavailable.to_string()],
    )
    .await;
}

#[tokio::test]
async fn submit_participant_info__should_store_attestation_on_verified_quote() {
    // Given
    let fx = setup_verified_fixture().await;
    let balance_before = fx.submitter.view_account().await.unwrap().balance;
    let submitted_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // When
    let (result, stored) = submit_dstack_verified(&fx.submitter, &fx.setup.contract).await;

    // Then
    let dtos::VerifiedAttestation::Dstack(stored) = stored else {
        panic!("expected a stored Dstack attestation, got: {stored:?}");
    };
    let expected_expiry = submitted_at + DEFAULT_EXPIRATION_DURATION_SECONDS;
    // The expiry is stamped from sandbox block time, which drifts from `submitted_at`
    const MAX_CLOCK_DRIFT_SECONDS: u64 = 600;
    assert!(
        stored.expiry_timestamp_seconds.abs_diff(expected_expiry) < MAX_CLOCK_DRIFT_SECONDS,
        "expiry {} should be about {expected_expiry} (submission time + default expiration)",
        stored.expiry_timestamp_seconds,
    );
    // The stored measurements are the allowlist entry the fixture matched; select
    // the expected entry by the fixture report's rtmrs, so the expectation stays
    // independent of what was stored.
    let fixture_rtmrs =
        Measurements::try_from(verified_report()).expect("fixture quote carries a TD report");
    let matched = default_measurements()
        .iter()
        .find(|m| m.rtmrs == fixture_rtmrs)
        .expect("the fixture's rtmrs must match one of the shipped measurement sets");
    let expected = dtos::VerifiedDstackAttestation {
        mpc_image_hash: image_digest(),
        launcher_compose_hash: launcher_compose_digest(),
        expiry_timestamp_seconds: stored.expiry_timestamp_seconds,
        measurements: dtos::VerifiedMeasurements {
            mrtd: matched.rtmrs.mrtd.into(),
            rtmr0: matched.rtmrs.rtmr0.into(),
            rtmr1: matched.rtmrs.rtmr1.into(),
            rtmr2: matched.rtmrs.rtmr2.into(),
            key_provider_event_digest: matched.key_provider_event_digest.into(),
        },
    };
    assert_eq!(stored, expected);
    // Storage is funded by the contract, so the submitter pays only gas.
    assert_only_gas_spent(&fx.submitter, balance_before, &result).await;
}

#[tokio::test]
async fn submit_participant_info__should_reject_verified_quote_when_tls_key_owned_by_other_account()
{
    // Given: NEAR allows the same public key on two accounts and report_data binds
    // only the key pair, so nothing in the attestation itself distinguishes the
    // second submitter; only the ownership guard does.
    let fx = setup_verified_fixture().await;
    let owner = &fx.submitter;
    let (_, stored_before) = submit_dstack_verified(owner, &fx.setup.contract).await;
    let attacker = create_fixture_account(&fx.setup.worker, "fixture-node-b").await;
    let balance_before = attacker.view_account().await.unwrap().balance;

    // When
    let result = submit_dstack(&attacker, &fx.setup.contract).await;

    // Then
    assert_failure_contains(
        &result,
        &[&AttestationSubmissionError::TlsKeyOwnedByOtherAccount.to_string()],
    );
    let stored_after = stored_fixture_attestation(&fx.setup.contract)
        .await
        .expect("the owner's attestation must survive the attack");
    assert_eq!(
        stored_after, stored_before,
        "the owner's entry must be unchanged"
    );
    let tee_accounts = get_tee_accounts(&fx.setup.contract).await.unwrap();
    assert!(
        tee_accounts
            .iter()
            .any(|node| node.account_id.as_str() == owner.id().as_str()
                && node.tls_public_key == p2p_tls_key().into()),
        "the fixture TLS key must still belong to the owner, got: {tee_accounts:?}"
    );
    assert_only_gas_spent(&attacker, balance_before, &result).await;
}

#[tokio::test]
async fn submit_participant_info__should_reject_verified_quote_when_compose_hash_not_allowed() {
    // Given
    let fx = setup_fixture(None).await;
    let balance_before = fx.submitter.view_account().await.unwrap().balance;

    // When
    let result = submit_dstack(&fx.submitter, &fx.setup.contract).await;

    // Then
    let expected_rejection = format!(
        "MPC launcher compose hash {:?} is not in the allowed hashes list",
        launcher_compose_digest()
    );
    assert_submission_failed_cleanly(
        &result,
        &fx.setup.contract,
        &fx.submitter,
        balance_before,
        &["failed verification", &expected_rejection],
    )
    .await;
}

#[tokio::test]
async fn submit_participant_info__should_reject_verified_quote_when_submitter_keys_do_not_match_report_data()
 {
    // Given: the fixture quote's report_data binds the fixture account's TLS and
    // account keys, so a submitter with different keys must be rejected after
    // DCAP.
    let fx = setup_verified_fixture().await;
    let submitter = &fx.setup.mpc_signer_accounts[0];
    let balance_before = prepay_grant_from_separate_payer(&fx.setup, submitter).await;

    // When
    let result = submit_dstack(submitter, &fx.setup.contract).await;

    // Then
    assert_submission_failed_cleanly(
        &result,
        &fx.setup.contract,
        submitter,
        balance_before,
        &["failed verification", "report_data"],
    )
    .await;
}
