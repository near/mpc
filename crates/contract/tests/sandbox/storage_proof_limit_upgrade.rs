//! Reproduces the mainnet `v1.signer` 3.14.0 -> 3.15.0 upgrade failure of 2026-09-14, and the
//! workaround for it.
//!
//! Four identical 1.23 MB proposals were pending. The threshold-reaching vote reads the winning
//! proposal and then, at state flush, removes all four entries. Each read and each removal records
//! the evicted value into the chunk's state witness, so the receipt records four blobs (~4.9 MB)
//! and exceeds nearcore's 4 MB per-receipt storage proof limit. This is the negative control
//! [`vote_update__should_fail_with_a_single_max_gas_vote`]: the upgrade cannot happen with one
//! vote, whatever gas it is given.
//!
//! Workaround: the witness recorder is shared across a chunk and deduplicates values by hash, and a
//! failed receipt's reads stay recorded. A first vote that *fails* in the chunk therefore leaves
//! its recorded blobs behind, and a second, full-gas vote in the same chunk deduplicates them and
//! records fewer new blobs of its own, landing under the per-receipt limit.
//!
//! The first vote's gas level is not cosmetic: it decides whether the second vote can join the
//! chunk at all, because the chunk soft limit is also 4 MB.
//!   * Under-gassed (~85 Tgas): dies building the deploy promise having recorded 1 blob (~1.23 MB).
//!     The chunk stays small, the second vote is scheduled in it, records the 3 stale blobs it
//!     removes (~3.7 MB, the winning blob deduplicated), and passes. See
//!     [`vote_update__should_pass_when_preceded_by_an_under_gassed_vote`].
//!   * Max gas: does not die early; at flush it records all 4 blobs (~4.9 MB) before the size check
//!     kills it, over-filling the chunk past 4 MB. The second vote is then deferred to a fresh
//!     chunk and fails like the control. See
//!     [`vote_update__should_not_pass_when_preceded_by_a_max_gas_vote`].
#![allow(non_snake_case)] // Tests use the `<sut>__should_<assertion>` form mandated by CLAUDE.md.

use crate::sandbox::{common::gen_accounts, utils::transactions::CallMpcContract};
use mpc_contract::primitives::thresholds::{GovernanceThreshold, GovernanceThresholdParameters};
use near_mpc_contract_interface::{
    method_names,
    types::{self as dtos, ProposeUpdateArgs, ProtocolContractState, UpdateId},
};
use near_sdk::Gas;
use near_workspaces::{
    Account, Contract, Worker, network::Sandbox, operations::CallTransaction,
    result::ExecutionFinalResult,
};
use serde_json::json;

const PENDING_PROPOSALS: usize = 4;
const STORAGE_PROOF_ERROR: &str =
    "Size of the recorded trie storage proof has exceeded the allowed limit";
const PREPAID_GAS_ERROR: &str = "Exceeded the prepaid gas";
/// Enough to read and record the winning proposal (~37 Tgas), but too little to reserve the 50 Tgas
/// `migrate` call when building the deploy promise, so the receipt dies there having recorded one
/// blob and performed no removals.
const UNDER_GASSED_FIRST_VOTE: Gas = Gas::from_tgas(85);
const SAME_CHUNK_ATTEMPTS: usize = 10;

struct MainnetLikeSetup {
    contract: Contract,
    /// `accounts[0]` has voted, `accounts[1]` casts the threshold vote, `accounts[2]` proposed.
    accounts: Vec<Account>,
    proposal_ids: Vec<UpdateId>,
}

/// Deploys the archived 3.14.0 binary, inits 3 participants with threshold 2, proposes the
/// archived 3.15.0 binary four times and casts one vote for the last proposal.
async fn mainnet_like_setup(worker: &Worker<Sandbox>) -> MainnetLikeSetup {
    let contract = worker
        .dev_deploy(contract_history::version_3_14_0())
        .await
        .unwrap();
    let (accounts, participants) = gen_accounts(worker, 3).await;
    let params: dtos::GovernanceThresholdParameters =
        GovernanceThresholdParameters::new(participants, GovernanceThreshold::new(2))
            .unwrap()
            .into();
    contract
        .as_account()
        .call_mpc(contract.id())
        .init(params, None)
        .await
        .unwrap()
        .into_result()
        .unwrap();
    let state: ProtocolContractState = contract
        .view(method_names::STATE)
        .await
        .unwrap()
        .json()
        .unwrap();
    assert!(
        matches!(state, ProtocolContractState::Running(_)),
        "3.14.0 init must leave the contract in Running state"
    );

    let proposer = &accounts[2];
    let mut proposal_ids = Vec::with_capacity(PENDING_PROPOSALS);
    for _ in 0..PENDING_PROPOSALS {
        let execution = proposer
            .call_mpc(contract.id())
            .propose_update(ProposeUpdateArgs {
                code: Some(contract_history::version_3_15_0().to_vec()),
                config: None,
            })
            .await
            .unwrap();
        assert!(execution.is_success(), "propose failed: {execution:#?}");
        proposal_ids.push(execution.json().unwrap());
    }

    let last = *proposal_ids.last().unwrap();
    let execution = vote(&accounts[0], &contract, last)
        .max_gas()
        .transact()
        .await
        .unwrap();
    let update_occurred: bool = execution.json().unwrap();
    assert!(!update_occurred, "first vote must not reach threshold");

    MainnetLikeSetup {
        contract,
        accounts,
        proposal_ids,
    }
}

fn vote(account: &Account, contract: &Contract, id: UpdateId) -> CallTransaction {
    account
        .call(contract.id(), method_names::VOTE_UPDATE)
        .args_json(json!({ "id": id }))
}

fn with_gas(call: CallTransaction, gas: Option<Gas>) -> CallTransaction {
    match gas {
        Some(gas) => call.gas(gas),
        None => call.max_gas(),
    }
}

fn failure_message(execution: ExecutionFinalResult) -> String {
    format!("{:?}", execution.into_result().unwrap_err())
}

async fn pending_proposal_count(contract: &Contract) -> usize {
    let view: serde_json::Value = contract
        .view(method_names::PROPOSED_UPDATES)
        .await
        .unwrap()
        .json()
        .unwrap();
    view["updates"].as_object().unwrap().len()
}

async fn assert_code_is(contract: &Contract, expected: &[u8]) {
    let code = contract.view_code().await.unwrap();
    assert_eq!(code.len(), expected.len());
    assert_eq!(code, expected);
}

/// Negative control: a lone threshold vote cannot land the upgrade even with max gas, so any
/// success in [`vote_update__should_pass_when_preceded_by_an_under_gassed_vote`] is attributable to
/// the preceding failing vote, not to the vote itself.
#[tokio::test]
async fn vote_update__should_fail_with_a_single_max_gas_vote() {
    // Given
    let worker = near_workspaces::sandbox_with_version(test_utils::DEFAULT_SANDBOX_VERSION)
        .await
        .unwrap();
    let MainnetLikeSetup {
        contract,
        accounts,
        proposal_ids,
    } = mainnet_like_setup(&worker).await;
    let last = *proposal_ids.last().unwrap();

    // When
    let execution = vote(&accounts[1], &contract, last)
        .max_gas()
        .transact()
        .await
        .unwrap();

    // Then
    assert!(execution.is_failure(), "threshold vote unexpectedly passed");
    let gas_burnt = execution.total_gas_burnt;
    let message = failure_message(execution);
    assert!(
        message.contains(STORAGE_PROOF_ERROR),
        "expected storage proof error, got: {message}"
    );
    assert!(
        (80..110).contains(&gas_burnt.as_tgas()),
        "unexpected gas profile: {} Tgas",
        gas_burnt.as_tgas()
    );
    assert_code_is(&contract, contract_history::version_3_14_0()).await;
    assert_eq!(pending_proposal_count(&contract).await, PENDING_PROPOSALS);
}

struct PairedAttempt {
    same_block: bool,
    first_burnt_tgas: u64,
    first_error: String,
    second: ExecutionFinalResult,
}

/// Casts two votes for `id` from `voter` with consecutive nonces, broadcast back to back so they
/// share a chunk whenever they share a block. The first uses `first_vote_gas` (None = max gas).
async fn paired_vote_attempt(
    voter: &Account,
    contract: &Contract,
    id: UpdateId,
    first_vote_gas: Option<Gas>,
) -> PairedAttempt {
    let first = with_gas(vote(voter, contract, id), first_vote_gas)
        .transact_async()
        .await
        .unwrap();
    let second = vote(voter, contract, id)
        .max_gas()
        .transact_async()
        .await
        .unwrap();
    let first = first.await.unwrap();
    let second = second.await.unwrap();

    let same_block =
        first.receipt_outcomes()[0].block_hash == second.receipt_outcomes()[0].block_hash;
    let first_burnt_tgas = first.receipt_outcomes()[0].gas_burnt.as_tgas();
    PairedAttempt {
        same_block,
        first_burnt_tgas,
        first_error: failure_message(first),
        second,
    }
}

async fn assert_upgraded_to_3_15_0(contract: &Contract) {
    assert_code_is(contract, contract_history::version_3_15_0()).await;
    assert_eq!(pending_proposal_count(contract).await, 0);
    let version: String = contract
        .view(method_names::VERSION)
        .await
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(version, "3.15.0");
}

/// The workaround: an under-gassed vote dies building the deploy promise having recorded only the
/// winning blob (~37 Tgas burnt), keeping the chunk small. A full-gas vote in the same chunk then
/// deduplicates that blob and passes. Success is tied to the shared chunk: a different-block pair
/// fails like the control.
#[tokio::test]
async fn vote_update__should_pass_when_preceded_by_an_under_gassed_vote() {
    // Given
    let worker = near_workspaces::sandbox_with_version(test_utils::DEFAULT_SANDBOX_VERSION)
        .await
        .unwrap();
    let MainnetLikeSetup {
        contract,
        accounts,
        proposal_ids,
    } = mainnet_like_setup(&worker).await;
    let last = *proposal_ids.last().unwrap();
    let voter = &accounts[1];

    // When / Then: retried only to get both votes into one block; the outcome per block is
    // deterministic.
    for attempt in 1..=SAME_CHUNK_ATTEMPTS {
        let outcome =
            paired_vote_attempt(voter, &contract, last, Some(UNDER_GASSED_FIRST_VOTE)).await;
        assert!(
            outcome.first_error.contains(PREPAID_GAS_ERROR),
            "under-gassed vote should die building the deploy promise: {}",
            outcome.first_error
        );
        println!(
            "attempt {attempt}: same block: {}, first burnt {} Tgas",
            outcome.same_block, outcome.first_burnt_tgas
        );

        if outcome.second.is_success() {
            assert!(
                outcome.same_block,
                "second vote passed but not in the first vote's block"
            );
            let update_occurred: bool = outcome.second.json().unwrap();
            assert!(update_occurred);
            assert_upgraded_to_3_15_0(&contract).await;
            println!("upgrade landed on attempt {attempt}");
            return;
        }

        // A miss is only acceptable when the votes did not share a chunk: with no shared witness the
        // second vote hits the same limit as the control. This ties success to the shared chunk.
        assert!(
            failure_message(outcome.second).contains(STORAGE_PROOF_ERROR),
            "second vote failed for an unexpected reason"
        );
        assert!(
            !outcome.same_block,
            "second vote hit the storage proof limit despite sharing a block with the first vote"
        );
    }
    panic!("votes never landed in the same chunk after {SAME_CHUNK_ATTEMPTS} attempts");
}

/// Shows the gas level is essential, not cosmetic: a max-gas first vote does not die early. It
/// records all four blobs (~94 Tgas burnt) before the size check kills it, over-filling the chunk
/// past its 4 MB soft limit. The second vote is then deferred to a fresh chunk (never the same
/// block) and fails like the control, so the upgrade never lands.
#[tokio::test]
async fn vote_update__should_not_pass_when_preceded_by_a_max_gas_vote() {
    // Given
    let worker = near_workspaces::sandbox_with_version(test_utils::DEFAULT_SANDBOX_VERSION)
        .await
        .unwrap();
    let MainnetLikeSetup {
        contract,
        accounts,
        proposal_ids,
    } = mainnet_like_setup(&worker).await;
    let last = *proposal_ids.last().unwrap();
    let voter = &accounts[1];

    // When / Then
    for attempt in 1..=SAME_CHUNK_ATTEMPTS {
        let outcome = paired_vote_attempt(voter, &contract, last, None).await;
        assert!(
            outcome.first_error.contains(STORAGE_PROOF_ERROR),
            "max-gas first vote should die at the storage proof limit: {}",
            outcome.first_error
        );
        println!(
            "attempt {attempt}: same block: {}, first burnt {} Tgas",
            outcome.same_block, outcome.first_burnt_tgas
        );
        assert!(
            outcome.second.is_failure(),
            "max-gas first vote over-fills the chunk, so the second vote must not pass"
        );
        assert!(
            !outcome.same_block,
            "the over-filled chunk should defer the second vote to a later block"
        );
        assert!(
            failure_message(outcome.second).contains(STORAGE_PROOF_ERROR),
            "second vote failed for an unexpected reason"
        );
    }
    assert_code_is(&contract, contract_history::version_3_14_0()).await;
    assert_eq!(pending_proposal_count(&contract).await, PENDING_PROPOSALS);
}
