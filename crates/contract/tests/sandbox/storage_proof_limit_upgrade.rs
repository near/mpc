//! Reproduces the mainnet `v1.signer` 3.14.0 -> 3.15.0 upgrade failure of 2026-09-14, and the
//! workaround for it.
//!
//! Four identical 1.23 MB proposals were pending. The threshold-reaching vote reads the winning
//! proposal and then, at state flush, removes all four entries. Each read and each removal records
//! the evicted value into the chunk's state witness, so the receipt records four blobs (~4.9 MB)
//! and exceeds nearcore's 4 MB per-receipt storage proof limit.
//!
//! Workaround: the witness recorder is shared across a chunk and deduplicates values by hash, and
//! a failed receipt's reads stay recorded. A first threshold-reaching vote that is under-gassed
//! dies while building the deploy promise, but only after it has read (and recorded) the winning
//! proposal's blob. A second, full-gas vote in the same chunk then deduplicates that blob and only
//! records the three stale entries it removes (~3.7 MB), landing under the limit.
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
/// `migrate` call when building the deploy promise. The receipt dies there, having recorded exactly
/// one blob and performed no removals.
const SACRIFICIAL_VOTE_GAS: Gas = Gas::from_tgas(85);
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

#[tokio::test]
async fn vote_update__should_hit_storage_proof_limit_when_four_proposals_are_pending() {
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

#[tokio::test]
async fn vote_update__should_pass_when_preceded_by_sacrificial_vote_in_same_chunk() {
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

    // When / Then: both votes come from one key with consecutive nonces, broadcast back to back, so
    // they land in the same chunk in this order whenever they share a block. Retried until they do.
    for attempt in 1..=SAME_CHUNK_ATTEMPTS {
        let sacrificial = vote(voter, &contract, last)
            .gas(SACRIFICIAL_VOTE_GAS)
            .transact_async()
            .await
            .unwrap();
        let real = vote(voter, &contract, last)
            .max_gas()
            .transact_async()
            .await
            .unwrap();
        let sacrificial = sacrificial.await.unwrap();
        let real = real.await.unwrap();

        let same_block =
            sacrificial.receipt_outcomes()[0].block_hash == real.receipt_outcomes()[0].block_hash;
        assert!(
            sacrificial.is_failure(),
            "sacrificial vote must not succeed"
        );
        let sacrificial_error = failure_message(sacrificial);
        assert!(
            sacrificial_error.contains(PREPAID_GAS_ERROR),
            "sacrificial vote should die building the deploy promise: {sacrificial_error}"
        );
        println!("attempt {attempt}: same block: {same_block}");

        if real.is_success() {
            assert!(
                same_block,
                "real vote passed but not in the sacrificial vote's block"
            );
            let update_occurred: bool = real.json().unwrap();
            assert!(update_occurred);
            assert_code_is(&contract, contract_history::version_3_15_0()).await;
            assert_eq!(pending_proposal_count(&contract).await, 0);
            let version: String = contract
                .view(method_names::VERSION)
                .await
                .unwrap()
                .json()
                .unwrap();
            assert_eq!(version, "3.15.0");
            println!("upgrade landed on attempt {attempt}");
            return;
        }

        let message = failure_message(real);
        assert!(
            message.contains(STORAGE_PROOF_ERROR),
            "real vote failed for an unexpected reason: {message}"
        );
        assert!(
            !same_block,
            "real vote hit the storage proof limit despite sharing a block with the sacrificial vote"
        );
    }
    panic!("votes never landed in the same chunk after {SAME_CHUNK_ATTEMPTS} attempts");
}
