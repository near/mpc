//! Pins how many pending code proposals `do_update` can still apply, and covers the
//! paired-vote recovery for the case where that budget has already been overrun.
//!
//! `do_update` reads the winning proposal and evicts every loser in a single receipt, so the
//! whole proposals map is charged to one receipt's storage-proof budget. Past NEAR's 4 MB
//! per-receipt limit the receipt reverts, taking the threshold-reaching vote with it, and the
//! upgrade can never be applied — there is no contract method that removes a proposal.
//! Mainnet reached that state on 2026-09-14 with four byte-identical proposals.
//!
//! The recovery leans on two nearcore properties: the proof recorder is chunk-scoped and
//! deduplicates by node hash, while the limit is a per-receipt *delta*. A deliberately
//! under-gassed vote that dies partway still leaves its reads in the chunk's recorder, so a
//! second vote in the same chunk re-reads those blobs for free.

#![expect(
    non_snake_case,
    reason = "tests follow the <sut>__should_<assertion> convention"
)]

use crate::sandbox::{
    common::{execute_key_generation_and_add_random_state, gen_accounts, submit_attestations},
    utils::{
        consts::PARTICIPANT_LEN, contract_build::current_contract, transactions::CallMpcContract,
    },
};
use mpc_contract::primitives::thresholds::{GovernanceThreshold, GovernanceThresholdParameters};
use near_mpc_contract_interface::call_args::VoteUpdateArgs;
use near_mpc_contract_interface::method_names;
use near_mpc_contract_interface::types::{ProposeUpdateArgs, UpdateId};
use near_sdk::Gas;
use near_workspaces::{Account, Contract, Worker, network::Sandbox, operations::TransactionStatus};
use rand_core::OsRng;
use rstest::rstest;

const FULL_VOTE_GAS: Gas = Gas::from_tgas(260);

/// Substring of the nearcore error raised when a receipt overruns its storage-proof budget.
const PROOF_LIMIT_ERROR: &str = "storage proof";

struct StagedContract {
    contract: Contract,
    /// Participants who have not voted yet, so a caller can still reach threshold.
    non_voters: Vec<Account>,
    /// Proposal the parked votes are stacked on, mirroring mainnet where every vote sits on
    /// the most recent id.
    contested_id: UpdateId,
}

/// Deploys the production mainnet binary, stages `duplicates` copies of the same upgrade, and
/// parks `threshold - 1` votes on the last of them.
///
/// Deploys the real binary rather than a fresh build so the proposal sizes under test match
/// the ones that actually wedged mainnet.
async fn stage_duplicate_proposals(
    worker: &Worker<Sandbox>,
    duplicates: usize,
) -> anyhow::Result<StagedContract> {
    let contract = worker
        .dev_deploy(contract_history::current_mainnet())
        .await?;
    let (accounts, participants) = gen_accounts(worker, PARTICIPANT_LEN).await;

    let threshold = ((participants.len() as f64) * 0.6).ceil() as u64;
    let threshold_parameters: near_mpc_contract_interface::types::GovernanceThresholdParameters =
        GovernanceThresholdParameters::new(
            participants.clone(),
            GovernanceThreshold::new(threshold),
        )
        .unwrap()
        .into();
    contract
        .as_account()
        .call_mpc(contract.id())
        .init(threshold_parameters, None)
        .await?
        .into_result()?;

    submit_attestations(&contract, &accounts, &participants).await;
    execute_key_generation_and_add_random_state(
        &accounts,
        participants,
        &contract,
        worker,
        &mut OsRng,
    )
    .await;

    let mut contested_id = UpdateId(0);
    for _ in 0..duplicates {
        contested_id = accounts[0]
            .call_mpc(contract.id())
            .propose_update(ProposeUpdateArgs {
                code: Some(current_contract().to_vec()),
                config: None,
            })
            .await?
            .into_result()?
            .json()?;
    }

    let voters = usize::try_from(threshold).unwrap() - 1;
    for voter in &accounts[..voters] {
        voter
            .call_mpc(contract.id())
            .vote_update(contested_id)
            .await?
            .into_result()?;
    }

    Ok(StagedContract {
        contract,
        non_voters: accounts[voters..].to_vec(),
        contested_id,
    })
}

/// Casts `vote_update` with an explicit gas budget, without waiting for the result.
///
/// Bypasses `MpcContractHandle`, which pins `vote_update` to 260 Tgas — the sacrificial vote
/// has to be able to run out of gas at a chosen moment.
async fn vote_update_async(
    voter: &Account,
    contract: &Contract,
    id: UpdateId,
    gas: Gas,
) -> anyhow::Result<TransactionStatus> {
    Ok(voter
        .call(contract.id(), method_names::VOTE_UPDATE)
        .args_json(VoteUpdateArgs::new(id))
        .gas(gas)
        .transact_async()
        .await?)
}

async fn deployed_code_matches(contract: &Contract, expected: &[u8]) -> anyhow::Result<bool> {
    Ok(near_sdk::env::sha256(&contract.view_code().await?) == near_sdk::env::sha256(expected))
}

/// Pins the number of pending code proposals `do_update` can still apply.
///
/// Three fit; the fourth is what wedged mainnet. If a future change grows the contract or the
/// proposal payload, this is the test that should start failing.
#[rstest]
#[case(3, true)]
#[case(4, false)]
#[tokio::test]
async fn vote_update__should_apply_upgrade_only_while_pending_proposals_fit_the_receipt_budget(
    #[case] duplicates: usize,
    #[case] expected_to_apply: bool,
) -> anyhow::Result<()> {
    // Given a contract with `duplicates` identical pending proposals and threshold - 1 votes.
    let worker = near_workspaces::sandbox_with_version(test_utils::DEFAULT_SANDBOX_VERSION).await?;
    let staged = stage_duplicate_proposals(&worker, duplicates).await?;

    // When the threshold-reaching vote is cast.
    let outcome = staged.non_voters[0]
        .call(staged.contract.id(), method_names::VOTE_UPDATE)
        .args_json(VoteUpdateArgs::new(staged.contested_id))
        .gas(FULL_VOTE_GAS)
        .transact()
        .await?;

    // Then the upgrade applies only while the proposals map still fits one receipt.
    if expected_to_apply {
        outcome.into_result()?;
        assert!(
            deployed_code_matches(&staged.contract, current_contract()).await?,
            "{duplicates} pending proposals should still upgrade"
        );
    } else {
        let failure = format!("{:?}", outcome.into_result().unwrap_err());
        assert!(
            failure.to_lowercase().contains(PROOF_LIMIT_ERROR),
            "expected a storage-proof failure with {duplicates} pending proposals, got: {failure}"
        );
    }

    Ok(())
}

/// Negative control for [`vote_update__should_land_when_preceded_by_under_gassed_vote`].
///
/// Identical to it in every respect — same staged state, same voter, same gas, same async
/// submission path — except that nothing is sent in front of it. Without this, a passing
/// paired test would look the same whether the pre-payment did the work or whether submitting
/// asynchronously happened to succeed for some unrelated reason.
#[tokio::test]
async fn vote_update__should_fail_when_submitted_alone_without_a_preceding_vote()
-> anyhow::Result<()> {
    // Given a contract wedged by four pending proposals.
    let worker = near_workspaces::sandbox_with_version(test_utils::DEFAULT_SANDBOX_VERSION).await?;
    let staged = stage_duplicate_proposals(&worker, 4).await?;

    // When the threshold-reaching vote is submitted with nothing ahead of it.
    let vote = vote_update_async(
        &staged.non_voters[1],
        &staged.contract,
        staged.contested_id,
        FULL_VOTE_GAS,
    )
    .await?;

    // Then it still fails, which is what makes the paired result attributable to vote A.
    assert!(
        vote.await?.into_result().is_err(),
        "a lone vote must still fail; otherwise the paired test is measuring something other \
         than the pre-payment"
    );

    Ok(())
}

/// The recovery: a sacrificial under-gassed vote pre-pays part of the proof into the chunk, so
/// the vote behind it only has to record what is left.
///
/// `vote_a_gas` is swept because the cut-off cannot be calculated — nearcore's `storage_remove`
/// reads the evicted value *before* charging `storage_remove_ret_value_byte` on its length, so
/// the per-byte fee is not the boundary. Gas exhaustion inside the trie traversal is, and where
/// that lands has to be found by experiment.
#[rstest]
#[case(Gas::from_tgas(35))]
#[case(Gas::from_tgas(40))]
#[case(Gas::from_tgas(45))]
#[case(Gas::from_tgas(50))]
#[case(Gas::from_tgas(55))]
#[case(Gas::from_tgas(60))]
#[tokio::test]
async fn vote_update__should_land_when_preceded_by_under_gassed_vote(
    #[case] vote_a_gas: Gas,
) -> anyhow::Result<()> {
    // Given a contract wedged by four pending proposals.
    let worker = near_workspaces::sandbox_with_version(test_utils::DEFAULT_SANDBOX_VERSION).await?;
    let staged = stage_duplicate_proposals(&worker, 4).await?;

    // When a sacrificial vote and a full-gas vote are submitted back to back, so both receipts
    // reach the contract in the same chunk and share one recorder.
    let vote_a = vote_update_async(
        &staged.non_voters[0],
        &staged.contract,
        staged.contested_id,
        vote_a_gas,
    )
    .await?;
    let vote_b = vote_update_async(
        &staged.non_voters[1],
        &staged.contract,
        staged.contested_id,
        FULL_VOTE_GAS,
    )
    .await?;
    let outcome_a = vote_a.await?;
    let outcome_b = vote_b.await?;

    // Then A reverts, having paid its reads into the chunk...
    assert!(
        outcome_a.into_result().is_err(),
        "vote A was meant to die; it succeeded at {vote_a_gas:?}, so it cleared the map on its \
         own and this case proves nothing"
    );

    // ...and B lands, reaching threshold and applying the upgrade.
    outcome_b
        .into_result()
        .map_err(|err| anyhow::anyhow!("vote B failed at vote_a_gas={vote_a_gas:?}: {err:?}"))?;
    assert!(
        deployed_code_matches(&staged.contract, current_contract()).await?,
        "contract code should match the proposed binary after the paired vote"
    );

    Ok(())
}
