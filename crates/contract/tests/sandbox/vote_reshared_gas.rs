#![allow(non_snake_case)]
//! Gas accounting for the `vote_reshared` call that concludes a resharing.
//!
//! That single call spawns six detached cleanup promises, each reserving
//! `Gas::from_tgas(config.<name>_tera_gas)` out of its own remaining prepaid gas. Raising
//! `clean_invalid_attestations_tera_gas` therefore competes with `vote_reshared`'s own
//! execution for the 300 TGas the node attaches, and over-reserving fails the deciding
//! reshare vote rather than merely the sweep.
//!
//! Run with:
//! ```sh
//! cargo test -p mpc-contract vote_reshared_gas -- --nocapture
//! ```

use crate::sandbox::{
    common::SandboxTestSetup,
    utils::{
        interface::IntoContractType,
        mpc_contract::{assert_running_return_participants, get_state},
        resharing_utils::{start_reshare_instance, vote_new_parameters},
    },
};
use anyhow::{Context, Result};
use mpc_contract::primitives::{
    participants::Participants,
    thresholds::{GovernanceThreshold, GovernanceThresholdParameters},
};
use near_mpc_contract_interface::{
    method_names,
    types::{self as dtos, AttemptId, EpochId, KeyEventId, Protocol, ProtocolContractState},
};
use near_workspaces::types::Gas;
use serde_json::json;

/// The gas the node attaches to `vote_reshared` in production
/// (`crates/node/src/indexer/types.rs`, `MAX_GAS`).
const PRODUCTION_VOTE_RESHARED_TGAS: u64 = 300;
/// Participant counts of the deployed contracts, read from `state` on 2026-08-05:
/// 11 on `v1.signer` (mainnet) and 17 on `v1.signer-prod.testnet`.
const DEPLOYED_PARTICIPANT_COUNTS: [(&str, usize); 2] = [("mainnet", 11), ("testnet", 17)];

/// Guard: the concluding `vote_reshared` must still fit inside the gas the node attaches,
/// after reserving every cleanup promise's budget.
///
/// Each promise reserves `Gas::from_tgas(config.…)` out of `vote_reshared`'s own remaining
/// prepaid gas, so raising any cleanup budget — `clean_invalid_attestations_tera_gas` in
/// particular (#4035) — eats into it. Over-reserving does not merely fail the cleanup: promise
/// creation fails inside `vote_reshared`, which fails the **deciding reshare vote**. This runs
/// a real resharing to completion at the deployed participant counts to catch that.
#[tokio::test]
async fn vote_reshared__reservation_fits_the_gas_the_node_attaches() -> Result<()> {
    for (network, n_participants) in DEPLOYED_PARTICIPANT_COUNTS {
        // A successful conclusion is itself the assertion: `measure_deciding_vote_reshared`
        // errors if any vote fails, which is what over-reserving would cause.
        let vote = measure_deciding_vote_reshared(None, n_participants).await?;
        let total = vote.burnt_tgas + vote.reserved_tgas as f64;

        anyhow::ensure!(
            total < PRODUCTION_VOTE_RESHARED_TGAS as f64,
            "{network}: vote_reshared burns {:.3} TGas and reserves {} TGas for cleanup \
             promises, totalling {total:.3} TGas against the {PRODUCTION_VOTE_RESHARED_TGAS} \
             TGas the node attaches",
            vote.burnt_tgas,
            vote.reserved_tgas,
        );
        println!(
            "  {network:<8} ({n_participants:>2} participants): burn {:.3} TGas + reserved {} \
             TGas = {total:.3} TGas ({:.1} TGas spare of {PRODUCTION_VOTE_RESHARED_TGAS})",
            vote.burnt_tgas,
            vote.reserved_tgas,
            PRODUCTION_VOTE_RESHARED_TGAS as f64 - total,
        );
    }
    Ok(())
}

#[tokio::test]
#[ignore = "measurement tool, not an assertion; run explicitly"]
async fn vote_reshared__gas_burn_and_promise_reservation_headroom() -> Result<()> {
    for (network, n_participants) in DEPLOYED_PARTICIPANT_COUNTS {
        for sweep_tgas in [None, Some(10)] {
            let label = match sweep_tgas {
                None => "sweep = default".to_string(),
                Some(t) => format!("sweep = {t}"),
            };

            let vote = measure_deciding_vote_reshared(sweep_tgas, n_participants).await?;
            let total = vote.burnt_tgas + vote.reserved_tgas as f64;

            println!(
                "  {network:<8} ({n_participants:>2} participants), {label:<16} \
                 burn {:>6.3} TGas + reserved {:>3} TGas = {total:>7.3} TGas \
                 ({:>6.1} TGas spare of {PRODUCTION_VOTE_RESHARED_TGAS})",
                vote.burnt_tgas,
                vote.reserved_tgas,
                PRODUCTION_VOTE_RESHARED_TGAS as f64 - total,
            );
        }
    }
    Ok(())
}

/// Drives a resharing to its concluding `vote_reshared` and returns that receipt's gas burn.
///
/// Votes are cast one at a time — rather than via the async helper — so the single vote that
/// crosses the threshold and spawns the cleanup promises can be identified and measured.
async fn measure_deciding_vote_reshared(
    sweep_tgas: Option<u64>,
    n_participants: usize,
) -> Result<DecidingVote> {
    // Votes are cast sequentially (one block each) so the deciding one can be isolated, which
    // takes more blocks than the default 30-block key-event timeout allows at these
    // participant counts. The timeout is unrelated to gas accounting, so it is lifted.
    let builder = SandboxTestSetup::builder()
        .with_protocols(&[Protocol::CaitSith])
        .with_number_of_participants(n_participants)
        .with_init_config(dtos::InitConfig {
            key_event_timeout_blocks: Some(10_000),
            clean_invalid_attestations_tera_gas: sweep_tgas,
            ..Default::default()
        });
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = builder.build().await;

    // Read the config back so the reservation is summed from what the contract actually holds
    // rather than from a duplicated constant, and so an `init_config` that fails to apply
    // cannot quietly turn an override into a measurement of the default.
    let on_chain_config: dtos::Config = contract.view(method_names::CONFIG).await?.json()?;
    anyhow::ensure!(
        on_chain_config.key_event_timeout_blocks == 10_000,
        "init_config did not apply the raised key-event timeout"
    );
    if let Some(expected) = sweep_tgas {
        anyhow::ensure!(
            on_chain_config.clean_invalid_attestations_tera_gas == expected,
            "init_config did not apply: contract reports {} TGas, expected {expected}",
            on_chain_config.clean_invalid_attestations_tera_gas,
        );
    }
    let reserved_tgas = reserved_cleanup_promise_tgas(&on_chain_config);

    let running_participants = assert_running_return_participants(&contract).await?;
    let participants: Participants = (&running_participants).into_contract_type();
    let threshold = GovernanceThresholdParameters::new(
        participants.clone(),
        GovernanceThreshold::new((participants.len() as u64 * 3).div_ceil(5)),
    )
    .unwrap();
    // `SandboxTestSetup` leaves the contract at epoch 5, and a reshare must advance it.
    let epoch = EpochId(6);

    vote_new_parameters(&contract, epoch.0, &threshold, &mpc_signer_accounts, &[]).await?;

    let ProtocolContractState::Resharing(resharing) = get_state(&contract).await else {
        anyhow::bail!("expected resharing state");
    };
    let domain_id = resharing.previous_running_state.domains.domains[0].id;
    let key_event_id = KeyEventId {
        epoch_id: epoch,
        domain_id,
        attempt_id: AttemptId(0),
    };
    start_reshare_instance(&contract, &mpc_signer_accounts, key_event_id).await?;

    // Vote one participant at a time and keep the most recent vote's gas burn. The state is
    // re-read before each vote rather than after: `get_state` is an optimistic view call and
    // can lag the receipt that commits the transition, so checking on the next iteration
    // gives it time to settle. Whichever vote was last before the state reads `Running` is
    // the concluding one — the vote that spawns the cleanup promises.
    let mut last_vote_tgas = None;
    for account in &mpc_signer_accounts {
        if matches!(
            get_state(&contract).await,
            ProtocolContractState::Running(_)
        ) {
            let burnt_tgas =
                last_vote_tgas.context("state reached Running before any vote was cast")?;
            return Ok(DecidingVote {
                burnt_tgas,
                reserved_tgas,
            });
        }

        let result = account
            .call(contract.id(), method_names::VOTE_RESHARED)
            .args_json(json!({ "key_event_id": key_event_id }))
            .gas(Gas::from_tgas(PRODUCTION_VOTE_RESHARED_TGAS))
            .transact()
            .await?;
        anyhow::ensure!(
            result.is_success(),
            "vote_reshared from {} failed: {:?}",
            account.id(),
            result.failures()
        );

        let receipt = result
            .receipt_outcomes()
            .first()
            .expect("function call produces at least one receipt");
        last_vote_tgas = Some(receipt.gas_burnt.as_gas() as f64 / 1e12);
    }

    anyhow::ensure!(
        matches!(
            get_state(&contract).await,
            ProtocolContractState::Running(_)
        ),
        "resharing did not conclude after every participant voted"
    );
    Ok(DecidingVote {
        burnt_tgas: last_vote_tgas.context("no vote was cast")?,
        reserved_tgas,
    })
}

/// Gas accounting for the `vote_reshared` call that concluded a resharing.
struct DecidingVote {
    /// Gas burnt by the `vote_reshared` function-call receipt itself.
    burnt_tgas: f64,
    /// Gas it reserved for the cleanup promises it scheduled, summed from the live config.
    reserved_tgas: u64,
}

/// Sums the budgets of the six cleanup promises `MpcContract::vote_reshared` schedules once a
/// resharing concludes. Reading them off the config keeps this in step with `Config::default()`
/// and with any value operators vote in.
fn reserved_cleanup_promise_tgas(config: &dtos::Config) -> u64 {
    config.remove_non_participant_update_votes_tera_gas
        + config.clean_tee_status_tera_gas
        + config.clean_invalid_attestations_tera_gas
        + config.cleanup_orphaned_node_migrations_tera_gas
        + config.clean_foreign_chain_data_tera_gas
        + config.remove_non_participant_tee_verifier_votes_tera_gas
}
