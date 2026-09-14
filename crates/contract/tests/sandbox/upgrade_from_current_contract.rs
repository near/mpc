#![allow(non_snake_case)] // Tests use the `<sut>__should_<assertion>` form mandated by CLAUDE.md.

use crate::sandbox::{
    common::{
        SandboxTestSetup, execute_key_generation_and_add_random_state,
        propose_and_vote_contract_binary, vote_update_till_completion,
    },
    utils::{
        consts::{
            ALL_PROTOCOLS, CURRENT_CONTRACT_DEPLOY_DEPOSIT, GAS_FOR_VOTE_BEFORE_THRESHOLD,
            MAX_GAS_FOR_THRESHOLD_VOTE, PARTICIPANT_LEN,
        },
        contract_build::{current_contract, migration_contract},
        interface::IntoContractType,
        mpc_contract::{
            assert_running_return_participants, assert_running_return_threshold, get_state,
        },
        transactions::CallMpcContract,
    },
};
use near_mpc_contract_interface::call_args::VoteUpdateArgs;
use near_mpc_contract_interface::method_names;
use near_mpc_contract_interface::types::{
    self as dtos, ProposeUpdateArgs, Protocol, ProtocolContractState, UpdateId,
};
use near_sdk::Gas;
use near_workspaces::{Contract, result::ExecutionFinalResult};
use rand_core::OsRng;
use rstest::rstest;

pub fn dummy_contract_proposal() -> ProposeUpdateArgs {
    ProposeUpdateArgs {
        code: Some(vec![1, 2, 3]),
        config: None,
    }
}

pub fn invalid_contract_proposal() -> ProposeUpdateArgs {
    let new_wasm = b"invalid wasm".to_vec();
    ProposeUpdateArgs {
        code: Some(new_wasm),
        config: None,
    }
}

pub fn current_contract_proposal() -> ProposeUpdateArgs {
    ProposeUpdateArgs {
        code: Some(current_contract().to_vec()),
        config: None,
    }
}

#[tokio::test]
async fn test_propose_contract_max_size_upload() {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .build()
        .await;
    dbg!(contract.id());

    // check that we can propose an update with the maximum contract size.
    let execution = mpc_signer_accounts[0]
        .call_mpc(contract.id())
        .propose_update(ProposeUpdateArgs {
            code: Some(vec![0; 1536 * 1024 - 400]), //3900 seems to not work locally
            config: None,
        })
        .await
        .unwrap();
    dbg!(&execution);
    assert!(
        execution.is_success(),
        "Failed to propose update with our highest contract size"
    );
}

#[tokio::test]
async fn test_propose_update_config() {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .build()
        .await;
    let threshold = assert_running_return_threshold(&contract).await;
    dbg!(contract.id());

    // contract should not be able to propose updates unless it's a part of the participant/voter set.
    let execution = contract
        .as_account()
        .call_mpc(contract.id())
        .propose_update(dummy_contract_proposal())
        .await
        .unwrap();
    dbg!(&execution);
    assert!(
        execution
            .into_result()
            .unwrap_err()
            .to_string()
            .contains("not a voter")
    );

    // have each participant propose a new update:
    let new_config = near_mpc_contract_interface::types::Config {
        key_event_timeout_blocks: 11,
        tee_upgrade_deadline_duration_seconds: 22,
        contract_upgrade_deposit_tera_gas: 33,
        sign_call_gas_attachment_requirement_tera_gas: 44,
        ckd_call_gas_attachment_requirement_tera_gas: 55,
        return_signature_and_clean_state_on_success_call_tera_gas: 66,
        return_ck_and_clean_state_on_success_call_tera_gas: 77,
        fail_on_timeout_tera_gas: 88,
        fail_attestation_submission_tera_gas: 89,
        clean_tee_status_tera_gas: 99,
        clean_invalid_attestations_tera_gas: 101,
        cleanup_orphaned_node_migrations_tera_gas: 11,
        remove_non_participant_update_votes_tera_gas: 12,
        clean_foreign_chain_data_tera_gas: 13,
        remove_non_participant_tee_verifier_votes_tera_gas: 14,
        verifier_tera_gas: 15,
        resolve_verification_tera_gas: 16,
        attestation_storage_fee_millinear: 20,
        // Must satisfy `Config::validate` (>= DEFAULT_EXPIRATION_DURATION_SECONDS).
        launcher_hash_unused_ttl_seconds: 14 * 24 * 60 * 60,
    };

    let propose_args = ProposeUpdateArgs {
        code: None,
        config: Some(new_config.clone()),
    };

    let mut proposals = Vec::with_capacity(mpc_signer_accounts.len());
    for account in &mpc_signer_accounts {
        let propose_execution = account
            .call_mpc(contract.id())
            .propose_update(propose_args.clone())
            .await
            .unwrap();
        dbg!(&propose_execution);
        assert!(propose_execution.is_success());
        let proposal_id: UpdateId = propose_execution.json().unwrap();
        dbg!(&proposal_id);
        proposals.push(proposal_id);
    }

    let old_config: near_mpc_contract_interface::types::Config = contract
        .view(method_names::CONFIG)
        .await
        .unwrap()
        .json()
        .unwrap();
    let state: ProtocolContractState = get_state(&contract).await;

    // check that each participant can vote on a singular proposal and have it reflect changes:
    let first_proposal = &proposals[0];
    for (i, voter) in mpc_signer_accounts.iter().enumerate() {
        dbg!(voter.id());
        let execution = voter
            .call_mpc(contract.id())
            .vote_update(*first_proposal)
            .await
            .unwrap();

        // NOTE: since threshold out of total participants are required to pass a proposal, having the `threshold+1` one also
        // vote should fail.
        if i < threshold.0 as usize {
            assert!(
                execution.is_success(),
                "execution should have succeeded: {state:#?}\n{execution:#?}"
            );
        } else {
            assert!(
                execution.is_failure(),
                "execution should have failed: {state:#?}\n{execution:#?}"
            );
        }
    }
    // check that the proposal executed since the threshold got changed.
    let config: near_mpc_contract_interface::types::Config = contract
        .view(method_names::CONFIG)
        .await
        .unwrap()
        .json()
        .unwrap();

    assert_ne!(config, old_config);
    assert_eq!(config, new_config);
}

#[tokio::test]
async fn test_propose_update_contract() {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .build()
        .await;
    propose_and_vote_contract_binary(&mpc_signer_accounts, &contract, current_contract()).await;
}

#[tokio::test]
async fn test_invalid_contract_deploy() {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .build()
        .await;
    dbg!(contract.id());

    // Let's propose a contract update instead now.
    let execution = mpc_signer_accounts[0]
        .call_mpc(contract.id())
        .propose_update(invalid_contract_proposal())
        .await
        .unwrap();
    dbg!(&execution);
    assert!(execution.is_success());
    let proposal_id: UpdateId = execution.json().unwrap();
    vote_update_till_completion(&contract, &mpc_signer_accounts, proposal_id).await;

    // Try calling into state and see if it works after the contract updates with an invalid
    // contract. It will fail in `migrate` so a state rollback on the contract code should have
    // happened.
    let execution = mpc_signer_accounts[0]
        .call(contract.id(), method_names::STATE)
        .transact()
        .await
        .unwrap();

    dbg!(&execution);
    let state: ProtocolContractState = execution.json().unwrap();
    dbg!(state);
}

// TODO(#496): Investigate flakiness of this test
#[tokio::test]
async fn test_propose_update_contract_many() {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .build()
        .await;
    dbg!(contract.id());

    const PROPOSAL_COUNT: usize = 2;
    let mut proposals = Vec::with_capacity(PROPOSAL_COUNT);
    // Try to propose multiple updates to check if they are being proposed correctly
    // and that we can have many at once living in the contract state.
    for i in 0..PROPOSAL_COUNT {
        let execution = mpc_signer_accounts[i % mpc_signer_accounts.len()]
            .call_mpc(contract.id())
            .propose_update(current_contract_proposal())
            .await
            .unwrap();

        assert!(
            execution.is_success(),
            "failed to propose update [i={i}]; {execution:#?}"
        );
        let proposal_id: UpdateId = execution
            .json()
            .expect("unable to convert into an update id");
        proposals.push(proposal_id);
    }

    // Vote for the last proposal
    vote_update_till_completion(&contract, &mpc_signer_accounts, *proposals.last().unwrap()).await;

    // Ensure all proposals are removed after update
    for proposal in proposals {
        let voter = mpc_signer_accounts.first().unwrap();
        let execution = voter
            .call_mpc(contract.id())
            .vote_update(proposal)
            .await
            .unwrap();
        dbg!(&execution);

        assert!(execution.is_failure());
    }

    // Let's check that we can call into the state and see all the proposals.
    let state: ProtocolContractState = get_state(&contract).await;
    dbg!(state);
}

/// Regression test for issue #1617: ensures that voting on contract updates (before reaching
/// threshold) is cheap.
#[tokio::test]
async fn test_vote_update_gas_before_threshold() {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .build()
        .await;

    let execution = mpc_signer_accounts[0]
        .call_mpc(contract.id())
        .propose_update(current_contract_proposal())
        .await
        .unwrap();

    assert!(execution.is_success(), "failed to propose update");
    let proposal_id: UpdateId = execution.json().unwrap();

    // Cast votes until threshold is reached (need 6 total votes)
    for (idx, account) in mpc_signer_accounts[1..=5].iter().enumerate() {
        let execution = account
            .call(contract.id(), method_names::VOTE_UPDATE)
            .args_json(serde_json::json!({
                "id": proposal_id,
            }))
            .gas(GAS_FOR_VOTE_BEFORE_THRESHOLD)
            .transact()
            .await
            .unwrap();

        let gas_burnt = execution.total_gas_burnt;

        assert!(execution.is_success());

        let update_occurred: bool = execution.json().unwrap();
        assert!(!update_occurred);

        assert!(
            gas_burnt.as_tgas() <= GAS_FOR_VOTE_BEFORE_THRESHOLD.as_tgas(),
            "Gas usage for vote {} ({} TGas) should be <= {} TGas",
            idx + 1,
            gas_burnt.as_tgas(),
            GAS_FOR_VOTE_BEFORE_THRESHOLD.as_tgas()
        );
    }

    // Cast the threshold vote (6th vote) that will trigger the update
    let threshold_execution = mpc_signer_accounts[6]
        .call(contract.id(), method_names::VOTE_UPDATE)
        .args_json(serde_json::json!({
            "id": proposal_id,
        }))
        .max_gas()
        .transact()
        .await
        .unwrap();

    let threshold_gas_burnt = threshold_execution.total_gas_burnt;

    assert!(threshold_execution.is_success());

    let update_occurred: bool = threshold_execution.json().unwrap();
    assert!(update_occurred);

    assert!(
        threshold_gas_burnt.as_tgas() <= MAX_GAS_FOR_THRESHOLD_VOTE.as_tgas(),
        "Gas usage for threshold vote ({} TGas) should be <= {} TGas",
        threshold_gas_burnt.as_tgas(),
        MAX_GAS_FOR_THRESHOLD_VOTE.as_tgas()
    );
}

#[tokio::test]
async fn test_propose_incorrect_updates() {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .build()
        .await;
    dbg!(contract.id());

    let dummy_config = near_mpc_contract_interface::types::InitConfig::default();

    // Can not propose update both to code and config
    let execution = mpc_signer_accounts[0]
        .call(contract.id(), method_names::PROPOSE_UPDATE)
        .args_borsh((dummy_contract_proposal(), dummy_config))
        .max_gas()
        .deposit(CURRENT_CONTRACT_DEPLOY_DEPOSIT)
        .transact()
        .await
        .unwrap();
    dbg!(&execution);
    assert!(execution.is_failure());

    // Should propose something
    let execution = mpc_signer_accounts[0]
        .call(contract.id(), method_names::PROPOSE_UPDATE)
        .args_borsh(())
        .max_gas()
        .deposit(CURRENT_CONTRACT_DEPLOY_DEPOSIT)
        .transact()
        .await
        .unwrap();
    dbg!(&execution);
    assert!(execution.is_failure());
}

/// Contract update include some logic regarding state clean-up,
/// thus we want to test whether some problem builds up eventually.
#[tokio::test]
async fn many_sequential_updates() {
    let number_of_participants = PARTICIPANT_LEN;
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .with_number_of_participants(number_of_participants)
        .build()
        .await;
    dbg!(contract.id());
    let number_of_updates = 3;
    for _ in 0..number_of_updates {
        propose_and_vote_contract_binary(&mpc_signer_accounts, &contract, current_contract()).await;
    }
}

/// There are:
///     * two proposals: A and B
///     * three participants (Alice, Bob, Carl), with a threshold two
/// What happens:
///     1. Alice votes for A
///     2. Alice votes for B
///     3. Bob votes for A -> Update for A _should not_ be triggered
///     4. Bob votes for B -> Update for B is triggered
#[tokio::test]
async fn only_one_vote_from_participant() {
    let number_of_participants = 3;
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .with_number_of_participants(number_of_participants)
        .build()
        .await;
    dbg!(contract.id());

    let contract_handle = mpc_signer_accounts[0].call_mpc(contract.id());
    let execution = contract_handle
        .propose_update(current_contract_proposal())
        .await
        .unwrap();
    dbg!(&execution);
    assert!(execution.is_success());
    let proposal_a: UpdateId = execution.json().unwrap();

    let execution = contract_handle
        .propose_update(current_contract_proposal())
        .await
        .unwrap();
    dbg!(&execution);
    assert!(execution.is_success());
    let proposal_b: UpdateId = execution.json().unwrap();

    let execution = mpc_signer_accounts[0]
        .call_mpc(contract.id())
        .vote_update(proposal_a)
        .await
        .unwrap();
    dbg!(&execution);
    assert!(execution.is_success());
    let update_occurred: bool = execution.json().unwrap();
    assert!(!update_occurred);

    let execution = mpc_signer_accounts[0]
        .call_mpc(contract.id())
        .vote_update(proposal_b)
        .await
        .unwrap();
    dbg!(&execution);
    assert!(execution.is_success());
    let update_occurred: bool = execution.json().unwrap();
    assert!(!update_occurred);

    let execution = mpc_signer_accounts[1]
        .call_mpc(contract.id())
        .vote_update(proposal_a)
        .await
        .unwrap();
    dbg!(&execution);
    assert!(execution.is_success());
    let update_occurred: bool = execution.json().unwrap();
    assert!(!update_occurred);

    let execution = mpc_signer_accounts[1]
        .call_mpc(contract.id())
        .vote_update(proposal_b)
        .await
        .unwrap();
    dbg!(&execution);
    assert!(execution.is_success());
    let update_occurred: bool = execution.json().unwrap();
    assert!(update_occurred);
}

/// Tests that we can upgrade the current contract to a new binary. The new contract binary used is
/// the migration contract, [`migration_contract`].
#[tokio::test]
async fn update_from_current_contract_to_migration_contract() {
    // We don't add any initial domains on init, since we will domains
    // in add_dummy_state_and_pending_sign_requests call below.
    let SandboxTestSetup {
        worker,
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder().build().await;

    let participants = assert_running_return_participants(&contract)
        .await
        .expect("Contract must be in running state.");

    execute_key_generation_and_add_random_state(
        &mpc_signer_accounts,
        participants.into_contract_type(),
        &contract,
        &worker,
        &mut OsRng,
    )
    .await;
    propose_and_vote_contract_binary(&mpc_signer_accounts, &contract, migration_contract()).await;
}

#[tokio::test]
async fn migration_function_rejects_external_callers() {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_number_of_participants(2)
        .build()
        .await;

    let execution_error = mpc_signer_accounts[0]
        .call(contract.id(), method_names::MIGRATE)
        .max_gas()
        .transact()
        .await
        .unwrap()
        .into_result()
        .expect_err("method is private and not callable from participant account.");

    let error_message = format!("{:?}", execution_error);

    let expected_error_message = "Smart contract panicked: Method migrate is private";

    assert!(
        error_message.contains(expected_error_message),
        "migrate call was accepted by external caller. expected method to be private. {:?}",
        error_message
    )
}

/// Reproduces the mainnet failure of 2026-09-14: the deciding `vote_update` sweeps every stored
/// entry in a single receipt, and with several full-size code proposals stored the receipt exceeds
/// the per-receipt storage proof limit. All proposals hold the same binary, mirroring `v1.signer`,
/// where the four stored entries are byte-identical.
#[rstest]
#[case::one_proposal(1)]
#[case::two_proposals(2)]
#[case::three_proposals(3)]
#[case::four_proposals(4)]
#[case::six_proposals(6)]
#[tokio::test]
async fn vote_update__should_apply_the_update_when_several_code_proposals_are_stored(
    #[case] stored_proposals: usize,
) {
    // Given
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(&[Protocol::CaitSith])
        .build()
        .await;

    let mut proposal_id = None;
    for (index, account) in mpc_signer_accounts
        .iter()
        .cycle()
        .take(stored_proposals)
        .enumerate()
    {
        let execution = account
            .call_mpc(contract.id())
            .propose_update(current_contract_proposal())
            .await
            .unwrap();
        assert!(
            execution.is_success(),
            "proposal {index} failed: {execution:#?}"
        );
        proposal_id = Some(execution.json().unwrap());
    }
    let proposal_id: UpdateId = proposal_id.expect("at least one proposal");

    // When
    let mut deciding_vote_gas = None;
    for voter in &mpc_signer_accounts {
        let execution = voter
            .call_mpc(contract.id())
            .vote_update(proposal_id)
            .await
            .unwrap();
        let gas_burnt = execution.total_gas_burnt;
        assert!(
            execution.is_success(),
            "stored_proposals={stored_proposals} voter={} gas={} TGas failures={:#?}",
            voter.id(),
            gas_burnt.as_tgas(),
            execution.failures()
        );
        let update_occurred: bool = execution.json().unwrap();
        println!(
            "stored_proposals={stored_proposals} voter={} gas={} TGas update_occurred={update_occurred}",
            voter.id(),
            gas_burnt.as_tgas(),
        );
        if update_occurred {
            deciding_vote_gas = Some(gas_burnt);
            break;
        }
    }

    // Then
    let deciding_vote_gas = deciding_vote_gas.expect("threshold reached");
    println!(
        "RESULT stored_proposals={stored_proposals} deciding_vote_gas={} TGas",
        deciding_vote_gas.as_tgas()
    );
    let proposed_updates: dtos::ProposedUpdates = contract
        .view(method_names::PROPOSED_UPDATES)
        .await
        .unwrap()
        .json()
        .unwrap();
    assert!(proposed_updates.updates.is_empty());
}

/// Diagnostic: maps the storage-proof boundary of the deciding `vote_update` against the number of
/// stored entries and their size, for byte-identical and for distinct payloads. Reports rather than
/// asserts, so a single run yields the whole table.
#[rstest]
#[case::identical_7x500k(7, 500_000, true)]
#[case::identical_8x500k(8, 500_000, true)]
#[case::distinct_7x500k(7, 500_000, false)]
#[case::distinct_8x500k(8, 500_000, false)]
#[case::distinct_3x1200k(3, 1_200_000, false)]
#[case::distinct_4x1200k(4, 1_200_000, false)]
#[tokio::test]
async fn vote_update__storage_proof_boundary(
    #[case] proposals: usize,
    #[case] payload_bytes: usize,
    #[case] identical: bool,
) {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(&[Protocol::CaitSith])
        .build()
        .await;

    let storage_before = contract.view_account().await.unwrap().storage_usage;
    let mut proposal_id = None;
    let mut storage_after_first = storage_before;
    for (index, account) in mpc_signer_accounts
        .iter()
        .cycle()
        .take(proposals)
        .enumerate()
    {
        let mut code = vec![0x42u8; payload_bytes];
        if !identical {
            code[0] = u8::try_from(index).unwrap();
        }
        let execution = account
            .call_mpc(contract.id())
            .propose_update(ProposeUpdateArgs {
                code: Some(code),
                config: None,
            })
            .await
            .unwrap();
        assert!(execution.is_success(), "proposal {index} failed");
        proposal_id = Some(execution.json().unwrap());
        if index == 0 {
            storage_after_first = contract.view_account().await.unwrap().storage_usage;
        }
    }
    let proposal_id: UpdateId = proposal_id.unwrap();

    let mut outcome = "no threshold".to_string();
    let mut deciding_gas = 0;
    for voter in &mpc_signer_accounts {
        let execution = voter
            .call_mpc(contract.id())
            .vote_update(proposal_id)
            .await
            .unwrap();
        deciding_gas = execution.total_gas_burnt.as_tgas();
        if !execution.is_success() {
            outcome = format!("FAIL {:?}", execution.failures()[0].clone().into_result());
            break;
        }
        if execution.json::<bool>().unwrap() {
            outcome = "PASS".to_string();
            break;
        }
    }

    println!(
        "BOUNDARY proposals={proposals} payload={payload_bytes} identical={identical} \
         value_bytes={} bytes_times_proposals={} deciding_gas={deciding_gas}TGas outcome={outcome}",
        storage_after_first - storage_before,
        (storage_after_first - storage_before) * u64::try_from(proposals).unwrap(),
    );
}

/// Number of stored proposals used by the overhead probe, matching mainnet's `v1.signer`.
const OVERHEAD_PROBE_PROPOSALS: usize = 4;

/// Runs one deciding `vote_update` against `OVERHEAD_PROBE_PROPOSALS` stored proposals of
/// `payload_bytes` each, and reports whether the receipt stayed inside the storage proof limit.
async fn probe_deciding_vote(payload_bytes: usize) -> bool {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .with_number_of_participants(15)
        .build()
        .await;

    let mut proposal_id = None;
    for (index, account) in mpc_signer_accounts
        .iter()
        .cycle()
        .take(OVERHEAD_PROBE_PROPOSALS)
        .enumerate()
    {
        let mut code = vec![0x42u8; payload_bytes];
        code[0] = u8::try_from(index).unwrap();
        let execution = account
            .call_mpc(contract.id())
            .propose_update(ProposeUpdateArgs {
                code: Some(code),
                config: None,
            })
            .await
            .unwrap();
        assert!(execution.is_success(), "proposal {index} failed");
        proposal_id = Some(execution.json().unwrap());
    }
    let proposal_id: UpdateId = proposal_id.unwrap();

    for voter in &mpc_signer_accounts {
        let execution = voter
            .call_mpc(contract.id())
            .vote_update(proposal_id)
            .await
            .unwrap();
        if !execution.is_success() {
            let failure = format!("{:?}", execution.failures()[0].clone().into_result());
            assert!(
                failure.contains("recorded trie storage proof"),
                "unexpected failure: {failure}"
            );
            return false;
        }
        if execution.json::<bool>().unwrap() {
            return true;
        }
    }
    panic!("threshold never reached");
}

/// Measures the non-value overhead the deciding `vote_update` records, by bisecting the payload
/// size against the live `per_receipt_storage_proof_size_limit`. The stored value of a proposal is
/// `payload + 25` bytes, so a run passes iff `proposals * (payload + 25) + overhead <= limit`.
#[tokio::test]
async fn vote_update__measure_storage_proof_overhead() {
    const LIMIT: usize = 4_000_000;
    const VALUE_OVERHEAD_BYTES: usize = 25;
    const TOLERANCE: usize = 2048;

    let mut passing = 900_000;
    let mut failing = 1_000_000;
    assert!(
        probe_deciding_vote(passing).await,
        "lower bound should pass"
    );
    assert!(
        !probe_deciding_vote(failing).await,
        "upper bound should fail"
    );

    while failing - passing > TOLERANCE {
        let midpoint = (passing + failing) / 2;
        if probe_deciding_vote(midpoint).await {
            passing = midpoint;
        } else {
            failing = midpoint;
        }
        println!("PROBE passing={passing} failing={failing}");
    }

    let recorded = |payload: usize| OVERHEAD_PROBE_PROPOSALS * (payload + VALUE_OVERHEAD_BYTES);
    println!(
        "OVERHEAD limit={LIMIT} largest_passing_payload={passing} smallest_failing_payload={failing} \
         overhead_lower_bound={} overhead_upper_bound={}",
        LIMIT.saturating_sub(recorded(failing)),
        LIMIT - recorded(passing),
    );
}

/// Gas values that halt a `proposed_updates` probe after it has read a given number of stored
/// entries. The host records an entry's value only once the read has been paid for, about 6.9 TGas
/// at mainnet's proposal size, and a full iteration over one entry costs about 41 TGas, most of it
/// hashing the code. So one entry is recorded between roughly 11 and 51 TGas, two between roughly
/// 52 and 93 TGas.
const PROBE_GAS_FOR_ONE_ENTRY: Gas = Gas::from_tgas(30);
const PROBE_GAS_FOR_TWO_ENTRIES: Gas = Gas::from_tgas(70);
/// Below the read charge for a single entry, so the probe records nothing.
const PROBE_GAS_BELOW_THE_FIRST_READ: Gas = Gas::from_tgas(10);

/// Gas the interface crate attaches to `vote_update`, and the protocol maximum.
const CLIENT_VOTE_GAS: Gas = Gas::from_tgas(260);
const MAX_VOTE_GAS: Gas = Gas::from_tgas(300);

/// Size of each code proposal stored on mainnet `v1.signer` (`signer-3_15_0.wasm`).
const MAINNET_PROPOSAL_PAYLOAD_BYTES: usize = 1_229_682;

/// Stores `stored_proposals` copies of `payload`, casts every vote below the threshold, asserts the
/// deciding vote fails on its own, then re-sends it behind a gas-capped `proposed_updates` probe in
/// the same chunk and returns that outcome together with the contract.
async fn deciding_vote_behind_probe(
    stored_proposals: usize,
    payload: Vec<u8>,
    probe_gas: Gas,
    vote_gas: Gas,
) -> (ExecutionFinalResult, Contract) {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .with_number_of_participants(15)
        .build()
        .await;

    let mut proposal_id = None;
    for account in mpc_signer_accounts.iter().cycle().take(stored_proposals) {
        let execution = account
            .call_mpc(contract.id())
            .propose_update(ProposeUpdateArgs {
                code: Some(payload.clone()),
                config: None,
            })
            .await
            .unwrap();
        assert!(execution.is_success(), "{execution:#?}");
        proposal_id = Some(execution.json().unwrap());
    }
    let proposal_id: UpdateId = proposal_id.unwrap();
    let vote_args = VoteUpdateArgs::new(proposal_id);

    let threshold = assert_running_return_threshold(&contract).await.0 as usize;
    for voter in &mpc_signer_accounts[..threshold - 1] {
        let execution = voter
            .call_mpc(contract.id())
            .vote_update(proposal_id)
            .await
            .unwrap();
        assert!(execution.is_success(), "{execution:#?}");
        assert!(!execution.json::<bool>().unwrap());
    }

    let decider = &mpc_signer_accounts[threshold - 1];
    let cold = decider
        .call(contract.id(), method_names::VOTE_UPDATE)
        .args_json(&vote_args)
        .gas(vote_gas)
        .transact()
        .await
        .unwrap();
    assert!(
        format!("{:?}", cold.failures()).contains("recorded trie storage proof"),
        "the deciding vote is expected to fail without a probe: {cold:#?}"
    );

    let mut attempt = 0;
    loop {
        attempt += 1;
        let probe = decider
            .call(contract.id(), method_names::PROPOSED_UPDATES)
            .args(b"{}".to_vec())
            .gas(probe_gas)
            .transact_async()
            .await
            .unwrap();
        let deciding = decider
            .call(contract.id(), method_names::VOTE_UPDATE)
            .args_json(&vote_args)
            .gas(vote_gas)
            .transact_async()
            .await
            .unwrap();
        let probe = probe.await.unwrap();
        let deciding = deciding.await.unwrap();
        let same_chunk =
            probe.receipt_outcomes()[0].block_hash == deciding.receipt_outcomes()[0].block_hash;
        println!(
            "stored_proposals={stored_proposals} payload={} probe_gas={}TGas attempt={attempt} \
             same_chunk={same_chunk} deciding_gas={}TGas storage_proof_error={}",
            payload.len(),
            probe_gas.as_tgas(),
            deciding.total_gas_burnt.as_tgas(),
            format!("{:?}", deciding.failures()).contains("recorded trie storage proof"),
        );
        if same_chunk {
            return (deciding, contract);
        }
        assert!(
            attempt < 5,
            "the probe and the deciding vote never shared a chunk"
        );
    }
}

/// Reads the ids of the proposals the contract still stores.
async fn stored_proposal_ids(contract: &Contract) -> Vec<UpdateId> {
    let proposed_updates: dtos::ProposedUpdates = contract
        .view(method_names::PROPOSED_UPDATES)
        .await
        .unwrap()
        .json()
        .unwrap();
    proposed_updates.updates.into_keys().collect()
}

/// The per-receipt storage proof limit is a delta against a recorder that lives for the whole
/// chunk, and that recorder bills a trie value once per chunk. A cheap earlier receipt in the same
/// chunk that reads stored entries therefore takes their bytes off the deciding vote's bill, which
/// is enough to bring mainnet's four stored proposals back under the limit without touching the
/// contract, the account or the runtime.
#[rstest]
#[case::four_proposals_one_entry_probed(4, PROBE_GAS_FOR_ONE_ENTRY, CLIENT_VOTE_GAS)]
#[case::four_proposals_two_entries_probed(4, PROBE_GAS_FOR_TWO_ENTRIES, CLIENT_VOTE_GAS)]
#[case::five_proposals_two_entries_probed(5, PROBE_GAS_FOR_TWO_ENTRIES, MAX_VOTE_GAS)]
#[tokio::test]
async fn vote_update__should_apply_when_an_earlier_receipt_in_the_chunk_recorded_proposals(
    #[case] stored_proposals: usize,
    #[case] probe_gas: Gas,
    #[case] vote_gas: Gas,
) {
    // Given / When
    let (deciding, contract) = deciding_vote_behind_probe(
        stored_proposals,
        current_contract().to_vec(),
        probe_gas,
        vote_gas,
    )
    .await;

    // Then
    assert!(deciding.is_success(), "{deciding:#?}");
    assert!(deciding.json::<bool>().unwrap());
    assert!(stored_proposal_ids(&contract).await.is_empty());
}

/// Mainnet stores four proposals of 1,229,682 bytes each, larger than the contract this test suite
/// builds. The payload is filler rather than wasm, so the deploy that follows the vote fails and
/// the cleared proposals are what shows the deciding vote itself applied.
#[tokio::test]
async fn vote_update__should_apply_at_the_mainnet_proposal_size_when_one_entry_is_probed() {
    // Given / When
    let (deciding, contract) = deciding_vote_behind_probe(
        4,
        vec![0x42; MAINNET_PROPOSAL_PAYLOAD_BYTES],
        PROBE_GAS_FOR_ONE_ENTRY,
        CLIENT_VOTE_GAS,
    )
    .await;

    // Then
    assert!(
        !format!("{:?}", deciding.failures()).contains("recorded trie storage proof"),
        "{deciding:#?}"
    );
    assert!(stored_proposal_ids(&contract).await.is_empty());
}

/// The host records an entry's value only after charging for the read, so a probe that cannot
/// afford one full entry read leaves the deciding vote with the whole bill.
#[tokio::test]
async fn vote_update__should_exceed_the_storage_proof_limit_when_the_probe_cannot_pay_for_a_read() {
    // Given / When
    let (deciding, contract) = deciding_vote_behind_probe(
        4,
        vec![0x42; MAINNET_PROPOSAL_PAYLOAD_BYTES],
        PROBE_GAS_BELOW_THE_FIRST_READ,
        CLIENT_VOTE_GAS,
    )
    .await;

    // Then
    assert!(
        format!("{:?}", deciding.failures()).contains("recorded trie storage proof"),
        "{deciding:#?}"
    );
    assert_eq!(stored_proposal_ids(&contract).await.len(), 4);
}

/// A probe only discounts the entries it actually read, so each probed entry buys exactly one
/// stored proposal of headroom: five stored proposals need two probed entries, not one.
#[tokio::test]
async fn vote_update__should_exceed_the_storage_proof_limit_when_the_probe_read_too_few_entries() {
    // Given / When
    let (deciding, contract) = deciding_vote_behind_probe(
        5,
        current_contract().to_vec(),
        PROBE_GAS_FOR_ONE_ENTRY,
        MAX_VOTE_GAS,
    )
    .await;

    // Then
    assert!(
        format!("{:?}", deciding.failures()).contains("recorded trie storage proof"),
        "{deciding:#?}"
    );
    assert_eq!(stored_proposal_ids(&contract).await.len(), 5);
}
