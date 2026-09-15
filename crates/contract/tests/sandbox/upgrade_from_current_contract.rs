#![expect(non_snake_case)]

use crate::sandbox::{
    common::{
        SandboxTestSetup, execute_key_generation_and_add_random_state,
        vote_and_submit_contract_binary, vote_update_till_approved,
    },
    utils::{
        consts::{ALL_PROTOCOLS, GAS_FOR_VOTE_UPDATE, MAX_GAS_FOR_SUBMIT_UPDATE, PARTICIPANT_LEN},
        contract_build::{current_contract, migration_contract},
        interface::IntoContractType,
        mpc_contract::{
            assert_running_return_participants, assert_running_return_threshold, get_state,
        },
        transactions::CallMpcContract,
    },
};
use near_mpc_contract_interface::method_names;
use near_mpc_contract_interface::types::{ProtocolContractState, Update};
use near_mpc_sdk::update::hash;
use rand_core::OsRng;
use sha2::Digest;

pub fn current_contract_update() -> Update {
    Update::Code(current_contract().to_vec())
}

/// Votes for `update_hash` until approved, then submits `update` from `accounts[0]`.
async fn vote_and_submit(
    accounts: &[near_workspaces::Account],
    contract: &near_workspaces::Contract,
    update: Update,
) -> near_workspaces::result::ExecutionFinalResult {
    vote_update_till_approved(contract, accounts, hash(&update)).await;
    accounts[0]
        .call_mpc(contract.id())
        .submit_update(update)
        .await
        .unwrap()
}

#[tokio::test]
async fn submit_update__should_accept_a_maximum_size_code_payload() {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .build()
        .await;

    // The payload is not valid Wasm, so only the call itself is expected to succeed: the deploy
    // receipt fails and rolls back.
    let execution = vote_and_submit(
        &mpc_signer_accounts,
        &contract,
        Update::Code(vec![0; 1536 * 1024 - 400]), //3900 seems to not work locally
    )
    .await;
    dbg!(&execution);
    assert!(
        execution.is_success(),
        "Failed to submit an update with our highest contract size"
    );
}

#[tokio::test]
async fn vote_update__should_reject_non_voters() {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .build()
        .await;

    // The contract account is not a participant.
    let execution = contract
        .as_account()
        .call_mpc(contract.id())
        .vote_update(hash(&current_contract_update()))
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

    let execution = mpc_signer_accounts[0]
        .call_mpc(contract.id())
        .vote_update(hash(&current_contract_update()))
        .await
        .unwrap();
    assert!(execution.is_success(), "{execution:#?}");
}

#[tokio::test]
async fn submit_update__should_apply_an_approved_config() {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .build()
        .await;
    let threshold = assert_running_return_threshold(&contract).await;

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
    let update = Update::Config(new_config.clone());

    let old_config: near_mpc_contract_interface::types::Config = contract
        .view(method_names::CONFIG)
        .await
        .unwrap()
        .json()
        .unwrap();
    assert_ne!(old_config, new_config);

    // Exactly `threshold` votes approve the hash; the approving vote returns `true`.
    for (i, voter) in mpc_signer_accounts.iter().enumerate() {
        let execution = voter
            .call_mpc(contract.id())
            .vote_update(hash(&update))
            .await
            .unwrap();
        let approved: bool = execution.json().unwrap();
        assert_eq!(approved, i + 1 == threshold.0 as usize, "vote {i}");
        if approved {
            break;
        }
    }

    let execution = mpc_signer_accounts[0]
        .call_mpc(contract.id())
        .submit_update(update)
        .await
        .unwrap();
    assert!(execution.failures().is_empty(), "{execution:#?}");

    let config: near_mpc_contract_interface::types::Config = contract
        .view(method_names::CONFIG)
        .await
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(config, new_config);
}

#[tokio::test]
async fn submit_update__should_deploy_the_approved_binary() {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .build()
        .await;
    vote_and_submit_contract_binary(&mpc_signer_accounts, &contract, current_contract()).await;
}

#[tokio::test]
async fn submit_update__should_roll_back_an_invalid_binary() {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .build()
        .await;
    let code_before = contract.view_code().await.unwrap();

    let execution = vote_and_submit(
        &mpc_signer_accounts,
        &contract,
        Update::Code(b"invalid wasm".to_vec()),
    )
    .await;
    dbg!(&execution);

    // The call is accepted; the deploy receipt fails and the state rolls back, so the previous
    // code keeps serving.
    assert!(execution.is_success());
    assert!(!execution.receipt_failures().is_empty());
    let code_after = contract.view_code().await.unwrap();
    assert_eq!(
        sha2::Sha256::digest(&code_before),
        sha2::Sha256::digest(&code_after)
    );
    let state: ProtocolContractState = get_state(&contract).await;
    dbg!(state);
}

#[tokio::test]
async fn submit_update__should_reject_a_payload_without_approval() {
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
        .submit_update(current_contract_update())
        .await
        .unwrap();
    dbg!(&execution);

    assert!(
        execution
            .into_result()
            .unwrap_err()
            .to_string()
            .contains("does not match the approved update hash")
    );
}

#[tokio::test]
async fn submit_update__should_consume_the_approval() {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .build()
        .await;

    vote_and_submit_contract_binary(&mpc_signer_accounts, &contract, current_contract()).await;

    let execution = mpc_signer_accounts[0]
        .call_mpc(contract.id())
        .submit_update(current_contract_update())
        .await
        .unwrap();
    dbg!(&execution);
    assert!(execution.is_failure());
}

/// Regression test for issue #1617: ensures that voting on contract updates is cheap, and bounds
/// the cost of submitting the binary.
#[tokio::test]
async fn vote_update__should_stay_cheap_and_submit_update_within_budget() {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .build()
        .await;
    let threshold = assert_running_return_threshold(&contract).await;
    let update = current_contract_update();

    for (idx, account) in mpc_signer_accounts.iter().enumerate() {
        let execution = account
            .call(contract.id(), method_names::VOTE_UPDATE)
            .args_json(serde_json::json!({
                "update_hash": hash(&update),
            }))
            .gas(GAS_FOR_VOTE_UPDATE)
            .transact()
            .await
            .unwrap();

        let gas_burnt = execution.total_gas_burnt;
        assert!(execution.is_success(), "vote {}: {execution:#?}", idx + 1);
        assert!(
            gas_burnt.as_tgas() <= GAS_FOR_VOTE_UPDATE.as_tgas(),
            "Gas usage for vote {} ({} TGas) should be <= {} TGas",
            idx + 1,
            gas_burnt.as_tgas(),
            GAS_FOR_VOTE_UPDATE.as_tgas()
        );

        let approved: bool = execution.json().unwrap();
        assert_eq!(approved, idx + 1 == threshold.0 as usize);
        if approved {
            break;
        }
    }

    let execution = mpc_signer_accounts[0]
        .call_mpc(contract.id())
        .submit_update(update)
        .await
        .unwrap();
    assert!(execution.failures().is_empty(), "{execution:#?}");
    let gas_burnt = execution.total_gas_burnt;
    assert!(
        gas_burnt.as_tgas() <= MAX_GAS_FOR_SUBMIT_UPDATE.as_tgas(),
        "Gas usage for submit_update ({} TGas) should be <= {} TGas",
        gas_burnt.as_tgas(),
        MAX_GAS_FOR_SUBMIT_UPDATE.as_tgas()
    );
}

#[tokio::test]
async fn submit_update__should_reject_malformed_payloads() {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .build()
        .await;

    // Not a borsh-encoded `Update`.
    let execution = mpc_signer_accounts[0]
        .call(contract.id(), method_names::SUBMIT_UPDATE)
        .args_borsh(())
        .max_gas()
        .transact()
        .await
        .unwrap();
    dbg!(&execution);
    assert!(execution.is_failure());

    // An unknown variant tag.
    let execution = mpc_signer_accounts[0]
        .call(contract.id(), method_names::SUBMIT_UPDATE)
        .args_borsh(7u8)
        .max_gas()
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
        vote_and_submit_contract_binary(&mpc_signer_accounts, &contract, current_contract()).await;
    }
}

/// There are:
///     * two update hashes: A and B
///     * three participants (Alice, Bob, Carl), with a threshold two
/// What happens:
///     1. Alice votes for A
///     2. Alice votes for B
///     3. Bob votes for A -> A _should not_ be approved
///     4. Bob votes for B -> B is approved
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

    let hash_a = hash(&Update::Code(vec![0xaa; 100]));
    let hash_b = hash(&Update::Code(vec![0xbb; 100]));

    for (voter, update_hash, expected_approved) in [
        (0, &hash_a, false),
        (0, &hash_b, false),
        (1, &hash_a, false),
        (1, &hash_b, true),
    ] {
        let execution = mpc_signer_accounts[voter]
            .call_mpc(contract.id())
            .vote_update(update_hash.clone())
            .await
            .unwrap();
        dbg!(&execution);
        assert!(execution.is_success());
        let approved: bool = execution.json().unwrap();
        assert_eq!(approved, expected_approved);
    }
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
    vote_and_submit_contract_binary(&mpc_signer_accounts, &contract, migration_contract()).await;
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
