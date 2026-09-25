#![expect(non_snake_case)]

use crate::sandbox::{
    common::{
        SandboxTestSetup, approve_contract_update, execute_key_generation_and_add_random_state,
        vote_and_submit_contract_binary,
    },
    utils::{
        consts::{ALL_PROTOCOLS, PARTICIPANT_LEN},
        contract_build::{current_contract, migration_contract},
        interface::IntoContractType,
        mpc_contract::assert_running_return_participants,
        transactions::CallMpcContract,
    },
};
use near_mpc_contract_interface::method_names;
use near_mpc_contract_interface::types::{ProtocolContractState, Update};
use near_mpc_sdk::update::hash;
use rand_core::OsRng;

pub fn dummy_contract_update() -> Update {
    Update::Code(vec![1, 2, 3])
}

pub fn invalid_contract_update() -> Update {
    Update::Code(b"invalid wasm".to_vec())
}

pub fn current_contract_update() -> Update {
    Update::Code(current_contract().to_vec())
}

#[tokio::test]
async fn submit_contract_update__should_accept_a_payload_of_the_maximum_contract_size() {
    // Given
    let SandboxTestSetup {
        worker: _worker,
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .build()
        .await;
    let update = Update::Code(vec![0; 1536 * 1024 - 400]); //3900 seems to not work locally
    approve_contract_update(&contract, &mpc_signer_accounts, hash(&update)).await;

    // When
    let execution = mpc_signer_accounts[0]
        .call_mpc(contract.id())
        .submit_contract_update(update)
        .await
        .unwrap();

    // Then
    assert!(execution.is_success(), "{execution:#?}");
}

#[tokio::test]
async fn vote_contract_update__should_reject_a_non_participant() {
    // Given
    let SandboxTestSetup {
        worker: _worker,
        contract,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .build()
        .await;

    // When
    let execution = contract
        .as_account()
        .call_mpc(contract.id())
        .vote_contract_update(hash(&dummy_contract_update()))
        .await
        .unwrap();

    // Then
    let failure = execution.into_result().unwrap_err().to_string();
    assert!(failure.contains("Not a participant"), "{failure}");
}

#[tokio::test]
async fn submit_contract_update__should_apply_an_approved_config() {
    // Given
    let SandboxTestSetup {
        worker: _worker,
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .build()
        .await;
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
        launcher_hash_unused_ttl_seconds: 14 * 24 * 60 * 60,
    };

    let update = Update::Config(new_config.clone());
    let old_config: near_mpc_contract_interface::types::Config = contract
        .view(method_names::CONFIG)
        .await
        .unwrap()
        .json()
        .unwrap();
    approve_contract_update(&contract, &mpc_signer_accounts, hash(&update)).await;

    // When
    let execution = mpc_signer_accounts[0]
        .call_mpc(contract.id())
        .submit_contract_update(update)
        .await
        .unwrap();

    // Then
    assert!(execution.failures().is_empty(), "{execution:#?}");
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
async fn submit_contract_update__should_apply_an_approved_code_update() {
    let SandboxTestSetup {
        worker: _worker,
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
async fn submit_contract_update__should_keep_the_old_code_when_the_new_binary_is_invalid() {
    // Given
    let SandboxTestSetup {
        worker: _worker,
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .build()
        .await;
    let update = invalid_contract_update();
    approve_contract_update(&contract, &mpc_signer_accounts, hash(&update)).await;

    // When
    let execution = mpc_signer_accounts[0]
        .call_mpc(contract.id())
        .submit_contract_update(update)
        .await
        .unwrap();

    // Then
    assert!(execution.is_success(), "{execution:#?}");
    assert!(!execution.receipt_failures().is_empty());
    let execution = mpc_signer_accounts[0]
        .call(contract.id(), method_names::STATE)
        .transact()
        .await
        .unwrap();
    let _state: ProtocolContractState = execution.json().unwrap();
}

#[tokio::test]
async fn submit_contract_update__should_consume_the_approval() {
    // Given
    let SandboxTestSetup {
        worker: _worker,
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .build()
        .await;
    vote_and_submit_contract_binary(&mpc_signer_accounts, &contract, current_contract()).await;

    // When
    let execution = mpc_signer_accounts[0]
        .call_mpc(contract.id())
        .submit_contract_update(current_contract_update())
        .await
        .unwrap();

    // Then
    dbg!(&execution);
    assert!(execution.is_failure());
}

/// Contract update include some logic regarding state clean-up,
/// thus we want to test whether some problem builds up eventually.
#[tokio::test]
async fn submit_contract_update__should_apply_several_updates_in_sequence() {
    let number_of_participants = PARTICIPANT_LEN;
    let SandboxTestSetup {
        worker: _worker,
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
async fn vote_contract_update__should_replace_the_participants_earlier_vote() {
    // Given
    let SandboxTestSetup {
        worker: _worker,
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .with_number_of_participants(3)
        .build()
        .await;
    let hash_a = hash(&dummy_contract_update());
    let hash_b = hash(&current_contract_update());
    let alice = mpc_signer_accounts[0].call_mpc(contract.id());
    let bob = mpc_signer_accounts[1].call_mpc(contract.id());
    for update_hash in [hash_a.clone(), hash_b.clone()] {
        alice
            .vote_contract_update(update_hash)
            .await
            .unwrap()
            .into_result()
            .unwrap();
    }

    // When
    let approved_a: bool = bob
        .vote_contract_update(hash_a)
        .await
        .unwrap()
        .json()
        .unwrap();
    let approved_b: bool = bob
        .vote_contract_update(hash_b)
        .await
        .unwrap()
        .json()
        .unwrap();

    // Then
    assert!(!approved_a);
    assert!(approved_b);
}

/// Tests that we can upgrade the current contract to a new binary. The new contract binary used is
/// the migration contract, [`migration_contract`].
#[tokio::test]
async fn submit_contract_update__should_apply_a_code_update_that_migrates_state() {
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
        worker: _worker,
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
