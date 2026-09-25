use crate::sandbox::{
    common::{
        SandboxTestSetup, execute_key_generation_and_add_random_state,
        vote_and_submit_contract_binary, vote_update_till_approved,
    },
    utils::{
        consts::{ALL_PROTOCOLS, PARTICIPANT_LEN},
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
async fn test_propose_contract_max_size_upload() {
    let SandboxTestSetup {
        worker: _worker,
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .build()
        .await;
    dbg!(contract.id());

    // check that we can submit an update with the maximum contract size. The payload is not
    // valid Wasm, so only the call itself succeeds.
    let update = Update::Code(vec![0; 1536 * 1024 - 400]); //3900 seems to not work locally
    vote_update_till_approved(&contract, &mpc_signer_accounts, hash(&update)).await;
    let execution = mpc_signer_accounts[0]
        .call_mpc(contract.id())
        .submit_contract_update(update)
        .await
        .unwrap();
    dbg!(&execution);
    assert!(
        execution.is_success(),
        "Failed to submit update with our highest contract size"
    );
}

#[tokio::test]
async fn test_propose_update_config() {
    let SandboxTestSetup {
        worker: _worker,
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .build()
        .await;
    let threshold = assert_running_return_threshold(&contract).await;
    dbg!(contract.id());

    // contract should not be able to vote for updates unless it's a part of the participant/voter set.
    let execution = contract
        .as_account()
        .call_mpc(contract.id())
        .vote_contract_update(hash(&dummy_contract_update()))
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

    // have each participant vote for a new config:
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
    let update_hash = hash(&update);

    let old_config: near_mpc_contract_interface::types::Config = contract
        .view(method_names::CONFIG)
        .await
        .unwrap()
        .json()
        .unwrap();
    let state: ProtocolContractState = get_state(&contract).await;

    // check that the threshold vote is the one that approves the config:
    for (i, voter) in mpc_signer_accounts.iter().enumerate() {
        dbg!(voter.id());
        let execution = voter
            .call_mpc(contract.id())
            .vote_contract_update(update_hash.clone())
            .await
            .unwrap();

        assert!(
            execution.is_success(),
            "execution should have succeeded: {state:#?}\n{execution:#?}"
        );
        let approved: bool = execution.json().unwrap();
        assert_eq!(approved, i + 1 == threshold.0 as usize);
        if approved {
            break;
        }
    }

    // check that submitting the approved config applies it.
    let execution = mpc_signer_accounts[0]
        .call_mpc(contract.id())
        .submit_contract_update(update)
        .await
        .unwrap();
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
async fn test_propose_update_contract() {
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
async fn test_invalid_contract_deploy() {
    let SandboxTestSetup {
        worker: _worker,
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .build()
        .await;
    dbg!(contract.id());

    // Let's submit an invalid contract update instead now.
    let update = invalid_contract_update();
    vote_update_till_approved(&contract, &mpc_signer_accounts, hash(&update)).await;
    let execution = mpc_signer_accounts[0]
        .call_mpc(contract.id())
        .submit_contract_update(update)
        .await
        .unwrap();
    dbg!(&execution);
    assert!(execution.is_success());
    assert!(!execution.receipt_failures().is_empty());

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

#[tokio::test]
#[expect(non_snake_case)]
async fn submit_update__should_consume_the_approval() {
    let SandboxTestSetup {
        worker: _worker,
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .build()
        .await;
    dbg!(contract.id());

    vote_and_submit_contract_binary(&mpc_signer_accounts, &contract, current_contract()).await;

    // Applying the update cleared the votes.
    let execution = mpc_signer_accounts[0]
        .call_mpc(contract.id())
        .submit_contract_update(current_contract_update())
        .await
        .unwrap();
    dbg!(&execution);
    assert!(execution.is_failure());

    let state: ProtocolContractState = get_state(&contract).await;
    dbg!(state);
}

#[tokio::test]
async fn test_propose_incorrect_updates() {
    let SandboxTestSetup {
        worker: _worker,
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .build()
        .await;
    dbg!(contract.id());

    // Can not submit an update that is not a borsh-encoded `Update`
    let execution = mpc_signer_accounts[0]
        .call(contract.id(), method_names::SUBMIT_CONTRACT_UPDATE)
        .args_borsh(())
        .max_gas()
        .transact()
        .await
        .unwrap();
    dbg!(&execution);
    assert!(execution.is_failure());

    // Can not submit an unknown `Update` variant
    let execution = mpc_signer_accounts[0]
        .call(contract.id(), method_names::SUBMIT_CONTRACT_UPDATE)
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
async fn only_one_vote_from_participant() {
    let number_of_participants = 3;
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

    let hash_a = hash(&dummy_contract_update());
    let hash_b = hash(&current_contract_update());

    let execution = mpc_signer_accounts[0]
        .call_mpc(contract.id())
        .vote_contract_update(hash_a.clone())
        .await
        .unwrap();
    dbg!(&execution);
    assert!(execution.is_success());
    let approved: bool = execution.json().unwrap();
    assert!(!approved);

    let execution = mpc_signer_accounts[0]
        .call_mpc(contract.id())
        .vote_contract_update(hash_b.clone())
        .await
        .unwrap();
    dbg!(&execution);
    assert!(execution.is_success());
    let approved: bool = execution.json().unwrap();
    assert!(!approved);

    let execution = mpc_signer_accounts[1]
        .call_mpc(contract.id())
        .vote_contract_update(hash_a)
        .await
        .unwrap();
    dbg!(&execution);
    assert!(execution.is_success());
    let approved: bool = execution.json().unwrap();
    assert!(!approved);

    let execution = mpc_signer_accounts[1]
        .call_mpc(contract.id())
        .vote_contract_update(hash_b)
        .await
        .unwrap();
    dbg!(&execution);
    assert!(execution.is_success());
    let approved: bool = execution.json().unwrap();
    assert!(approved);
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
