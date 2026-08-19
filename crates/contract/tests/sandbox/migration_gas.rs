//! Gas headroom for the `3.14.1` migration, which rewrites one stored dstack attestation per
//! participant inside the deploy + migrate receipt. That receipt's gas is capped by
//! `contract_upgrade_deposit_tera_gas`, and a migration that overruns it reverts the whole
//! upgrade, so the cost has to be checked against the largest participant set we expect.

#![allow(non_snake_case)]

use crate::sandbox::{
    common::{SandboxTestSetup, propose_and_vote_contract_binary},
    utils::{
        contract_build::current_contract_with_sandbox_test_methods,
        mpc_contract::assert_running_return_participants,
    },
};
use near_mpc_contract_interface::{method_names, types::VerifiedAttestation};
use serde_json::json;

const PARTICIPANTS: usize = 25;
const SEEDED_EXPIRY_SECONDS: u64 = 1_000_000;

/// `DEFAULT_EXPIRATION_DURATION_SECONDS` minus `PRE_3_14_1_EXPIRATION_DURATION_SECONDS`.
const EXPECTED_SHIFT_SECONDS: u64 = 14 * 24 * 60 * 60;

#[tokio::test]
async fn migrate__should_extend_every_participant_expiry_within_the_upgrade_gas_budget() {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_number_of_participants(PARTICIPANTS)
        .with_sandbox_test_methods()
        .build()
        .await;

    let participants = assert_running_return_participants(&contract).await.unwrap();
    let entries = participants.participants.clone();
    assert_eq!(entries.len(), PARTICIPANTS);

    for (account_id, _, info) in &entries {
        let outcome = contract
            .as_account()
            .call(contract.id(), "store_dstack_attestation")
            .args_json(json!({
                "node_id": {
                    "account_id": account_id,
                    "tls_public_key": info.tls_public_key,
                    "account_public_key": info.tls_public_key,
                },
                "expiry_timestamp_seconds": SEEDED_EXPIRY_SECONDS,
            }))
            .max_gas()
            .transact()
            .await
            .expect("seeding a stored dstack attestation should not error");
        assert!(outcome.is_success(), "seeding failed: {outcome:#?}");
    }

    propose_and_vote_contract_binary(
        &mpc_signer_accounts,
        &contract,
        current_contract_with_sandbox_test_methods(),
    )
    .await;

    // Every participant's expiry advanced, so `migrate` ran to completion. Had it exceeded the
    // receipt's gas, the deploy would have reverted with it and these would be unchanged.
    for (_, _, info) in &entries {
        let stored: Option<VerifiedAttestation> = contract
            .view(method_names::GET_ATTESTATION)
            .args_json(json!({ "tls_public_key": info.tls_public_key }))
            .await
            .expect("get_attestation view should succeed")
            .json()
            .expect("get_attestation should return a verified attestation");

        let Some(VerifiedAttestation::Dstack(dstack)) = stored else {
            panic!("expected a stored dstack attestation, got {stored:?}");
        };
        assert_eq!(
            dstack.expiry_timestamp_seconds,
            SEEDED_EXPIRY_SECONDS + EXPECTED_SHIFT_SECONDS
        );
    }
}
