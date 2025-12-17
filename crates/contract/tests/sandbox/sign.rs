use crate::sandbox::common::{
    candidates, init, init_env, submit_signature_response, ContractSetup, PARTICIPANT_LEN,
};
use mpc_contract::{
    errors,
    primitives::{
        domain::SignatureScheme,
        participants::Participants,
        thresholds::{Threshold, ThresholdParameters},
    },
};
use near_workspaces::types::NearToken;
use utilities::AccountIdExtV1;

const NON_CKD_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::Secp256k1,
    SignatureScheme::V2Secp256k1,
    SignatureScheme::Ed25519,
];

const SIGNATURE_TIMEOUT_BLOCKS: u64 = 200;
const NUM_BLOCKS_BETWEEN_REQUESTS: u64 = 2;

#[tokio::test]
async fn test_contract_sign_request_all_schemes() -> anyhow::Result<()> {
    let ContractSetup {
        worker,
        contract,
        mpc_signer_accounts,
        keys,
    } = init_env(NON_CKD_SCHEMES, PARTICIPANT_LEN).await;

    let attested_account = &mpc_signer_accounts[0];
    let path = "test";
    let alice = worker.dev_create_account().await.unwrap();
    let predecessor_id = alice.id();
    let messages = [
        "hello world",
        "hello world!",
        "hello world!!",
        "hello world!!!",
        "hello world!!!!",
    ];

    for key in &keys {
        for msg in messages {
            {
                println!("submitting: {msg}");
                let req = key.create_sign_request(&predecessor_id.as_v2_account_id(), msg, path);
                req.sign_and_validate(&alice, &contract, attested_account)
                    .await
                    .unwrap();
            }
        }

        {
            // check that in case of duplicate request, only the most recent will be signed:
            let msg = "welp";
            println!("submitting: {msg}");
            let req = key.create_sign_request(&predecessor_id.as_v2_account_id(), msg, path);
            let status_1 = req.sign_ensure_included(&alice, &contract).await?;
            worker
                .fast_forward(NUM_BLOCKS_BETWEEN_REQUESTS)
                .await
                .unwrap();
            let status_2 = req.sign_ensure_included(&alice, &contract).await?;
            worker
                .fast_forward(NUM_BLOCKS_BETWEEN_REQUESTS)
                .await
                .unwrap();
            submit_signature_response(&req.response, &contract, attested_account).await?;
            req.verify_execution_outcome(status_2)
                .await
                .expect("most recent signature request should succeed");
            worker.fast_forward(SIGNATURE_TIMEOUT_BLOCKS).await.unwrap();
            req.verify_timeout(status_1)
                .await
                .expect("initial signature request should time out");
        }

        {
            // Check that a sign with no response from MPC network properly errors out:
            let msg = "this should timeout";
            println!("submitting: {msg}");
            let req = key.create_sign_request(&predecessor_id.as_v2_account_id(), msg, path);
            let status = req.sign_ensure_included(&alice, &contract).await?;
            worker.fast_forward(SIGNATURE_TIMEOUT_BLOCKS).await.unwrap();
            req.verify_timeout(status).await.unwrap();
        }
    }
    Ok(())
}

#[tokio::test]
async fn test_contract_sign_success_refund() -> anyhow::Result<()> {
    let ContractSetup {
        worker,
        contract,
        mpc_signer_accounts,
        keys,
    } = init_env(NON_CKD_SCHEMES, PARTICIPANT_LEN).await;
    let attested_account = &mpc_signer_accounts[0];

    let alice = worker.dev_create_account().await?;
    let balance = alice.view_account().await?.balance;
    let contract_balance = contract.view_account().await?.balance;
    let path = "test";
    let msg = "hello world!";

    for key in &keys {
        println!("submitting: {msg}");
        let req = key.create_sign_request(&alice.id().as_v2_account_id(), msg, path);
        req.sign_and_validate(&alice, &contract, attested_account)
            .await?;

        let new_balance = alice.view_account().await?.balance;
        let new_contract_balance = contract.view_account().await?.balance;
        assert!(
            balance.as_millinear() - new_balance.as_millinear() < 10,
            "refund should happen"
        );
        assert!(
            contract_balance.as_millinear() <= new_contract_balance.as_millinear(),
            "contract balance should not decrease after refunding deposit"
        );
        // probably not necessary, but better safe than race condition
        worker
            .fast_forward(NUM_BLOCKS_BETWEEN_REQUESTS)
            .await
            .unwrap();
    }
    Ok(())
}

#[tokio::test]
async fn test_contract_sign_fail_refund() -> anyhow::Result<()> {
    let ContractSetup {
        worker,
        contract,
        keys,
        ..
    } = init_env(NON_CKD_SCHEMES, PARTICIPANT_LEN).await;
    let alice = worker.dev_create_account().await?;
    let balance = alice.view_account().await?.balance;
    let contract_balance = contract.view_account().await?.balance;
    let path = "test";

    let msg = "hello world!";
    println!("submitting: {msg}");
    for key in &keys {
        let req = key.create_sign_request(&alice.id().as_v2_account_id(), msg, path);
        let status = req.sign_ensure_included(&alice, &contract).await?;
        worker.fast_forward(SIGNATURE_TIMEOUT_BLOCKS).await.unwrap();
        // we do not respond, sign will fail due to timeout
        req.verify_timeout(status).await?;

        let new_balance = alice.view_account().await?.balance;
        let new_contract_balance = contract.view_account().await?.balance;
        assert!(balance >= new_balance, "user balance should not increase");
        assert!(
            balance.as_millinear() - new_balance.as_millinear() < 10,
            "refund should happen"
        );
        assert!(
            contract_balance.as_millinear() <= new_contract_balance.as_millinear(),
            "contract balance should not decrease after refunding deposit"
        );
    }
    Ok(())
}

#[tokio::test]
async fn test_contract_sign_request_deposits() -> anyhow::Result<()> {
    let ContractSetup {
        contract,
        mpc_signer_accounts,
        keys,
        ..
    } = init_env(NON_CKD_SCHEMES, PARTICIPANT_LEN).await;
    let attested_account = &mpc_signer_accounts[0];
    let predecessor_id = contract.id();
    let path = "testing-no-deposit";

    for key in &keys {
        // Try to sign with no deposit, should fail.
        let msg = "without-deposit";
        let req = key.create_sign_request(&predecessor_id.as_v2_account_id(), msg, path);
        let status = contract
            .call("sign")
            .args_json(req.request_json_args())
            .max_gas()
            .transact_async()
            .await?;
        dbg!(&status);

        // Responding to the request should fail with missing request because the deposit is too low,
        // so the request should have never made it into the request queue and subsequently the MPC network.
        let respond = submit_signature_response(&req.response, &contract, attested_account).await;
        dbg!(&respond);
        assert!(respond
            .unwrap_err()
            .to_string()
            .contains(&errors::InvalidParameters::RequestNotFound.to_string()));

        let execution = status.await?;
        dbg!(&execution);
        assert!(execution
            .into_result()
            .unwrap_err()
            .to_string()
            .contains(&errors::InvalidParameters::InsufficientDeposit.to_string()));
    }
    Ok(())
}

#[tokio::test]
async fn test_sign_v1_compatibility() -> anyhow::Result<()> {
    let ContractSetup {
        contract,
        mpc_signer_accounts,
        keys,
        ..
    } = init_env(&[SignatureScheme::Secp256k1], PARTICIPANT_LEN).await;
    let key = &keys[0];
    const LEGACY_KEY_VERSION: u64 = 0; // this is the first cait-sith domain in the contract
    assert_eq!(key.domain_id().0, LEGACY_KEY_VERSION);
    let attested_account = &mpc_signer_accounts[0];
    let predecessor_id = contract.id();
    let path = "test";

    let messages = [
        "hello world",
        "hello world!",
        "hello world!!",
        "hello world!!!",
        "hello world!!!!",
    ];

    for msg in messages {
        println!("submitting: {msg}");
        let req = key.create_sign_request(&predecessor_id.as_v2_account_id(), msg, path);
        let status = contract
            .call("sign")
            .args_json(serde_json::json!({
                "request": {
                    "payload": req.payload().as_ecdsa().unwrap(),
                    "path": path,
                    "key_version": LEGACY_KEY_VERSION,
                },
            }))
            .deposit(NearToken::from_yoctonear(1))
            .max_gas()
            .transact_async()
            .await?;
        dbg!(&status);

        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

        // Call `respond` as if we are the MPC network itself.
        submit_signature_response(&req.response, &contract, attested_account).await?;
        req.verify_execution_outcome(status).await?;
    }
    Ok(())
}

#[tokio::test]
async fn test_contract_initialization() -> anyhow::Result<()> {
    let (_, contract) = init().await;

    // Empty candidates should fail.
    let participants = Participants::new();
    let threshold = Threshold::new(0);
    let proposed_parameters = ThresholdParameters::new_unvalidated(participants, threshold);
    let result = contract
        .call("init")
        .args_json(serde_json::json!({
            "parameters": proposed_parameters,
        }))
        .transact()
        .await?;
    assert!(
        result.is_failure(),
        "initializing with zero candidates or less than threshold candidates should fail"
    );

    let proposed_parameters =
        ThresholdParameters::new(candidates(None), Threshold::new(3)).unwrap();
    let result = contract
        .call("init")
        .args_json(serde_json::json!({
            "parameters": proposed_parameters,
        }))
        .transact()
        .await?;
    assert!(
        result.is_success(),
        "initializing with valid candidates should succeed"
    );

    // Reinitializing after the first successful initialization should fail.
    let result = contract
        .call("init")
        .args_json(serde_json::json!({
            "parameters": proposed_parameters,
            "config": "null",
        }))
        .transact()
        .await?;
    assert!(
        result.is_failure(),
        "initializing with valid candidates again should fail"
    );

    Ok(())
}
