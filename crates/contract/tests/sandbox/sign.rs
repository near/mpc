use crate::sandbox::{
    common::{candidates, create_account_given_id, init, init_env, SandboxTestSetup},
    utils::{
        consts::{ALL_SIGNATURE_SCHEMES, PARTICIPANT_LEN},
        shared_key_utils::SharedSecretKey,
        sign_utils::{
            gen_secp_256k1_sign_test, submit_signature_response, verify_timeout, DomainResponseTest,
        },
    },
};
use anyhow::Context;
use mpc_contract::{
    errors,
    primitives::{
        domain::SignatureScheme,
        participants::Participants,
        thresholds::{Threshold, ThresholdParameters},
    },
};
use near_account_id::AccountId;
use near_workspaces::types::NearToken;
use rand::SeedableRng;
use std::time::Duration;

const SIGNATURE_TIMEOUT_BLOCKS: u64 = 200;
const NUM_BLOCKS_BETWEEN_REQUESTS: u64 = 2;

#[tokio::test]
async fn test_contract_request_all_schemes() -> anyhow::Result<()> {
    let mut rng = rand::rngs::StdRng::from_seed([1u8; 32]);
    let SandboxTestSetup {
        worker,
        contract,
        mpc_signer_accounts,
        keys,
    } = init_env(ALL_SIGNATURE_SCHEMES, PARTICIPANT_LEN).await;
    let attested_account = &mpc_signer_accounts[0];

    let account_ids: [AccountId; 5] = [
        "alice".parse().unwrap(),
        "this_is_an_app".parse().unwrap(),
        "another".parse().unwrap(),
        "a_better_one".parse().unwrap(),
        "a_fake_one".parse().unwrap(),
    ];

    for predecessor_id in account_ids {
        let alice = create_account_given_id(&worker, predecessor_id)
            .await
            .unwrap()
            .unwrap();
        let predecessor_id = alice.id();
        for key in &keys {
            {
                let req = DomainResponseTest::new(&mut rng, key, predecessor_id);
                req.run(&alice, &contract, attested_account)
                    .await
                    .with_context(|| format!("{:?}", req))
                    .unwrap();
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn test_contract_request_duplicate_requests_all_schemes() -> anyhow::Result<()> {
    let mut rng = rand::rngs::StdRng::from_seed([1u8; 32]);
    let SandboxTestSetup {
        worker,
        contract,
        mpc_signer_accounts,
        keys,
    } = init_env(ALL_SIGNATURE_SCHEMES, PARTICIPANT_LEN).await;
    let attested_account = &mpc_signer_accounts[0];

    for key in &keys {
        let alice = worker.dev_create_account().await.unwrap();
        let predecessor_id = alice.id();
        // check that in case of duplicate request, only the most recent will be signed:
        let req = DomainResponseTest::new(&mut rng, key, predecessor_id);
        let status_1 = req
            .submit_request_ensure_included(&alice, &contract)
            .await?;
        worker
            .fast_forward(NUM_BLOCKS_BETWEEN_REQUESTS)
            .await
            .unwrap();
        let status_2 = req
            .submit_request_ensure_included(&alice, &contract)
            .await?;

        // unfortunately, we still can't completely get rid of this sleep
        // TODO(#1306): remove the need to sleep
        tokio::time::sleep(Duration::from_secs(3)).await;
        worker
            .fast_forward(NUM_BLOCKS_BETWEEN_REQUESTS)
            .await
            .unwrap();
        req.submit_response(&contract, attested_account).await?;
        req.verify_execution_outcome(status_2)
            .await
            .expect("most recent signature request should succeed");
        worker.fast_forward(SIGNATURE_TIMEOUT_BLOCKS).await.unwrap();
        verify_timeout(status_1)
            .await
            .expect("initial signature request should time out");
    }
    Ok(())
}

#[tokio::test]
async fn test_contract_request_timeout_all_schemes() -> anyhow::Result<()> {
    let mut rng = rand::rngs::StdRng::from_seed([1u8; 32]);
    let SandboxTestSetup {
        worker,
        contract,
        keys,
        ..
    } = init_env(ALL_SIGNATURE_SCHEMES, PARTICIPANT_LEN).await;

    for key in &keys {
        let alice = worker.dev_create_account().await.unwrap();
        let predecessor_id = alice.id();
        // Check that a sign with no response from MPC network properly errors out:
        let req = DomainResponseTest::new(&mut rng, key, predecessor_id);
        let status = req
            .submit_request_ensure_included(&alice, &contract)
            .await?;
        worker.fast_forward(SIGNATURE_TIMEOUT_BLOCKS).await.unwrap();
        verify_timeout(status).await.unwrap();
    }
    Ok(())
}

#[tokio::test]
async fn test_contract_success_refund_all_schemes() -> anyhow::Result<()> {
    let SandboxTestSetup {
        worker,
        contract,
        mpc_signer_accounts,
        keys,
    } = init_env(ALL_SIGNATURE_SCHEMES, PARTICIPANT_LEN).await;
    let mut rng = rand::rngs::StdRng::from_seed([1u8; 32]);
    let attested_account = &mpc_signer_accounts[0];

    let alice = worker.dev_create_account().await?;
    let balance = alice.view_account().await?.balance;
    let mut contract_balance = contract.view_account().await?.balance;

    for key in &keys {
        let req = DomainResponseTest::new(&mut rng, key, alice.id());
        req.run(&alice, &contract, attested_account).await?;

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

        contract_balance = new_contract_balance
    }
    Ok(())
}

#[tokio::test]
async fn test_contract_fail_refund_all_schemes() -> anyhow::Result<()> {
    let SandboxTestSetup {
        worker,
        contract,
        keys,
        ..
    } = init_env(ALL_SIGNATURE_SCHEMES, PARTICIPANT_LEN).await;
    let mut rng = rand::rngs::StdRng::from_seed([2u8; 32]);
    let alice = worker.dev_create_account().await?;
    let balance = alice.view_account().await?.balance;
    let mut contract_balance = contract.view_account().await?.balance;

    for key in &keys {
        let req = DomainResponseTest::new(&mut rng, key, alice.id());
        let status = req
            .submit_request_ensure_included(&alice, &contract)
            .await?;
        worker.fast_forward(SIGNATURE_TIMEOUT_BLOCKS).await.unwrap();
        // we do not respond, sign will fail due to timeout
        verify_timeout(status).await?;

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
        contract_balance = new_contract_balance;
    }
    Ok(())
}

#[tokio::test]
async fn test_contract_request_deposits_all_schemes() -> anyhow::Result<()> {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        keys,
        ..
    } = init_env(ALL_SIGNATURE_SCHEMES, PARTICIPANT_LEN).await;
    let mut rng = rand::rngs::StdRng::from_seed([1u8; 32]);
    let attested_account = &mpc_signer_accounts[0];
    let predecessor_id = contract.id();

    for key in &keys {
        // Try to sign with no deposit, should fail.
        let req = DomainResponseTest::new(&mut rng, key, predecessor_id);
        let status = match &req {
            DomainResponseTest::Sign(req) => {
                let status = contract
                    .call("sign")
                    .args_json(req.request_json_args())
                    .max_gas()
                    .transact_async()
                    .await?;
                dbg!(&status);
                status
            }
            DomainResponseTest::CKD(req) => {
                let status = contract
                    .call("request_app_private_key")
                    .args_json(req.request_json_args())
                    .max_gas()
                    .transact_async()
                    .await?;
                dbg!(&status);
                status
            }
        };

        // Responding to the request should fail with missing request because the deposit is too low,
        // so the request should have never made it into the request queue and subsequently the MPC network.
        let respond = req.submit_response(&contract, attested_account).await;
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
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        keys,
        ..
    } = init_env(&[SignatureScheme::Secp256k1], PARTICIPANT_LEN).await;
    let mut rng = rand::rngs::StdRng::from_seed([1u8; 32]);
    let key = &keys[0];
    const LEGACY_KEY_VERSION: u64 = 0; // this is the first cait-sith domain in the contract
    const NUM_MSGS: usize = 5;
    assert_eq!(key.domain_id().0, LEGACY_KEY_VERSION);
    let SharedSecretKey::Secp256k1(sk) = &key.domain_secret_key else {
        anyhow::bail!("expected secp256k1");
    };
    let attested_account = &mpc_signer_accounts[0];
    let predecessor_id = contract.id();

    for _ in 0..NUM_MSGS {
        let req = gen_secp_256k1_sign_test(&mut rng, key.domain_id(), predecessor_id, sk);

        let status = contract
            .call("sign")
            .args_json(serde_json::json!({
                "request": {
                    "payload": req.payload().as_ecdsa().unwrap(),
                    "path": req.path(),
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
