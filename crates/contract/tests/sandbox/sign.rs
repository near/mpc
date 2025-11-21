use crate::sandbox::common::{
    candidates, create_message_payload_and_response, init, init_env, sign_and_validate,
    PARTICIPANT_LEN,
};
use mpc_contract::{
    config::InitConfig,
    crypto_shared::SignatureResponse,
    errors,
    primitives::{
        domain::{DomainId, SignatureScheme},
        participants::Participants,
        signature::SignRequestArgs,
        thresholds::{Threshold, ThresholdParameters},
    },
};
use near_workspaces::types::NearToken;

// TODO: #1194
// Domain id 0 is always present if we have at least one domain on the contract.
// In all tests below we initialize at least one domain to test sign requests against.
const DOMAIN_ID_ZERO: DomainId = DomainId(0);

#[tokio::test]
async fn test_contract_sign_request() -> anyhow::Result<()> {
    let (worker, contract, mpc_nodes, sks) =
        init_env(&[SignatureScheme::Secp256k1], PARTICIPANT_LEN).await;
    let attested_account = &mpc_nodes[0];

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

    for msg in messages {
        println!("submitting: {msg}");
        let (payload, respond_req, respond_resp) =
            create_message_payload_and_response(DOMAIN_ID_ZERO, predecessor_id, msg, path, &sks[0])
                .await;
        let request = SignRequestArgs {
            payload_v2: Some(payload),
            path: path.into(),
            domain_id: Some(DOMAIN_ID_ZERO),
            ..Default::default()
        };

        sign_and_validate(
            &alice,
            &request,
            Some((&respond_req, &respond_resp)),
            &contract,
            attested_account,
        )
        .await?;
    }

    // check duplicate requests can also be signed:
    let duplicate_msg = "welp";
    let (payload, respond_req, respond_resp) = create_message_payload_and_response(
        DOMAIN_ID_ZERO,
        predecessor_id,
        duplicate_msg,
        path,
        &sks[0],
    )
    .await;
    let request = SignRequestArgs {
        payload_v2: Some(payload),
        path: path.into(),
        domain_id: Some(DOMAIN_ID_ZERO),
        ..Default::default()
    };
    sign_and_validate(
        &alice,
        &request,
        Some((&respond_req, &respond_resp)),
        &contract,
        attested_account,
    )
    .await?;
    sign_and_validate(
        &alice,
        &request,
        Some((&respond_req, &respond_resp)),
        &contract,
        attested_account,
    )
    .await?;

    // Check that a sign with no response from MPC network properly errors out:
    let err = sign_and_validate(&alice, &request, None, &contract, attested_account)
        .await
        .expect_err("should have failed with timeout");
    assert!(err
        .to_string()
        .contains(&errors::RequestError::Timeout.to_string()));

    Ok(())
}

#[tokio::test]
async fn test_contract_sign_success_refund() -> anyhow::Result<()> {
    let (worker, contract, mpc_nodes, sks) =
        init_env(&[SignatureScheme::Secp256k1], PARTICIPANT_LEN).await;
    let attested_account = &mpc_nodes[0];

    let alice = worker.dev_create_account().await?;
    let balance = alice.view_account().await?.balance;
    let contract_balance = contract.view_account().await?.balance;
    let path = "test";

    let msg = "hello world!";
    println!("submitting: {msg}");
    let (payload, respond_req, respond_resp) =
        create_message_payload_and_response(DOMAIN_ID_ZERO, alice.id(), msg, path, &sks[0]).await;
    let request = SignRequestArgs {
        payload_v2: Some(payload),
        path: path.into(),
        domain_id: Some(DOMAIN_ID_ZERO),
        ..Default::default()
    };

    let status = alice
        .call(contract.id(), "sign")
        .args_json(serde_json::json!({
            "request": request,
        }))
        .deposit(NearToken::from_near(1))
        .max_gas()
        .transact_async()
        .await?;
    dbg!(&status);
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    // Call `respond` as an attested node.
    let respond = attested_account
        .call(contract.id(), "respond")
        .args_json(serde_json::json!({
            "request": respond_req,
            "response": respond_resp
        }))
        .max_gas()
        .transact()
        .await?;
    dbg!(&respond);

    let execution = status.await?;
    dbg!(&execution);

    let execution = execution.into_result()?;

    // Finally wait the result:
    let returned_resp: SignatureResponse = execution.json()?;
    assert_eq!(
        returned_resp, respond_resp,
        "Returned signature request does not match"
    );

    let new_balance = alice.view_account().await?.balance;
    let new_contract_balance = contract.view_account().await?.balance;
    assert!(
        balance.as_millinear() - new_balance.as_millinear() < 10,
        "refund should happen"
    );
    println!(
        "{} {} {} {}",
        balance.as_millinear(),
        new_balance.as_millinear(),
        contract_balance.as_millinear(),
        new_contract_balance.as_millinear(),
    );
    assert!(
        contract_balance.as_millinear() <= new_contract_balance.as_millinear(),
        "contract balance should not decrease after refunding deposit"
    );

    Ok(())
}

#[tokio::test]
async fn test_contract_sign_fail_refund() -> anyhow::Result<()> {
    let (worker, contract, _, sks) = init_env(&[SignatureScheme::Secp256k1], PARTICIPANT_LEN).await;
    let alice = worker.dev_create_account().await?;
    let balance = alice.view_account().await?.balance;
    let contract_balance = contract.view_account().await?.balance;
    let path = "test";

    let msg = "hello world!";
    println!("submitting: {msg}");
    let (payload, _, _) =
        create_message_payload_and_response(DOMAIN_ID_ZERO, alice.id(), msg, path, &sks[0]).await;
    let request = SignRequestArgs {
        payload_v2: Some(payload),
        path: path.into(),
        domain_id: Some(DOMAIN_ID_ZERO),
        ..Default::default()
    };

    let status = alice
        .call(contract.id(), "sign")
        .args_json(serde_json::json!({
            "request": request,
        }))
        .deposit(NearToken::from_near(1))
        .max_gas()
        .transact_async()
        .await?;
    dbg!(&status);
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    // we do not respond, sign will fail due to timeout
    let execution = status.await;
    dbg!(&execution);
    let err = execution
        .unwrap()
        .into_result()
        .expect_err("should have failed with timeout");
    assert!(err
        .to_string()
        .contains(&errors::RequestError::Timeout.to_string()));

    let new_balance = alice.view_account().await?.balance;
    let new_contract_balance = contract.view_account().await?.balance;
    println!(
        "{} {} {} {}",
        balance.as_millinear(),
        new_balance.as_millinear(),
        contract_balance.as_yoctonear(),
        new_contract_balance.as_yoctonear(),
    );
    assert!(balance >= new_balance, "user balance should not increase");
    assert!(
        balance.as_millinear() - new_balance.as_millinear() < 10,
        "refund should happen"
    );
    assert!(
        contract_balance.as_millinear() <= new_contract_balance.as_millinear(),
        "contract balance should not decrease after refunding deposit"
    );

    Ok(())
}

#[tokio::test]
async fn test_contract_sign_request_deposits() -> anyhow::Result<()> {
    let (_, contract, mpc_nodes, sks) =
        init_env(&[SignatureScheme::Secp256k1], PARTICIPANT_LEN).await;
    let attested_account = &mpc_nodes[0];

    let predecessor_id = contract.id();
    let path = "testing-no-deposit";

    // Try to sign with no deposit, should fail.
    let msg = "without-deposit";
    let (payload, respond_req, respond_resp) =
        create_message_payload_and_response(DOMAIN_ID_ZERO, predecessor_id, msg, path, &sks[0])
            .await;
    let request = SignRequestArgs {
        payload_v2: Some(payload),
        path: path.into(),
        domain_id: Some(DOMAIN_ID_ZERO),
        ..Default::default()
    };

    let status = contract
        .call("sign")
        .args_json(serde_json::json!({
            "request": request,
        }))
        .max_gas()
        .transact_async()
        .await?;
    dbg!(&status);

    // Responding to the request should fail with missing request because the deposit is too low,
    // so the request should have never made it into the request queue and subsequently the MPC network.
    let respond = attested_account
        .call(contract.id(), "respond")
        .args_json(serde_json::json!({
            "request": respond_req,
            "response": respond_resp
        }))
        .max_gas()
        .transact()
        .await?;
    dbg!(&respond);
    assert!(respond
        .into_result()
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

    Ok(())
}

#[tokio::test]
async fn test_sign_v1_compatibility() -> anyhow::Result<()> {
    let (_, contract, mpc_nodes, sks) =
        init_env(&[SignatureScheme::Secp256k1], PARTICIPANT_LEN).await;
    let attested_account = &mpc_nodes[0];
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
        let (payload, respond_req, respond_resp) =
            create_message_payload_and_response(DOMAIN_ID_ZERO, predecessor_id, msg, path, &sks[0])
                .await;
        let status = contract
            .call("sign")
            .args_json(serde_json::json!({
                "request": {
                    "payload": *payload.as_ecdsa().unwrap(),
                    "path": path,
                    "key_version": 0,
                },
            }))
            .deposit(NearToken::from_yoctonear(1))
            .max_gas()
            .transact_async()
            .await?;
        dbg!(&status);

        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

        // Call `respond` as if we are the MPC network itself.
        let respond = attested_account
            .call(contract.id(), "respond")
            .args_json(serde_json::json!({
                "request": respond_req,
                "response": respond_resp
            }))
            .max_gas()
            .transact()
            .await?;
        dbg!(&respond);

        let execution = status.await?;
        dbg!(&execution);
        let execution = execution.into_result()?;

        // Finally wait the result:
        let returned_resp: SignatureResponse = execution.json()?;
        assert_eq!(
            returned_resp, respond_resp,
            "Returned signature request does not match"
        );
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
            "init_config": None::<InitConfig>,
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
            "init_config": None::<InitConfig>,
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
            "init_config": None::<InitConfig>,
        }))
        .transact()
        .await?;
    assert!(
        result.is_failure(),
        "initializing with valid candidates again should fail"
    );

    Ok(())
}

#[tokio::test]
async fn test_contract_sign_request_eddsa() -> anyhow::Result<()> {
    let (worker, contract, mpc_nodes, sks) =
        init_env(&[SignatureScheme::Ed25519], PARTICIPANT_LEN).await;
    let attested_account = &mpc_nodes[0];

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

    for msg in messages {
        println!("submitting: {msg}");
        let (payload, respond_req, respond_resp) =
            create_message_payload_and_response(DOMAIN_ID_ZERO, predecessor_id, msg, path, &sks[0])
                .await;

        let request = SignRequestArgs {
            payload_v2: Some(payload),
            path: path.into(),
            domain_id: Some(DomainId(0)),
            ..Default::default()
        };

        sign_and_validate(
            &alice,
            &request,
            Some((&respond_req, &respond_resp)),
            &contract,
            attested_account,
        )
        .await?;
    }

    // check duplicate requests can also be signed:
    let duplicate_msg = "welp";
    let (payload, respond_req, respond_resp) = create_message_payload_and_response(
        DOMAIN_ID_ZERO,
        predecessor_id,
        duplicate_msg,
        path,
        &sks[0],
    )
    .await;
    let request = SignRequestArgs {
        payload_v2: Some(payload),
        path: path.into(),
        domain_id: Some(DomainId(0)),
        ..Default::default()
    };
    sign_and_validate(
        &alice,
        &request,
        Some((&respond_req, &respond_resp)),
        &contract,
        attested_account,
    )
    .await?;
    sign_and_validate(
        &alice,
        &request,
        Some((&respond_req, &respond_resp)),
        &contract,
        attested_account,
    )
    .await?;

    // Check that a sign with no response from MPC network properly errors out:
    let err = sign_and_validate(&alice, &request, None, &contract, attested_account)
        .await
        .expect_err("should have failed with timeout");
    assert!(err
        .to_string()
        .contains(&errors::RequestError::Timeout.to_string()));

    Ok(())
}
