use crate::sandbox::{
    common::{
        SandboxTestSetup, bitcoin_extracted_values, bitcoin_request, create_account_given_id,
        make_foreign_chain_available, sign_foreign_tx_payload,
    },
    read_rpc::{AnnouncedYield, await_announced_yield},
    utils::{consts::ALL_PROTOCOLS, sign_utils::DomainResponseTest, transactions::CallMpcContract},
};
use near_mpc_contract_interface::types::{
    self as dtos, ForeignTxSignPayload, ForeignTxSignPayloadV2, ForeignTxVerificationOutcome,
    VerifyForeignTransactionRequestV2, VerifyForeignTransactionResponseV2,
};
use rand::SeedableRng;
use test_utils::MAINNET_PROTOCOL_VERSION;

#[tokio::test]
#[expect(non_snake_case)]
#[ignore = "pinned to mainnet's protocol. It runs in the Mainnet protocol compatibility CI job"]
async fn contract__should_serve_requests_at_mainnet_protocol_version() {
    // Given
    let mut rng = rand::rngs::StdRng::from_seed([1u8; 32]);
    let SandboxTestSetup {
        worker,
        contract,
        mpc_signer_accounts,
        keys,
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .at_protocol_version(MAINNET_PROTOCOL_VERSION)
        .build()
        .await;
    let user = create_account_given_id(&worker, "alice".parse().unwrap())
        .await
        .unwrap()
        .unwrap();

    // When
    for key in &keys {
        DomainResponseTest::new(&mut rng, key, user.id())
            .run(&user, &contract, &mpc_signer_accounts[0])
            .await
            .unwrap();
    }

    // Then
    assert_eq!(
        worker.status().await.unwrap().protocol_version,
        MAINNET_PROTOCOL_VERSION
    );
}

#[tokio::test]
#[expect(non_snake_case)]
#[ignore = "pinned to mainnet's protocol. It runs in the Mainnet protocol compatibility CI job"]
async fn read_rpc__should_return_the_signed_outcome_at_mainnet_protocol_version() {
    // Given
    let rpc_request = bitcoin_request();
    let setup = SandboxTestSetup::builder()
        .with_foreign_tx_domain()
        .at_protocol_version(MAINNET_PROTOCOL_VERSION)
        .build()
        .await;
    let foreign_tx_key = setup.foreign_tx_key();
    make_foreign_chain_available(
        rpc_request.chain(),
        &setup.contract,
        &setup.mpc_signer_accounts,
    )
    .await;
    let user = setup.worker.dev_create_account().await.unwrap();
    let request = VerifyForeignTransactionRequestV2 {
        request: rpc_request,
        domain_id: dtos::DomainId(foreign_tx_key.domain_id().0),
        expected_values: bitcoin_extracted_values(),
    };
    let status = user
        .call_mpc_async(setup.contract.id())
        .read_rpc(request.clone())
        .await
        .unwrap();
    let AnnouncedYield {
        yield_id,
        block_height,
    } = await_announced_yield(&setup.worker, &status).await;
    let outcome = ForeignTxVerificationOutcome::Verified {};
    let payload = ForeignTxSignPayload::V2(ForeignTxSignPayloadV2 {
        request: request.request.clone(),
        expected_values_hash: request.expected_values_hash().unwrap(),
        request_block_height: block_height,
        yield_id,
        outcome: outcome.clone(),
    });
    let signature = sign_foreign_tx_payload(&payload, foreign_tx_key.as_secp256k1());

    // When
    let response = setup.mpc_signer_accounts[0]
        .call_mpc(setup.contract.id())
        .respond_verify_foreign_tx_v2(yield_id, outcome.clone(), signature.clone())
        .await
        .unwrap()
        .into_result();
    let execution = status.await.unwrap().into_result().unwrap();

    // Then
    assert!(
        response.is_ok(),
        "the response should succeed: {response:?}"
    );
    let returned: VerifyForeignTransactionResponseV2 = execution.json().unwrap();
    assert_eq!(
        returned,
        VerifyForeignTransactionResponseV2 {
            payload_hash: payload.compute_msg_hash().unwrap(),
            signature,
            request_block_height: block_height,
            yield_id,
            outcome,
        }
    );
    assert_eq!(
        setup.worker.status().await.unwrap().protocol_version,
        MAINNET_PROTOCOL_VERSION
    );
}
