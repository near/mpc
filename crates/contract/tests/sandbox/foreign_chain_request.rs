#![allow(non_snake_case)]

use crate::sandbox::common::{
    SandboxAsyncCaller, SandboxCaller, SandboxTestSetup, abstract_evm_request,
    aptos_extracted_values, aptos_request, arbitrum_evm_request,
    await_pending_foreign_tx_request_observed_on_contract, base_evm_request,
    bitcoin_extracted_values, bitcoin_request, bnb_evm_request, bogus_ton_log_extracted_value,
    ethereum_evm_request, evm_block_hash_extracted_values, hyper_evm_request, polygon_evm_request,
    register_foreign_chain_configuration, sign_foreign_tx_response, starknet_extracted_values,
    starknet_request, ton_request,
};
use near_mpc_contract_interface::call_args::{
    respond_verify_foreign_transaction, send_verify_foreign_transaction,
};
use near_mpc_contract_interface::types::{
    self as dtos, ExtractedValue, ForeignChainRpcRequest, ForeignTxPayloadVersion,
    VerifyForeignTransactionRequest, VerifyForeignTransactionResponse,
};
use rstest::rstest;

const SIGNATURE_TIMEOUT_BLOCKS: u64 = 200;

#[rstest]
#[case::ethereum(ethereum_evm_request(), evm_block_hash_extracted_values())]
#[case::abstract_(abstract_evm_request(), evm_block_hash_extracted_values())]
#[case::bitcoin(bitcoin_request(), bitcoin_extracted_values())]
#[case::starknet(starknet_request(), starknet_extracted_values())]
#[case::bnb(bnb_evm_request(), evm_block_hash_extracted_values())]
#[case::base(base_evm_request(), evm_block_hash_extracted_values())]
#[case::arbitrum(arbitrum_evm_request(), evm_block_hash_extracted_values())]
#[case::polygon(polygon_evm_request(), evm_block_hash_extracted_values())]
#[case::hyper_evm(hyper_evm_request(), evm_block_hash_extracted_values())]
#[case::ton(ton_request(), bogus_ton_log_extracted_value())]
#[case::aptos(aptos_request(), aptos_extracted_values())]
#[tokio::test]
async fn verify_foreign_transaction__should_succeed(
    #[case] rpc_request: ForeignChainRpcRequest,
    #[case] extracted_values: Vec<ExtractedValue>,
) {
    let chain = rpc_request.chain();
    let setup = SandboxTestSetup::builder()
        .with_foreign_tx_domain()
        .build()
        .await;
    let foreign_tx_key = setup.foreign_tx_key();
    register_foreign_chain_configuration(chain, &setup.contract, &setup.mpc_signer_accounts).await;

    let user = setup.worker.dev_create_account().await.unwrap();
    let domain_id = dtos::DomainId(foreign_tx_key.domain_id().0);

    let request_args = dtos::VerifyForeignTransactionRequestArgs {
        domain_id,
        payload_version: ForeignTxPayloadVersion::V1,
        request: rpc_request.clone(),
    };

    let status = send_verify_foreign_transaction(
        &SandboxAsyncCaller(&user),
        setup.contract.id(),
        &request_args,
    )
    .await
    .unwrap();

    let verify_request = VerifyForeignTransactionRequest {
        domain_id,
        payload_version: ForeignTxPayloadVersion::V1,
        request: rpc_request,
    };

    await_pending_foreign_tx_request_observed_on_contract(&setup.contract, &verify_request).await;

    let (payload, response) = sign_foreign_tx_response(
        &verify_request.request,
        extracted_values,
        foreign_tx_key.as_secp256k1(),
    );
    let respond_result = respond_verify_foreign_transaction(
        &SandboxCaller(&setup.mpc_signer_accounts[0]),
        setup.contract.id(),
        &verify_request,
        &response,
    )
    .await
    .unwrap()
    .into_result();

    assert!(
        respond_result.is_ok(),
        "respond_verify_foreign_tx should succeed for {chain:?}: {respond_result:?}",
    );

    let execution = status.await.unwrap().into_result().unwrap();
    let returned: VerifyForeignTransactionResponse = execution.json().unwrap();
    assert_eq!(returned.payload_hash, payload.compute_msg_hash().unwrap());
}

#[tokio::test]
async fn verify_foreign_transaction__should_fan_out_response_to_duplicates_from_different_callers()
{
    // Given
    let rpc_request = bitcoin_request();
    let extracted_values = bitcoin_extracted_values();
    let chain = rpc_request.chain();
    let setup = SandboxTestSetup::builder()
        .with_foreign_tx_domain()
        .build()
        .await;
    let foreign_tx_key = setup.foreign_tx_key();
    register_foreign_chain_configuration(chain, &setup.contract, &setup.mpc_signer_accounts).await;

    let alice = setup.worker.dev_create_account().await.unwrap();
    let bob = setup.worker.dev_create_account().await.unwrap();
    let domain_id = dtos::DomainId(foreign_tx_key.domain_id().0);
    let request_args = dtos::VerifyForeignTransactionRequestArgs {
        domain_id,
        payload_version: ForeignTxPayloadVersion::V1,
        request: rpc_request.clone(),
    };
    let verify_request = VerifyForeignTransactionRequest {
        domain_id,
        payload_version: ForeignTxPayloadVersion::V1,
        request: rpc_request,
    };

    // When
    let status_alice = send_verify_foreign_transaction(
        &SandboxAsyncCaller(&alice),
        setup.contract.id(),
        &request_args,
    )
    .await
    .unwrap();
    let status_bob = send_verify_foreign_transaction(
        &SandboxAsyncCaller(&bob),
        setup.contract.id(),
        &request_args,
    )
    .await
    .unwrap();
    await_pending_foreign_tx_request_observed_on_contract(&setup.contract, &verify_request).await;

    let (payload, response) = sign_foreign_tx_response(
        &verify_request.request,
        extracted_values,
        foreign_tx_key.as_secp256k1(),
    );

    let respond_result = respond_verify_foreign_transaction(
        &SandboxCaller(&setup.mpc_signer_accounts[0]),
        setup.contract.id(),
        &verify_request,
        &response,
    )
    .await
    .unwrap()
    .into_result();

    // Then
    assert!(
        respond_result.is_ok(),
        "single respond_verify_foreign_tx should drain both queued yields: {respond_result:?}",
    );
    let expected_payload_hash = payload.compute_msg_hash().unwrap();

    let exec_alice = status_alice.await.unwrap().into_result().unwrap();
    let returned_alice: VerifyForeignTransactionResponse = exec_alice.json().unwrap();
    assert_eq!(
        returned_alice.payload_hash, expected_payload_hash,
        "alice's tx should receive the fanned-out response",
    );

    let exec_bob = status_bob.await.unwrap().into_result().unwrap();
    let returned_bob: VerifyForeignTransactionResponse = exec_bob.json().unwrap();
    assert_eq!(
        returned_bob.payload_hash, expected_payload_hash,
        "bob's tx should receive the same fanned-out response and not be displaced by alice",
    );
}

#[rstest]
#[case::ethereum(ethereum_evm_request())]
#[case::abstract_(abstract_evm_request())]
#[case::bitcoin(bitcoin_request())]
#[case::starknet(starknet_request())]
#[case::bnb(bnb_evm_request())]
#[case::base(base_evm_request())]
#[case::arbitrum(arbitrum_evm_request())]
#[case::polygon(polygon_evm_request())]
#[case::hyper_evm(hyper_evm_request())]
#[case::ton(ton_request())]
#[case::aptos(aptos_request())]
#[tokio::test]
async fn verify_foreign_transaction__should_reject_without_policy(
    #[case] rpc_request: ForeignChainRpcRequest,
) {
    let setup = SandboxTestSetup::builder()
        .with_foreign_tx_domain()
        .build()
        .await;
    let foreign_tx_key = setup.foreign_tx_key();
    let user = setup.worker.dev_create_account().await.unwrap();

    let request_args = dtos::VerifyForeignTransactionRequestArgs {
        domain_id: dtos::DomainId(foreign_tx_key.domain_id().0),
        payload_version: ForeignTxPayloadVersion::V1,
        request: rpc_request,
    };

    let result =
        send_verify_foreign_transaction(&SandboxCaller(&user), setup.contract.id(), &request_args)
            .await
            .unwrap()
            .into_result();

    assert!(
        result.is_err(),
        "verify_foreign_transaction should fail without chain in policy"
    );
}

#[rstest]
#[case::ethereum(ethereum_evm_request())]
#[case::abstract_(abstract_evm_request())]
#[case::bitcoin(bitcoin_request())]
#[case::starknet(starknet_request())]
#[case::bnb(bnb_evm_request())]
#[case::base(base_evm_request())]
#[case::arbitrum(arbitrum_evm_request())]
#[case::polygon(polygon_evm_request())]
#[case::hyper_evm(hyper_evm_request())]
#[case::ton(ton_request())]
#[case::aptos(aptos_request())]
#[tokio::test]
async fn verify_foreign_transaction__should_timeout_without_response(
    #[case] rpc_request: ForeignChainRpcRequest,
) {
    let chain = rpc_request.chain();
    let setup = SandboxTestSetup::builder()
        .with_foreign_tx_domain()
        .build()
        .await;
    let foreign_tx_key = setup.foreign_tx_key();
    register_foreign_chain_configuration(chain, &setup.contract, &setup.mpc_signer_accounts).await;

    let user = setup.worker.dev_create_account().await.unwrap();

    let request_args = dtos::VerifyForeignTransactionRequestArgs {
        domain_id: dtos::DomainId(foreign_tx_key.domain_id().0),
        payload_version: ForeignTxPayloadVersion::V1,
        request: rpc_request,
    };

    let status = send_verify_foreign_transaction(
        &SandboxAsyncCaller(&user),
        setup.contract.id(),
        &request_args,
    )
    .await
    .unwrap();

    setup
        .worker
        .fast_forward(SIGNATURE_TIMEOUT_BLOCKS)
        .await
        .unwrap();
    let execution = status.await.unwrap();
    assert!(
        execution.is_failure(),
        "request should time out without a response"
    );
}
