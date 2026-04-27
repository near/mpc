#![allow(non_snake_case)]

use crate::sandbox::common::{
    abstract_evm_request, await_pending_foreign_tx_request_observed_on_contract, base_evm_request,
    bitcoin_extracted_values, bitcoin_request, bnb_evm_request, ethereum_evm_request,
    evm_block_hash_extracted_values, register_foreign_chain_configuration,
    sign_foreign_tx_response, starknet_extracted_values, starknet_request, SandboxTestSetup,
};
use near_mpc_contract_interface::method_names;
use near_mpc_contract_interface::types::{
    self as dtos, ExtractedValue, ForeignChainRpcRequest, ForeignTxPayloadVersion,
    VerifyForeignTransactionRequest, VerifyForeignTransactionResponse,
};
use near_workspaces::types::NearToken;
use rstest::rstest;
use serde_json::json;

const SIGNATURE_TIMEOUT_BLOCKS: u64 = 200;

#[rstest]
#[case::ethereum(ethereum_evm_request(), evm_block_hash_extracted_values())]
#[case::abstract_(abstract_evm_request(), evm_block_hash_extracted_values())]
#[case::bitcoin(bitcoin_request(), bitcoin_extracted_values())]
#[case::starknet(starknet_request(), starknet_extracted_values())]
#[case::bnb(bnb_evm_request(), evm_block_hash_extracted_values())]
#[case::base(base_evm_request(), evm_block_hash_extracted_values())]
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

    let status = user
        .call(
            setup.contract.id(),
            method_names::VERIFY_FOREIGN_TRANSACTION,
        )
        .args_json(json!({ "request": request_args }))
        .deposit(NearToken::from_yoctonear(1))
        .max_gas()
        .transact_async()
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

    let respond_result = setup.mpc_signer_accounts[0]
        .call(setup.contract.id(), method_names::RESPOND_VERIFY_FOREIGN_TX)
        .args_json(json!({
            "request": verify_request,
            "response": response,
        }))
        .max_gas()
        .transact()
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

#[rstest]
#[case::ethereum(ethereum_evm_request())]
#[case::abstract_(abstract_evm_request())]
#[case::bitcoin(bitcoin_request())]
#[case::starknet(starknet_request())]
#[case::bnb(bnb_evm_request())]
#[case::base(base_evm_request())]
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

    let result = user
        .call(
            setup.contract.id(),
            method_names::VERIFY_FOREIGN_TRANSACTION,
        )
        .args_json(json!({ "request": request_args }))
        .deposit(NearToken::from_yoctonear(1))
        .max_gas()
        .transact()
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

    let status = user
        .call(
            setup.contract.id(),
            method_names::VERIFY_FOREIGN_TRANSACTION,
        )
        .args_json(json!({ "request": request_args }))
        .deposit(NearToken::from_yoctonear(1))
        .max_gas()
        .transact_async()
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
