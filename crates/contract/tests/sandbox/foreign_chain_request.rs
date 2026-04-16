#![allow(non_snake_case)]

use crate::sandbox::common::{
    abstract_evm_request, await_pending_foreign_tx_request_observed_on_contract, base_evm_request,
    bitcoin_extracted_values, bitcoin_request, bnb_evm_request, ethereum_evm_request,
    evm_block_hash_extracted_values, setup_foreign_tx_env, sign_foreign_tx_response,
    starknet_extracted_values, starknet_request, vote_chain_policy,
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
    let env = setup_foreign_tx_env().await;
    vote_chain_policy(chain, &env.contract, &env.accounts).await;

    let user = env.worker.dev_create_account().await.unwrap();

    let request_args = dtos::VerifyForeignTransactionRequestArgs {
        domain_id: dtos::DomainId(env.domain_id.0),
        payload_version: ForeignTxPayloadVersion::V1,
        request: rpc_request.clone(),
    };

    let status = user
        .call(env.contract.id(), method_names::VERIFY_FOREIGN_TRANSACTION)
        .args_json(json!({ "request": request_args }))
        .deposit(NearToken::from_yoctonear(1))
        .max_gas()
        .transact_async()
        .await
        .unwrap();

    let verify_request = VerifyForeignTransactionRequest {
        domain_id: dtos::DomainId(env.domain_id.0),
        payload_version: ForeignTxPayloadVersion::V1,
        request: rpc_request,
    };

    await_pending_foreign_tx_request_observed_on_contract(&env.contract, &verify_request).await;

    let (payload, response) =
        sign_foreign_tx_response(&verify_request.request, extracted_values, &env.secret_key);

    let respond_result = env.accounts[0]
        .call(env.contract.id(), method_names::RESPOND_VERIFY_FOREIGN_TX)
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
    let env = setup_foreign_tx_env().await;
    let user = env.worker.dev_create_account().await.unwrap();

    let request_args = dtos::VerifyForeignTransactionRequestArgs {
        domain_id: dtos::DomainId(env.domain_id.0),
        payload_version: ForeignTxPayloadVersion::V1,
        request: rpc_request,
    };

    let result = user
        .call(env.contract.id(), method_names::VERIFY_FOREIGN_TRANSACTION)
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
    let env = setup_foreign_tx_env().await;
    vote_chain_policy(chain, &env.contract, &env.accounts).await;

    let user = env.worker.dev_create_account().await.unwrap();

    let request_args = dtos::VerifyForeignTransactionRequestArgs {
        domain_id: dtos::DomainId(env.domain_id.0),
        payload_version: ForeignTxPayloadVersion::V1,
        request: rpc_request,
    };

    let status = user
        .call(env.contract.id(), method_names::VERIFY_FOREIGN_TRANSACTION)
        .args_json(json!({ "request": request_args }))
        .deposit(NearToken::from_yoctonear(1))
        .max_gas()
        .transact_async()
        .await
        .unwrap();

    env.worker
        .fast_forward(SIGNATURE_TIMEOUT_BLOCKS)
        .await
        .unwrap();
    let execution = status.await.unwrap();
    assert!(
        execution.is_failure(),
        "request should time out without a response"
    );
}
