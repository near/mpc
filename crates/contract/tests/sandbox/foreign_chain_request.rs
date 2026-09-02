#![allow(non_snake_case)]

use crate::sandbox::common::{
    SandboxTestSetup, abstract_evm_request, adi_evm_request, aptos_extracted_values, aptos_request,
    arbitrum_evm_request, avalanche_evm_request,
    await_pending_foreign_tx_request_observed_on_contract, base_evm_request,
    bitcoin_extracted_values, bitcoin_request, bnb_evm_request, bogus_ton_log_extracted_value,
    ethereum_evm_request, evm_block_hash_extracted_values, fogo_request, hyper_evm_request,
    make_foreign_chain_available, polygon_evm_request, sign_foreign_tx_response, solana_request,
    starknet_extracted_values, starknet_request, sui_extracted_values, sui_request,
    svm_extracted_values, ton_request,
};
use crate::sandbox::utils::transactions::CallMpcContract;
use near_mpc_bounded_collections::BoundedVecOutOfBounds;
use near_mpc_contract_interface::deposits::SIGN_DEPOSIT_YOCTONEAR;
use near_mpc_contract_interface::method_names;
use near_mpc_contract_interface::types::{
    self as dtos, EvmExtractor, EvmFinality, EvmRpcRequest, EvmTxId, ExtractedValue,
    ForeignChainRpcRequest, ForeignTxPayloadVersion, MAX_EXTRACTORS_PER_REQUEST,
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
#[case::arbitrum(arbitrum_evm_request(), evm_block_hash_extracted_values())]
#[case::polygon(polygon_evm_request(), evm_block_hash_extracted_values())]
#[case::hyper_evm(hyper_evm_request(), evm_block_hash_extracted_values())]
#[case::ton(ton_request(), bogus_ton_log_extracted_value())]
#[case::aptos(aptos_request(), aptos_extracted_values())]
#[case::sui(sui_request(), sui_extracted_values())]
#[case::avalanche(avalanche_evm_request(), evm_block_hash_extracted_values())]
#[case::adi(adi_evm_request(), evm_block_hash_extracted_values())]
#[case::solana(solana_request(), svm_extracted_values())]
#[case::fogo(fogo_request(), svm_extracted_values())]
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
    make_foreign_chain_available(chain, &setup.contract, &setup.mpc_signer_accounts).await;

    let user = setup.worker.dev_create_account().await.unwrap();
    let domain_id = dtos::DomainId(foreign_tx_key.domain_id().0);

    let request_args = dtos::VerifyForeignTransactionRequestArgs {
        domain_id,
        payload_version: ForeignTxPayloadVersion::V1,
        expected_payload_hash: None,
        request: rpc_request.clone(),
    };

    let status = user
        .call_mpc_async(setup.contract.id())
        .verify_foreign_transaction(request_args.clone())
        .await
        .unwrap();

    let verify_request = VerifyForeignTransactionRequest {
        domain_id,
        payload_version: ForeignTxPayloadVersion::V1,
        expected_payload_hash: None,
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
    make_foreign_chain_available(chain, &setup.contract, &setup.mpc_signer_accounts).await;

    let alice = setup.worker.dev_create_account().await.unwrap();
    let bob = setup.worker.dev_create_account().await.unwrap();
    let domain_id = dtos::DomainId(foreign_tx_key.domain_id().0);
    let request_args = dtos::VerifyForeignTransactionRequestArgs {
        domain_id,
        payload_version: ForeignTxPayloadVersion::V1,
        expected_payload_hash: None,
        request: rpc_request.clone(),
    };
    let verify_request = VerifyForeignTransactionRequest {
        domain_id,
        payload_version: ForeignTxPayloadVersion::V1,
        expected_payload_hash: None,
        request: rpc_request,
    };

    // When
    let status_alice = alice
        .call_mpc_async(setup.contract.id())
        .verify_foreign_transaction(request_args.clone())
        .await
        .unwrap();
    let status_bob = bob
        .call_mpc_async(setup.contract.id())
        .verify_foreign_transaction(request_args.clone())
        .await
        .unwrap();
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

#[tokio::test]
async fn respond_verify_foreign_tx__should_reject_response_not_matching_expected_payload_hash() {
    // Given
    let rpc_request = bitcoin_request();
    let chain = rpc_request.chain();
    let setup = SandboxTestSetup::builder()
        .with_foreign_tx_domain()
        .build()
        .await;
    let foreign_tx_key = setup.foreign_tx_key();
    make_foreign_chain_available(chain, &setup.contract, &setup.mpc_signer_accounts).await;

    let user = setup.worker.dev_create_account().await.unwrap();
    let domain_id = dtos::DomainId(foreign_tx_key.domain_id().0);
    let request_args = dtos::VerifyForeignTransactionRequestArgs {
        domain_id,
        payload_version: ForeignTxPayloadVersion::V1,
        expected_payload_hash: Some(dtos::Hash256([1u8; 32])),
        request: rpc_request.clone(),
    };
    let verify_request = VerifyForeignTransactionRequest {
        domain_id,
        payload_version: ForeignTxPayloadVersion::V1,
        expected_payload_hash: Some(dtos::Hash256([1u8; 32])),
        request: rpc_request,
    };

    let _status = user
        .call_mpc_async(setup.contract.id())
        .verify_foreign_transaction(request_args)
        .await
        .unwrap();
    await_pending_foreign_tx_request_observed_on_contract(&setup.contract, &verify_request).await;

    let (_payload, response) = sign_foreign_tx_response(
        &verify_request.request,
        bitcoin_extracted_values(),
        foreign_tx_key.as_secp256k1(),
    );

    // When
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

    // Then
    let error_message = respond_result.unwrap_err().to_string();
    assert!(
        error_message
            .contains(&mpc_contract::errors::RespondError::UnexpectedPayloadHash.to_string()),
        "respond_verify_foreign_tx must reject with UnexpectedPayloadHash, got: {error_message}",
    );
}

#[tokio::test]
async fn verify_foreign_transaction__should_succeed_when_response_matches_expected_payload_hash() {
    // Given
    let rpc_request = bitcoin_request();
    let extracted_values = bitcoin_extracted_values();
    let chain = rpc_request.chain();
    let setup = SandboxTestSetup::builder()
        .with_foreign_tx_domain()
        .build()
        .await;
    let foreign_tx_key = setup.foreign_tx_key();
    make_foreign_chain_available(chain, &setup.contract, &setup.mpc_signer_accounts).await;

    let user = setup.worker.dev_create_account().await.unwrap();
    let domain_id = dtos::DomainId(foreign_tx_key.domain_id().0);

    let (payload, response) = sign_foreign_tx_response(
        &rpc_request,
        extracted_values,
        foreign_tx_key.as_secp256k1(),
    );
    let expected_payload_hash = payload.compute_msg_hash().unwrap();

    let request_args = dtos::VerifyForeignTransactionRequestArgs {
        domain_id,
        payload_version: ForeignTxPayloadVersion::V1,
        expected_payload_hash: Some(expected_payload_hash.clone()),
        request: rpc_request.clone(),
    };
    let verify_request = VerifyForeignTransactionRequest {
        domain_id,
        payload_version: ForeignTxPayloadVersion::V1,
        expected_payload_hash: Some(expected_payload_hash.clone()),
        request: rpc_request,
    };

    // When
    let status = user
        .call_mpc_async(setup.contract.id())
        .verify_foreign_transaction(request_args)
        .await
        .unwrap();
    await_pending_foreign_tx_request_observed_on_contract(&setup.contract, &verify_request).await;

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

    // Then
    assert!(
        respond_result.is_ok(),
        "respond_verify_foreign_tx should accept the matching response: {respond_result:?}",
    );
    let execution = status.await.unwrap().into_result().unwrap();
    let returned: VerifyForeignTransactionResponse = execution.json().unwrap();
    assert_eq!(returned.payload_hash, expected_payload_hash);
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
#[case::sui(sui_request())]
#[case::avalanche(avalanche_evm_request())]
#[case::adi(adi_evm_request())]
#[case::solana(solana_request())]
#[case::fogo(fogo_request())]
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
        expected_payload_hash: None,
        request: rpc_request,
    };

    let result = user
        .call_mpc(setup.contract.id())
        .verify_foreign_transaction(request_args.clone())
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
#[case::sui(sui_request())]
#[case::avalanche(avalanche_evm_request())]
#[case::adi(adi_evm_request())]
#[case::solana(solana_request())]
#[case::fogo(fogo_request())]
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
    make_foreign_chain_available(chain, &setup.contract, &setup.mpc_signer_accounts).await;

    let user = setup.worker.dev_create_account().await.unwrap();

    let request_args = dtos::VerifyForeignTransactionRequestArgs {
        domain_id: dtos::DomainId(foreign_tx_key.domain_id().0),
        payload_version: ForeignTxPayloadVersion::V1,
        expected_payload_hash: None,
        request: rpc_request,
    };

    let status = user
        .call_mpc_async(setup.contract.id())
        .verify_foreign_transaction(request_args.clone())
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

fn evm_request_args_with_extractors(
    domain_id: dtos::DomainId,
    extractor_count: usize,
) -> dtos::VerifyForeignTransactionRequestArgs {
    let extractors: Vec<EvmExtractor> = (0..extractor_count)
        .map(|log_index| EvmExtractor::Log {
            log_index: log_index as u64,
        })
        .collect();
    dtos::VerifyForeignTransactionRequestArgs {
        domain_id,
        payload_version: ForeignTxPayloadVersion::V1,
        expected_payload_hash: Some(dtos::Hash256([9u8; 32])),
        request: ForeignChainRpcRequest::Ethereum(EvmRpcRequest {
            tx_id: EvmTxId([0xbb; 32]),
            extractors: extractors.try_into().unwrap(),
            finality: EvmFinality::Finalized,
        }),
    }
}

async fn contract_storage_usage(setup: &SandboxTestSetup) -> u64 {
    setup
        .worker
        .view_account(setup.contract.id())
        .await
        .unwrap()
        .storage_usage
}

#[tokio::test]
async fn verify_foreign_transaction__should_release_storage_when_request_at_extractor_cap_times_out()
 {
    // Given
    let setup = SandboxTestSetup::builder()
        .with_foreign_tx_domain()
        .build()
        .await;
    make_foreign_chain_available(
        dtos::ForeignChain::Ethereum,
        &setup.contract,
        &setup.mpc_signer_accounts,
    )
    .await;
    let user = setup.worker.dev_create_account().await.unwrap();
    let domain_id = dtos::DomainId(setup.foreign_tx_key().domain_id().0);
    let request_args = evm_request_args_with_extractors(domain_id, MAX_EXTRACTORS_PER_REQUEST);
    let request = VerifyForeignTransactionRequest {
        domain_id,
        payload_version: request_args.payload_version,
        expected_payload_hash: request_args.expected_payload_hash.clone(),
        request: request_args.request.clone(),
    };
    let storage_before = contract_storage_usage(&setup).await;

    // When
    let status = user
        .call_mpc_async(setup.contract.id())
        .verify_foreign_transaction(request_args)
        .await
        .unwrap();
    await_pending_foreign_tx_request_observed_on_contract(&setup.contract, &request).await;
    let storage_while_pending = contract_storage_usage(&setup).await;
    setup
        .worker
        .fast_forward(SIGNATURE_TIMEOUT_BLOCKS)
        .await
        .unwrap();
    let execution = status.await.unwrap();

    // Then
    assert!(
        execution.is_failure(),
        "request should time out without a response"
    );
    assert!(
        storage_while_pending > storage_before,
        "a pending request must occupy contract storage"
    );
    assert_eq!(
        contract_storage_usage(&setup).await,
        storage_before,
        "the timeout must release the pending request's storage"
    );
}

#[tokio::test]
async fn verify_foreign_transaction__should_reject_request_above_extractor_cap() {
    // Given
    let setup = SandboxTestSetup::builder()
        .with_foreign_tx_domain()
        .build()
        .await;
    make_foreign_chain_available(
        dtos::ForeignChain::Ethereum,
        &setup.contract,
        &setup.mpc_signer_accounts,
    )
    .await;
    let user = setup.worker.dev_create_account().await.unwrap();
    let domain_id = dtos::DomainId(setup.foreign_tx_key().domain_id().0);
    let mut request_args = serde_json::to_value(evm_request_args_with_extractors(
        domain_id,
        MAX_EXTRACTORS_PER_REQUEST,
    ))
    .unwrap();
    request_args["request"]["Ethereum"]["extractors"]
        .as_array_mut()
        .unwrap()
        .push(
            serde_json::to_value(EvmExtractor::Log {
                log_index: MAX_EXTRACTORS_PER_REQUEST as u64,
            })
            .unwrap(),
        );
    let storage_before = contract_storage_usage(&setup).await;

    // When
    let result = user
        .call(
            setup.contract.id(),
            method_names::VERIFY_FOREIGN_TRANSACTION,
        )
        .args_json(json!({ "request": request_args }))
        .deposit(NearToken::from_yoctonear(SIGN_DEPOSIT_YOCTONEAR))
        .max_gas()
        .transact()
        .await
        .unwrap()
        .into_result();

    // Then
    let error_message = result.unwrap_err().to_string();
    let expected_error = BoundedVecOutOfBounds::UpperBoundError {
        upper_bound: MAX_EXTRACTORS_PER_REQUEST,
        got: MAX_EXTRACTORS_PER_REQUEST + 1,
    }
    .to_string();
    assert!(
        error_message.contains(&expected_error),
        "the request must be rejected for exceeding the extractor cap, got: {error_message}"
    );
    assert_eq!(contract_storage_usage(&setup).await, storage_before);
}
