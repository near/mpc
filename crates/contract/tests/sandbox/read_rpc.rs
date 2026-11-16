#![allow(non_snake_case)]

use crate::sandbox::common::{
    SandboxTestSetup, bitcoin_extracted_values, bitcoin_request, make_foreign_chain_available,
};
use crate::sandbox::utils::transactions::CallMpcContract;
use mpc_contract::errors::RequestError;
use near_mpc_contract_interface::events::VerifyForeignTxV2YieldCreated;
use near_mpc_contract_interface::types::{self as dtos, VerifyForeignTransactionRequestV2};

const SIGNATURE_TIMEOUT_BLOCKS: u64 = 200;

fn yield_created_events(logs: &[&str]) -> Vec<VerifyForeignTxV2YieldCreated> {
    logs.iter()
        .filter_map(|line| VerifyForeignTxV2YieldCreated::from_log_line(line))
        .collect()
}

#[tokio::test]
async fn read_rpc__should_announce_one_yield_id_and_time_out_without_a_response() {
    // Given
    let rpc_request = bitcoin_request();
    let setup = SandboxTestSetup::builder()
        .with_foreign_tx_domain()
        .with_foreign_tx_v2()
        .build()
        .await;
    make_foreign_chain_available(
        rpc_request.chain(),
        &setup.contract,
        &setup.mpc_signer_accounts,
    )
    .await;
    let user = setup.worker.dev_create_account().await.unwrap();
    let request = VerifyForeignTransactionRequestV2 {
        request: rpc_request,
        domain_id: dtos::DomainId(setup.foreign_tx_key().domain_id().0),
        expected_values: bitcoin_extracted_values(),
    };

    // When
    let status = user
        .call_mpc_async(setup.contract.id())
        .read_rpc(request)
        .await
        .unwrap();
    setup
        .worker
        .fast_forward(SIGNATURE_TIMEOUT_BLOCKS)
        .await
        .unwrap();
    let execution = status.await.unwrap();

    // Then
    assert_eq!(yield_created_events(&execution.logs()).len(), 1);
    let failure = execution.into_result().unwrap_err().to_string();
    assert!(
        failure.contains(&RequestError::Timeout.to_string()),
        "the request should time out, got: {failure}"
    );
}

#[tokio::test]
async fn read_rpc__should_not_exist_in_the_release_build() {
    // Given
    let setup = SandboxTestSetup::builder()
        .with_foreign_tx_domain()
        .build()
        .await;
    let user = setup.worker.dev_create_account().await.unwrap();
    let request = VerifyForeignTransactionRequestV2 {
        request: bitcoin_request(),
        domain_id: dtos::DomainId(setup.foreign_tx_key().domain_id().0),
        expected_values: bitcoin_extracted_values(),
    };

    // When
    let result = user
        .call_mpc(setup.contract.id())
        .read_rpc(request)
        .await
        .unwrap()
        .into_result();

    // Then
    let failure = result.unwrap_err().to_string();
    assert!(
        failure.contains("MethodNotFound"),
        "the release build must not have read_rpc, got: {failure}"
    );
}
