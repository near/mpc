use crate::sandbox::{common::SandboxTestSetup, utils::mpc_contract::get_participants};
use near_mpc_contract_interface::method_names;
use near_mpc_contract_interface::types::{MAX_PARTICIPANT_URL_BYTES, Protocol};
use near_workspaces::types::NearToken;
use serde_json::json;

#[tokio::test]
#[expect(non_snake_case)]
async fn update_participant_url__should_reject_a_url_over_the_byte_limit() -> anyhow::Result<()> {
    // Given
    let SandboxTestSetup {
        worker: _worker,
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(&[Protocol::CaitSith])
        .build()
        .await;
    let participants_before = get_participants(&contract).await?;
    let oversized_url = "u".repeat(MAX_PARTICIPANT_URL_BYTES + 1);

    // When
    // The typed client cannot send an oversized url.
    let result = mpc_signer_accounts[0]
        .call(contract.id(), method_names::UPDATE_PARTICIPANT_URL)
        .args_json(json!({ "url": oversized_url }))
        .deposit(NearToken::from_yoctonear(1))
        .max_gas()
        .transact()
        .await?;

    // Then
    let error_msg = format!("{:?}", result.into_result());
    assert!(
        error_msg.contains("Upper bound violation"),
        "expected the url bound to reject the call, got: {error_msg}"
    );
    assert_eq!(get_participants(&contract).await?, participants_before);
    Ok(())
}
