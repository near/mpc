use crate::sandbox::{
    common::{SandboxTestSetup, create_account_given_id},
    utils::{consts::ALL_PROTOCOLS, sign_utils::DomainResponseTest},
};
use rand::SeedableRng;
use test_utils::MAINNET_PROTOCOL_VERSION;

#[tokio::test]
#[expect(non_snake_case)]
#[ignore = "pinned to mainnet's protocol; runs in the Mainnet protocol compatibility CI job"]
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
