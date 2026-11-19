use super::super::test_utils::*;
use super::super::*;
use foreign_chain_rpc_factory::inspectors::InspectorFactory;
use foreign_chain_rpc_interfaces::sui::Status;
use foreign_chain_rpc_interfaces::sui::proto::GetServiceInfoResponse;
use rstest::rstest;

#[tokio::test]
async fn probe_all_providers__should_report_every_evm_and_svm_chain_on_its_expected_network_as_healthy()
 {
    // Given
    // Every chain in one config, each answering its own fingerprint, so a cross wired arm would
    // compare one chain's against another's.
    let mainnets: Vec<(ForeignChain, String, String)> = EVM_MAINNETS
        .iter()
        .map(|mainnet| (mainnet.chain, mainnet.expected(), mainnet.answered()))
        .chain([
            (
                ForeignChain::Solana,
                SOLANA_MAINNET.to_string(),
                SOLANA_MAINNET.to_string(),
            ),
            (
                ForeignChain::Fogo,
                FOGO_MAINNET.to_string(),
                FOGO_MAINNET.to_string(),
            ),
        ])
        .collect();
    let mut servers = Vec::new();
    let mut config = ForeignChainsConfig::default();
    for (chain, expected, answered) in &mainnets {
        let server = httpmock::MockServer::start_async().await;
        mock_fingerprint(&server, answered).await;
        put_chain(
            &mut config,
            *chain,
            chain_config(
                Some(expected),
                one_provider(PROVIDER_NAME, &server.base_url()),
            ),
        );
        servers.push(server);
    }

    // When
    let report = probe_all_providers(&config, &InspectorFactory).await;

    // Then
    for (chain, _, _) in mainnets {
        assert_eq!(
            status_of(&report, chain, PROVIDER_NAME),
            ProviderStatus::Healthy,
            "{chain:?}"
        );
    }
}

#[rstest]
#[case::starknet_normalizes_the_reported_fingerprint(
    ForeignChain::Starknet,
    MAINNET,
    PADDED_UPPERCASE_MAINNET,
    ProviderStatus::Healthy
)]
#[case::starknet_normalizes_the_configured_fingerprint(
    ForeignChain::Starknet,
    PADDED_UPPERCASE_MAINNET,
    MAINNET,
    ProviderStatus::Healthy
)]
#[case::bitcoin_on_its_genesis_block(
    ForeignChain::Bitcoin,
    BITCOIN_MAINNET,
    BITCOIN_MAINNET,
    ProviderStatus::Healthy
)]
#[case::bitcoin_on_another_network(
    ForeignChain::Bitcoin,
    BITCOIN_MAINNET,
    BITCOIN_TESTNET3,
    ProviderStatus::WrongNetwork {
        expected: NetworkFingerprint::new(BITCOIN_MAINNET),
        observed: NetworkFingerprint::new(BITCOIN_TESTNET3),
    }
)]
#[case::solana_on_another_network(
    ForeignChain::Solana,
    SOLANA_MAINNET,
    SOLANA_DEVNET,
    ProviderStatus::WrongNetwork {
        expected: NetworkFingerprint::new(SOLANA_MAINNET),
        observed: NetworkFingerprint::new(SOLANA_DEVNET),
    }
)]
#[case::evm_on_another_network(
    ForeignChain::Base,
    "8453",
    "0x14a34",
    ProviderStatus::WrongNetwork {
        expected: NetworkFingerprint::new("8453"),
        observed: NetworkFingerprint::new("84532"),
    }
)]
#[tokio::test]
async fn probe_all_providers__should_classify_the_jsonrpc_fingerprint_answer(
    #[case] chain: ForeignChain,
    #[case] expected: &str,
    #[case] answered: &str,
    #[case] status: ProviderStatus,
) {
    // Given
    let server = httpmock::MockServer::start_async().await;
    mock_fingerprint(&server, answered).await;
    let config = single_chain(
        chain,
        chain_config(
            Some(expected),
            one_provider(PROVIDER_NAME, &server.base_url()),
        ),
    );

    // When
    let report = probe_all_providers(&config, &InspectorFactory).await;

    // Then
    assert_eq!(status_of(&report, chain, PROVIDER_NAME), status);
}

#[rstest]
#[case::on_its_expected_chain_id(APTOS_MAINNET, ProviderStatus::Healthy)]
#[case::on_another_network(
    APTOS_TESTNET,
    ProviderStatus::WrongNetwork {
        expected: NetworkFingerprint::new(APTOS_MAINNET.to_string()),
        observed: NetworkFingerprint::new(APTOS_TESTNET.to_string()),
    }
)]
#[tokio::test]
async fn probe_all_providers__should_classify_the_aptos_answer(
    #[case] answered: u64,
    #[case] status: ProviderStatus,
) {
    // Given
    let server = httpmock::MockServer::start_async().await;
    mock_ledger_info(&server, answered).await;
    let config = single_chain(
        ForeignChain::Aptos,
        chain_config(
            Some(&APTOS_MAINNET.to_string()),
            one_provider(PROVIDER_NAME, &server.base_url()),
        ),
    );

    // When
    let report = probe_all_providers(&config, &InspectorFactory).await;

    // Then
    assert_eq!(
        status_of(&report, ForeignChain::Aptos, PROVIDER_NAME),
        status
    );
}

#[rstest]
#[case::on_its_genesis_digest(
    Ok(GetServiceInfoResponse::default().with_chain_id(SUI_MAINNET)),
    ProviderStatus::Healthy
)]
#[case::on_another_network(
    Ok(GetServiceInfoResponse::default().with_chain_id(SUI_TESTNET)),
    ProviderStatus::WrongNetwork {
        expected: NetworkFingerprint::new(SUI_MAINNET),
        observed: NetworkFingerprint::new(SUI_TESTNET),
    }
)]
#[case::missing_chain_id(
    Ok(GetServiceInfoResponse::default()),
    ProviderStatus::MalformedResponse
)]
#[case::not_serving_the_api(
    Err(Status::not_found("no such service")),
    ProviderStatus::RequestRejected
)]
#[case::slow_answer(Err(Status::deadline_exceeded("too slow")), ProviderStatus::TimedOut)]
#[tokio::test]
async fn probe_all_providers__should_classify_the_sui_answer(
    #[case] answer: Result<GetServiceInfoResponse, Status>,
    #[case] expected: ProviderStatus,
) {
    // Given
    let server = sui_answering(answer).await;
    let config = single_chain(
        ForeignChain::Sui,
        chain_config(Some(SUI_MAINNET), one_provider(PROVIDER_NAME, &server.url)),
    );

    // When
    let report = probe_all_providers(&config, &InspectorFactory).await;

    // Then
    assert_eq!(
        status_of(&report, ForeignChain::Sui, PROVIDER_NAME),
        expected
    );
}
