use super::super::test_utils::*;
use super::super::*;
use foreign_chain_rpc_factory::inspectors::InspectorFactory;
use foreign_chain_rpc_interfaces::sui::Status;
use foreign_chain_rpc_interfaces::sui::proto::GetServiceInfoResponse;
use rstest::rstest;

#[tokio::test]
async fn probe_all_providers__should_report_every_evm_chain_on_its_expected_network_as_healthy() {
    // Given
    let mut servers = Vec::new();
    let mut config = ForeignChainsConfig::default();
    for mainnet in EVM_MAINNETS {
        let server = httpmock::MockServer::start_async().await;
        mock_fingerprint(&server, &mainnet.answered()).await;
        put_chain(
            &mut config,
            mainnet.chain,
            chain_config(
                Some(&mainnet.expected()),
                one_provider("publicnode", &server.base_url()),
            ),
        );
        servers.push(server);
    }

    // When
    let report = probe_all_providers(&config, &InspectorFactory).await;

    // Then
    for EvmMainnet { chain, .. } in EVM_MAINNETS {
        assert_eq!(
            status_of(&report, chain, "publicnode"),
            ProviderStatus::Healthy,
            "{chain:?}"
        );
    }
}

#[tokio::test]
async fn probe_all_providers__should_report_every_svm_chain_on_its_expected_network_as_healthy() {
    // Given — each chain answers its own genesis hash, so a cross-wired arm would
    // compare Solana's against Fogo's.
    let expected = [
        (ForeignChain::Solana, SOLANA_MAINNET),
        (ForeignChain::Fogo, FOGO_MAINNET),
    ];
    let mut servers = Vec::new();
    let mut config = ForeignChainsConfig::default();
    for (chain, genesis_hash) in expected {
        let server = httpmock::MockServer::start_async().await;
        mock_fingerprint(&server, genesis_hash).await;
        put_chain(
            &mut config,
            chain,
            chain_config(
                Some(genesis_hash),
                one_provider("publicnode", &server.base_url()),
            ),
        );
        servers.push(server);
    }

    // When
    let report = probe_all_providers(&config, &InspectorFactory).await;

    // Then
    for (chain, _) in expected {
        assert_eq!(
            status_of(&report, chain, "publicnode"),
            ProviderStatus::Healthy,
            "{chain:?}"
        );
    }
}

#[tokio::test]
async fn probe_all_providers__should_report_an_svm_provider_on_another_network_as_wrong_network() {
    // Given — a provider on Solana devnet against a mainnet expectation.
    let mainnet = SOLANA_MAINNET;
    let devnet = SOLANA_DEVNET;
    let server = httpmock::MockServer::start_async().await;
    mock_fingerprint(&server, devnet).await;
    let mut config = ForeignChainsConfig::default();
    put_chain(
        &mut config,
        ForeignChain::Solana,
        chain_config(
            Some(mainnet),
            one_provider("publicnode", &server.base_url()),
        ),
    );

    // When
    let report = probe_all_providers(&config, &InspectorFactory).await;

    // Then
    assert_eq!(
        status_of(&report, ForeignChain::Solana, "publicnode"),
        ProviderStatus::WrongNetwork {
            expected: NetworkFingerprint::new(mainnet),
            observed: NetworkFingerprint::new(devnet),
        }
    );
}

#[tokio::test]
async fn probe_all_providers__should_report_an_evm_provider_on_another_network_as_wrong_network() {
    // Given
    let server = httpmock::MockServer::start_async().await;
    mock_fingerprint(&server, "0x14a34").await;
    let mut config = ForeignChainsConfig::default();
    put_chain(
        &mut config,
        ForeignChain::Base,
        chain_config(Some("8453"), one_provider("publicnode", &server.base_url())),
    );

    // When
    let report = probe_all_providers(&config, &InspectorFactory).await;

    // Then
    assert_eq!(
        status_of(&report, ForeignChain::Base, "publicnode"),
        ProviderStatus::WrongNetwork {
            expected: NetworkFingerprint::new("8453"),
            observed: NetworkFingerprint::new("84532"),
        }
    );
}

#[tokio::test]
async fn probe_all_providers__should_report_bitcoin_on_its_genesis_block_as_healthy() {
    // Given
    let server = httpmock::MockServer::start_async().await;
    mock_fingerprint(&server, BITCOIN_MAINNET).await;
    let config = bitcoin_only(chain_config(
        Some(BITCOIN_MAINNET),
        one_provider("publicnode", &server.base_url()),
    ));

    // When
    let report = probe_all_providers(&config, &InspectorFactory).await;

    // Then
    assert_eq!(
        status_of(&report, ForeignChain::Bitcoin, "publicnode"),
        ProviderStatus::Healthy
    );
}

#[tokio::test]
async fn probe_all_providers__should_report_bitcoin_on_another_network_as_wrong_network() {
    // Given
    let server = httpmock::MockServer::start_async().await;
    mock_fingerprint(&server, BITCOIN_TESTNET3).await;
    let config = bitcoin_only(chain_config(
        Some(BITCOIN_MAINNET),
        one_provider("publicnode", &server.base_url()),
    ));

    // When
    let report = probe_all_providers(&config, &InspectorFactory).await;

    // Then
    assert_eq!(
        status_of(&report, ForeignChain::Bitcoin, "publicnode"),
        ProviderStatus::WrongNetwork {
            expected: NetworkFingerprint::new(BITCOIN_MAINNET),
            observed: NetworkFingerprint::new(BITCOIN_TESTNET3),
        }
    );
}

#[tokio::test]
async fn probe_all_providers__should_report_aptos_on_its_expected_chain_id_as_healthy() {
    // Given
    let server = httpmock::MockServer::start_async().await;
    mock_ledger_info(&server, APTOS_MAINNET).await;
    let config = ForeignChainsConfig {
        aptos: Some(chain_config(
            Some(&APTOS_MAINNET.to_string()),
            one_provider(PROVIDER_NAME, &server.base_url()),
        )),
        ..Default::default()
    };

    // When
    let report = probe_all_providers(&config, &InspectorFactory).await;

    // Then
    assert_eq!(
        status_of(&report, ForeignChain::Aptos, PROVIDER_NAME),
        ProviderStatus::Healthy
    );
}

#[tokio::test]
async fn probe_all_providers__should_report_aptos_on_another_network_as_wrong_network() {
    // Given
    let server = httpmock::MockServer::start_async().await;
    mock_ledger_info(&server, APTOS_TESTNET).await;
    let config = ForeignChainsConfig {
        aptos: Some(chain_config(
            Some(&APTOS_MAINNET.to_string()),
            one_provider(PROVIDER_NAME, &server.base_url()),
        )),
        ..Default::default()
    };

    // When
    let report = probe_all_providers(&config, &InspectorFactory).await;

    // Then
    assert_eq!(
        status_of(&report, ForeignChain::Aptos, PROVIDER_NAME),
        ProviderStatus::WrongNetwork {
            expected: NetworkFingerprint::new(APTOS_MAINNET.to_string()),
            observed: NetworkFingerprint::new(APTOS_TESTNET.to_string()),
        }
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
    let config = sui_only(chain_config(
        Some(SUI_MAINNET),
        one_provider(PROVIDER_NAME, &server.url),
    ));

    // When
    let report = probe_all_providers(&config, &InspectorFactory).await;

    // Then
    assert_eq!(
        status_of(&report, ForeignChain::Sui, PROVIDER_NAME),
        expected
    );
}

#[tokio::test]
async fn probe_all_providers__should_report_an_unreachable_sui_provider() {
    // Given
    let config = sui_only(chain_config(
        Some(SUI_MAINNET),
        one_provider(PROVIDER_NAME, CLOSED_PORT_URL),
    ));

    // When
    let report = probe_all_providers(&config, &InspectorFactory).await;

    // Then
    assert_eq!(
        status_of(&report, ForeignChain::Sui, PROVIDER_NAME),
        ProviderStatus::Unreachable
    );
}
