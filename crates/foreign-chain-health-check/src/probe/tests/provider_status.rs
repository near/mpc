use super::super::test_utils::*;
use super::super::*;
use foreign_chain_inspector::mock::{MockInspector, MockReply};
use foreign_chain_rpc_factory::inspectors::InspectorFactory;
use mpc_node_config::{AuthConfig, TokenConfig};
use near_mpc_bounded_collections::NonEmptyBTreeMap;
use rstest::rstest;
use std::assert_matches;
use std::time::Duration;

#[rstest]
#[case::on_the_expected_network(vec![answering(MAINNET)], 1, ProviderStatus::Healthy, 1)]
#[case::on_another_network(
    vec![answering(SEPOLIA)],
    1,
    ProviderStatus::WrongNetwork {
        expected: NetworkFingerprint::new(MAINNET),
        observed: NetworkFingerprint::new(SEPOLIA),
    },
    1
)]
#[case::refusing_the_request(
    vec![MockReply::refusal(Duration::ZERO)],
    3,
    ProviderStatus::RequestRejected,
    1
)]
#[case::not_answering_in_time(vec![MockReply::Hang], 1, ProviderStatus::TimedOut, 1)]
#[case::failing_transiently(
    vec![
        MockReply::transient(Duration::from_millis(10)),
        MockReply::transient(Duration::from_millis(10)),
    ],
    2,
    ProviderStatus::Unreachable,
    2
)]
#[tokio::test(start_paused = true)]
async fn probe_all_providers__should_classify_the_answer_and_retry_only_transient_failures(
    #[case] replies: Vec<MockReply>,
    #[case] max_retries: u64,
    #[case] status: ProviderStatus,
    #[case] tries: usize,
) {
    // Given
    let url = "http://mock.invalid/only";
    let inspector = MockInspector::new(replies);
    let config = single_chain(
        ForeignChain::Starknet,
        with_retries(
            chain_config(Some(MAINNET), one_provider(PROVIDER_NAME, url)),
            max_retries,
        ),
    );
    let inspectors = MockInspectors::new([(url, inspector.clone())]);

    // When
    let report = probe_all_providers(&config, &inspectors).await;

    // Then
    assert_eq!(
        status_of(&report, ForeignChain::Starknet, PROVIDER_NAME),
        status
    );
    assert_eq!(inspector.calls(), tries, "tries for {status:?}");
}

#[rstest]
#[case::unreachable(
    ForeignChain::Starknet,
    MAINNET,
    provider(CLOSED_PORT_URL),
    ProviderStatus::Unreachable
)]
#[case::unreachable_sui(
    ForeignChain::Sui,
    SUI_MAINNET,
    provider(CLOSED_PORT_URL),
    ProviderStatus::Unreachable
)]
#[case::auth_token_unresolved(
    ForeignChain::Starknet,
    MAINNET,
    ForeignChainProviderConfig {
        rpc_url: CLOSED_PORT_URL.to_string(),
        auth: AuthConfig::Header {
            name: http::HeaderName::from_static("authorization"),
            scheme: Some("Bearer".to_string()),
            token: TokenConfig::Env {
                env: "PROBE_TEST_TOKEN_THAT_IS_NOT_SET".to_string(),
            },
        },
    },
    ProviderStatus::AuthTokenUnresolved
)]
#[case::unsupported_url_scheme(
    ForeignChain::Starknet,
    MAINNET,
    provider("ws://127.0.0.1:9"),
    ProviderStatus::ClientSetupFailed
)]
#[tokio::test]
async fn probe_all_providers__should_report_a_provider_it_cannot_query(
    #[case] chain: ForeignChain,
    #[case] expected: &str,
    #[case] provider_config: ForeignChainProviderConfig,
    #[case] status: ProviderStatus,
) {
    // Given
    let config = single_chain(
        chain,
        chain_config(
            Some(expected),
            NonEmptyBTreeMap::new(PROVIDER_NAME.to_string().into(), provider_config),
        ),
    );

    // When
    let report = probe_all_providers(&config, &InspectorFactory).await;

    // Then
    assert_eq!(status_of(&report, chain, PROVIDER_NAME), status);
}

#[tokio::test]
async fn probe_all_providers__should_report_a_chain_without_an_expected_fingerprint_without_probing()
 {
    // Given
    let server = httpmock::MockServer::start_async().await;
    let mock = mock_fingerprint(&server, MAINNET).await;
    let config = single_chain(
        ForeignChain::Starknet,
        chain_config(None, one_provider("publicnode", &server.base_url())),
    );

    // When
    let report = probe_all_providers(&config, &InspectorFactory).await;

    // Then
    assert_eq!(
        status_of(&report, ForeignChain::Starknet, "publicnode"),
        ProviderStatus::MissingExpectedFingerprint
    );
    mock.assert_calls_async(0).await;
}

#[tokio::test]
async fn probe_all_providers__should_report_a_provider_answering_with_a_jsonrpc_error() {
    // Given
    let server = httpmock::MockServer::start_async().await;
    mock_unsupported_method(&server).await;
    let config = single_chain(
        ForeignChain::Starknet,
        chain_config(
            Some(MAINNET),
            one_provider("publicnode", &server.base_url()),
        ),
    );

    // When
    let report = probe_all_providers(&config, &InspectorFactory).await;

    // Then
    assert_eq!(
        status_of(&report, ForeignChain::Starknet, "publicnode"),
        ProviderStatus::RequestRejected
    );
}

#[tokio::test]
async fn probe_all_providers__should_report_a_provider_answering_with_an_unusable_body() {
    // Given
    let server = httpmock::MockServer::start_async().await;
    mock_non_jsonrpc_body(&server).await;
    let config = single_chain(
        ForeignChain::Starknet,
        chain_config(
            Some(MAINNET),
            one_provider("publicnode", &server.base_url()),
        ),
    );

    // When
    let report = probe_all_providers(&config, &InspectorFactory).await;

    // Then
    assert_eq!(
        status_of(&report, ForeignChain::Starknet, "publicnode"),
        ProviderStatus::MalformedResponse
    );
}

#[tokio::test]
async fn probe_all_providers__should_report_each_provider_of_a_chain_separately() {
    // Given
    let server = httpmock::MockServer::start_async().await;
    mock_fingerprint(&server, MAINNET).await;
    let mut providers = one_provider("healthy", &server.base_url());
    providers.insert("broken".to_string().into(), provider(CLOSED_PORT_URL));
    let config = single_chain(
        ForeignChain::Starknet,
        chain_config(Some(MAINNET), providers),
    );

    // When
    let report = probe_all_providers(&config, &InspectorFactory).await;

    // Then
    assert_eq!(
        status_of(&report, ForeignChain::Starknet, "healthy"),
        ProviderStatus::Healthy
    );
    assert_eq!(
        status_of(&report, ForeignChain::Starknet, "broken"),
        ProviderStatus::Unreachable
    );
    assert_eq!(
        report.counts_per_chain()[&ForeignChain::Starknet],
        ProviderCounts {
            configured: 2,
            healthy: 1,
        }
    );
}

#[tokio::test]
async fn probe_all_providers__should_report_a_chain_with_no_inspector_as_not_implemented() {
    // Given
    let config = single_chain(
        ForeignChain::Sui,
        chain_config(
            Some(ANY_FINGERPRINT),
            one_provider("publicnode", CLOSED_PORT_URL),
        ),
    );

    // When
    let report = probe_all_providers(&config, &NoInspectors).await;

    // Then
    assert_eq!(
        status_of(&report, ForeignChain::Sui, "publicnode"),
        ProviderStatus::ProbeNotImplemented
    );
}

#[tokio::test]
async fn probe_all_providers__should_report_every_configured_chain_under_its_own_chain() {
    // Given
    let server = httpmock::MockServer::start_async().await;
    mock_fingerprint(&server, MAINNET).await;
    let config = ForeignChainsConfig {
        starknet: Some(chain_config(
            Some(MAINNET),
            one_provider("publicnode", &server.base_url()),
        )),
        bitcoin: Some(chain_config(
            Some(ANY_FINGERPRINT),
            one_provider("publicnode", CLOSED_PORT_URL),
        )),
        ..Default::default()
    };

    // When
    let report = probe_all_providers(&config, &InspectorFactory).await;

    // Then
    assert_eq!(
        status_of(&report, ForeignChain::Starknet, "publicnode"),
        ProviderStatus::Healthy
    );
    assert_eq!(
        status_of(&report, ForeignChain::Bitcoin, "publicnode"),
        ProviderStatus::Unreachable
    );
    assert_eq!(report.counts_per_chain().len(), 2);
}

#[tokio::test]
async fn probe_all_providers__should_bound_the_fingerprint_a_provider_reports() {
    // Given
    let server = httpmock::MockServer::start_async().await;
    let flood = "n".repeat(5_000);
    mock_fingerprint(&server, &flood).await;
    let config = single_chain(
        ForeignChain::Starknet,
        chain_config(
            Some(MAINNET),
            one_provider("publicnode", &server.base_url()),
        ),
    );

    // When
    let report = probe_all_providers(&config, &InspectorFactory).await;

    // Then
    let ProviderStatus::WrongNetwork { observed, .. } =
        status_of(&report, ForeignChain::Starknet, "publicnode")
    else {
        panic!("expected the flood to read as the wrong network");
    };
    let observed = observed.to_string();
    assert!(observed.ends_with("_TRUNCATED"), "{observed}");
    assert_eq!(
        observed.chars().count(),
        NetworkFingerprint::MAX_CHARS,
        "{observed}"
    );
}

#[test]
fn classify__should_report_a_transaction_state_answer_as_malformed() {
    // Given
    let expected = NetworkFingerprint::new(MAINNET);

    // When
    let status = classify(&expected, Err(ForeignChainInspectionError::NotFinalized));

    // Then
    assert_eq!(status, ProviderStatus::MalformedResponse);
}

#[tokio::test]
async fn probe_all_providers__should_return_an_empty_report_when_no_chains_are_configured() {
    // Given
    let config = ForeignChainsConfig::default();

    // When
    let report = probe_all_providers(&config, &InspectorFactory).await;

    // Then
    assert!(report.rows().is_empty());
    assert!(report.counts_per_chain().is_empty());
}

#[tokio::test]
async fn probe_all_providers__should_keep_auth_material_out_of_the_report() {
    // Given
    let server = httpmock::MockServer::start_async().await;
    mock_fingerprint(&server, SEPOLIA).await;
    let config = single_chain(
        ForeignChain::Starknet,
        chain_config(
            Some(MAINNET),
            NonEmptyBTreeMap::new(
                "keyed".to_string().into(),
                ForeignChainProviderConfig {
                    rpc_url: format!("{}/v2/API_KEY", server.base_url()),
                    auth: AuthConfig::Path {
                        placeholder: "API_KEY".to_string(),
                        token: TokenConfig::Val {
                            val: "super-secret".to_string(),
                        },
                    },
                },
            ),
        ),
    );

    // When
    let report = probe_all_providers(&config, &InspectorFactory).await;

    // Then
    assert_matches!(
        status_of(&report, ForeignChain::Starknet, "keyed"),
        ProviderStatus::WrongNetwork { .. }
    );
    let rendered = format!("{report:?}");
    assert!(!rendered.contains("super-secret"), "{rendered}");
    assert!(!rendered.contains("127.0.0.1"), "{rendered}");
}
