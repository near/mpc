use super::super::test_utils::*;
use super::super::*;
use foreign_chain_inspector::mock::{MockInspector, MockReply};
use foreign_chain_rpc_factory::inspectors::InspectorFactory;
use mpc_node_config::{AuthConfig, TokenConfig};
use near_mpc_bounded_collections::NonEmptyBTreeMap;
use std::assert_matches;

#[tokio::test]
async fn probe_all_providers__should_report_a_provider_on_the_expected_network_as_healthy() {
    // Given
    let url = "http://mock.invalid/only";
    let config = starknet_only(chain_config(Some(MAINNET), one_provider("publicnode", url)));
    let inspector = MockInspector::new([answering(MAINNET)]);
    let inspectors = MockInspectors::new([(url, inspector.clone())]);

    // When
    let report = probe_all_providers(&config, &inspectors).await;

    // Then
    assert_eq!(inspector.calls(), 1);
    assert_eq!(
        status_of(&report, ForeignChain::Starknet, "publicnode"),
        ProviderStatus::Healthy
    );
}

#[tokio::test]
async fn probe_all_providers__should_report_a_provider_on_another_network_as_wrong_network() {
    // Given
    let url = "http://mock.invalid/only";
    let config = starknet_only(chain_config(Some(MAINNET), one_provider("publicnode", url)));
    let inspectors = MockInspectors::new([(url, MockInspector::new([answering(SEPOLIA)]))]);

    // When
    let report = probe_all_providers(&config, &inspectors).await;

    // Then
    assert_eq!(
        status_of(&report, ForeignChain::Starknet, "publicnode"),
        ProviderStatus::WrongNetwork {
            expected: NetworkFingerprint::new(MAINNET),
            observed: NetworkFingerprint::new(SEPOLIA),
        }
    );
}

#[tokio::test]
async fn probe_all_providers__should_normalize_the_reported_fingerprint_before_comparing() {
    // Given
    let server = httpmock::MockServer::start_async().await;
    mock_fingerprint(&server, PADDED_UPPERCASE_MAINNET).await;
    let config = starknet_only(chain_config(
        Some(MAINNET),
        one_provider("publicnode", &server.base_url()),
    ));

    // When
    let report = probe_all_providers(&config, &InspectorFactory).await;

    // Then
    assert_eq!(
        status_of(&report, ForeignChain::Starknet, "publicnode"),
        ProviderStatus::Healthy
    );
}

#[tokio::test]
async fn probe_all_providers__should_report_a_chain_without_an_expected_fingerprint_without_probing()
 {
    // Given
    let server = httpmock::MockServer::start_async().await;
    let mock = mock_fingerprint(&server, MAINNET).await;
    let config = starknet_only(chain_config(
        None,
        one_provider("publicnode", &server.base_url()),
    ));

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
async fn probe_all_providers__should_report_an_unreachable_provider() {
    // Given
    let config = starknet_only(chain_config(
        Some(MAINNET),
        one_provider("publicnode", CLOSED_PORT_URL),
    ));

    // When
    let report = probe_all_providers(&config, &InspectorFactory).await;

    // Then
    assert_eq!(
        status_of(&report, ForeignChain::Starknet, "publicnode"),
        ProviderStatus::Unreachable
    );
}

#[tokio::test]
async fn probe_all_providers__should_report_a_provider_refusing_the_request_without_retrying() {
    // Given
    let url = "http://mock.invalid/only";
    let inspector = MockInspector::new([MockReply::refusal(std::time::Duration::ZERO)]);
    let config = starknet_only(with_retries(
        chain_config(Some(MAINNET), one_provider("keyed", url)),
        3,
    ));
    let inspectors = MockInspectors::new([(url, inspector.clone())]);

    // When
    let report = probe_all_providers(&config, &inspectors).await;

    // Then
    assert_eq!(
        status_of(&report, ForeignChain::Starknet, "keyed"),
        ProviderStatus::RequestRejected
    );
    assert_eq!(inspector.calls(), 1, "a refusal must not be retried");
}

#[tokio::test]
async fn probe_all_providers__should_report_a_provider_answering_with_a_jsonrpc_error() {
    // Given
    let server = httpmock::MockServer::start_async().await;
    mock_unsupported_method(&server).await;
    let config = starknet_only(chain_config(
        Some(MAINNET),
        one_provider("publicnode", &server.base_url()),
    ));

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
    let config = starknet_only(chain_config(
        Some(MAINNET),
        one_provider("publicnode", &server.base_url()),
    ));

    // When
    let report = probe_all_providers(&config, &InspectorFactory).await;

    // Then
    assert_eq!(
        status_of(&report, ForeignChain::Starknet, "publicnode"),
        ProviderStatus::MalformedResponse
    );
}

#[tokio::test(start_paused = true)]
async fn probe_all_providers__should_report_a_provider_that_does_not_answer_in_time() {
    // Given
    let url = "http://mock.invalid/slow";
    let config = starknet_only(chain_config(Some(MAINNET), one_provider("slow", url)));
    let inspectors = MockInspectors::new([(url, MockInspector::new([MockReply::Hang]))]);

    // When
    let report = probe_all_providers(&config, &inspectors).await;

    // Then
    assert_eq!(
        status_of(&report, ForeignChain::Starknet, "slow"),
        ProviderStatus::TimedOut
    );
}

#[tokio::test]
async fn probe_all_providers__should_normalize_the_configured_fingerprint_before_comparing() {
    // Given
    let server = httpmock::MockServer::start_async().await;
    mock_fingerprint(&server, MAINNET).await;
    let config = starknet_only(chain_config(
        Some(PADDED_UPPERCASE_MAINNET),
        one_provider("publicnode", &server.base_url()),
    ));

    // When
    let report = probe_all_providers(&config, &InspectorFactory).await;

    // Then
    assert_eq!(
        status_of(&report, ForeignChain::Starknet, "publicnode"),
        ProviderStatus::Healthy
    );
}

#[tokio::test]
async fn probe_all_providers__should_report_a_provider_whose_auth_token_does_not_resolve() {
    // Given
    let config = starknet_only(chain_config(
        Some(MAINNET),
        NonEmptyBTreeMap::new(
            "keyed".to_string().into(),
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
        ),
    ));

    // When
    let report = probe_all_providers(&config, &InspectorFactory).await;

    // Then
    assert_eq!(
        status_of(&report, ForeignChain::Starknet, "keyed"),
        ProviderStatus::AuthTokenUnresolved
    );
}

#[tokio::test]
async fn probe_all_providers__should_report_a_provider_whose_client_cannot_be_built() {
    // Given
    let config = starknet_only(chain_config(
        Some(MAINNET),
        one_provider("wrong-scheme", "ws://127.0.0.1:9"),
    ));

    // When
    let report = probe_all_providers(&config, &InspectorFactory).await;

    // Then
    assert_eq!(
        status_of(&report, ForeignChain::Starknet, "wrong-scheme"),
        ProviderStatus::ClientSetupFailed
    );
}

#[tokio::test]
async fn probe_all_providers__should_report_each_provider_of_a_chain_separately() {
    // Given
    let server = httpmock::MockServer::start_async().await;
    mock_fingerprint(&server, MAINNET).await;
    let mut providers = one_provider("healthy", &server.base_url());
    providers.insert("broken".to_string().into(), provider(CLOSED_PORT_URL));
    let config = starknet_only(chain_config(Some(MAINNET), providers));

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
    let config = sui_only(chain_config(
        Some(ANY_FINGERPRINT),
        one_provider("publicnode", CLOSED_PORT_URL),
    ));

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

#[tokio::test(start_paused = true)]
async fn probe_all_providers__should_retry_a_provider_that_refused_with_a_rate_limit_code() {
    // Given
    let url = "http://mock.invalid/keyed";
    let inspector = MockInspector::new([
        MockReply::transient(std::time::Duration::from_millis(10)),
        MockReply::transient(std::time::Duration::from_millis(10)),
    ]);
    let config = starknet_only(with_retries(
        chain_config(Some(MAINNET), one_provider("keyed", url)),
        2,
    ));
    let inspectors = MockInspectors::new([(url, inspector.clone())]);

    // When
    let report = probe_all_providers(&config, &inspectors).await;

    // Then
    assert_eq!(
        status_of(&report, ForeignChain::Starknet, "keyed"),
        ProviderStatus::Unreachable
    );
    assert_eq!(
        inspector.calls(),
        2,
        "the transient failure should be retried"
    );
}

#[tokio::test]
async fn probe_all_providers__should_bound_the_fingerprint_a_provider_reports() {
    // Given
    let server = httpmock::MockServer::start_async().await;
    let flood = "n".repeat(5_000);
    mock_fingerprint(&server, &flood).await;
    let config = starknet_only(chain_config(
        Some(MAINNET),
        one_provider("publicnode", &server.base_url()),
    ));

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
    let config = starknet_only(chain_config(
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
    ));

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
