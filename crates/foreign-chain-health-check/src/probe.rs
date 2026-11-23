//! Asks every configured RPC provider which network it serves and compares the answer against the
//! operator's `expected_network_fingerprint`.

use foreign_chain_inspector::{
    BuildInspectors, FanOut, ForeignChainInspectionError, NetworkFingerprint, ProviderFailure,
};
use mpc_node_config::{ForeignChainConfig, ForeignChainProviderConfig, ForeignChainsConfig};
use near_mpc_bounded_collections::NonEmptyVec;
use near_mpc_contract_interface::types::{ForeignChain, ProviderId};

mod report;
#[cfg(test)]
mod test_utils;

pub use report::{ProbeReport, ProviderCounts, ProviderHealth, ProviderStatus};

/// Probe every configured provider concurrently.
///
/// Each provider is tried up to `max_retries` times, `timeout_sec` per try, and only for as long as
/// the failures stay transient. This returns within the largest configured `timeout_sec *
/// max_retries`, plus the [`foreign_chain_inspector::RETRY_BACKOFF`] between tries.
pub async fn probe_all_providers<InspectorFactory>(
    config: &ForeignChainsConfig,
    inspectors: &InspectorFactory,
) -> ProbeReport
where
    InspectorFactory: BuildInspectors,
{
    let probe_attempts = config.into_iter().map(|(chain, chain_config)| {
        let timeout = chain_config.timeout_duration();
        async move {
            probe_chain(chain, chain_config, |provider| {
                inspectors.build(chain, provider, timeout)
            })
            .await
        }
    });

    futures::future::join_all(probe_attempts)
        .await
        .concat()
        .into()
}

async fn probe_chain<I>(
    chain: ForeignChain,
    config: &ForeignChainConfig,
    build_new_inspector: impl Fn(&ForeignChainProviderConfig) -> anyhow::Result<Option<I>>,
) -> Vec<ProviderHealth>
where
    I: foreign_chain_inspector::ChainInspector,
{
    let mut inspectors = Vec::new();
    let mut rows = Vec::new();
    for (name, provider) in config.providers.iter() {
        let provider_id = ProviderId(name.as_str().to_owned());
        match build_new_inspector(provider) {
            // Inspector not implemented for the chain
            Ok(None) => return rows_of(chain, config, ProviderStatus::ProbeNotImplemented),
            Ok(Some(inspector)) => inspectors.push((provider_id, inspector)),
            Err(error) => rows.push(ProviderHealth {
                chain,
                provider: provider_id,
                status: setup_failure(&error),
            }),
        }
    }

    let Some(expected) = &config.expected_network_fingerprint else {
        return rows_of(chain, config, ProviderStatus::MissingExpectedFingerprint);
    };

    let Ok(inspectors) = NonEmptyVec::try_from(inspectors) else {
        return rows;
    };
    // Any of the chain's inspectors normalizes the same way; the first one that built is enough.
    let (_, inspector) = inspectors.first();
    let expected = inspector.canonical_fingerprint(expected);

    let fingerprints = FanOut::new(inspectors)
        .network_fingerprints(config.timeout_duration(), config.max_retries)
        .await;
    for (provider, reported) in fingerprints {
        rows.push(ProviderHealth {
            chain,
            provider,
            status: classify(&expected, reported),
        });
    }
    rows
}

/// [`ProviderStatus`] carries no error text, so the one actionable cause gets its own variant. Only
/// a token read from the environment can fail to resolve; a [`std::env::VarError`] identifies it.
fn setup_failure(error: &anyhow::Error) -> ProviderStatus {
    if error.chain().any(|cause| cause.is::<std::env::VarError>()) {
        ProviderStatus::AuthTokenUnresolved
    } else {
        ProviderStatus::ClientSetupFailed
    }
}

fn rows_of(
    chain: ForeignChain,
    config: &ForeignChainConfig,
    status: ProviderStatus,
) -> Vec<ProviderHealth> {
    config
        .providers
        .keys()
        .map(|name| ProviderHealth {
            chain,
            provider: ProviderId(name.as_str().to_owned()),
            status: status.clone(),
        })
        .collect()
}

fn classify(
    expected: &NetworkFingerprint,
    reported: Result<NetworkFingerprint, ForeignChainInspectionError>,
) -> ProviderStatus {
    match reported {
        Ok(observed) if &observed == expected => ProviderStatus::Healthy,
        Ok(observed) => ProviderStatus::WrongNetwork {
            expected: expected.clone(),
            observed,
        },
        Err(error) => match error.provider_failure() {
            Some(ProviderFailure::Unreachable) => ProviderStatus::Unreachable,
            Some(ProviderFailure::Rejected) => ProviderStatus::RequestRejected,
            Some(ProviderFailure::TimedOut) => ProviderStatus::TimedOut,
            Some(ProviderFailure::Malformed) => ProviderStatus::MalformedResponse,
            // Probing does not inspect transactions, so an answer about transaction state
            // means an impl answered outside its contract.
            None => ProviderStatus::MalformedResponse,
        },
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::test_utils::*;
    use super::*;
    use foreign_chain_inspector::mock::{MockInspector, MockReply};
    use foreign_chain_rpc_factory::inspectors::InspectorFactory;
    use foreign_chain_rpc_interfaces::sui::Status;
    use foreign_chain_rpc_interfaces::sui::proto::GetServiceInfoResponse;
    use mpc_node_config::{AuthConfig, TokenConfig};
    use near_mpc_bounded_collections::NonEmptyBTreeMap;
    use rstest::rstest;
    use std::assert_matches;
    use std::num::NonZeroU64;
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
            ForeignChainConfig {
                max_retries: NonZeroU64::new(max_retries).unwrap(),
                ..chain_config(Some(MAINNET), one_provider(PROVIDER_NAME, url))
            },
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
        let mock = mock_jsonrpc(&server, JsonRpcAnswer::Fingerprint(MAINNET)).await;
        let config = single_chain(
            ForeignChain::Starknet,
            chain_config(None, one_provider(PROVIDER_NAME, &server.base_url())),
        );

        // When
        let report = probe_all_providers(&config, &InspectorFactory).await;

        // Then
        assert_eq!(
            status_of(&report, ForeignChain::Starknet, PROVIDER_NAME),
            ProviderStatus::MissingExpectedFingerprint
        );
        mock.assert_calls_async(0).await;
    }

    #[tokio::test]
    async fn probe_all_providers__should_report_each_provider_of_a_chain_separately() {
        // Given
        let server = httpmock::MockServer::start_async().await;
        mock_jsonrpc(&server, JsonRpcAnswer::Fingerprint(MAINNET)).await;
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
                one_provider(PROVIDER_NAME, CLOSED_PORT_URL),
            ),
        );

        // When
        let report = probe_all_providers(&config, &NoInspectors).await;

        // Then
        assert_eq!(
            status_of(&report, ForeignChain::Sui, PROVIDER_NAME),
            ProviderStatus::ProbeNotImplemented
        );
    }

    #[tokio::test]
    async fn probe_all_providers__should_report_every_jsonrpc_chain_on_its_expected_network_as_healthy()
     {
        // Given
        // Every chain in one config, each answering its own fingerprint, so a cross wired arm would
        // compare one chain's against another's.
        let mainnets: Vec<(ForeignChain, String, String)> = EVM_MAINNETS
            .iter()
            .map(|mainnet| (mainnet.chain, mainnet.expected(), mainnet.answered()))
            .chain(
                [
                    (ForeignChain::Solana, SOLANA_MAINNET),
                    (ForeignChain::Fogo, FOGO_MAINNET),
                    (ForeignChain::Starknet, MAINNET),
                    (ForeignChain::Bitcoin, BITCOIN_MAINNET),
                ]
                .map(|(chain, fingerprint)| {
                    (chain, fingerprint.to_string(), fingerprint.to_string())
                }),
            )
            .collect();
        let mut servers = Vec::new();
        let mut config = ForeignChainsConfig::default();
        for (chain, expected, answered) in &mainnets {
            let server = httpmock::MockServer::start_async().await;
            mock_jsonrpc(&server, JsonRpcAnswer::Fingerprint(answered)).await;
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
        for (chain, _, _) in &mainnets {
            assert_eq!(
                status_of(&report, *chain, PROVIDER_NAME),
                ProviderStatus::Healthy,
                "{chain:?}"
            );
        }
        assert_eq!(report.counts_per_chain().len(), mainnets.len());
    }

    #[tokio::test]
    async fn probe_all_providers__should_report_each_chain_under_its_own_chain() {
        // Given
        let server = httpmock::MockServer::start_async().await;
        mock_jsonrpc(&server, JsonRpcAnswer::Fingerprint(MAINNET)).await;
        let mut config = single_chain(
            ForeignChain::Starknet,
            chain_config(
                Some(MAINNET),
                one_provider(PROVIDER_NAME, &server.base_url()),
            ),
        );
        put_chain(
            &mut config,
            ForeignChain::Bitcoin,
            chain_config(
                Some(BITCOIN_MAINNET),
                one_provider(PROVIDER_NAME, CLOSED_PORT_URL),
            ),
        );

        // When
        let report = probe_all_providers(&config, &InspectorFactory).await;

        // Then
        assert_eq!(
            status_of(&report, ForeignChain::Starknet, PROVIDER_NAME),
            ProviderStatus::Healthy
        );
        assert_eq!(
            status_of(&report, ForeignChain::Bitcoin, PROVIDER_NAME),
            ProviderStatus::Unreachable
        );
    }

    #[rstest]
    #[case::starknet_normalizes_the_reported_fingerprint(
        ForeignChain::Starknet,
        MAINNET,
        JsonRpcAnswer::Fingerprint(PADDED_UPPERCASE_MAINNET),
        ProviderStatus::Healthy
    )]
    #[case::starknet_normalizes_the_configured_fingerprint(
        ForeignChain::Starknet,
        PADDED_UPPERCASE_MAINNET,
        JsonRpcAnswer::Fingerprint(MAINNET),
        ProviderStatus::Healthy
    )]
    #[case::bitcoin_on_another_network(
        ForeignChain::Bitcoin,
        BITCOIN_MAINNET,
        JsonRpcAnswer::Fingerprint(BITCOIN_TESTNET3),
        ProviderStatus::WrongNetwork {
            expected: NetworkFingerprint::new(BITCOIN_MAINNET),
            observed: NetworkFingerprint::new(BITCOIN_TESTNET3),
        }
    )]
    #[case::solana_on_another_network(
        ForeignChain::Solana,
        SOLANA_MAINNET,
        JsonRpcAnswer::Fingerprint(SOLANA_DEVNET),
        ProviderStatus::WrongNetwork {
            expected: NetworkFingerprint::new(SOLANA_MAINNET),
            observed: NetworkFingerprint::new(SOLANA_DEVNET),
        }
    )]
    #[case::evm_on_another_network(
        ForeignChain::Base,
        "8453",
        JsonRpcAnswer::Fingerprint("0x14a34"),
        ProviderStatus::WrongNetwork {
            expected: NetworkFingerprint::new("8453"),
            observed: NetworkFingerprint::new("84532"),
        }
    )]
    #[case::jsonrpc_error(
        ForeignChain::Starknet,
        MAINNET,
        JsonRpcAnswer::UnsupportedMethod,
        ProviderStatus::RequestRejected
    )]
    #[case::not_jsonrpc(
        ForeignChain::Starknet,
        MAINNET,
        JsonRpcAnswer::NotJsonRpc,
        ProviderStatus::MalformedResponse
    )]
    #[tokio::test]
    async fn probe_all_providers__should_classify_the_jsonrpc_answer(
        #[case] chain: ForeignChain,
        #[case] expected: &str,
        #[case] answer: JsonRpcAnswer<'static>,
        #[case] status: ProviderStatus,
    ) {
        // Given
        let server = httpmock::MockServer::start_async().await;
        mock_jsonrpc(&server, answer).await;
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

    #[tokio::test]
    async fn probe_all_providers__should_bound_the_fingerprint_a_provider_reports() {
        // Given
        let server = httpmock::MockServer::start_async().await;
        let flood = "n".repeat(5_000);
        mock_jsonrpc(&server, JsonRpcAnswer::Fingerprint(&flood)).await;
        let config = single_chain(
            ForeignChain::Starknet,
            chain_config(
                Some(MAINNET),
                one_provider(PROVIDER_NAME, &server.base_url()),
            ),
        );

        // When
        let report = probe_all_providers(&config, &InspectorFactory).await;

        // Then
        let ProviderStatus::WrongNetwork { observed, .. } =
            status_of(&report, ForeignChain::Starknet, PROVIDER_NAME)
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
        mock_jsonrpc(&server, JsonRpcAnswer::Fingerprint(SEPOLIA)).await;
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
}
