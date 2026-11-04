use anyhow::Context;
use base64::{Engine, engine::general_purpose::STANDARD};
#[cfg(feature = "embedded-node")]
use chain_gateway::ChainGateway;
use chain_gateway::errors::NearViewClientError;
#[cfg(feature = "embedded-node")]
use chain_gateway::primitives::FetchLatestFinalBlockInfo;
use chain_gateway::types::LatestFinalBlockInfo;
use mpc_node_config::IndexerConfig;
use near_account_id::AccountId;
#[cfg(feature = "embedded-node")]
use near_async::{
    messaging::CanSendAsync, multithread::MultithreadRuntimeHandle, tokio::TokioRuntimeHandle,
};
#[cfg(feature = "embedded-node")]
use near_client::{RpcHandlerActor, Status, client_actor::ClientActor};
use near_contract_transport::{
    NearKitCaller, NearKitViewError, PollInterval, SerializedObservation, ViewArgs, ViewContract,
};
use near_indexer_primitives::CryptoHash;
use near_indexer_primitives::near_primitives::transaction::SignedTransaction;
use near_indexer_primitives::types::BlockHeight;
use near_kit::rpc::{BlockReference, Finality, TxExecutionStatus};
use near_kit::transaction::Final;
use serde::Deserialize;
use std::time::Duration;

/// Overrides [`IndexerConfig::rpc_url`]. Startup scripts and the e2e harness set it.
pub const NEAR_RPC_URL_ENV: &str = "MPC_NEAR_RPC_URL";

/// Paces nothing in the node, which never subscribes through [`NearChain`], but
/// [`NearKitCaller`] requires one.
const HTTP_VIEW_POLL_INTERVAL: Duration = Duration::from_secs(1);
const HTTP_VIEW_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// How the node reaches NEAR, resolved once at startup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IndexerBackend {
    /// Indexes, views and submits transactions through an external RPC node
    /// serving `EXPERIMENTAL_indexer_block`.
    Http { rpc_url: url::Url },
    /// Runs a NEAR node inside the MPC node process.
    #[cfg(feature = "embedded-node")]
    Embedded,
}

impl IndexerBackend {
    pub fn from_env_and_config(config: &IndexerConfig) -> anyhow::Result<Self> {
        let env_url = match std::env::var(NEAR_RPC_URL_ENV) {
            Ok(url) => Some(url),
            Err(std::env::VarError::NotPresent) => None,
            Err(err) => return Err(err).context(format!("{NEAR_RPC_URL_ENV} is not valid UTF-8")),
        };
        Self::resolve(env_url.as_deref(), config.rpc_url.as_deref())
    }

    fn resolve(env_url: Option<&str>, config_url: Option<&str>) -> anyhow::Result<Self> {
        let (source, url) = match (env_url, config_url) {
            (Some(url), _) => (NEAR_RPC_URL_ENV, url),
            (None, Some(url)) => ("indexer.rpc_url", url),
            (None, None) => return Self::without_rpc_url(),
        };
        // The URL may carry an API key, so it is never echoed back.
        let rpc_url = url::Url::parse(url).map_err(|err| anyhow::anyhow!("{source}: {err}"))?;
        Ok(Self::Http { rpc_url })
    }

    #[cfg(feature = "embedded-node")]
    fn without_rpc_url() -> anyhow::Result<Self> {
        Ok(Self::Embedded)
    }

    #[cfg(not(feature = "embedded-node"))]
    fn without_rpc_url() -> anyhow::Result<Self> {
        anyhow::bail!(
            "set indexer.rpc_url or {NEAR_RPC_URL_ENV}: this build has no embedded NEAR node"
        )
    }

    pub fn is_embedded(&self) -> bool {
        !matches!(self, Self::Http { .. })
    }
}

/// The NEAR node the indexer reads state from and submits transactions to.
#[derive(Clone)]
pub(crate) enum NearChain {
    #[cfg(feature = "embedded-node")]
    Embedded(EmbeddedChain),
    Http(HttpChain),
}

#[cfg(feature = "embedded-node")]
#[derive(Clone)]
pub(crate) struct EmbeddedChain {
    pub gateway: ChainGateway,
    pub client: TokioRuntimeHandle<ClientActor>,
    pub rpc_handler: MultithreadRuntimeHandle<RpcHandlerActor>,
}

#[derive(Clone)]
pub(crate) struct HttpChain {
    near: near_kit::Near,
    views: NearKitCaller<Final>,
}

impl HttpChain {
    pub fn connect(rpc_url: &url::Url) -> Self {
        // near-kit only reports the chain id back; the node never signs through it.
        Self::new(near_kit::Near::custom(rpc_url.as_str(), "unknown").build())
    }

    fn new(near: near_kit::Near) -> Self {
        let poll_interval =
            PollInterval::new(HTTP_VIEW_POLL_INTERVAL).expect("the poll interval is non-zero");
        Self {
            views: NearKitCaller::new(near.clone(), poll_interval, HTTP_VIEW_READ_TIMEOUT),
            near,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum NearChainViewError {
    #[error(transparent)]
    Embedded(#[from] NearViewClientError),
    #[error(transparent)]
    Http(#[from] NearKitViewError),
}

impl ViewContract for NearChain {
    type Error = NearChainViewError;

    async fn view_contract(
        &self,
        contract_id: &AccountId,
        view_args: ViewArgs,
    ) -> Result<SerializedObservation, Self::Error> {
        match self {
            #[cfg(feature = "embedded-node")]
            Self::Embedded(chain) => {
                Ok(chain.gateway.view_contract(contract_id, view_args).await?)
            }
            Self::Http(chain) => Ok(chain.views.view_contract(contract_id, view_args).await?),
        }
    }
}

/// What a submission established about a transaction reaching the chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SubmissionAck {
    /// The embedded node routed the transaction to a validator.
    #[cfg(any(feature = "embedded-node", test))]
    Routed,
    /// The RPC node accepted the transaction into its queue.
    Queued,
    /// No acknowledgement arrived; the transaction may or may not have been
    /// accepted, including on an attempt whose response was lost.
    Unknown,
}

impl SubmissionAck {
    /// Whether a NEAR node accepted the transaction, so an effect still
    /// unobserved after the confirmation wait counts as timed out.
    pub fn was_accepted(self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

#[derive(Deserialize)]
struct SendTxResponse {
    // Parsed only to reject a malformed success body.
    #[serde(rename = "final_execution_status")]
    _status: TxExecutionStatus,
}

impl NearChain {
    pub async fn latest_final_block(&self) -> anyhow::Result<LatestFinalBlockInfo> {
        match self {
            #[cfg(feature = "embedded-node")]
            Self::Embedded(chain) => Ok(chain.gateway.fetch_latest_final_block_info().await?),
            Self::Http(chain) => {
                let block = chain
                    .near
                    .rpc()
                    .block(BlockReference::Finality(Finality::Final))
                    .await
                    .map_err(NearKitViewError::from)?;
                Ok(LatestFinalBlockInfo {
                    observed_at: block.header.height.into(),
                    value: CryptoHash(block.header.hash.into()),
                })
            }
        }
    }

    /// Polls sync status, yielding `(syncing, head_height)`, or `None` on a
    /// failed request.
    pub async fn sync_info(&self) -> Option<(bool, BlockHeight)> {
        match self {
            #[cfg(feature = "embedded-node")]
            Self::Embedded(chain) => {
                let status_request = Status {
                    is_health_check: false,
                    detailed: false,
                };
                let Ok(Ok(status)) = chain
                    .client
                    .send_async(
                        near_o11y::span_wrapped_msg::SpanWrappedMessageExt::span_wrap(
                            status_request,
                        ),
                    )
                    .await
                else {
                    return None;
                };
                Some((
                    status.sync_info.syncing,
                    status.sync_info.latest_block_height,
                ))
            }
            Self::Http(chain) => {
                let status = chain.near.rpc().status().await.ok()?;
                Some((
                    status.sync_info.syncing,
                    status.sync_info.latest_block_height,
                ))
            }
        }
    }

    /// Submits an already signed transaction without changing its bytes, so a
    /// transport retry can never produce a second, differently signed copy.
    pub async fn submit_tx(&self, transaction: SignedTransaction) -> anyhow::Result<SubmissionAck> {
        match self {
            #[cfg(feature = "embedded-node")]
            Self::Embedded(chain) => {
                let response = chain
                    .rpc_handler
                    .send_async(near_client::ProcessTxRequest {
                        transaction,
                        is_forwarded: false,
                        check_only: false,
                    })
                    .await?;
                match response {
                    // We're not a validator, so we should always be routing the transaction.
                    near_client::ProcessTxResponse::RequestRouted => Ok(SubmissionAck::Routed),
                    other => anyhow::bail!("unexpected ProcessTxResponse: {other:?}"),
                }
            }
            Self::Http(chain) => {
                let signed_tx_base64 = STANDARD.encode(borsh::to_vec(&transaction)?);
                let response = chain
                    .near
                    .rpc()
                    .call::<_, SendTxResponse>(
                        "send_tx",
                        serde_json::json!({
                            "signed_tx_base64": signed_tx_base64,
                            "wait_until": "NONE",
                        }),
                    )
                    .await;
                Ok(match response {
                    Ok(_) => SubmissionAck::Queued,
                    Err(err) => {
                        tracing::warn!(
                            error = %NearKitViewError::from(err),
                            tx_hash = %transaction.get_hash(),
                            "HTTP transaction submission was not acknowledged"
                        );
                        SubmissionAck::Unknown
                    }
                })
            }
        }
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::{HttpChain, IndexerBackend, NearChain, STANDARD, SubmissionAck};
    use crate::indexer::tx_signer::TransactionSigner;
    use base64::Engine;
    use ed25519_dalek::SigningKey;
    use near_indexer_primitives::CryptoHash;
    use near_indexer_primitives::types::Gas;
    use near_kit::rpc::{BoxFuture, RetryConfig, RpcError, RpcTransport, TransportResponse};
    use serde_json::{Value, json};
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    #[test]
    fn resolve__should_prefer_the_environment_over_the_config() {
        // Given
        let env_url = Some("http://env.example:3030");
        let config_url = Some("http://config.example:3030");

        // When
        let backend = IndexerBackend::resolve(env_url, config_url).unwrap();

        // Then
        assert_eq!(
            backend,
            IndexerBackend::Http {
                rpc_url: "http://env.example:3030".parse().unwrap()
            }
        );
    }

    #[test]
    fn resolve__should_reject_a_malformed_url_without_echoing_it() {
        // Given
        let secret = "not a url?apikey=hunter2";

        // When
        let err = IndexerBackend::resolve(None, Some(secret)).unwrap_err();

        // Then
        assert!(!format!("{err:#}").contains("hunter2"), "{err:#}");
    }

    #[cfg(feature = "embedded-node")]
    #[test]
    fn resolve__should_select_the_embedded_node_without_an_rpc_url() {
        // When
        let backend = IndexerBackend::resolve(None, None).unwrap();

        // Then
        assert_eq!(backend, IndexerBackend::Embedded);
    }

    #[cfg(not(feature = "embedded-node"))]
    #[test]
    fn resolve__should_require_an_rpc_url_without_the_embedded_node() {
        // When
        let result = IndexerBackend::resolve(None, None);

        // Then
        result.unwrap_err();
    }

    #[test]
    fn was_accepted__should_hold_for_routed_and_queued_submissions() {
        // When
        let routed = SubmissionAck::Routed.was_accepted();
        let queued = SubmissionAck::Queued.was_accepted();
        let unknown = SubmissionAck::Unknown.was_accepted();

        // Then
        assert!(routed);
        assert!(queued);
        assert!(!unknown);
    }

    struct RecordingTransport {
        requests: Mutex<Vec<Value>>,
        responses: Mutex<VecDeque<Result<TransportResponse, RpcError>>>,
    }

    impl RpcTransport for RecordingTransport {
        fn post_json(
            &self,
            _url: &str,
            body: Vec<u8>,
        ) -> BoxFuture<'_, Result<TransportResponse, RpcError>> {
            Box::pin(async move {
                self.requests
                    .lock()
                    .unwrap()
                    .push(serde_json::from_slice(&body).unwrap());
                self.responses.lock().unwrap().pop_front().unwrap()
            })
        }
    }

    fn must_respond(body: Value) -> TransportResponse {
        TransportResponse {
            status: 200,
            body: serde_json::to_vec(&body).unwrap(),
        }
    }

    /// Submits one signed transaction and returns its acknowledgement, every
    /// request body sent, and the base64 transaction each of them must carry.
    async fn must_submit_with_responses(
        responses: Vec<Result<TransportResponse, RpcError>>,
    ) -> (SubmissionAck, Vec<Value>, String) {
        let signer = TransactionSigner::from_key(
            "sender.test".parse().unwrap(),
            SigningKey::from_bytes(&[7; 32]),
        );
        let transaction = signer.create_and_sign_function_call_tx(
            "mpc.test".parse().unwrap(),
            "respond".into(),
            b"{}".to_vec(),
            Gas::from_gas(30_000_000_000_000),
            CryptoHash::default(),
            100,
        );
        let expected = STANDARD.encode(borsh::to_vec(&transaction).unwrap());
        let transport = Arc::new(RecordingTransport {
            requests: Mutex::new(vec![]),
            responses: Mutex::new(responses.into()),
        });
        let near = near_kit::Near::custom("http://fixture.invalid", "test")
            .transport(SharedTransport(transport.clone()))
            .retry_config(RetryConfig {
                max_retries: 1,
                initial_delay_ms: 1,
                max_delay_ms: 1,
            })
            .build();
        let ack = NearChain::Http(HttpChain::new(near))
            .submit_tx(transaction)
            .await
            .unwrap();
        let requests = transport.requests.lock().unwrap().clone();
        (ack, requests, expected)
    }

    struct SharedTransport(Arc<RecordingTransport>);

    impl RpcTransport for SharedTransport {
        fn post_json(
            &self,
            url: &str,
            body: Vec<u8>,
        ) -> BoxFuture<'_, Result<TransportResponse, RpcError>> {
            self.0.post_json(url, body)
        }
    }

    #[tokio::test]
    async fn submit_tx__should_retry_identical_signed_bytes_after_a_lost_response() {
        // Given
        let responses = vec![
            Err(RpcError::network("response lost", None, true)),
            Ok(must_respond(
                json!({"jsonrpc": "2.0", "id": 1, "result": {"final_execution_status": "NONE"}}),
            )),
        ];

        // When
        let (ack, requests, expected) = must_submit_with_responses(responses).await;

        // Then
        assert_eq!(ack, SubmissionAck::Queued);
        assert_eq!(requests.len(), 2);
        for request in requests {
            assert_eq!(request["method"], "send_tx");
            assert_eq!(
                request["params"],
                json!({"signed_tx_base64": expected, "wait_until": "NONE"})
            );
        }
    }

    #[tokio::test]
    async fn submit_tx__should_report_a_malformed_success_as_unknown() {
        // Given
        let responses = vec![Ok(must_respond(
            json!({"jsonrpc": "2.0", "id": 1, "result": {}}),
        ))];

        // When
        let (ack, requests, expected) = must_submit_with_responses(responses).await;

        // Then
        assert_eq!(ack, SubmissionAck::Unknown);
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0]["params"]["signed_tx_base64"], expected);
    }

    #[tokio::test]
    async fn submit_tx__should_report_a_rejected_retry_after_a_lost_response_as_unknown() {
        // Given
        // the first attempt may have landed, so rejecting the retry cannot disprove that
        let responses = vec![
            Err(RpcError::network("response lost", None, true)),
            Ok(must_respond(json!({"jsonrpc": "2.0", "id": 1, "error": {
                "name": "HANDLER_ERROR",
                "cause": {"name": "INVALID_TRANSACTION", "info": {}},
                "code": -32000,
                "message": "Server error",
                "data": {"TxExecutionError": {"InvalidTxError": {"InvalidNonce": {"tx_nonce": 6, "ak_nonce": 20}}}}
            }}))),
        ];

        // When
        let (ack, requests, expected) = must_submit_with_responses(responses).await;

        // Then
        assert_eq!(ack, SubmissionAck::Unknown);
        assert_eq!(requests.len(), 2);
        assert!(
            requests
                .iter()
                .all(|request| request["params"]["signed_tx_base64"] == expected)
        );
    }
}
