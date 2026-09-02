use std::hash::Hash;
use std::num::NonZeroU64;
use std::sync::Arc;
use std::time::Duration;

use derive_more::{Deref, Display, From};
use ethereum_types::H256;
use jsonrpsee::core::client::error::Error as RpcClientError;
use jsonrpsee::core::http_helpers::HttpError;
use jsonrpsee::http_client::transport::Error as HttpTransportError;
use mpc_node_config::ForeignChainProviderConfig;
use near_mpc_bounded_collections::NonEmptyVec;
use near_mpc_contract_interface::types::{ForeignChain, ProviderId};
use thiserror::Error;

pub use jsonrpsee::http_client;

pub mod abstract_chain;
pub mod adi;
pub mod aptos;
pub mod arbitrum;
pub mod avalanche;
pub mod base;
pub mod bitcoin;
pub mod bnb;
pub mod contract_interface_conversions;
pub mod ethereum;
pub mod evm;
pub mod hyperevm;
#[cfg(any(test, feature = "test-utils"))]
pub mod mock;
pub mod polygon;
pub mod rpc_inspector;
pub mod starknet;
pub mod sui;

pub trait ForeignChainInspector {
    type TransactionId;
    type Finality;
    type Extractor;
    type ExtractedValue;
    fn extract(
        &self,
        tx_id: Self::TransactionId,
        finality: Self::Finality,
        extractors: Vec<Self::Extractor>,
    ) -> impl Future<Output = Result<Verdict<Self::ExtractedValue>, ForeignChainInspectionError>> + Send;
}

/// The settled answer from a transaction inspection. Inspection producing a negative verdict is
/// still a successful inspection. Failing to obtain any verdict is instead a
/// [`ForeignChainInspectionError`].
#[derive(Debug, Clone, PartialEq, Eq, Display)]
pub enum Verdict<V> {
    #[display("extracted {} values", _0.len())]
    Extracted(Vec<V>),
    #[display("the transaction's status was not success")]
    TransactionFailed,
    /// Deliberately a verdict rather than a tolerated error. Honest providers cannot extract
    /// anything from a transaction that does not exist.
    #[display("the transaction was not found")]
    TransactionNotFound,
    #[display(
        "the transaction's block does not match the canonical chain at height {block_number}: \
         receipt block {receipt_hash}, canonical block {canonical_hash}"
    )]
    NonCanonicalBlock {
        block_number: u64,
        receipt_hash: HexBytes,
        canonical_hash: HexBytes,
    },
    #[display("a requested log index is out of bounds")]
    LogIndexOutOfBounds,
}

impl<V> Verdict<V> {
    pub fn into_extracted(self) -> Result<Vec<V>, Verdict<V>> {
        match self {
            Self::Extracted(values) => Ok(values),
            failing => Err(failing),
        }
    }
}

/// Parameters for an RPC that takes none. Sent as an explicit empty array.
pub(crate) const NO_PARAMS: [(); 0] = [];

/// The network a provider serves, as the chain itself reports it: a chain id or a genesis hash, in
/// one canonical text form per chain.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Display)]
pub struct NetworkFingerprint(String);

impl NetworkFingerprint {
    /// Values are compared after the cut, so this must exceed every fingerprint in use. The
    /// longest is Bitcoin's genesis hash at 64 characters.
    pub const MAX_CHARS: usize = 96;
    const CUT_SHORT_MARKER: &str = "_TRUNCATED";

    /// Text longer than [`Self::MAX_CHARS`] is cut short, so a very long string answered by a
    /// faulty provider does not reach the logs in full length.
    pub fn new(fingerprint: impl Into<String>) -> Self {
        const KEPT_CHARS: usize =
            NetworkFingerprint::MAX_CHARS - NetworkFingerprint::CUT_SHORT_MARKER.len();

        let fingerprint = fingerprint.into();
        let mut characters = fingerprint.chars();
        let within_cap: String = characters.by_ref().take(Self::MAX_CHARS).collect();
        match characters.next() {
            None => Self(within_cap),
            Some(_) => {
                let kept: String = within_cap.chars().take(KEPT_CHARS).collect();
                Self(format!("{kept}{}", Self::CUT_SHORT_MARKER))
            }
        }
    }
}

/// Reports the [`NetworkFingerprint`] of the provider an inspector talks to, in the form
/// [`Self::canonical_fingerprint`] produces.
pub trait NetworkFingerprintInspector {
    fn network_fingerprint(
        &self,
    ) -> impl Future<Output = Result<NetworkFingerprint, ForeignChainInspectionError>> + Send;

    /// Normalizes any spec-legal spelling of this chain's fingerprint into the single form the trait
    /// compares. Idempotent.
    fn canonical_fingerprint(&self, fingerprint: &str) -> NetworkFingerprint;
}

/// Combines multiple inspectors that target the same chain into a single inspector.
///
/// All inner inspectors are queried concurrently. Every [`Verdict`] reached must be identical;
/// any disagreement returns [`ForeignChainInspectionError::InspectorResponseMismatch`]. Errors
/// are tolerated as long as any inspector reached a verdict, so a single unavailable or
/// misbehaving RPC does not take the whole node out of signing. When no inspector reached a
/// verdict, the first error is propagated.
///
/// With a recorder set through [`FanOut::measuring`], each provider call metric is recorded when it
/// completes, or as [`ProviderFailure::TimedOut`] if the future is dropped first.
#[derive(Clone)]
pub struct FanOut<Inspector> {
    inspectors: NonEmptyVec<(ProviderId, Inspector)>,
    recorder: Option<Arc<dyn RecordProviderCall>>,
}

impl<Inspector> FanOut<Inspector> {
    pub fn new(inspectors: NonEmptyVec<(ProviderId, Inspector)>) -> Self {
        Self {
            inspectors,
            recorder: None,
        }
    }

    pub fn measuring(mut self, recorder: Arc<dyn RecordProviderCall>) -> Self {
        self.recorder = Some(recorder);
        self
    }
}

pub trait RecordProviderCall: Send + Sync {
    fn record(&self, provider: &ProviderId, elapsed: Duration, failure: Option<ProviderFailure>);
}

struct TimedCall {
    recorder: Option<Arc<dyn RecordProviderCall>>,
    provider: ProviderId,
    started: tokio::time::Instant,
}

impl TimedCall {
    fn start(recorder: Option<Arc<dyn RecordProviderCall>>, provider: ProviderId) -> Self {
        Self {
            recorder,
            provider,
            started: tokio::time::Instant::now(),
        }
    }

    fn report(&mut self, failure: Option<ProviderFailure>) {
        if let Some(recorder) = self.recorder.take() {
            recorder.record(&self.provider, self.started.elapsed(), failure);
        }
    }
}

impl Drop for TimedCall {
    fn drop(&mut self) {
        self.report(Some(ProviderFailure::TimedOut));
    }
}

impl<Inspector> ForeignChainInspector for FanOut<Inspector>
where
    Inspector: ForeignChainInspector + Clone + Send + Sync + 'static,
    Inspector::TransactionId: Clone + Send + 'static,
    Inspector::Finality: Clone + Send + 'static,
    Inspector::Extractor: Clone + Send + 'static,
    Inspector::ExtractedValue: Send + 'static + PartialEq + Eq + Hash + std::fmt::Debug,
{
    type TransactionId = Inspector::TransactionId;
    type Finality = Inspector::Finality;
    type Extractor = Inspector::Extractor;
    type ExtractedValue = Inspector::ExtractedValue;

    async fn extract(
        &self,
        tx_id: Self::TransactionId,
        finality: Self::Finality,
        extractors: Vec<Self::Extractor>,
    ) -> Result<Verdict<Self::ExtractedValue>, ForeignChainInspectionError> {
        let mut join_set = tokio::task::JoinSet::new();
        for (provider, inspector) in self.inspectors.iter() {
            let tx_id = tx_id.clone();
            let finality = finality.clone();
            let extractors = extractors.clone();
            let inspector = inspector.clone();
            let provider = provider.clone();
            let recorder = self.recorder.clone();
            join_set.spawn(async move {
                let mut call = TimedCall::start(recorder, provider.clone());
                let result = inspector.extract(tx_id, finality, extractors).await;
                call.report(result.as_ref().err().and_then(|err| err.provider_failure()));
                (provider, result)
            });
        }

        let mut verdicts: Vec<(ProviderId, Verdict<Self::ExtractedValue>)> = Vec::new();
        let mut first_error: Option<ForeignChainInspectionError> = None;

        for (provider, result) in join_set.join_all().await {
            match result {
                Ok(verdict) => verdicts.push((provider, verdict)),
                Err(err) => {
                    if err.provider_failure() == Some(ProviderFailure::Malformed) {
                        tracing::error!(
                            %provider,
                            error = %err,
                            "fan-out inspector answered with unusable data",
                        );
                    } else {
                        tracing::warn!(
                            %provider,
                            error = %err,
                            "fan-out inspector failed to reach a verdict",
                        );
                    }
                    first_error.get_or_insert(err);
                }
            }
        }

        let mut verdicts = verdicts.into_iter();
        let Some((first_provider, first_verdict)) = verdicts.next() else {
            return Err(first_error.expect(
                "inspectors is a `NonEmptyVec`, so with no verdicts at least one error must \
                 have been recorded",
            ));
        };

        let disagreeing: Vec<_> = verdicts
            .filter(|(_, verdict)| *verdict != first_verdict)
            .collect();
        if !disagreeing.is_empty() {
            tracing::error!(
                %first_provider,
                ?first_verdict,
                ?disagreeing,
                "fan-out: inspectors returned mismatching verdicts",
            );
            return Err(ForeignChainInspectionError::InspectorResponseMismatch);
        }

        Ok(first_verdict)
    }
}

pub trait ChainInspector: NetworkFingerprintInspector + Clone + Send + Sync + 'static {}

impl<T: NetworkFingerprintInspector + Clone + Send + Sync + 'static> ChainInspector for T {}

pub trait BuildInspectors: Sync {
    type Inspector: ChainInspector;

    fn build(
        &self,
        chain: ForeignChain,
        provider: &ForeignChainProviderConfig,
        timeout: Duration,
    ) -> anyhow::Result<Option<Self::Inspector>>;
}

/// Pause between two tries at the same provider.
pub const RETRY_BACKOFF: Duration = Duration::from_millis(200);

impl<Inspector> FanOut<Inspector>
where
    Inspector: ChainInspector,
{
    /// Ask every provider for the network it serves concurrently, one result each.
    /// Unlike [`FanOut::extract`], disagreement is not an error: a diagnostic caller needs the
    /// individual answers. Each provider gets up to `attempts` tries, `timeout` per try plus
    /// [`RETRY_BACKOFF`] between them, and only a transient failure is retried.
    pub async fn network_fingerprints(
        &self,
        timeout: Duration,
        attempts: NonZeroU64,
    ) -> Vec<(
        ProviderId,
        Result<NetworkFingerprint, ForeignChainInspectionError>,
    )> {
        let mut join_set = tokio::task::JoinSet::new();
        for (provider, inspector) in self.inspectors.iter() {
            let inspector = inspector.clone();
            let provider = provider.clone();
            join_set.spawn(async move {
                let ask = || async {
                    tokio::time::timeout(timeout, inspector.network_fingerprint())
                        .await
                        .unwrap_or(Err(ForeignChainInspectionError::Timeout))
                };
                let mut outcome = ask().await;
                for _ in 1..attempts.get() {
                    if !matches!(&outcome, Err(err) if err.is_transient()) {
                        break;
                    }
                    tokio::time::sleep(RETRY_BACKOFF).await;
                    outcome = ask().await;
                }
                (provider, outcome)
            });
        }
        join_set.join_all().await
    }
}

#[derive(From, Debug, Display, Clone, Copy, Deref, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlockConfirmations(u64);

/// Chain-agnostic byte buffer that formats as `0x`-prefixed lowercase hex.
/// Used in error messages and verdicts to keep block hash logs readable across chains
/// whose hashes have different native types (EVM `H256`, Bitcoin's reversed
/// 32-byte hash, Starknet felt, ...).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Display, From)]
#[display("0x{}", hex::encode(_0))]
pub struct HexBytes(pub Vec<u8>);

impl From<H256> for HexBytes {
    fn from(hash: H256) -> Self {
        HexBytes(hash.as_bytes().to_vec())
    }
}

impl std::fmt::Debug for HexBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EthereumFinality {
    Finalized,
    Safe,
    Latest,
}

/// A failure to obtain a [`Verdict`]: the RPC request failed or the transaction's state
/// has not settled yet.
#[derive(Error, Debug)]
pub enum ForeignChainInspectionError {
    /// Transient provider failure (transport error, timeout, rate limit, 5xx).
    #[error("RPC request failed: {0}")]
    RpcRequestFailed(String),
    #[error("RPC request did not complete within the configured timeout")]
    Timeout,
    /// The provider rejected the request with a deterministic client error (4xx other than
    /// 408/429); retrying cannot change the outcome.
    #[error("RPC rejected the request: {0}")]
    RpcRequestRejected(String),
    /// The provider answered, but a field needed for verification is missing or unparseable.
    #[error("malformed RPC response: {0}")]
    MalformedRpcResponse(String),
    #[error(
        "transaction did not have enough block confirmations associated with it, expected: {expected} got: {got}"
    )]
    NotEnoughBlockConfirmations {
        expected: BlockConfirmations,
        got: BlockConfirmations,
    },
    #[error("transaction has not reached expected finality level")]
    NotFinalized,
    #[error(
        "RPC backend response does not match the hash it was queried by: requested={requested_hash}, returned={returned_hash}"
    )]
    InconsistentRpcResponse {
        requested_hash: HexBytes,
        returned_hash: HexBytes,
    },
    #[error(
        "log at index {log_index} is not bound to its receipt: log points at tx={log_transaction_hash}, block={log_block_hash} (height {log_block_number}); receipt is tx={receipt_transaction_hash}, block={receipt_block_hash} (height {receipt_block_number})"
    )]
    LogNotBoundToReceipt {
        log_index: u64,
        log_transaction_hash: HexBytes,
        log_block_hash: HexBytes,
        log_block_number: u64,
        receipt_transaction_hash: HexBytes,
        receipt_block_hash: HexBytes,
        receipt_block_number: u64,
    },
    #[error("inspector clients returned mismatching verdicts")]
    InspectorResponseMismatch,
}

impl ForeignChainInspectionError {
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            Self::RpcRequestFailed(_)
                | Self::Timeout
                | Self::NotFinalized
                | Self::NotEnoughBlockConfirmations { .. }
        )
    }

    /// Maps a raw RPC client error to an error with context.
    pub fn classify_rpc_client_error(error: RpcClientError) -> Self {
        match error {
            RpcClientError::Call(object) => {
                let code = object.code();
                let message = format!("JSON-RPC error code {code}");
                if is_rate_limit_error_code(code) {
                    Self::RpcRequestFailed(message)
                } else {
                    Self::RpcRequestRejected(message)
                }
            }
            RpcClientError::ParseError(error) => Self::MalformedRpcResponse(error.to_string()),
            RpcClientError::RequestTimeout => Self::Timeout,
            RpcClientError::Transport(error) => {
                match error.downcast_ref::<HttpTransportError>() {
                    Some(HttpTransportError::Rejected { status_code }) => {
                        let status = format!("HTTP status {status_code}");
                        if is_retryable_status(*status_code) {
                            Self::RpcRequestFailed(status)
                        } else {
                            Self::RpcRequestRejected(status)
                        }
                    }
                    // Not a response the caller can use, as opposed to no response at all.
                    Some(HttpTransportError::Http(HttpError::Malformed)) => {
                        Self::MalformedRpcResponse("response was not valid JSON-RPC".to_string())
                    }
                    Some(HttpTransportError::Http(HttpError::TooLarge)) => {
                        Self::MalformedRpcResponse("response exceeded the size limit".to_string())
                    }
                    Some(HttpTransportError::Url(_)) => {
                        Self::RpcRequestRejected("invalid RPC URL".to_string())
                    }
                    _ => Self::RpcRequestFailed("transport failure".to_string()),
                }
            }
            other => Self::RpcRequestFailed(other.to_string()),
        }
    }

    /// How the provider failed, or [`None`] when the provider did not: the remaining variants
    /// report a transaction state the chain has not settled yet, which is an answer rather than
    /// a fault.
    pub fn provider_failure(&self) -> Option<ProviderFailure> {
        match self {
            Self::RpcRequestFailed(_) => Some(ProviderFailure::Unreachable),
            Self::Timeout => Some(ProviderFailure::TimedOut),
            Self::RpcRequestRejected(_) => Some(ProviderFailure::Rejected),
            Self::MalformedRpcResponse(_)
            | Self::InconsistentRpcResponse { .. }
            | Self::LogNotBoundToReceipt { .. }
            | Self::InspectorResponseMismatch => Some(ProviderFailure::Malformed),
            Self::NotFinalized | Self::NotEnoughBlockConfirmations { .. } => None,
        }
    }
}

/// Some providers report throttling as a JSON-RPC error object over HTTP 200 rather than a 429, and
/// it is the one refusal worth retrying. Alchemy and Infura send `-32005`, others `-32029`.
fn is_rate_limit_error_code(code: i32) -> bool {
    const LIMIT_EXCEEDED: i32 = -32005;
    const TOO_MANY_REQUESTS: i32 = -32029;

    matches!(code, LIMIT_EXCEEDED | TOO_MANY_REQUESTS)
}

fn is_retryable_status(status_code: u16) -> bool {
    const REQUEST_TIMEOUT: u16 = 408;
    const TOO_MANY_REQUESTS: u16 = 429;
    const SERVER_ERROR: u16 = 500;

    matches!(status_code, REQUEST_TIMEOUT | TOO_MANY_REQUESTS) || status_code >= SERVER_ERROR
}

/// Classifies a raw client outcome into a [`ForeignChainInspectionError`], one implementation per
/// client error type. Transaction inspection and the network fingerprint probe both go through
/// this.
pub(crate) trait ClassifyRpcOutcome {
    type Response;

    fn classified(self) -> Result<Self::Response, ForeignChainInspectionError>;
}

impl<T> ClassifyRpcOutcome for Result<T, RpcClientError> {
    type Response = T;

    fn classified(self) -> Result<T, ForeignChainInspectionError> {
        self.map_err(ForeignChainInspectionError::classify_rpc_client_error)
    }
}

/// Groups the ways a provider itself can fail, for callers that report an outcome rather than act
/// on it. Says nothing about retryability: see [`ForeignChainInspectionError::is_transient`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProviderFailure {
    /// No answer arrived: transport failure, 5xx, or rate limiting.
    Unreachable,
    /// The provider answered and refused. Retrying cannot change it.
    Rejected,
    /// The provider answered with something the caller could not use.
    Malformed,
    TimedOut,
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use rstest::rstest;

    fn transport(error: HttpTransportError) -> RpcClientError {
        RpcClientError::Transport(Box::new(error))
    }

    #[rstest]
    #[case(400)]
    #[case(401)]
    #[case(403)]
    #[case(404)]
    fn classify_rpc_client_error__should_report_a_deterministic_status_as_a_refusal(
        #[case] status_code: u16,
    ) {
        // Given
        let error = transport(HttpTransportError::Rejected { status_code });

        // When
        let classified = ForeignChainInspectionError::classify_rpc_client_error(error);

        // Then
        assert_matches!(
            &classified,
            ForeignChainInspectionError::RpcRequestRejected(_)
        );
        assert!(!classified.is_transient());
    }

    #[rstest]
    #[case(408)]
    #[case(429)]
    #[case(500)]
    #[case(503)]
    fn classify_rpc_client_error__should_report_a_retryable_status_as_a_transient_failure(
        #[case] status_code: u16,
    ) {
        // Given
        let error = transport(HttpTransportError::Rejected { status_code });

        // When
        let classified = ForeignChainInspectionError::classify_rpc_client_error(error);

        // Then
        assert_matches!(
            &classified,
            ForeignChainInspectionError::RpcRequestFailed(_)
        );
        assert!(classified.is_transient());
    }

    #[test]
    fn classify_rpc_client_error__should_report_a_jsonrpc_error_object_as_a_refusal() {
        // Given
        let error = RpcClientError::Call(jsonrpsee::types::ErrorObject::owned(
            -32600,
            "Must be authenticated!",
            None::<()>,
        ));

        // When
        let classified = ForeignChainInspectionError::classify_rpc_client_error(error);

        // Then
        assert_matches!(
            &classified,
            ForeignChainInspectionError::RpcRequestRejected(_)
        );
        assert!(!classified.is_transient());
    }

    #[test]
    fn classify_rpc_client_error__should_report_an_unparseable_result_as_malformed() {
        // Given
        let parse_error =
            serde_json::from_str::<String>("7").expect_err("a number is not a string");
        let error = RpcClientError::ParseError(parse_error);

        // When
        let classified = ForeignChainInspectionError::classify_rpc_client_error(error);

        // Then
        assert_matches!(
            classified,
            ForeignChainInspectionError::MalformedRpcResponse(_)
        );
    }

    #[test]
    fn classify_rpc_client_error__should_report_a_body_that_is_not_jsonrpc_as_malformed() {
        // Given
        let error = transport(HttpTransportError::Http(HttpError::Malformed));

        // When
        let classified = ForeignChainInspectionError::classify_rpc_client_error(error);

        // Then
        assert_matches!(
            classified,
            ForeignChainInspectionError::MalformedRpcResponse(_)
        );
    }

    #[test]
    fn classify_rpc_client_error__should_report_a_connection_failure_as_transient() {
        // Given
        let error = transport(HttpTransportError::Http(HttpError::Stream(Box::new(
            std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "connection refused"),
        ))));

        // When
        let classified = ForeignChainInspectionError::classify_rpc_client_error(error);

        // Then
        assert_matches!(
            &classified,
            ForeignChainInspectionError::RpcRequestFailed(_)
        );
        assert!(classified.is_transient());
    }

    /// [`Path`] and [`Query`] auth splice the API key into the URL, and jsonrpsee puts that URL in the
    /// text of the error it reports for it.
    #[test]
    fn classify_rpc_client_error__should_keep_the_rpc_url_out_of_the_message() {
        // Given
        let url_carrying_a_key = "http://provider.example/v2/super-secret".to_string();

        // When
        let error = transport(HttpTransportError::Url(url_carrying_a_key));
        let classified = ForeignChainInspectionError::classify_rpc_client_error(error);

        // Then
        let rendered = classified.to_string();
        assert!(!rendered.contains("super-secret"), "{rendered}");
    }

    #[test]
    fn classify_rpc_client_error__should_report_a_client_side_timeout_as_a_timeout() {
        // Given
        let error = RpcClientError::RequestTimeout;

        // When
        let classified = ForeignChainInspectionError::classify_rpc_client_error(error);

        // Then
        assert_matches!(classified, ForeignChainInspectionError::Timeout);
    }

    #[rstest]
    #[case(-32005)]
    #[case(-32029)]
    fn classify_rpc_client_error__should_report_a_rate_limit_code_as_a_transient_failure(
        #[case] code: i32,
    ) {
        // Given
        let error = RpcClientError::Call(jsonrpsee::types::ErrorObject::owned(
            code,
            "limit exceeded",
            None::<()>,
        ));

        // When
        let classified = ForeignChainInspectionError::classify_rpc_client_error(error);

        // Then
        assert_matches!(
            &classified,
            ForeignChainInspectionError::RpcRequestFailed(_)
        );
        assert!(classified.is_transient());
    }

    #[rstest]
    #[case(ForeignChainInspectionError::RpcRequestFailed("_".to_string()), Some(ProviderFailure::Unreachable))]
    #[case(ForeignChainInspectionError::RpcRequestRejected("_".to_string()), Some(ProviderFailure::Rejected))]
    #[case(ForeignChainInspectionError::Timeout, Some(ProviderFailure::TimedOut))]
    #[case(ForeignChainInspectionError::MalformedRpcResponse("_".to_string()), Some(ProviderFailure::Malformed))]
    #[case(
        ForeignChainInspectionError::InspectorResponseMismatch,
        Some(ProviderFailure::Malformed)
    )]
    // The transaction's own state is an answer, not a fault of the provider that reported it.
    #[case(ForeignChainInspectionError::NotFinalized, None)]
    #[case(ForeignChainInspectionError::NotEnoughBlockConfirmations {
        expected: BlockConfirmations::from(6),
        got: BlockConfirmations::from(1),
    }, None)]
    fn provider_failure__should_name_only_the_failures_the_provider_owns(
        #[case] error: ForeignChainInspectionError,
        #[case] expected: Option<ProviderFailure>,
    ) {
        // When
        let failure = error.provider_failure();

        // Then
        assert_eq!(failure, expected);
    }

    #[rstest]
    #[case::transaction_failed(Verdict::TransactionFailed)]
    #[case::transaction_not_found(Verdict::TransactionNotFound)]
    #[case::non_canonical_block(Verdict::NonCanonicalBlock {
        block_number: 1,
        receipt_hash: HexBytes(vec![1]),
        canonical_hash: HexBytes(vec![2]),
    })]
    #[case::log_index_out_of_bounds(Verdict::LogIndexOutOfBounds)]
    fn into_extracted__should_return_a_failing_verdict_as_the_error(#[case] verdict: Verdict<u8>) {
        // When / Then
        assert_eq!(verdict.clone().into_extracted(), Err(verdict));
    }

    #[test]
    fn into_extracted__should_return_the_extracted_values() {
        // When / Then
        let extracted = Verdict::<u8>::Extracted(vec![1, 2]).into_extracted();
        assert_eq!(extracted, Ok(vec![1, 2]));
    }

    #[test]
    fn network_fingerprint_new__should_keep_the_longest_real_fingerprint_whole() {
        // Given
        let bitcoin_genesis_hash =
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";

        // When
        let fingerprint = NetworkFingerprint::new(bitcoin_genesis_hash);

        // Then
        assert_eq!(fingerprint.to_string(), bitcoin_genesis_hash);
    }

    #[test]
    fn network_fingerprint_new__should_keep_an_answer_exactly_at_length() {
        // Given
        let answered = "a".repeat(NetworkFingerprint::MAX_CHARS);

        // When
        let fingerprint = NetworkFingerprint::new(&answered);

        // Then
        assert_eq!(fingerprint.to_string(), answered);
    }

    #[test]
    fn network_fingerprint_new__should_truncate_long_provider_results_based_on_chars() {
        // Given
        // Four bytes wide character
        let wide_char = "\u{1F642}";
        let answered = wide_char.repeat(200);

        // When
        let fingerprint = NetworkFingerprint::new(answered);

        // Then
        let reported = fingerprint.to_string();
        assert!(reported.starts_with(wide_char));
        assert!(reported.ends_with(NetworkFingerprint::CUT_SHORT_MARKER));
        assert_eq!(reported.chars().count(), NetworkFingerprint::MAX_CHARS);
    }
}
