use std::hash::Hash;
use std::num::NonZeroU64;
use std::sync::Arc;
use std::time::Duration;

use derive_more::{Deref, Display, From};
use ethereum_types::H256;
use http::{HeaderMap, HeaderName, HeaderValue};
use jsonrpsee::core::client::error::Error as RpcClientError;
use jsonrpsee::core::http_helpers::HttpError;
use jsonrpsee::http_client::transport::Error as HttpTransportError;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use near_mpc_bounded_collections::NonEmptyVec;
use near_mpc_contract_interface::types::ProviderId;
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
pub mod polygon;
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
    ) -> impl Future<Output = Result<Vec<Self::ExtractedValue>, ForeignChainInspectionError>> + Send;
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
    fn canonical_fingerprint(fingerprint: &str) -> NetworkFingerprint;
}

/// Combines multiple inspectors that target the same chain into a single inspector.
///
/// All inner inspectors are queried concurrently. The fan-out treats every
/// non-transient outcome (success or non-transient error, see
/// [`ForeignChainInspectionError::is_transient`]) as a substantive verdict that must
/// agree across inspectors. Transient errors (network issues, finality not yet reached,
/// etc.) are tolerated so that a single unavailable RPC does not take the whole node
/// out of signing.
///
/// Outcomes:
/// * All substantive verdicts are `Ok` with the same extracted values → returns those values.
/// * All substantive verdicts are non-transient errors of the same variant → returns one of
///   them (e.g. all inspectors agree the transaction failed).
/// * Substantive verdicts disagree (`Ok` vs. non-transient error, two different non-transient
///   error variants, or two different success values) → returns
///   [`ForeignChainInspectionError::InspectorResponseMismatch`].
/// * Every inspector returned a transient error → the first such error is propagated.
///
/// Variant-level comparison is used for non-transient errors, so inspectors that all report
/// the same failure mode (e.g. [`NonCanonicalBlock`](ForeignChainInspectionError::NonCanonicalBlock))
/// are considered to agree even if the
/// inner fields differ.
pub struct FanOut<Inspector, Recorder: RecordProviderCall = ()> {
    inspectors: NonEmptyVec<(ProviderId, Inspector)>,
    measurement: Option<Measurement<Recorder>>,
}

impl<Inspector: Clone, Recorder: RecordProviderCall> Clone for FanOut<Inspector, Recorder> {
    fn clone(&self) -> Self {
        Self {
            inspectors: self.inspectors.clone(),
            measurement: self.measurement.clone(),
        }
    }
}

impl<Inspector> FanOut<Inspector, ()> {
    /// Creates a fan-out whose provider calls are not measured.
    pub fn new(inspectors: NonEmptyVec<(ProviderId, Inspector)>) -> Self {
        Self {
            inspectors,
            measurement: None,
        }
    }

    /// Reports every provider call [`FanOut::extract`] makes, under the label `chain`.
    ///
    /// [`FanOut::network_fingerprints`] is never measured: probe traffic shares these providers
    /// and would drown the verify latencies.
    pub fn measuring<Recorder: RecordProviderCall>(
        self,
        chain: &'static str,
        record_call: Arc<Recorder>,
    ) -> FanOut<Inspector, Recorder> {
        FanOut {
            inspectors: self.inspectors,
            measurement: Some(Measurement { chain, record_call }),
        }
    }
}

/// Times one provider call made by [`FanOut::extract`] and reports how long it took and how it
/// ended. Implemented by the node to record Prometheus metrics; the unit type implements it as
/// a no-op for fan-outs without measurement.
pub trait RecordProviderCall: Send + Sync {
    fn record(
        &self,
        chain: &str,
        provider: &ProviderId,
        elapsed: Duration,
        outcome: ProviderCallOutcome,
    );
}

/// How one provider's call ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderCallOutcome {
    /// The provider answered, whether with extracted values or with a verdict about the
    /// transaction itself. See [`ForeignChainInspectionError::provider_failure`].
    Answered,
    Failed(ProviderFailure),
    /// The call was still in flight when the caller dropped the fan-out, so no answer will ever
    /// arrive.
    Abandoned,
}

impl ProviderCallOutcome {
    fn of<T>(result: &Result<T, ForeignChainInspectionError>) -> Self {
        match result {
            Ok(_) => Self::Answered,
            Err(error) => error
                .provider_failure()
                .map_or(Self::Answered, Self::Failed),
        }
    }
}

impl RecordProviderCall for () {
    fn record(
        &self,
        _chain: &str,
        _provider: &ProviderId,
        _elapsed: Duration,
        _outcome: ProviderCallOutcome,
    ) {
    }
}

struct Measurement<Recorder: RecordProviderCall> {
    chain: &'static str,
    record_call: Arc<Recorder>,
}

impl<Recorder: RecordProviderCall> Clone for Measurement<Recorder> {
    fn clone(&self) -> Self {
        Self {
            chain: self.chain,
            record_call: Arc::clone(&self.record_call),
        }
    }
}

/// Times one provider's call and reports it once, from [`Drop`]: a caller's deadline aborts the
/// spawned task mid-call, so no ordinary return path runs for a provider that never answers.
#[derive(Clone)]
struct TimedCall<Recorder: RecordProviderCall> {
    measurement: Option<Measurement<Recorder>>,
    provider: ProviderId,
    /// tokio's, so a paused clock in a test drives the reported duration.
    started: tokio::time::Instant,
    outcome: Option<ProviderCallOutcome>,
}

impl<Recorder: RecordProviderCall> TimedCall<Recorder> {
    fn start(measurement: Option<Measurement<Recorder>>, provider: ProviderId) -> Self {
        Self {
            measurement,
            provider,
            started: tokio::time::Instant::now(),
            outcome: None,
        }
    }

    fn ended<T>(&mut self, result: &Result<T, ForeignChainInspectionError>) {
        self.outcome = Some(ProviderCallOutcome::of(result));
    }
}

impl<Recorder: RecordProviderCall> Drop for TimedCall<Recorder> {
    fn drop(&mut self) {
        // A panicking inspector unwinds through this guard: the call was torn down, not
        // abandoned, and recording mid-unwind risks a double panic.
        if std::thread::panicking() {
            return;
        }
        let Some(measurement) = &self.measurement else {
            return;
        };
        measurement.record_call.record(
            measurement.chain,
            &self.provider,
            self.started.elapsed(),
            self.outcome.unwrap_or(ProviderCallOutcome::Abandoned),
        );
    }
}

impl<Inspector, Recorder: RecordProviderCall> ForeignChainInspector for FanOut<Inspector, Recorder>
where
    Inspector: ForeignChainInspector + Clone + Send + Sync + 'static,
    Inspector::TransactionId: Clone + Send + 'static,
    Inspector::Finality: Clone + Send + 'static,
    Inspector::Extractor: Clone + Send + 'static,
    Inspector::ExtractedValue: Send + 'static + PartialEq + Eq + Hash + std::fmt::Debug,
    // The spawned task must stay alive until every call has been reported, so `Recorder` must
    // not outlive it.
    Recorder: 'static,
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
    ) -> Result<Vec<Self::ExtractedValue>, ForeignChainInspectionError> {
        let mut join_set = tokio::task::JoinSet::new();
        for (provider, inspector) in self.inspectors.iter() {
            let tx_id = tx_id.clone();
            let finality = finality.clone();
            let extractors = extractors.clone();
            let inspector = inspector.clone();
            let provider = provider.clone();
            let measurement = self.measurement.clone();
            join_set.spawn(async move {
                let mut call = TimedCall::start(measurement, provider.clone());
                let result = inspector.extract(tx_id, finality, extractors).await;
                call.ended(&result);
                (provider, result)
            });
        }

        let mut successes: Vec<(ProviderId, Vec<Self::ExtractedValue>)> = Vec::new();
        let mut non_transient_errors: Vec<(ProviderId, ForeignChainInspectionError)> = Vec::new();
        let mut first_transient_error: Option<ForeignChainInspectionError> = None;

        for (provider, result) in join_set.join_all().await {
            match result {
                Ok(values) => successes.push((provider, values)),
                Err(err) if err.is_transient() => {
                    tracing::warn!(
                        %provider,
                        error = %err,
                        "fan-out inspector failed (transient)",
                    );
                    first_transient_error.get_or_insert(err);
                }
                Err(err) => {
                    tracing::error!(
                        %provider,
                        error = %err,
                        "fan-out inspector failed (non-transient)",
                    );
                    non_transient_errors.push((provider, err));
                }
            }
        }

        let inspectors_split_between_success_and_failure =
            !successes.is_empty() && !non_transient_errors.is_empty();

        if inspectors_split_between_success_and_failure {
            tracing::error!(
                ?successes,
                ?non_transient_errors,
                "fan-out: inspectors split between success and non-transient failure",
            );
            return Err(ForeignChainInspectionError::InspectorResponseMismatch);
        }

        if let Some(first_values) = successes.first() {
            let all_successes_agree = successes.iter().all(|(_, v)| v == &first_values.1);
            if !all_successes_agree {
                tracing::error!(
                    responses = ?successes,
                    "fan-out: inspectors returned mismatching extracted values",
                );
                return Err(ForeignChainInspectionError::InspectorResponseMismatch);
            }
            let (_, first) = successes.into_iter().next().expect("checked non-empty");

            return Ok(first);
        }

        if let Some(first_non_transient_error) = non_transient_errors.first() {
            let first_variant = std::mem::discriminant(&first_non_transient_error.1);
            let all_failures_have_same_variant = non_transient_errors
                .iter()
                .all(|(_, e)| std::mem::discriminant(e) == first_variant);
            if !all_failures_have_same_variant {
                tracing::error!(
                    errors = ?non_transient_errors,
                    "fan-out: inspectors disagreed on non-transient failure mode",
                );
                return Err(ForeignChainInspectionError::InspectorResponseMismatch);
            }
            let (_, first) = non_transient_errors
                .into_iter()
                .next()
                .expect("checked non-empty");
            return Err(first);
        }

        Err(first_transient_error.expect(
            "inspectors is a `NonEmptyVec`, so with no successes and no non-transient errors, \
             at least one transient error must have been recorded",
        ))
    }
}

/// Pause between two tries at the same provider.
pub const RETRY_BACKOFF: Duration = Duration::from_millis(200);

impl<Inspector, Recorder: RecordProviderCall> FanOut<Inspector, Recorder>
where
    Inspector: NetworkFingerprintInspector + Clone + Send + Sync + 'static,
    Recorder: 'static,
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

#[derive(Debug, Clone)]
pub enum RpcAuthentication {
    /// The key is in the URL (e.g., Alchemy, QuickNode).
    /// Example: `https://eth-mainnet.alchemyapi.io/v2/your-api-key`
    KeyInUrl,
    /// Custom header for providers like NOWNodes or GetBlock.
    /// Example: key="x-api-key", value="your-secret-token"
    CustomHeader {
        header_name: HeaderName,
        header_value: HeaderValue,
    },
}

#[derive(From, Debug, Display, Clone, Copy, Deref, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlockConfirmations(u64);

/// Chain-agnostic byte buffer that formats as `0x`-prefixed lowercase hex.
/// Used in error messages to keep block-hash logs readable across chains
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

#[derive(Error, Debug)]
pub enum ForeignChainInspectionError {
    #[error("inner network client failed to fetch")]
    ClientError(#[from] jsonrpsee::core::client::error::Error),
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
    // TODO: return specific error types ber inspector type.
    // EVM errors
    NotEnoughBlockConfirmations {
        expected: BlockConfirmations,
        got: BlockConfirmations,
    },
    #[error("transaction has not reached expected finality level")]
    NotFinalized,
    #[error(
        "transaction receipt's block_hash does not match the canonical chain at block {block_number}: receipt_hash={receipt_hash}, canonical_hash={canonical_hash}"
    )]
    NonCanonicalBlock {
        block_number: u64,
        receipt_hash: HexBytes,
        canonical_hash: HexBytes,
    },
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
    #[error("The transaction's status was not success")]
    TransactionFailed,
    #[error("transaction not found")]
    TransactionNotFound,
    #[error("provided log index is out of bounds")]
    LogIndexOutOfBounds,
    #[error("failed to borsh serialize log event")]
    EventLogFailedBorshSerialization(std::io::Error),
    #[error("inspector clients returned mismatching extracted values")]
    InspectorResponseMismatch,
}

impl ForeignChainInspectionError {
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            Self::ClientError(_)
                | Self::RpcRequestFailed(_)
                | Self::Timeout
                | Self::NotFinalized
                | Self::NotEnoughBlockConfirmations { .. }
        )
    }

    /// Maps a raw RPC client error to an error with context.
    pub fn classify_rpc_client_error(error: RpcClientError) -> Self {
        Self::from_rpc_client_error(&error)
    }

    /// Never produces a [`Self::ClientError`], so [`Self::provider_failure`] can call it on the
    /// wrapped error without recursing.
    fn from_rpc_client_error(error: &RpcClientError) -> Self {
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
    /// report what the provider answered — the transaction's own state, or a request it could not
    /// serve — rather than a fault of its own.
    pub fn provider_failure(&self) -> Option<ProviderFailure> {
        match self {
            // Only the fingerprint probe classifies; transaction inspection lets the raw client
            // error through, so without this every fault there would look like an unreachable host.
            Self::ClientError(error) => Self::from_rpc_client_error(error).provider_failure(),
            Self::RpcRequestFailed(_) => Some(ProviderFailure::Unreachable),
            Self::Timeout => Some(ProviderFailure::TimedOut),
            Self::RpcRequestRejected(_) => Some(ProviderFailure::Rejected),
            Self::MalformedRpcResponse(_)
            | Self::InconsistentRpcResponse { .. }
            | Self::LogNotBoundToReceipt { .. }
            | Self::EventLogFailedBorshSerialization(_)
            | Self::InspectorResponseMismatch => Some(ProviderFailure::Malformed),
            Self::NotFinalized
            | Self::NotEnoughBlockConfirmations { .. }
            | Self::NonCanonicalBlock { .. }
            | Self::TransactionFailed
            | Self::TransactionNotFound
            | Self::LogIndexOutOfBounds => None,
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

/// A provider returning "not found" status on a path/method could have different meanings,
/// depending on which method was called.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AbsenceMeaning {
    TransactionIsAbsent,
    ApiIsNotServed,
}

pub(crate) trait HasAbsenceMeaning {
    const ABSENCE: AbsenceMeaning;
}

pub(crate) trait ClassifyRpcOutcome {
    type Response: HasAbsenceMeaning;

    fn classified(self) -> Result<Self::Response, ForeignChainInspectionError>;
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

/// Builds an HTTP client with the specified authentication method.
/// This client can be used to construct a [`ForeignChainInspector`] such
/// as [`bitcoin::inspector::BitcoinInspector`].
pub fn build_http_client(
    base_url: String,
    rpc_authentication: RpcAuthentication,
) -> Result<HttpClient, jsonrpsee::core::client::error::Error> {
    let mut headers = HeaderMap::new();

    match rpc_authentication {
        RpcAuthentication::KeyInUrl => {}
        RpcAuthentication::CustomHeader {
            header_name,
            header_value,
        } => {
            headers.insert(header_name, header_value);
        }
    }

    let client = HttpClientBuilder::default()
        .set_headers(headers)
        .build(&base_url)?;

    Ok(client)
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
        let error = transport(HttpTransportError::Url(url_carrying_a_key));

        // When
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
    #[case(ForeignChainInspectionError::TransactionNotFound, None)]
    #[case(ForeignChainInspectionError::TransactionFailed, None)]
    #[case(ForeignChainInspectionError::NotFinalized, None)]
    #[case(ForeignChainInspectionError::NotEnoughBlockConfirmations {
        expected: BlockConfirmations::from(6),
        got: BlockConfirmations::from(1),
    }, None)]
    // Transaction inspection lets the raw client error through unclassified, so the
    // classification has to survive the round trip through `ClientError` too.
    #[case(
        ForeignChainInspectionError::ClientError(transport(HttpTransportError::Rejected {
            status_code: 401,
        })),
        Some(ProviderFailure::Rejected)
    )]
    #[case(
        ForeignChainInspectionError::ClientError(transport(HttpTransportError::Rejected {
            status_code: 503,
        })),
        Some(ProviderFailure::Unreachable)
    )]
    #[case(
        ForeignChainInspectionError::ClientError(RpcClientError::RequestTimeout),
        Some(ProviderFailure::TimedOut)
    )]
    fn provider_failure__should_name_only_the_failures_the_provider_owns(
        #[case] error: ForeignChainInspectionError,
        #[case] expected: Option<ProviderFailure>,
    ) {
        // When
        let failure = error.provider_failure();

        // Then
        assert_eq!(failure, expected);
    }

    #[derive(Default)]
    struct RecordedCalls(std::sync::Mutex<Vec<(String, ProviderId, ProviderCallOutcome)>>);

    impl RecordedCalls {
        fn taken(&self) -> Vec<(String, ProviderId, ProviderCallOutcome)> {
            std::mem::take(&mut self.0.lock().unwrap())
        }
    }

    impl RecordProviderCall for RecordedCalls {
        fn record(
            &self,
            chain: &str,
            provider: &ProviderId,
            _elapsed: Duration,
            outcome: ProviderCallOutcome,
        ) {
            self.0
                .lock()
                .unwrap()
                .push((chain.to_owned(), provider.clone(), outcome));
        }
    }

    fn measured_call(recorded: &Arc<RecordedCalls>) -> TimedCall<RecordedCalls> {
        TimedCall::start(
            Some(Measurement {
                chain: "testchain",
                record_call: Arc::clone(recorded),
            }),
            ProviderId("only".to_string()),
        )
    }

    #[test]
    fn timed_call__should_report_the_outcome_the_call_ended_with() {
        // Given
        let recorded = Arc::new(RecordedCalls::default());
        let mut call = measured_call(&recorded);

        // When
        call.ended(&Err::<(), _>(ForeignChainInspectionError::Timeout));
        drop(call);

        // Then
        assert_eq!(
            recorded.taken(),
            vec![(
                "testchain".to_string(),
                ProviderId("only".to_string()),
                ProviderCallOutcome::Failed(ProviderFailure::TimedOut),
            )]
        );
    }

    #[test]
    fn timed_call__should_report_a_call_that_never_ended_as_abandoned() {
        // Given: a call whose task the caller's deadline aborted mid-flight.
        let recorded = Arc::new(RecordedCalls::default());
        let call = measured_call(&recorded);

        // When
        drop(call);

        // Then
        assert_matches!(
            recorded.taken()[..],
            [(_, _, ProviderCallOutcome::Abandoned)]
        );
    }

    #[test]
    fn timed_call__should_report_nothing_while_its_task_is_panicking() {
        // Given
        let recorded = Arc::new(RecordedCalls::default());

        // When: the inspector panics, so the guard drops as part of the unwind.
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _call = measured_call(&recorded);
            panic!("the inspector blew up");
        }));

        // Then
        assert!(panicked.is_err());
        assert_eq!(recorded.taken(), vec![]);
    }

    #[rstest]
    #[case(Ok(()), ProviderCallOutcome::Answered)]
    #[case(
        Err(ForeignChainInspectionError::RpcRequestFailed("_".to_string())),
        ProviderCallOutcome::Failed(ProviderFailure::Unreachable)
    )]
    // A verdict about the transaction is an answer, so the provider is not at fault.
    #[case(
        Err(ForeignChainInspectionError::NotFinalized),
        ProviderCallOutcome::Answered
    )]
    fn provider_call_outcome_of__should_blame_the_provider_only_for_its_own_failures(
        #[case] result: Result<(), ForeignChainInspectionError>,
        #[case] expected: ProviderCallOutcome,
    ) {
        // When
        let outcome = ProviderCallOutcome::of(&result);

        // Then
        assert_eq!(outcome, expected);
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
