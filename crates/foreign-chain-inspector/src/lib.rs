use std::hash::Hash;
use std::num::NonZeroU64;
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
pub mod aptos;
pub mod arbitrum;
pub mod base;
pub mod bitcoin;
pub mod bnb;
pub mod contract_interface_conversions;
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

/// The network a provider serves, as the chain itself reports it: a chain id or a genesis hash, in
/// one canonical text form per chain.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Display, From)]
pub struct NetworkFingerprint(String);

/// Reports the [`NetworkFingerprint`] of the provider an inspector talks to.
///
/// Fingerprints are compared verbatim, so both the reported and the expected one go through the
/// impl's canonical form. Fetches a chain-wide constant providers never prune.
pub trait NetworkFingerprintInspector {
    fn network_fingerprint(
        &self,
    ) -> impl Future<Output = Result<NetworkFingerprint, ForeignChainInspectionError>> + Send;

    /// Puts an operator-supplied fingerprint into the form [`Self::network_fingerprint`] returns,
    /// so that a spec-legal spelling of the right network does not read as the wrong network.
    fn canonical_fingerprint(expected: &str) -> NetworkFingerprint;
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
/// the same failure mode (e.g. `NonCanonicalBlock`) are considered to agree even if the
/// inner fields differ.
#[derive(Clone, derive_more::Constructor)]
pub struct FanOut<Inspector> {
    inspectors: NonEmptyVec<(ProviderId, Inspector)>,
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
    ) -> Result<Vec<Self::ExtractedValue>, ForeignChainInspectionError> {
        let mut join_set = tokio::task::JoinSet::new();
        for (provider, inspector) in self.inspectors.iter() {
            let tx_id = tx_id.clone();
            let finality = finality.clone();
            let extractors = extractors.clone();
            let inspector = inspector.clone();
            let provider = provider.clone();
            join_set.spawn(async move {
                (
                    provider,
                    inspector.extract(tx_id, finality, extractors).await,
                )
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

impl<Inspector> FanOut<Inspector>
where
    Inspector: NetworkFingerprintInspector + Clone + Send + Sync + 'static,
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

    /// Splits by what the provider did, where the [`From`] impl collapses everything into the one
    /// [`Self::ClientError`] that [`Self::is_transient`] retries wholesale. A caller reporting why a
    /// provider is unusable needs a 401 told apart from a 429.
    ///
    /// Messages name the HTTP status or JSON-RPC code, never the URL.
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
                    Some(HttpTransportError::Http(HttpError::Malformed | HttpError::TooLarge)) => {
                        Self::MalformedRpcResponse("response was not valid JSON-RPC".to_string())
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
    /// report the transaction's own state, which is an answer rather than a fault.
    pub fn provider_failure(&self) -> Option<ProviderFailure> {
        match self {
            Self::ClientError(_) | Self::RpcRequestFailed(_) => Some(ProviderFailure::Unreachable),
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
