use std::hash::Hash;

use derive_more::{Deref, Display, From};
use ethereum_types::H256;
use http::{HeaderMap, HeaderName, HeaderValue};
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use near_mpc_bounded_collections::NonEmptyVec;
use thiserror::Error;

pub use jsonrpsee::http_client;

pub mod abstract_chain;
pub mod arbitrum;
pub mod base;
pub mod bitcoin;
pub mod bnb;
pub mod contract_interface_conversions;
pub mod evm;
pub mod hyperevm;
pub mod polygon;
pub mod starknet;
pub mod ton;

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
    inspectors: NonEmptyVec<Inspector>,
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
        for (idx, inspector) in self.inspectors.iter().enumerate() {
            let tx_id = tx_id.clone();
            let finality = finality.clone();
            let extractors = extractors.clone();
            let inspector = inspector.clone();
            join_set
                .spawn(async move { (idx, inspector.extract(tx_id, finality, extractors).await) });
        }

        let mut successes: Vec<(usize, Vec<Self::ExtractedValue>)> = Vec::new();
        let mut non_transient_errors: Vec<(usize, ForeignChainInspectionError)> = Vec::new();
        let mut first_transient_error: Option<ForeignChainInspectionError> = None;

        for (idx, result) in join_set.join_all().await {
            match result {
                Ok(values) => successes.push((idx, values)),
                Err(err) if err.is_transient() => {
                    tracing::warn!(
                        inspector_index = idx,
                        error = %err,
                        "fan-out inspector failed (transient)",
                    );
                    first_transient_error.get_or_insert(err);
                }
                Err(err) => {
                    tracing::error!(
                        inspector_index = idx,
                        error = %err,
                        "fan-out inspector failed (non-transient)",
                    );
                    non_transient_errors.push((idx, err));
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
        "RPC backend returned a block that does not match the one queried by hash: requested={requested_hash}, returned={returned_hash}"
    )]
    InconsistentRpcResponse {
        requested_hash: HexBytes,
        returned_hash: HexBytes,
    },
    #[error("The transaction's status was not success")]
    TransactionFailed,
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
            Self::ClientError(_) | Self::NotFinalized | Self::NotEnoughBlockConfirmations { .. }
        )
    }
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
