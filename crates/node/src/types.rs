use std::fmt;

use chain_gateway::{event_subscriber::block_events::BlockContext, types::BlockHeight};
use mpc_primitives::domain::DomainId;
use near_account_id::AccountId;
use near_crypto::Signature;
use near_indexer_primitives::CryptoHash;
use near_indexer_primitives::types::{BlockHeight as NearBlockHeight, Nonce};
use near_mpc_contract_interface::types::{Ed25519PublicKey, Payload, Tweak};
use near_mpc_crypto_types::kdf::derive_tweak;
use near_time::Utc;
use serde::{Deserialize, Serialize};

use near_mpc_contract_interface::types as dtos;

use crate::{
    indexer::handler::{
        CKDRequestFromChain, SignatureRequestFromChain, VerifyForeignTxRequestFromChain,
    },
    requests::recent_blocks_tracker::BlockStatusHandle,
};

pub(crate) struct RequestsUpdate<T> {
    pub(crate) requests: Vec<T>,
    pub(crate) completed_requests: Vec<RequestId>,
    pub(crate) block_height: BlockHeight,
    pub(crate) block_status: BlockStatusHandle,
}

impl<T> RequestsUpdate<T> {
    pub(crate) fn from_chain<U>(
        block: &BlockContext,
        block_status: BlockStatusHandle,
        new_requests: Vec<U>,
        completed_requests: Vec<RequestId>,
    ) -> RequestsUpdate<T>
    where
        T: FromChain<U>,
    {
        let requests = new_requests
            .into_iter()
            .map(|request_from_chain| T::from_chain(request_from_chain, block))
            .collect::<Vec<_>>();

        RequestsUpdate {
            requests,
            completed_requests,
            block_height: block.height,
            block_status,
        }
    }
}

pub enum RequestType {
    Signature,
    CKD,
    VerifyForeignTx,
}

pub type RequestId = CryptoHash;

/// The trait that defines common functionality of MPC requests:
/// currently CKD and signatures
pub trait Request {
    fn get_id(&self) -> RequestId;
    fn get_receipt_id(&self) -> CryptoHash;
    fn get_entropy(&self) -> [u8; 32];
    fn get_timestamp_nanosec(&self) -> u64;
    fn get_domain_id(&self) -> DomainId;
    fn get_type() -> RequestType;
}

pub type CKDId = CryptoHash;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CKDRequest {
    /// The unique ID that identifies the ckd, and can also uniquely identify the response.
    pub id: CKDId,
    /// The receipt that generated the ckd request, which can be used to look up on chain.
    pub receipt_id: CryptoHash,
    pub app_public_key: dtos::CKDAppPublicKey,
    pub app_id: dtos::CkdAppId,
    pub entropy: [u8; 32],
    pub timestamp_nanosec: u64,
    pub domain_id: DomainId,
}

pub(crate) trait FromChain<T> {
    fn from_chain(chain_value: T, block: &BlockContext) -> Self;
}

impl FromChain<CKDRequestFromChain> for CKDRequest {
    fn from_chain(chain_value: CKDRequestFromChain, block: &BlockContext) -> Self {
        let CKDRequestFromChain {
            ckd_id,
            receipt_id,
            request,
        } = chain_value;
        Self {
            id: ckd_id,
            receipt_id,
            app_public_key: request.app_public_key,
            app_id: request.app_id,
            entropy: block.entropy.clone().into(),
            timestamp_nanosec: block.timestamp_nanosec,
            domain_id: request.domain_id,
        }
    }
}

pub type SignatureId = CryptoHash;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignatureRequest {
    /// The unique ID that identifies the signature, and can also uniquely identify the response.
    pub id: SignatureId,
    /// The receipt that generated the signature request, which can be used to look up on chain.
    pub receipt_id: CryptoHash,
    pub payload: Payload,
    pub tweak: Tweak,
    pub entropy: [u8; 32],
    pub timestamp_nanosec: u64,
    pub domain: DomainId,
}

impl FromChain<SignatureRequestFromChain> for SignatureRequest {
    fn from_chain(chain_value: SignatureRequestFromChain, block: &BlockContext) -> Self {
        let SignatureRequestFromChain {
            signature_id,
            receipt_id,
            request,
            predecessor_id,
        } = chain_value;
        Self {
            id: signature_id,
            receipt_id,
            payload: request.payload,
            tweak: derive_tweak(&predecessor_id, &request.path),
            entropy: block.entropy.clone().into(),
            timestamp_nanosec: block.timestamp_nanosec,
            domain: request.domain_id,
        }
    }
}

impl fmt::Display for RequestType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RequestType::Signature => write!(f, "signature"),
            RequestType::CKD => write!(f, "ckd"),
            RequestType::VerifyForeignTx => write!(f, "verify_foreign_tx"),
        }
    }
}

pub type VerifyForeignTxId = CryptoHash;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VerifyForeignTxRequest {
    /// The unique ID that identifies the verify_foreign_tx, and can also uniquely identify the response.
    pub id: VerifyForeignTxId,
    /// The receipt that generated the verify_foreign_tx request, which can be used to look up on chain.
    pub receipt_id: CryptoHash,
    pub request: dtos::ForeignChainRpcRequest,
    pub payload_version: dtos::ForeignTxPayloadVersion,
    pub entropy: [u8; 32],
    pub timestamp_nanosec: u64,
    pub domain_id: DomainId,
}

impl FromChain<VerifyForeignTxRequestFromChain> for VerifyForeignTxRequest {
    fn from_chain(chain_value: VerifyForeignTxRequestFromChain, block: &BlockContext) -> Self {
        let VerifyForeignTxRequestFromChain {
            verify_foreign_tx_id,
            receipt_id,
            request,
        } = chain_value;
        VerifyForeignTxRequest {
            id: verify_foreign_tx_id,
            receipt_id,
            domain_id: request.domain_id,
            entropy: block.entropy.clone().into(),
            payload_version: request.payload_version,
            request: request.request,
            timestamp_nanosec: block.timestamp_nanosec,
        }
    }
}

impl Request for CKDRequest {
    fn get_id(&self) -> RequestId {
        self.id
    }

    fn get_receipt_id(&self) -> CryptoHash {
        self.receipt_id
    }

    fn get_entropy(&self) -> [u8; 32] {
        self.entropy
    }

    fn get_timestamp_nanosec(&self) -> u64 {
        self.timestamp_nanosec
    }

    fn get_domain_id(&self) -> DomainId {
        self.domain_id
    }

    fn get_type() -> RequestType {
        RequestType::CKD
    }
}

impl Request for SignatureRequest {
    fn get_id(&self) -> RequestId {
        self.id
    }

    fn get_receipt_id(&self) -> CryptoHash {
        self.receipt_id
    }

    fn get_entropy(&self) -> [u8; 32] {
        self.entropy
    }

    fn get_timestamp_nanosec(&self) -> u64 {
        self.timestamp_nanosec
    }

    fn get_domain_id(&self) -> DomainId {
        self.domain
    }

    fn get_type() -> RequestType {
        RequestType::Signature
    }
}

impl Request for VerifyForeignTxRequest {
    fn get_id(&self) -> RequestId {
        self.id
    }

    fn get_receipt_id(&self) -> CryptoHash {
        self.receipt_id
    }

    fn get_entropy(&self) -> [u8; 32] {
        self.entropy
    }

    fn get_timestamp_nanosec(&self) -> u64 {
        self.timestamp_nanosec
    }

    fn get_domain_id(&self) -> DomainId {
        self.domain_id
    }

    fn get_type() -> RequestType {
        RequestType::VerifyForeignTx
    }
}

/// The observed lifecycle outcome of a submitted transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubmittedTransactionStatus {
    /// Building, signing, or routing the transaction failed locally; it never
    /// reached the network.
    SubmitFailed,
    /// The transaction's intended effect was observed on chain.
    Executed,
    /// The transaction's intended effect was not observed before the timeout
    /// (it may have been rejected, e.g. for a stale nonce, or simply delayed).
    NotExecuted,
    /// The transaction type has no on-chain effect we verify, so the outcome is
    /// not determinable from contract state.
    Unknown,
    /// An error occurred while trying to observe the on-chain effect.
    ObserveError,
}

/// A single submitted transaction and its final status.
#[derive(Clone, Debug, PartialEq, Eq, derive_more::Display)]
#[display(
    "  {submitted_at}  {:<12}  method={method:<24}  signer={signer_account_id} key={}  {}",
    format!("{status:?}"),
    String::from(signer_public_key),
    metadata
        .as_ref()
        .map_or_else(|| "(not submitted)".to_string(), |m| m.to_string())
)]
pub struct SubmittedTransaction {
    /// The built-and-signed transaction details (txid, nonce, signature, block
    /// height). Absent if building/signing failed before they were produced;
    /// present otherwise, all together.
    pub metadata: Option<SubmittedTxMetadata>,
    /// The account the transaction was submitted from.
    pub signer_account_id: AccountId,
    /// The access key (public key) the transaction was signed with.
    pub signer_public_key: Ed25519PublicKey,
    /// The contract method invoked (e.g. `respond`, `respond_ckd`).
    pub method: &'static str,
    /// Wall-clock time at which the transaction was routed (or, on the
    /// submit-failed path, at which the failure was recorded). Captured at
    /// submission time, not when the outcome was later observed.
    pub submitted_at: Utc,
    /// The final observed outcome.
    pub status: SubmittedTransactionStatus,
}

/// The signer-specific context for a submission, known before the transaction
/// is built and shared by every record produced for that submission.
pub struct SignerContext {
    pub account_id: AccountId,
    pub public_key: Ed25519PublicKey,
    pub method: &'static str,
}

/// The metadata of a successfully built-and-submitted transaction, captured in
/// `crate::indexer::tx_sender`.
#[derive(Clone, Debug, PartialEq, Eq, derive_more::Display)]
#[display("txid={tx_hash}  nonce={nonce}  block={block_height}  sig={signature}")]
pub struct SubmittedTxMetadata {
    pub tx_hash: CryptoHash,
    pub nonce: Nonce,
    pub signature: Signature,
    pub block_height: NearBlockHeight,
}

impl SubmittedTransaction {
    /// A record for a transaction that was successfully built and routed, with
    /// its observed on-chain [`SubmittedTransactionStatus`]. `submitted_at` is
    /// the time the transaction was routed, captured by the caller before it
    /// waited to observe the outcome.
    pub fn submitted(
        signer: SignerContext,
        metadata: SubmittedTxMetadata,
        status: SubmittedTransactionStatus,
        submitted_at: Utc,
    ) -> Self {
        Self::new(signer, Some(metadata), status, submitted_at)
    }

    /// A record for a transaction that could not be built, signed, or routed and
    /// so never reached the network. `submitted_at` is the time the failure was
    /// recorded.
    pub fn submit_failed(signer: SignerContext, submitted_at: Utc) -> Self {
        Self::new(
            signer,
            None,
            SubmittedTransactionStatus::SubmitFailed,
            submitted_at,
        )
    }

    /// Builds a record from the signer context and, when the transaction was
    /// successfully built, its metadata.
    fn new(
        signer: SignerContext,
        metadata: Option<SubmittedTxMetadata>,
        status: SubmittedTransactionStatus,
        submitted_at: Utc,
    ) -> Self {
        Self {
            metadata,
            signer_account_id: signer.account_id,
            signer_public_key: signer.public_key,
            method: signer.method,
            submitted_at,
            status,
        }
    }
}

/// Receives a record of each transaction the indexer submitted (with its
/// outcome), to show on the `/debug/recent_transactions` page. It's a trait so
/// the indexer needn't know where the records go, and `log_transaction` can't
/// fail or block — recording is best-effort and never slows transaction
/// processing.
pub trait TransactionLogger: Clone + Send + Sync + 'static {
    fn log_transaction(&self, transaction: SubmittedTransaction);
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use std::str::FromStr;

    /// A submitted (Executed) transaction whose hash is fixed
    /// (`CryptoHash::default()`). Used by the `Display` tests, which pin the
    /// exact rendered txid.
    fn test_transaction(method: &'static str) -> SubmittedTransaction {
        SubmittedTransaction {
            metadata: Some(SubmittedTxMetadata {
                tx_hash: CryptoHash::default(),
                nonce: 7,
                signature: Signature::empty(near_crypto::KeyType::ED25519),
                block_height: 42,
            }),
            signer_account_id: AccountId::from_str("responder.near").unwrap(),
            signer_public_key: Ed25519PublicKey::from([7u8; 32]),
            method,
            submitted_at: Utc::from_unix_timestamp(1_700_000_000).unwrap(),
            status: SubmittedTransactionStatus::Executed,
        }
    }

    #[test]
    fn submitted_transaction_display__should_render_exact_line_with_padding() {
        // Given
        let transaction = test_transaction("respond");

        // When
        let rendered = transaction.to_string();

        // Then
        let expected = "  2023-11-14 22:13:20.0 +00:00:00  Executed      method=respond                   signer=responder.near key=ed25519:US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx  txid=11111111111111111111111111111111  nonce=7  block=42  sig=ed25519:1111111111111111111111111111111111111111111111111111111111111111";
        assert_eq!(rendered, expected);
    }

    #[test]
    fn submitted_transaction_display__should_render_marker_without_metadata() {
        // Given
        let transaction = SubmittedTransaction {
            metadata: None,
            status: SubmittedTransactionStatus::SubmitFailed,
            ..test_transaction("respond")
        };

        // When
        let rendered = transaction.to_string();

        // Then
        let expected = "  2023-11-14 22:13:20.0 +00:00:00  SubmitFailed  method=respond                   signer=responder.near key=ed25519:US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx  (not submitted)";
        assert_eq!(rendered, expected);
    }
}
