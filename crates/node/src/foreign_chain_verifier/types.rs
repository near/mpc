//! Types for foreign chain transaction verification.

use mpc_contract::primitives::foreign_chain::BlockId;
use thiserror::Error;

/// Output from a successful transaction verification
#[derive(Debug, Clone)]
pub struct VerificationOutput {
    /// Whether the transaction was successful
    pub success: bool,
    /// Block/slot identifier where transaction was verified
    pub block_id: BlockId,
    /// Status of the transaction
    pub tx_status: TxStatus,
}

/// Status of a transaction on the foreign chain
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxStatus {
    /// Transaction succeeded
    Success,
    /// Transaction failed (e.g., reverted)
    Failed,
    /// Transaction is still pending
    Pending,
    /// Transaction was not found on chain
    NotFound,
}

/// Errors that can occur during foreign chain verification
#[derive(Debug, Clone, Error)]
pub enum VerificationError {
    #[error("RPC request failed: {0}")]
    RpcError(String),

    #[error("Transaction not found: {0}")]
    TransactionNotFound(String),

    #[error("Transaction failed: {0}")]
    TransactionFailed(String),

    #[error("Transaction not yet finalized")]
    NotFinalized,

    #[error("Invalid transaction ID format: {0}")]
    InvalidTransactionId(String),

    #[error("Unsupported chain: {0}")]
    UnsupportedChain(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Timeout waiting for transaction confirmation")]
    Timeout,

    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<reqwest::Error> for VerificationError {
    fn from(err: reqwest::Error) -> Self {
        VerificationError::RpcError(err.to_string())
    }
}
