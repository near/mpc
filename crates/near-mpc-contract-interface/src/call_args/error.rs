//! Error type for building and executing MPC contract calls.

/// Failure building a [`FunctionCallArgs`](mpc_call_args::FunctionCallArgs) or
/// executing it against a contract via [`CallContract`](super::CallContract).
#[derive(Debug, thiserror::Error)]
pub enum CallError {
    /// The call arguments could not be JSON-serialized.
    #[error("failed to serialize call arguments: {0}")]
    Serialize(#[from] serde_json::Error),
    /// The call arguments could not be borsh-encoded.
    #[error("failed to borsh-encode call arguments: {0}")]
    Encode(#[from] std::io::Error),
    /// The contract call itself failed (transport or execution).
    #[error("contract call failed: {0}")]
    Call(Box<dyn std::error::Error + Send + Sync>),
}
