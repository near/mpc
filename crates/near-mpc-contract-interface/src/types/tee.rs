//! DTO types for TEE-related data.

use serde::{Deserialize, Serialize};

/// Identifier for a TEE node.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct NodeId {
    /// Operator account.
    pub account_id: near_account_id::AccountId,
    /// TLS public key, encoded as a string (e.g., "ed25519:...").
    pub tls_public_key: String,
    /// Account public key, if available.
    pub account_public_key: Option<String>,
}
