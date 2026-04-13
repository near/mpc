//! DTO types for node migration data.

use near_mpc_crypto_types::Ed25519PublicKey;
use serde::{Deserialize, Serialize};

use super::participants::ParticipantInfo;

/// Information about a backup service for a node.
#[derive(Debug, Clone, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct BackupServiceInfo {
    pub public_key: Ed25519PublicKey,
}

/// Information about the destination node for a migration.
#[derive(Debug, Clone, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct DestinationNodeInfo {
    /// The public key used by the node to sign transactions to the contract.
    /// This key is different from the TLS key called `sign_pk` stored in `ParticipantInfo`.
    /// Encoded as a string (e.g., "ed25519:...") to avoid near-sdk dependency.
    pub signer_account_pk: String,
    /// The participant info for the destination node.
    pub destination_node_info: ParticipantInfo,
}
