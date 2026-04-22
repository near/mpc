use crate::types::{Ed25519PublicKey, ParticipantInfo};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct BackupServiceInfo {
    pub public_key: Ed25519PublicKey,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct DestinationNodeInfo {
    /// The public key used by the node to sign transactions to the contract.
    /// This key is different from the TLS key stored in [`ParticipantInfo::tls_public_key`].
    pub signer_account_pk: Ed25519PublicKey,
    pub destination_node_info: ParticipantInfo,
}
