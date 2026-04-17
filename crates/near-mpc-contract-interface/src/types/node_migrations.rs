use crate::types::participants::ParticipantInfo;
use borsh::{BorshDeserialize, BorshSerialize};
use near_mpc_crypto_types::Ed25519PublicKey;
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
    /// This key is different from the TLS key stored in [`ParticipantInfo::sign_pk`].
    pub signer_account_pk: Ed25519PublicKey,
    pub destination_node_info: ParticipantInfo,
}
