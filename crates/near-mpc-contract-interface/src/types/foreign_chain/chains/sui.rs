use borsh::{BorshDeserialize, BorshSerialize};
use near_mpc_bounded_collections::UpperBoundedVec;
use serde::{Deserialize, Serialize};
use serde_with::{hex::Hex, serde_as};

use crate::types::MAX_EXTRACTORS_PER_REQUEST;

/// 32-byte Sui transaction digest (Blake2b-256 of the signed transaction data).
/// Sui APIs display it base58-encoded; here it is carried as raw bytes (hex in JSON).
#[serde_as]
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    derive_more::Into,
    derive_more::From,
    derive_more::AsRef,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct SuiTxId(#[serde_as(as = "Hex")] pub [u8; 32]);

#[serde_as]
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    derive_more::Into,
    derive_more::From,
    derive_more::AsRef,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct SuiAddress(#[serde_as(as = "Hex")] pub [u8; 32]);

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct SuiRpcRequest {
    pub tx_id: SuiTxId,
    pub finality: SuiFinality,
    pub extractors: UpperBoundedVec<SuiExtractor, MAX_EXTRACTORS_PER_REQUEST>,
}

/// Sui has no reorgs; a transaction is final once it is included in a
/// committee-certified checkpoint.
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
#[non_exhaustive]
pub enum SuiFinality {
    Checkpointed,
}

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
#[non_exhaustive]
#[repr(u8)]
#[borsh(use_discriminant = true)]
pub enum SuiExtractor {
    Event { event_index: u64 } = 1,
}

/// A Sui Move event as observed on-chain.
///
/// `type_tag` carries every address in canonical long form (`0x` + 64 lowercase hex),
/// and `bcs` carries the BCS-serialized event contents. Both are provider-independent,
/// unlike the API's `parsedJson` rendering, which may vary across node versions.
#[serde_as]
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct SuiEvent {
    pub package_id: SuiAddress,
    pub transaction_module: String,
    pub sender: SuiAddress,
    pub type_tag: String,
    #[serde_as(as = "Hex")]
    pub bcs: Vec<u8>,
}

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
#[non_exhaustive]
pub enum SuiExtractedValue {
    Event(SuiEvent),
}
