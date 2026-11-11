use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::types::Ed25519PublicKey;

#[derive(
    Debug,
    Copy,
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
pub enum ForeignChain {
    Solana,
    Bitcoin,
    Ethereum,
    Base,
    Bnb,
    Arbitrum,
    Abstract,
    Starknet,
    Polygon,
    HyperEvm,
    Ton,
    Aptos,
    Sui,
    Avalanche,
    Adi,
    Fogo,
}
impl ForeignChain {
    /// The chain's key in an operator's `foreign_chains` config, also used as its metric label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Solana => "solana",
            Self::Bitcoin => "bitcoin",
            Self::Ethereum => "ethereum",
            Self::Base => "base",
            Self::Bnb => "bnb",
            Self::Arbitrum => "arbitrum",
            Self::Abstract => "abstract",
            Self::Starknet => "starknet",
            Self::Polygon => "polygon",
            Self::HyperEvm => "hyper_evm",
            Self::Ton => "ton",
            Self::Aptos => "aptos",
            Self::Sui => "sui",
            Self::Avalanche => "avalanche",
            Self::Adi => "adi",
            Self::Fogo => "fogo",
        }
    }
}
/// Set of foreign chains a node reports it can serve; aggregated into [`AvailableForeignChains`] by the contract.
#[derive(
    Debug,
    Clone,
    Default,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    derive_more::From,
    derive_more::Deref,
    derive_more::DerefMut,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct ForeignChainsConfig(BTreeSet<ForeignChain>);
/// Per-node foreign-chain configs, keyed by each node's TLS public key.
#[derive(
    Debug,
    Clone,
    Default,
    Eq,
    PartialEq,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    derive_more::From,
    derive_more::Deref,
    derive_more::DerefMut,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct ForeignChainsConfigs(BTreeMap<Ed25519PublicKey, ForeignChainsConfig>);
/// The set of foreign chains available across the threshold of active participants. Returned by
/// `get_available_foreign_chains`; computed from the per-node [`ForeignChainsConfig`] reports.
#[derive(
    Debug,
    Clone,
    Default,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    derive_more::From,
    derive_more::Deref,
    derive_more::DerefMut,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct AvailableForeignChains(BTreeSet<ForeignChain>);
