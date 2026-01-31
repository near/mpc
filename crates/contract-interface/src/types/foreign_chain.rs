use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::types::{
    PublicKey,
    primitives::{DomainId, SignatureResponse, Tweak},
};

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct VerifyForeignTransactionRequestArgs {
    pub foreign_transaction: ForeignTransactionConfig,
    pub path: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct VerifyForeignTransactionRequest {
    pub foreign_transaction: ForeignTransactionConfig,
    pub tweak: Tweak,
    pub domain_id: DomainId,
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct VerifyForeignTransactionResponse {
    pub signature: SignatureResponse,
    pub public_key: PublicKey,
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub enum ForeignTransactionConfig {
    Solana(SolanaTransaction),
    Bitcoin(BitcoinTransaction),
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct SolanaTransaction {
    pub transaction_id: SolanaTransactionId,
    pub finality: Finality,
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct BitcoinTransaction {
    pub transaction_id: BitcoinTransactionId,
    pub confirmations: BlockConfirmations,
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub enum Finality {
    Optimistic,
    Final,
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
    derive_more::Into,
    derive_more::From,
    derive_more::AsRef,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct BlockConfirmations(pub u64);

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
    derive_more::Into,
    derive_more::From,
    derive_more::AsRef,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]

pub struct SolanaTransactionId(
    #[cfg_attr(
            all(feature = "abi", not(target_arch = "wasm32")),
            schemars(with = "Vec<u8>") // Schemars doesn't support arrays of size greater than 32. 
        )]
    #[serde_as(as = "[_; 64]")]
    pub [u8; 64],
);

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
    derive_more::Into,
    derive_more::From,
    derive_more::AsRef,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct BitcoinTransactionId(pub [u8; 32]);
