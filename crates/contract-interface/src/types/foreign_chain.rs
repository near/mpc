use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::types::primitives::{DomainId, Tweak};

// The request coming from the user
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
pub struct VerifyForeignTxRequestArgs {
    pub chain: ForeignChain,
    pub tx_id: TransactionId,        // TxID is the payload we're signing
    pub path: String,                // Key derivation path
    pub domain_id: Option<DomainId>, // Defaults to 0 (legacy ECDSA)
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
enum ForeignChain {
    Solana,
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
// The request coming from the user
pub struct VerifyForeignRequest {
    pub rpc_request: ForeignChainRpcRequest,
    pub tweak: Tweak,
    pub domain_id: DomainId,
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub enum ForeignChainRpcRequest {
    Solana(SolanaRpcRequest),
    Bitcoin(BitcoinRpcRequest),
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct SolanaRpcRequest {
    pub tx_id: SolanaSignature,
    pub finality: Finality,
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct BitcoinRpcRequest {
    pub tx_id: BitcoinSignature,
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

pub struct SolanaSignature(
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
pub struct BitcoinSignature(
    #[cfg_attr(
            all(feature = "abi", not(target_arch = "wasm32")),
            schemars(with = "Vec<u8>") // Schemars doesn't support arrays of size greater than 32. 
        )]
    #[serde_as(as = "[_; 64]")]
    pub [u8; 64],
);
