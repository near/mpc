use borsh::{BorshDeserialize, BorshSerialize};
use bounded_collections::NonEmptyBTreeSet;
use serde::{Deserialize, Serialize};
use serde_with::{hex::Hex, serde_as};
use sha2::Digest;
use std::collections::BTreeMap;

use crate::types::primitives::{AccountId, DomainId, SignatureResponse, Tweak};

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct VerifyForeignTransactionRequestArgs {
    pub request: ForeignChainRpcRequest,
    pub derivation_path: String,
    pub domain_id: DomainId,
    pub payload_version: u8,
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
    derive(schemars::JsonSchema)
)]
pub struct VerifyForeignTransactionRequest {
    pub request: ForeignChainRpcRequest,
    pub tweak: Tweak,
    pub domain_id: DomainId,
    pub payload_version: u8,
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct VerifyForeignTransactionResponse {
    pub payload_hash: Hash256,
    pub signature: SignatureResponse,
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
    derive(schemars::JsonSchema)
)]
#[non_exhaustive]
pub enum ForeignChainRpcRequest {
    Abstract(EvmRpcRequest),
    Ethereum(EvmRpcRequest),
    Solana(SolanaRpcRequest),
    Bitcoin(BitcoinRpcRequest),
    Starknet(StarknetRpcRequest),
}

impl ForeignChainRpcRequest {
    pub fn chain(&self) -> ForeignChain {
        match self {
            Self::Abstract(_) => ForeignChain::Abstract,
            Self::Ethereum(_) => ForeignChain::Ethereum,
            Self::Solana(_) => ForeignChain::Solana,
            Self::Bitcoin(_) => ForeignChain::Bitcoin,
            Self::Starknet(_) => ForeignChain::Starknet,
        }
    }
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
    derive(schemars::JsonSchema)
)]
pub struct EvmRpcRequest {
    pub tx_id: EvmTxId,
    pub extractors: Vec<EvmExtractor>,
    pub finality: EvmFinality,
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
    derive(schemars::JsonSchema)
)]
pub struct SolanaRpcRequest {
    pub tx_id: SolanaTxId,
    pub finality: SolanaFinality,
    pub extractors: Vec<SolanaExtractor>,
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
    derive(schemars::JsonSchema)
)]
pub struct BitcoinRpcRequest {
    pub tx_id: BitcoinTxId,
    pub confirmations: BlockConfirmations,
    pub extractors: Vec<BitcoinExtractor>,
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
    derive(schemars::JsonSchema)
)]
pub struct StarknetRpcRequest {
    pub tx_id: StarknetTxId,
    pub finality: StarknetFinality,
    pub extractors: Vec<StarknetExtractor>,
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
    derive(schemars::JsonSchema)
)]
#[non_exhaustive]
pub enum EvmFinality {
    Latest,
    Safe,
    Finalized,
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
    derive(schemars::JsonSchema)
)]
#[non_exhaustive]
pub enum SolanaFinality {
    Processed,
    Confirmed,
    Finalized,
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
    derive(schemars::JsonSchema)
)]
#[non_exhaustive]
pub enum StarknetFinality {
    AcceptedOnL2,
    AcceptedOnL1,
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
    derive(schemars::JsonSchema)
)]
#[non_exhaustive]
#[repr(u8)]
#[borsh(use_discriminant = true)]
pub enum EvmExtractor {
    BlockHash = 0,
    Log { log_index: u64 } = 1,
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
    derive(schemars::JsonSchema)
)]
pub struct EvmLog {
    pub removed: bool,
    pub log_index: u64,
    pub transaction_index: u64,
    pub transaction_hash: Hash256,
    pub block_hash: Hash256,
    pub block_number: u64,
    pub address: Hash160,
    pub data: String,
    pub topics: Vec<Hash256>,
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
    derive(schemars::JsonSchema)
)]
#[non_exhaustive]
pub enum SolanaExtractor {
    SolanaProgramIdIndex { ix_index: u32 },
    SolanaDataHash { ix_index: u32 },
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
    derive(schemars::JsonSchema)
)]
#[non_exhaustive]
#[repr(u8)]
#[borsh(use_discriminant = true)]
pub enum BitcoinExtractor {
    BlockHash = 0,
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
    derive(schemars::JsonSchema)
)]
#[non_exhaustive]
#[repr(u8)]
#[borsh(use_discriminant = true)]
pub enum StarknetExtractor {
    BlockHash = 0,
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
    derive(schemars::JsonSchema)
)]
#[non_exhaustive]
pub enum ExtractedValue {
    BitcoinExtractedValue(BitcoinExtractedValue),
    EvmExtractedValue(EvmExtractedValue),
    StarknetExtractedValue(StarknetExtractedValue),
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
    derive(schemars::JsonSchema)
)]
#[non_exhaustive]
pub enum EvmExtractedValue {
    BlockHash(Hash256),
    Log(EvmLog),
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
    derive(schemars::JsonSchema)
)]
#[non_exhaustive]
pub enum BitcoinExtractedValue {
    BlockHash(Hash256),
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
    derive(schemars::JsonSchema)
)]
#[non_exhaustive]
pub enum StarknetExtractedValue {
    BlockHash(StarknetFelt),
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
    derive(schemars::JsonSchema)
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
}

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
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct ForeignChainPolicy {
    pub chains: BTreeMap<ForeignChain, NonEmptyBTreeSet<RpcProvider>>,
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
    derive(schemars::JsonSchema)
)]
pub struct RpcProvider {
    pub rpc_url: String,
}

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
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct ForeignChainPolicyVotes {
    pub proposal_by_account: BTreeMap<AccountId, ForeignChainPolicy>,
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
    BorshSerialize,
    BorshDeserialize,
    derive_more::Into,
    derive_more::From,
    derive_more::AsRef,
    derive_more::Deref,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct Hash256(#[serde_as(as = "Hex")] pub [u8; 32]);

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
    derive_more::Deref,
    derive_more::Into,
    derive_more::From,
    derive_more::AsRef,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct Hash160(#[serde_as(as = "Hex")] pub [u8; 20]);

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
    derive(schemars::JsonSchema)
)]
pub struct EvmTxId(#[serde_as(as = "Hex")] pub [u8; 32]);

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
    derive(schemars::JsonSchema)
)]
pub struct SolanaTxId(
    #[cfg_attr(
        all(feature = "abi", not(target_arch = "wasm32")),
        schemars(with = "Vec<u8>") // Schemars doesn't support arrays of size greater than 32.
    )]
    #[serde_as(as = "Hex")]
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
    BorshSerialize,
    BorshDeserialize,
    derive_more::Into,
    derive_more::From,
    derive_more::AsRef,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct BitcoinTxId(#[serde_as(as = "Hex")] pub [u8; 32]);

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
    derive(schemars::JsonSchema)
)]
pub struct StarknetFelt(#[serde_as(as = "Hex")] pub [u8; 32]);

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
    derive(schemars::JsonSchema)
)]
pub struct StarknetTxId(pub StarknetFelt);

/// Canonical payload for foreign-chain transaction verification signatures.
///
/// This enum is Borsh-serialized and SHA-256 hashed to produce the 32-byte
/// `msg_hash` that the MPC network signs. Callers select the payload version
/// via `VerifyForeignTransactionRequestArgs::payload_version`.
///
/// IMPORTANT: Never reorder existing enum variants or struct fields, as this
/// would change the Borsh encoding and break signature verification.
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
    derive(schemars::JsonSchema)
)]
pub enum ForeignTxSignPayload {
    V1(ForeignTxSignPayloadV1),
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
    derive(schemars::JsonSchema)
)]
pub struct ForeignTxSignPayloadV1 {
    pub request: ForeignChainRpcRequest,
    pub values: Vec<ExtractedValue>,
}

impl ForeignTxSignPayload {
    pub fn compute_msg_hash(&self) -> std::io::Result<Hash256> {
        let mut hasher = sha2::Sha256::new();
        borsh::BorshSerialize::serialize(self, &mut hasher)?;
        Ok(Hash256(hasher.finalize().into()))
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[test]
    fn foreign_tx_sign_payload_v1_ethereum__should_have_consistent_hash() {
        // Given
        let payload = ForeignTxSignPayload::V1(ForeignTxSignPayloadV1 {
            request: ForeignChainRpcRequest::Ethereum(EvmRpcRequest {
                tx_id: EvmTxId([0xab; 32]),
                extractors: vec![EvmExtractor::BlockHash],
                finality: EvmFinality::Finalized,
            }),
            values: vec![ExtractedValue::EvmExtractedValue(
                EvmExtractedValue::BlockHash(Hash256([0xef; 32])),
            )],
        });

        // When
        let hash = payload.compute_msg_hash().unwrap();

        // Then
        insta::assert_json_snapshot!(hex::encode(hash.0));
    }

    #[test]
    fn foreign_tx_sign_payload_v1_solana__should_have_consistent_hash() {
        // Given
        let payload = ForeignTxSignPayload::V1(ForeignTxSignPayloadV1 {
            request: ForeignChainRpcRequest::Solana(SolanaRpcRequest {
                tx_id: SolanaTxId([0x11; 64]),
                finality: SolanaFinality::Finalized,
                extractors: vec![
                    SolanaExtractor::SolanaProgramIdIndex { ix_index: 0 },
                    SolanaExtractor::SolanaDataHash { ix_index: 1 },
                ],
            }),
            values: vec![
                ExtractedValue::EvmExtractedValue(EvmExtractedValue::BlockHash(Hash256(
                    [0x33; 32],
                ))),
                ExtractedValue::EvmExtractedValue(EvmExtractedValue::BlockHash(Hash256(
                    [0x44; 32],
                ))),
            ],
        });

        // When
        let hash = payload.compute_msg_hash().unwrap();

        // Then
        insta::assert_json_snapshot!(hex::encode(hash.0));
    }

    #[test]
    fn foreign_tx_sign_payload_v1_bitcoin__should_have_consistent_hash() {
        // Given
        let payload = ForeignTxSignPayload::V1(ForeignTxSignPayloadV1 {
            request: ForeignChainRpcRequest::Bitcoin(BitcoinRpcRequest {
                tx_id: BitcoinTxId([0x55; 32]),
                confirmations: BlockConfirmations(6),
                extractors: vec![BitcoinExtractor::BlockHash],
            }),
            values: vec![ExtractedValue::BitcoinExtractedValue(
                BitcoinExtractedValue::BlockHash([42u8; 32].into()),
            )],
        });

        // When
        let hash = payload.compute_msg_hash().unwrap();

        // Then
        insta::assert_json_snapshot!(hex::encode(hash.0));
    }

    #[test]
    fn foreign_tx_sign_payload_v1_starknet__should_have_consistent_hash() {
        // Given
        let payload = ForeignTxSignPayload::V1(ForeignTxSignPayloadV1 {
            request: ForeignChainRpcRequest::Starknet(StarknetRpcRequest {
                tx_id: StarknetTxId(StarknetFelt([0x77; 32])),
                finality: StarknetFinality::AcceptedOnL1,
                extractors: vec![StarknetExtractor::BlockHash],
            }),
            values: vec![ExtractedValue::StarknetExtractedValue(
                StarknetExtractedValue::BlockHash(StarknetFelt([0x88; 32])),
            )],
        });

        // When
        let hash = payload.compute_msg_hash().unwrap();

        // Then
        insta::assert_json_snapshot!(hex::encode(hash.0));
    }

    #[rstest]
    #[case::abstract_(
        ForeignChainRpcRequest::Abstract(EvmRpcRequest {
            tx_id: EvmTxId([0; 32]),
            extractors: vec![],
            finality: EvmFinality::Finalized,
        }),
        ForeignChain::Abstract,
    )]
    #[case::ethereum(
        ForeignChainRpcRequest::Ethereum(EvmRpcRequest {
            tx_id: EvmTxId([0; 32]),
            extractors: vec![],
            finality: EvmFinality::Finalized,
        }),
        ForeignChain::Ethereum,
    )]
    #[case::solana(
        ForeignChainRpcRequest::Solana(SolanaRpcRequest {
            tx_id: SolanaTxId([0; 64]),
            finality: SolanaFinality::Finalized,
            extractors: vec![],
        }),
        ForeignChain::Solana,
    )]
    #[case::bitcoin(
        ForeignChainRpcRequest::Bitcoin(BitcoinRpcRequest {
            tx_id: BitcoinTxId([0; 32]),
            confirmations: BlockConfirmations(1),
            extractors: vec![],
        }),
        ForeignChain::Bitcoin,
    )]
    #[case::starknet(
        ForeignChainRpcRequest::Starknet(StarknetRpcRequest {
            tx_id: StarknetTxId(StarknetFelt([0; 32])),
            finality: StarknetFinality::AcceptedOnL1,
            extractors: vec![],
        }),
        ForeignChain::Starknet,
    )]
    fn foreign_chain_rpc_request_chain__should_return_correct_chain(
        #[case] request: ForeignChainRpcRequest,
        #[case] expected_chain: ForeignChain,
    ) {
        assert_eq!(request.chain(), expected_chain);
    }

    #[test]
    fn foreign_tx_sign_payload_v1__should_produce_different_hashes_for_different_requests() {
        // Given
        let payload_a = ForeignTxSignPayload::V1(ForeignTxSignPayloadV1 {
            request: ForeignChainRpcRequest::Ethereum(EvmRpcRequest {
                tx_id: EvmTxId([0x01; 32]),
                extractors: vec![EvmExtractor::BlockHash],
                finality: EvmFinality::Finalized,
            }),

            values: vec![ExtractedValue::EvmExtractedValue(
                EvmExtractedValue::BlockHash(Hash256([0xbb; 32])),
            )],
        });
        let payload_b = ForeignTxSignPayload::V1(ForeignTxSignPayloadV1 {
            request: ForeignChainRpcRequest::Ethereum(EvmRpcRequest {
                tx_id: EvmTxId([0x02; 32]),
                extractors: vec![EvmExtractor::BlockHash],
                finality: EvmFinality::Finalized,
            }),
            values: vec![ExtractedValue::EvmExtractedValue(
                EvmExtractedValue::BlockHash(Hash256([0xbb; 32])),
            )],
        });

        // When
        let hash_a = payload_a.compute_msg_hash().unwrap();
        let hash_b = payload_b.compute_msg_hash().unwrap();

        // Then
        assert_ne!(hash_a, hash_b);
    }
}
