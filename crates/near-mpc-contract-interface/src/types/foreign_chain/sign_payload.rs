use borsh::{BorshDeserialize, BorshSerialize};
use near_block_primitives::BlockHeight;
use serde::{Deserialize, Serialize};
use serde_with::{hex::Hex, serde_as};
use sha2::Digest;

use super::{ExtractedValue, ForeignChainRpcRequest, ForeignTxPayloadVersion, Hash256};

/// Canonical payload for foreign-chain transaction verification signatures.
///
/// This enum is Borsh-serialized and SHA-256 hashed to produce the 32-byte
/// `msg_hash` that the MPC network signs. Callers select V1 with
/// [`VerifyForeignTransactionRequestArgs`](super::VerifyForeignTransactionRequestArgs) and V2 with
/// [`VerifyForeignTransactionRequestV2`](super::VerifyForeignTransactionRequestV2).
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
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub enum ForeignTxSignPayload {
    V1(ForeignTxSignPayloadV1),
    V2(ForeignTxSignPayloadV2),
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
pub struct ForeignTxSignPayloadV1 {
    pub request: ForeignChainRpcRequest,
    pub values: Vec<ExtractedValue>,
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
pub struct ForeignTxSignPayloadV2 {
    pub request: ForeignChainRpcRequest,
    /// See [`VerifyForeignTransactionRequestV2::expected_values_hash`](super::VerifyForeignTransactionRequestV2::expected_values_hash).
    pub expected_values_hash: Hash256,
    /// The block the request's yield was created in.
    pub request_block_height: BlockHeight,
    /// The one yield this payload answers.
    pub yield_id: YieldId,
    pub outcome: ForeignTxVerificationOutcome,
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
pub enum ForeignTxVerificationOutcome {
    /// The extracted values equal the expected ones.
    Verified {},
    Negative {
        verdict: ForeignTxVerificationNegativeVerdict,
    },
    /// The network could not reach a verdict. This says nothing about the
    /// transaction.
    Inconclusive {},
}

/// The network's negative answer about the requested foreign chain
/// transaction, as observed while the request was pending, which starts at
/// [`ForeignTxSignPayloadV2::request_block_height`].
///
/// A later check may answer differently, for example once a transaction that
/// was not found lands.
#[derive(
    Debug,
    Clone,
    Copy,
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
pub enum ForeignTxVerificationNegativeVerdict {
    TransactionFailed,
    LogIndexOutOfBounds,
    TransactionNotFound,
    AccountNotFound,
    NonCanonicalBlock,
    /// The transaction was found, but its extracted values differ from
    /// [`VerifyForeignTransactionRequestV2::expected_values`](super::VerifyForeignTransactionRequestV2::expected_values).
    ValuesMismatch,
}

/// Identifies the yield a V2 verification request waits on. The contract picks
/// it, so a signature naming it answers that one request only.
#[serde_as]
#[derive(
    Debug,
    Clone,
    Copy,
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
pub struct YieldId(#[serde_as(as = "Hex")] pub [u8; 32]);

impl ForeignTxSignPayload {
    pub fn new(
        version: ForeignTxPayloadVersion,
        request: ForeignChainRpcRequest,
        values: Vec<ExtractedValue>,
    ) -> Self {
        match version {
            ForeignTxPayloadVersion::V1 => Self::V1(ForeignTxSignPayloadV1 { request, values }),
        }
    }

    pub fn compute_msg_hash(&self) -> std::io::Result<Hash256> {
        let mut hasher = sha2::Sha256::new();
        borsh::BorshSerialize::serialize(self, &mut hasher)?;
        Ok(Hash256(hasher.finalize().into()))
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::types::primitives::DomainId;
    use crate::types::{
        AptosAddress, AptosEvent, AptosExtractedValue, AptosExtractor, AptosFinality,
        AptosRpcRequest, AptosTxId, BitcoinExtractedValue, BitcoinExtractor, BitcoinRpcRequest,
        BitcoinTxId, BlockConfirmations, EvmExtractedValue, EvmExtractor, EvmFinality,
        EvmRpcRequest, EvmTxId, StarknetExtractedValue, StarknetExtractor, StarknetFelt,
        StarknetFinality, StarknetRpcRequest, StarknetTxId, SuiAddress, SuiEvent,
        SuiExtractedValue, SuiExtractor, SuiFinality, SuiRpcRequest, SuiTxId, SvmAccount,
        SvmAddress, SvmExtractedValue, SvmExtractor, SvmFinality, SvmInnerInstruction,
        SvmRpcRequest, SvmTxId, TonAddress, TonCellBody, TonExtractedValue, TonExtractor,
        TonFinality, TonLog, TonRpcRequest, TonTxId, VerifyForeignTransactionRequestV2,
    };
    use rstest::rstest;
    use serde_json::json;
    use std::collections::BTreeMap;

    #[test]
    fn foreign_tx_sign_payload_v1_ethereum__should_have_consistent_hash() {
        // Given
        let payload = ForeignTxSignPayload::V1(ForeignTxSignPayloadV1 {
            request: ForeignChainRpcRequest::Ethereum(EvmRpcRequest {
                tx_id: EvmTxId([0xab; 32]),
                extractors: [EvmExtractor::BlockHash].into(),
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
            request: ForeignChainRpcRequest::Solana(SvmRpcRequest {
                tx_id: SvmTxId([0x11; 64]),
                finality: SvmFinality::Finalized,
                extractors: [
                    SvmExtractor::InnerInstruction {
                        instruction_index: 2,
                        inner_instruction_index: 0,
                    },
                    SvmExtractor::AccountState {
                        pubkey: SvmAddress([0x22; 32]),
                    },
                ]
                .into(),
            }),
            values: vec![
                ExtractedValue::SvmExtractedValue(SvmExtractedValue::InnerInstruction(
                    SvmInnerInstruction {
                        program_id: SvmAddress([0x33; 32]),
                        accounts: vec![SvmAddress([0x44; 32]), SvmAddress([0x55; 32])],
                        data: vec![0xde, 0xad, 0xbe, 0xef],
                    },
                )),
                ExtractedValue::SvmExtractedValue(SvmExtractedValue::AccountState(SvmAccount {
                    owner: SvmAddress([0x66; 32]),
                    data: vec![0xca, 0xfe],
                })),
            ],
        });

        // When
        let hash = payload.compute_msg_hash().unwrap();

        // Then
        insta::assert_json_snapshot!(hex::encode(hash.0));
    }

    #[test]
    fn foreign_tx_sign_payload_v1_fogo__should_have_consistent_hash() {
        // Given
        let payload = ForeignTxSignPayload::V1(ForeignTxSignPayloadV1 {
            request: ForeignChainRpcRequest::Fogo(SvmRpcRequest {
                tx_id: SvmTxId([0x77; 64]),
                finality: SvmFinality::Confirmed,
                extractors: [SvmExtractor::InnerInstruction {
                    instruction_index: 0,
                    inner_instruction_index: 1,
                }]
                .into(),
            }),
            values: vec![ExtractedValue::SvmExtractedValue(
                SvmExtractedValue::InnerInstruction(SvmInnerInstruction {
                    program_id: SvmAddress([0x88; 32]),
                    accounts: vec![SvmAddress([0x99; 32])],
                    data: vec![0x01, 0x02, 0x03],
                }),
            )],
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
                extractors: [BitcoinExtractor::BlockHash].into(),
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
                extractors: [StarknetExtractor::BlockHash].into(),
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

    #[test]
    fn foreign_tx_sign_payload_v1__should_produce_different_hashes_for_different_requests() {
        // Given
        let payload_a = ForeignTxSignPayload::V1(ForeignTxSignPayloadV1 {
            request: ForeignChainRpcRequest::Ethereum(EvmRpcRequest {
                tx_id: EvmTxId([0x01; 32]),
                extractors: [EvmExtractor::BlockHash].into(),
                finality: EvmFinality::Finalized,
            }),

            values: vec![ExtractedValue::EvmExtractedValue(
                EvmExtractedValue::BlockHash(Hash256([0xbb; 32])),
            )],
        });
        let payload_b = ForeignTxSignPayload::V1(ForeignTxSignPayloadV1 {
            request: ForeignChainRpcRequest::Ethereum(EvmRpcRequest {
                tx_id: EvmTxId([0x02; 32]),
                extractors: [EvmExtractor::BlockHash].into(),
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

    #[test]
    fn foreign_tx_sign_payload_v2__should_have_consistent_hashes() {
        // Given
        let request = VerifyForeignTransactionRequestV2 {
            request: ForeignChainRpcRequest::Ethereum(EvmRpcRequest {
                tx_id: EvmTxId([0xab; 32]),
                extractors: [EvmExtractor::BlockHash].into(),
                finality: EvmFinality::Finalized,
            }),
            domain_id: DomainId(0),
            expected_values: vec![ExtractedValue::EvmExtractedValue(
                EvmExtractedValue::BlockHash(Hash256([0xef; 32])),
            )],
        };
        let negative = |verdict| ForeignTxVerificationOutcome::Negative { verdict };
        let outcomes = [
            ("verified", ForeignTxVerificationOutcome::Verified {}),
            (
                "transaction_failed",
                negative(ForeignTxVerificationNegativeVerdict::TransactionFailed),
            ),
            (
                "log_index_out_of_bounds",
                negative(ForeignTxVerificationNegativeVerdict::LogIndexOutOfBounds),
            ),
            (
                "transaction_not_found",
                negative(ForeignTxVerificationNegativeVerdict::TransactionNotFound),
            ),
            (
                "account_not_found",
                negative(ForeignTxVerificationNegativeVerdict::AccountNotFound),
            ),
            (
                "non_canonical_block",
                negative(ForeignTxVerificationNegativeVerdict::NonCanonicalBlock),
            ),
            (
                "values_mismatch",
                negative(ForeignTxVerificationNegativeVerdict::ValuesMismatch),
            ),
            (
                "inconclusive",
                ForeignTxVerificationOutcome::Inconclusive {},
            ),
        ];

        // When
        let hashes: BTreeMap<_, _> = outcomes
            .into_iter()
            .map(|(name, outcome)| {
                let payload = ForeignTxSignPayload::V2(ForeignTxSignPayloadV2 {
                    request: request.request.clone(),
                    expected_values_hash: request.expected_values_hash().unwrap(),
                    request_block_height: BlockHeight::new(0x0102_0304_0506_0708),
                    yield_id: YieldId([0xcd; 32]),
                    outcome,
                });
                (name, hex::encode(payload.compute_msg_hash().unwrap().0))
            })
            .collect();

        // Then
        insta::assert_json_snapshot!(hashes);
    }

    #[test]
    fn yield_id__should_serialize_as_hex() {
        // Given
        let yield_id = YieldId([0xcd; 32]);

        // When
        let json = serde_json::to_value(yield_id).unwrap();

        // Then
        assert_eq!(json, json!("cd".repeat(32)));
    }

    #[rstest]
    #[case::verified(ForeignTxVerificationOutcome::Verified {}, json!({"Verified": {}}))]
    #[case::negative(
        ForeignTxVerificationOutcome::Negative {
            verdict: ForeignTxVerificationNegativeVerdict::TransactionNotFound,
        },
        json!({"Negative": {"verdict": "TransactionNotFound"}})
    )]
    #[case::inconclusive(ForeignTxVerificationOutcome::Inconclusive {}, json!({"Inconclusive": {}}))]
    fn foreign_tx_verification_outcome__should_serialize_every_arm_as_an_object(
        #[case] outcome: ForeignTxVerificationOutcome,
        #[case] expected: serde_json::Value,
    ) {
        assert_eq!(serde_json::to_value(outcome).unwrap(), expected);
    }

    #[test]
    fn foreign_tx_sign_payload_v1_ton__should_have_consistent_hash() {
        // Given
        let payload = ForeignTxSignPayload::V1(ForeignTxSignPayloadV1 {
            request: ForeignChainRpcRequest::Ton(TonRpcRequest {
                tx_id: TonTxId([0x99; 32]),
                account: TonAddress {
                    workchain: 0,
                    hash: Hash256([0xaa; 32]),
                },
                finality: TonFinality::MasterchainIncluded,
                extractors: [TonExtractor::Log { message_index: 0 }].into(),
            }),
            values: vec![ExtractedValue::TonExtractedValue(TonExtractedValue::Log(
                TonLog {
                    from_address: TonAddress {
                        workchain: 0,
                        hash: Hash256([0xaa; 32]),
                    },
                    body: TonCellBody::new(vec![0xde, 0xad, 0xbe, 0xef].try_into().unwrap(), 32)
                        .unwrap(),
                    body_refs: vec![Hash256([0x01; 32]), Hash256([0x02; 32])]
                        .try_into()
                        .unwrap(),
                },
            ))],
        });

        // When
        let hash = payload.compute_msg_hash().unwrap();

        // Then
        insta::assert_json_snapshot!(hex::encode(hash.0));
    }

    #[test]
    fn foreign_tx_sign_payload_v1_aptos__should_have_consistent_hash() {
        // Given
        let payload = ForeignTxSignPayload::V1(ForeignTxSignPayloadV1 {
            request: ForeignChainRpcRequest::Aptos(AptosRpcRequest {
                tx_id: AptosTxId([0xcc; 32]),
                finality: AptosFinality::Committed,
                extractors: [AptosExtractor::Event { event_index: 0 }].into(),
            }),
            values: vec![ExtractedValue::AptosExtractedValue(
                AptosExtractedValue::Event(AptosEvent {
                    account_address: AptosAddress([0x00; 32]),
                    sequence_number: 0,
                    type_tag: "0xdeadbeef::omni_bridge::InitTransfer".to_string(),
                    data: "{\"amount\":\"100\"}".to_string(),
                }),
            )],
        });

        // When
        let hash = payload.compute_msg_hash().unwrap();

        // Then
        insta::assert_json_snapshot!(hex::encode(hash.0));
    }

    #[test]
    fn foreign_tx_sign_payload_v1_sui__should_have_consistent_hash() {
        // Given
        let payload = ForeignTxSignPayload::V1(ForeignTxSignPayloadV1 {
            request: ForeignChainRpcRequest::Sui(SuiRpcRequest {
                tx_id: SuiTxId([0xdd; 32]),
                finality: SuiFinality::Checkpointed,
                extractors: [SuiExtractor::Event { event_index: 0 }].into(),
            }),
            values: vec![ExtractedValue::SuiExtractedValue(SuiExtractedValue::Event(
                SuiEvent {
                    package_id: SuiAddress([0x11; 32]),
                    transaction_module: "omni_bridge".to_string(),
                    sender: SuiAddress([0x22; 32]),
                    type_tag: format!("0x{}::omni_bridge::InitTransfer", "11".repeat(32)),
                    bcs: vec![0xde, 0xad, 0xbe, 0xef],
                },
            ))],
        });

        // When
        let hash = payload.compute_msg_hash().unwrap();

        // Then
        insta::assert_json_snapshot!(hex::encode(hash.0));
    }
}
