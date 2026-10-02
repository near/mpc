use crate::{
    foreign_chain::{ForeignChainRequestBuilder, ForeignChainRpcRequestWithExpectations},
    sign::NotSet,
};

use near_mpc_bounded_collections::BoundedVecOutOfBounds;
use near_mpc_contract_interface::types::ExtractedValue;

pub use near_mpc_contract_interface::types::{
    ForeignChainRpcRequest, SvmAccount, SvmAddress, SvmExtractedValue, SvmExtractor, SvmFinality,
    SvmInnerInstruction, SvmRpcRequest, SvmTxId,
};

pub trait SvmChainVariant {
    fn wrap(request: SvmRpcRequest) -> ForeignChainRpcRequest;
}

pub type BuildableSvmRequest<Chain> = SvmRequest<Chain, SvmTxId, SvmFinality>;

#[derive(Debug, Clone)]
pub struct SvmRequest<Chain, TxId, Finality> {
    pub(crate) tx_id: TxId,
    pub(crate) finality: Finality,
    pub(crate) expected_values: Vec<ExpectedSvmValue>,
    pub(crate) _chain: std::marker::PhantomData<Chain>,
}

/// An extractor paired with the value the caller expects it to yield. Kept in
/// insertion order because the order of extractors is part of the signed payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedSvmValue {
    pub(crate) extractor: SvmExtractor,
    pub(crate) value: SvmExtractedValue,
}

impl<Chain: SvmChainVariant> TryFrom<BuildableSvmRequest<Chain>>
    for ForeignChainRpcRequestWithExpectations
{
    type Error = BoundedVecOutOfBounds;

    fn try_from(built_request: BuildableSvmRequest<Chain>) -> Result<Self, Self::Error> {
        let (extractors, expected_values): (Vec<_>, Vec<_>) = built_request
            .expected_values
            .into_iter()
            .map(|expected| {
                (
                    expected.extractor,
                    ExtractedValue::SvmExtractedValue(expected.value),
                )
            })
            .unzip();

        Ok(ForeignChainRpcRequestWithExpectations {
            request: Chain::wrap(SvmRpcRequest {
                tx_id: built_request.tx_id,
                finality: built_request.finality,
                extractors: extractors.try_into()?,
            }),
            expected_values,
        })
    }
}

impl<Chain> ForeignChainRequestBuilder<SvmRequest<Chain, NotSet, NotSet>, NotSet> {
    pub fn with_tx_id(
        self,
        tx_id: impl Into<SvmTxId>,
    ) -> ForeignChainRequestBuilder<SvmRequest<Chain, SvmTxId, NotSet>, NotSet> {
        ForeignChainRequestBuilder {
            request: SvmRequest {
                tx_id: tx_id.into(),
                finality: NotSet,
                expected_values: vec![],
                _chain: std::marker::PhantomData,
            },
            domain_id: self.domain_id,
        }
    }
}

impl<Chain> ForeignChainRequestBuilder<SvmRequest<Chain, SvmTxId, NotSet>, NotSet> {
    pub fn with_finality(
        self,
        finality: impl Into<SvmFinality>,
    ) -> ForeignChainRequestBuilder<BuildableSvmRequest<Chain>, NotSet> {
        ForeignChainRequestBuilder {
            request: SvmRequest {
                tx_id: self.request.tx_id,
                finality: finality.into(),
                expected_values: self.request.expected_values,
                _chain: std::marker::PhantomData,
            },
            domain_id: self.domain_id,
        }
    }
}

impl<Chain> ForeignChainRequestBuilder<BuildableSvmRequest<Chain>, NotSet> {
    /// Expects the inner instruction at `inner_instruction_index` of the top-level
    /// instruction at `instruction_index` to equal `inner_instruction`.
    pub fn with_expected_inner_instruction(
        mut self,
        instruction_index: u64,
        inner_instruction_index: u64,
        inner_instruction: SvmInnerInstruction,
    ) -> Self {
        self.request.expected_values.push(ExpectedSvmValue {
            extractor: SvmExtractor::InnerInstruction {
                instruction_index,
                inner_instruction_index,
            },
            value: SvmExtractedValue::InnerInstruction(inner_instruction),
        });
        self
    }

    /// Expects the account at `pubkey` to hold `account` once the transaction reaches
    /// the requested finality.
    pub fn with_expected_account_state(
        mut self,
        pubkey: impl Into<SvmAddress>,
        account: SvmAccount,
    ) -> Self {
        self.request.expected_values.push(ExpectedSvmValue {
            extractor: SvmExtractor::AccountState {
                pubkey: pubkey.into(),
            },
            value: SvmExtractedValue::AccountState(account),
        });
        self
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod test {
    use assert_matches::assert_matches;
    use near_mpc_contract_interface::types::{DomainId, VerifyForeignTransactionRequestArgs};

    use crate::foreign_chain::{
        DEFAULT_PAYLOAD_VERSION, ForeignChainRequestBuilder, ForeignChainSignatureVerifier,
        ForeignTxSignPayload, ForeignTxSignPayloadV1,
    };

    use super::*;

    fn test_inner_instruction(seed: u8) -> SvmInnerInstruction {
        SvmInnerInstruction {
            program_id: SvmAddress([seed; 32]),
            accounts: vec![SvmAddress([seed + 1; 32]), SvmAddress([seed + 2; 32])],
            data: vec![seed, seed, seed],
        }
    }

    fn test_account(seed: u8) -> SvmAccount {
        SvmAccount {
            owner: SvmAddress([seed; 32]),
            data: vec![seed, seed],
        }
    }

    #[test]
    fn build__should_preserve_extractor_insertion_order() {
        // Given
        let inner_instruction = test_inner_instruction(3);
        let account = test_account(4);
        let pubkey = [7; 32];

        // When
        let (verifier, request_args) = ForeignChainRequestBuilder::new_solana()
            .with_tx_id(SvmTxId::from([123; 64]))
            .with_finality(SvmFinality::Finalized)
            .with_expected_account_state(pubkey, account.clone())
            .with_expected_inner_instruction(0, 1, inner_instruction.clone())
            .with_domain_id(DomainId::from(1))
            .build()
            .unwrap();

        // Then
        assert_matches!(&request_args.request, ForeignChainRpcRequest::Solana(rpc_request) => {
            assert_eq!(
                rpc_request.extractors.to_vec(),
                vec![
                    SvmExtractor::AccountState { pubkey: SvmAddress(pubkey) },
                    SvmExtractor::InnerInstruction {
                        instruction_index: 0,
                        inner_instruction_index: 1,
                    },
                ]
            );
        });
        assert_eq!(
            verifier.expected_extracted_values,
            vec![
                ExtractedValue::SvmExtractedValue(SvmExtractedValue::AccountState(account)),
                ExtractedValue::SvmExtractedValue(SvmExtractedValue::InnerInstruction(
                    inner_instruction
                )),
            ]
        );
    }

    #[test]
    fn build__should_produce_correct_request_args() {
        // Given
        let domain_id = DomainId::from(2);
        let tx_id = SvmTxId::from([123; 64]);
        let inner_instruction = test_inner_instruction(3);
        let account = test_account(4);
        let pubkey = [7; 32];

        // When
        let (_verifier, request_args) = ForeignChainRequestBuilder::new_solana()
            .with_tx_id(tx_id.clone())
            .with_finality(SvmFinality::Finalized)
            .with_expected_inner_instruction(2, 0, inner_instruction.clone())
            .with_expected_account_state(pubkey, account.clone())
            .with_domain_id(domain_id)
            .build()
            .unwrap();

        // Then
        let expected_request = ForeignChainRpcRequest::Solana(SvmRpcRequest {
            tx_id,
            finality: SvmFinality::Finalized,
            extractors: [
                SvmExtractor::InnerInstruction {
                    instruction_index: 2,
                    inner_instruction_index: 0,
                },
                SvmExtractor::AccountState {
                    pubkey: SvmAddress(pubkey),
                },
            ]
            .into(),
        });
        let expected_payload_hash = ForeignTxSignPayload::V1(ForeignTxSignPayloadV1 {
            request: expected_request.clone(),
            values: vec![
                ExtractedValue::SvmExtractedValue(SvmExtractedValue::InnerInstruction(
                    inner_instruction,
                )),
                ExtractedValue::SvmExtractedValue(SvmExtractedValue::AccountState(account)),
            ],
        })
        .compute_msg_hash()
        .unwrap();
        let expected = VerifyForeignTransactionRequestArgs {
            request: expected_request,
            domain_id,
            payload_version: DEFAULT_PAYLOAD_VERSION,
            expected_payload_hash: Some(expected_payload_hash),
        };

        assert_eq!(request_args, expected);
    }

    #[test]
    fn build__should_produce_correct_verifier() {
        // Given
        let tx_id = SvmTxId::from([123; 64]);
        let inner_instruction = test_inner_instruction(3);

        // When
        let (verifier, _request_args) = ForeignChainRequestBuilder::new_solana()
            .with_tx_id(tx_id.clone())
            .with_finality(SvmFinality::Confirmed)
            .with_expected_inner_instruction(1, 1, inner_instruction.clone())
            .with_domain_id(DomainId::from(1))
            .build()
            .unwrap();

        // Then
        let expected_verifier = ForeignChainSignatureVerifier {
            expected_extracted_values: vec![ExtractedValue::SvmExtractedValue(
                SvmExtractedValue::InnerInstruction(inner_instruction),
            )],
            request: ForeignChainRpcRequest::Solana(SvmRpcRequest {
                tx_id,
                finality: SvmFinality::Confirmed,
                extractors: [SvmExtractor::InnerInstruction {
                    instruction_index: 1,
                    inner_instruction_index: 1,
                }]
                .into(),
            }),
        };

        assert_eq!(verifier, expected_verifier);
    }

    #[test]
    fn build__should_give_verifier_and_request_args_the_same_request() {
        // Given
        let builder = ForeignChainRequestBuilder::new_solana()
            .with_tx_id(SvmTxId::from([123; 64]))
            .with_finality(SvmFinality::Finalized)
            .with_expected_account_state([7; 32], test_account(4))
            .with_domain_id(DomainId::from(1));

        // When
        let (verifier, request_args) = builder.build().unwrap();

        // Then
        assert_eq!(verifier.request, request_args.request);
    }

    #[test]
    fn build__should_produce_empty_extractors_without_expectations() {
        // Given
        let builder = ForeignChainRequestBuilder::new_solana()
            .with_tx_id(SvmTxId::from([42; 64]))
            .with_finality(SvmFinality::Confirmed)
            .with_domain_id(DomainId::from(1));

        // When
        let (_verifier, request_args) = builder.build().unwrap();

        // Then
        assert_matches!(&request_args.request, ForeignChainRpcRequest::Solana(rpc_request) => {
            assert!(rpc_request.extractors.is_empty());
        });
    }
}
