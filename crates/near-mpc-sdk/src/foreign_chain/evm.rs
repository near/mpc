use crate::{
    foreign_chain::{ForeignChainRequestBuilder, ForeignChainRpcRequestWithExpectations},
    sign::NotSet,
};

use near_mpc_contract_interface::types::{ExtractedValue, Hash256};

pub use near_mpc_contract_interface::types::{
    EvmExtractedValue, EvmExtractor, EvmFinality, EvmLog, EvmRpcRequest, EvmTxId,
    ForeignChainRpcRequest,
};

/// Trait that maps an [`EvmRpcRequest`] to the correct [`ForeignChainRpcRequest`] variant.
pub trait EvmChainVariant {
    fn wrap(request: EvmRpcRequest) -> ForeignChainRpcRequest;
}

/// Type alias with concrete types for when the request is ready to be built.
pub type BuildableEvmRequest<Chain> = EvmRequest<Chain, EvmTxId, EvmFinality>;

#[derive(Debug, Clone, derive_more::From, derive_more::Deref)]
pub struct EvmBlockHash([u8; 32]);

#[derive(Debug, Clone)]
pub struct EvmRequest<Chain, TxId, Finality> {
    pub(crate) tx_id: TxId,
    pub(crate) finality: Finality,
    pub(crate) expected_block_hash: Option<EvmBlockHash>,
    pub(crate) expected_logs: Vec<ExpectedLog>,
    pub(crate) _chain: std::marker::PhantomData<Chain>,
}

#[derive(Debug, Clone)]
pub struct ExpectedLog {
    pub(crate) log_index: u64,
    pub(crate) log: EvmLog,
}

impl<Chain: EvmChainVariant> From<BuildableEvmRequest<Chain>>
    for ForeignChainRpcRequestWithExpectations
{
    fn from(built_request: BuildableEvmRequest<Chain>) -> Self {
        let mut extractors = vec![];
        let mut expected_values = vec![];

        if let Some(expected_block_hash) = built_request.expected_block_hash {
            extractors.push(EvmExtractor::BlockHash);
            expected_values.push(ExtractedValue::EvmExtractedValue(
                EvmExtractedValue::BlockHash(Hash256::from(*expected_block_hash)),
            ));
        }

        for expected_log in built_request.expected_logs {
            extractors.push(EvmExtractor::Log {
                log_index: expected_log.log_index,
            });
            expected_values.push(ExtractedValue::EvmExtractedValue(EvmExtractedValue::Log(
                expected_log.log,
            )));
        }

        ForeignChainRpcRequestWithExpectations {
            request: Chain::wrap(EvmRpcRequest {
                tx_id: built_request.tx_id,
                finality: built_request.finality,
                extractors,
            }),
            expected_values,
        }
    }
}

impl<Chain> ForeignChainRequestBuilder<EvmRequest<Chain, NotSet, NotSet>, NotSet> {
    pub fn with_tx_id(
        self,
        tx_id: impl Into<EvmTxId>,
    ) -> ForeignChainRequestBuilder<EvmRequest<Chain, EvmTxId, NotSet>, NotSet> {
        ForeignChainRequestBuilder {
            request: EvmRequest {
                tx_id: tx_id.into(),
                finality: NotSet,
                expected_block_hash: None,
                expected_logs: vec![],
                _chain: std::marker::PhantomData,
            },
            domain_id: self.domain_id,
        }
    }
}

impl<Chain> ForeignChainRequestBuilder<EvmRequest<Chain, EvmTxId, NotSet>, NotSet> {
    pub fn with_finality(
        self,
        finality: impl Into<EvmFinality>,
    ) -> ForeignChainRequestBuilder<BuildableEvmRequest<Chain>, NotSet> {
        ForeignChainRequestBuilder {
            request: EvmRequest {
                finality: finality.into(),
                tx_id: self.request.tx_id,
                expected_block_hash: self.request.expected_block_hash,
                expected_logs: self.request.expected_logs,
                _chain: std::marker::PhantomData,
            },
            domain_id: self.domain_id,
        }
    }
}

impl<Chain> ForeignChainRequestBuilder<BuildableEvmRequest<Chain>, NotSet> {
    pub fn with_expected_block_hash(self, block_hash: impl Into<EvmBlockHash>) -> Self {
        ForeignChainRequestBuilder {
            request: EvmRequest {
                tx_id: self.request.tx_id,
                finality: self.request.finality,
                expected_block_hash: Some(block_hash.into()),
                expected_logs: self.request.expected_logs,
                _chain: std::marker::PhantomData,
            },
            domain_id: self.domain_id,
        }
    }

    pub fn with_expected_log(mut self, log_index: u64, log: EvmLog) -> Self {
        self.request
            .expected_logs
            .push(ExpectedLog { log_index, log });
        self
    }
}

/// Tests for the generic EVM builder logic. Uses Abstract as the representative chain
/// since the builder is generic over `Chain` — chain-specific variant tests live in each
/// chain module.
#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use near_mpc_contract_interface::types::{
        DomainId, Hash160, Hash256, VerifyForeignTransactionRequestArgs,
    };

    use crate::foreign_chain::ForeignChainSignatureVerifier;
    use crate::foreign_chain::{DEFAULT_PAYLOAD_VERSION, ForeignChainRequestBuilder};
    use near_mpc_contract_interface::types::ExtractedValue;

    use super::*;

    fn test_evm_log(log_index: u64) -> EvmLog {
        EvmLog {
            removed: false,
            log_index,
            transaction_index: 0,
            transaction_hash: Hash256::from([1; 32]),
            block_hash: Hash256::from([2; 32]),
            block_number: 100,
            address: Hash160::from([3; 20]),
            data: "0x".to_string(),
            topics: vec![],
        }
    }

    #[test]
    fn with_tx_id_sets_expected_value() {
        let tx_id = EvmTxId::from([123; 32]);

        let builder = ForeignChainRequestBuilder::new_abstract().with_tx_id(tx_id.clone());

        assert_eq!(builder.request.tx_id, tx_id);
    }

    #[test]
    fn with_finality_sets_expected_value() {
        let tx_id = EvmTxId::from([123; 32]);

        let builder = ForeignChainRequestBuilder::new_abstract()
            .with_tx_id(tx_id)
            .with_finality(EvmFinality::Finalized);

        assert_eq!(builder.request.finality, EvmFinality::Finalized);
    }

    #[test]
    fn with_expected_block_hash_sets_expected_value() {
        let tx_id = EvmTxId::from([123; 32]);
        let expected_hash = [9; 32];

        let builder = ForeignChainRequestBuilder::new_abstract()
            .with_tx_id(tx_id)
            .with_finality(EvmFinality::Finalized)
            .with_expected_block_hash(expected_hash);

        assert_eq!(
            builder.request.expected_block_hash.as_deref(),
            Some(&expected_hash)
        );
    }

    #[test]
    fn with_expected_log_sets_expected_value() {
        let tx_id = EvmTxId::from([123; 32]);
        let log = test_evm_log(3);

        let builder = ForeignChainRequestBuilder::new_abstract()
            .with_tx_id(tx_id)
            .with_finality(EvmFinality::Finalized)
            .with_expected_log(3, log.clone());

        assert_eq!(builder.request.expected_logs.len(), 1);
        assert_eq!(builder.request.expected_logs[0].log_index, 3);
        assert_eq!(builder.request.expected_logs[0].log, log);
    }

    #[test]
    fn with_multiple_expected_logs_produces_correct_extractors_and_values() {
        let tx_id = EvmTxId::from([123; 32]);
        let log_a = test_evm_log(1);
        let log_b = test_evm_log(2);

        let (verifier, request_args) = ForeignChainRequestBuilder::new_abstract()
            .with_tx_id(tx_id.clone())
            .with_finality(EvmFinality::Finalized)
            .with_expected_log(1, log_a.clone())
            .with_expected_log(2, log_b.clone())
            .with_domain_id(DomainId::from(1))
            .build();

        assert_matches!(&request_args.request, ForeignChainRpcRequest::Abstract(rpc_request) => {
            assert_eq!(
                rpc_request.extractors,
                vec![
                    EvmExtractor::Log { log_index: 1 },
                    EvmExtractor::Log { log_index: 2 },
                ]
            );
        });

        assert_eq!(
            verifier.expected_extracted_values,
            vec![
                ExtractedValue::EvmExtractedValue(EvmExtractedValue::Log(log_a)),
                ExtractedValue::EvmExtractedValue(EvmExtractedValue::Log(log_b)),
            ]
        );
    }

    #[test]
    fn build_produces_correct_request_args() {
        let domain_id = DomainId::from(2);
        let tx_id = EvmTxId::from([123; 32]);
        let expected_hash = [9; 32];
        let log = test_evm_log(5);

        let (_verifier, request_args) = ForeignChainRequestBuilder::new_abstract()
            .with_tx_id(tx_id.clone())
            .with_finality(EvmFinality::Finalized)
            .with_expected_block_hash(expected_hash)
            .with_expected_log(5, log.clone())
            .with_domain_id(domain_id)
            .build();

        let expected = VerifyForeignTransactionRequestArgs {
            request: ForeignChainRpcRequest::Abstract(EvmRpcRequest {
                tx_id,
                finality: EvmFinality::Finalized,
                extractors: vec![EvmExtractor::BlockHash, EvmExtractor::Log { log_index: 5 }],
            }),
            domain_id,
            payload_version: DEFAULT_PAYLOAD_VERSION,
        };

        assert_eq!(request_args, expected);
    }

    #[test]
    fn build_produces_correct_verifier() {
        let tx_id = EvmTxId::from([123; 32]);
        let expected_hash = [9; 32];
        let log = test_evm_log(5);

        let (verifier, _request_args) = ForeignChainRequestBuilder::new_abstract()
            .with_tx_id(tx_id.clone())
            .with_finality(EvmFinality::Finalized)
            .with_expected_block_hash(expected_hash)
            .with_expected_log(5, log.clone())
            .with_domain_id(DomainId::from(1))
            .build();

        let expected_verifier = ForeignChainSignatureVerifier {
            expected_extracted_values: vec![
                ExtractedValue::EvmExtractedValue(EvmExtractedValue::BlockHash(
                    expected_hash.into(),
                )),
                ExtractedValue::EvmExtractedValue(EvmExtractedValue::Log(log)),
            ],
            request: ForeignChainRpcRequest::Abstract(EvmRpcRequest {
                tx_id,
                finality: EvmFinality::Finalized,
                extractors: vec![EvmExtractor::BlockHash, EvmExtractor::Log { log_index: 5 }],
            }),
        };

        assert_eq!(verifier, expected_verifier);
    }

    #[test]
    fn verifier_request_matches_request_args() {
        let (verifier, request_args) = ForeignChainRequestBuilder::new_abstract()
            .with_tx_id(EvmTxId::from([123; 32]))
            .with_finality(EvmFinality::Safe)
            .with_domain_id(DomainId::from(1))
            .build();

        assert_eq!(verifier.request, request_args.request);
    }

    #[test]
    fn build_without_extractors_produces_empty_extractors() {
        let (_verifier, request_args) = ForeignChainRequestBuilder::new_abstract()
            .with_tx_id(EvmTxId::from([42; 32]))
            .with_finality(EvmFinality::Latest)
            .with_domain_id(DomainId::from(1))
            .build();

        assert_matches!(&request_args.request, ForeignChainRpcRequest::Abstract(rpc_request) => {
            assert_eq!(rpc_request.extractors, vec![]);
        });
    }
}
