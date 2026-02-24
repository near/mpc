use crate::{
    foreign_chain::{BuildableForeignChainRequest, ForeignChainRequestBuilder},
    sign::NotSet,
};

use contract_interface::types::{ExtractedValue, Hash256};

// API types
pub use contract_interface::types::{
    EvmExtractedValue, EvmExtractor, EvmFinality, EvmLog, EvmRpcRequest, EvmTxId,
    ForeignChainRpcRequest,
};

/// Type alias with concrete types for when [`AbstractRequest`] is ready to be built
/// as part of the [`ForeignChainRequestBuilder`] builder.
type BuildableAbstractRequest = AbstractRequest<EvmTxId, EvmFinality>;

#[derive(Debug, Clone, derive_more::From, derive_more::Deref)]
pub struct AbstractBlockHash([u8; 32]);

#[derive(Debug, Clone)]
pub struct AbstractRequest<TxId, Finality> {
    tx_id: TxId,
    finality: Finality,

    // Extractors
    expected_block_hash: Option<AbstractBlockHash>,
    expected_logs: Vec<ExpectedLog>,
}

#[derive(Debug, Clone)]
struct ExpectedLog {
    log_index: u64,
    log: EvmLog,
}

// This means the request can be built
impl BuildableForeignChainRequest for BuildableAbstractRequest {}

impl From<BuildableAbstractRequest> for (ForeignChainRpcRequest, Vec<ExtractedValue>) {
    fn from(built_request: BuildableAbstractRequest) -> Self {
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
            expected_values.push(ExtractedValue::EvmExtractedValue(
                EvmExtractedValue::Log(expected_log.log),
            ));
        }

        (
            ForeignChainRpcRequest::Abstract(EvmRpcRequest {
                tx_id: built_request.tx_id,
                finality: built_request.finality,
                extractors,
            }),
            expected_values,
        )
    }
}

impl ForeignChainRequestBuilder<NotSet, NotSet, NotSet> {
    pub fn with_abstract_tx_id(
        self,
        tx_id: impl Into<EvmTxId>,
    ) -> ForeignChainRequestBuilder<AbstractRequest<EvmTxId, NotSet>, NotSet, NotSet> {
        ForeignChainRequestBuilder {
            request: AbstractRequest {
                tx_id: tx_id.into(),
                finality: NotSet,
                expected_block_hash: None,
                expected_logs: vec![],
            },
            derivation_path: self.derivation_path,
            domain_id: self.domain_id,
            payload_version: self.payload_version,
        }
    }
}

impl ForeignChainRequestBuilder<AbstractRequest<EvmTxId, NotSet>, NotSet, NotSet> {
    pub fn with_finality(
        self,
        finality: impl Into<EvmFinality>,
    ) -> ForeignChainRequestBuilder<BuildableAbstractRequest, NotSet, NotSet> {
        ForeignChainRequestBuilder {
            request: AbstractRequest {
                finality: finality.into(),
                tx_id: self.request.tx_id,
                expected_block_hash: self.request.expected_block_hash,
                expected_logs: self.request.expected_logs,
            },
            derivation_path: self.derivation_path,
            domain_id: self.domain_id,
            payload_version: self.payload_version,
        }
    }
}

impl ForeignChainRequestBuilder<BuildableAbstractRequest, NotSet, NotSet> {
    pub fn with_expected_block_hash(self, block_hash: impl Into<AbstractBlockHash>) -> Self {
        ForeignChainRequestBuilder {
            request: AbstractRequest {
                tx_id: self.request.tx_id,
                finality: self.request.finality,
                expected_block_hash: Some(block_hash.into()),
                expected_logs: self.request.expected_logs,
            },
            derivation_path: self.derivation_path,
            domain_id: self.domain_id,
            payload_version: self.payload_version,
        }
    }

    pub fn with_expected_log(mut self, log_index: u64, log: EvmLog) -> Self {
        self.request.expected_logs.push(ExpectedLog { log_index, log });
        self
    }
}

#[cfg(test)]
mod test {
    use contract_interface::types::{DomainId, Hash160, VerifyForeignTransactionRequestArgs};

    use crate::foreign_chain::{DEFAULT_PAYLOAD_VERSION, ForeignChainSignatureVerifier};

    use super::*;

    #[test]
    fn with_abstract_tx_id_sets_expected_value() {
        // given
        let tx_id = EvmTxId::from([123; 32]);

        // when
        let builder = ForeignChainRequestBuilder::new().with_abstract_tx_id(tx_id.clone());

        // then
        assert_eq!(builder.request.tx_id, tx_id);
    }

    #[test]
    fn with_finality_sets_expected_value() {
        // given
        let tx_id = EvmTxId::from([123; 32]);

        // when
        let builder = ForeignChainRequestBuilder::new()
            .with_abstract_tx_id(tx_id)
            .with_finality(EvmFinality::Finalized);

        // then
        assert_eq!(builder.request.finality, EvmFinality::Finalized);
    }

    #[test]
    fn with_expected_block_hash_sets_expected_value() {
        // given
        let tx_id = EvmTxId::from([123; 32]);
        let expected_hash = [9; 32];

        // when
        let builder = ForeignChainRequestBuilder::new()
            .with_abstract_tx_id(tx_id)
            .with_finality(EvmFinality::Finalized)
            .with_expected_block_hash(expected_hash);

        // then
        assert_eq!(
            builder.request.expected_block_hash.as_deref(),
            Some(&expected_hash)
        );
    }

    #[test]
    fn with_expected_log_sets_expected_value() {
        // given
        let tx_id = EvmTxId::from([123; 32]);
        let log = make_test_log(3);

        // when
        let builder = ForeignChainRequestBuilder::new()
            .with_abstract_tx_id(tx_id)
            .with_finality(EvmFinality::Finalized)
            .with_expected_log(3, log.clone());

        // then
        assert_eq!(builder.request.expected_logs.len(), 1);
        assert_eq!(builder.request.expected_logs[0].log_index, 3);
        assert_eq!(builder.request.expected_logs[0].log, log);
    }

    #[test]
    fn with_expected_log_can_add_multiple_logs() {
        // given
        let tx_id = EvmTxId::from([123; 32]);
        let log_a = make_test_log(1);
        let log_b = make_test_log(2);

        // when
        let builder = ForeignChainRequestBuilder::new()
            .with_abstract_tx_id(tx_id)
            .with_finality(EvmFinality::Finalized)
            .with_expected_log(1, log_a)
            .with_expected_log(2, log_b);

        // then
        assert_eq!(builder.request.expected_logs.len(), 2);
    }

    #[test]
    fn build_produces_correct_request_args() {
        // given
        let path = "test_path".to_string();
        let domain_id = DomainId::from(2);
        let tx_id = EvmTxId::from([123; 32]);
        let expected_hash = [9; 32];
        let log = make_test_log(5);

        // when
        let (_verifier, request_args) = ForeignChainRequestBuilder::new()
            .with_abstract_tx_id(tx_id.clone())
            .with_finality(EvmFinality::Finalized)
            .with_expected_block_hash(expected_hash)
            .with_expected_log(5, log.clone())
            .with_derivation_path(path.clone())
            .with_domain_id(domain_id)
            .build();

        // then
        let expected = VerifyForeignTransactionRequestArgs {
            request: ForeignChainRpcRequest::Abstract(EvmRpcRequest {
                tx_id,
                finality: EvmFinality::Finalized,
                extractors: vec![
                    EvmExtractor::BlockHash,
                    EvmExtractor::Log { log_index: 5 },
                ],
            }),
            derivation_path: path,
            domain_id,
            payload_version: DEFAULT_PAYLOAD_VERSION,
        };

        assert_eq!(request_args, expected);
    }

    #[test]
    fn build_produces_correct_verifier() {
        // given
        let tx_id = EvmTxId::from([123; 32]);
        let expected_hash = [9; 32];
        let log = make_test_log(5);

        // when
        let (verifier, _request_args) = ForeignChainRequestBuilder::new()
            .with_abstract_tx_id(tx_id.clone())
            .with_finality(EvmFinality::Finalized)
            .with_expected_block_hash(expected_hash)
            .with_expected_log(5, log.clone())
            .with_derivation_path("path".to_string())
            .with_domain_id(DomainId::from(1))
            .build();

        // then
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
                extractors: vec![
                    EvmExtractor::BlockHash,
                    EvmExtractor::Log { log_index: 5 },
                ],
            }),
        };

        assert_eq!(verifier, expected_verifier);
    }

    #[test]
    fn verifier_request_matches_request_args() {
        // given
        let (verifier, request_args) = ForeignChainRequestBuilder::new()
            .with_abstract_tx_id(EvmTxId::from([123; 32]))
            .with_finality(EvmFinality::Safe)
            .with_derivation_path("path".to_string())
            .with_domain_id(DomainId::from(1))
            // when
            .build();

        // then
        assert_eq!(verifier.request, request_args.request);
    }

    #[test]
    fn build_without_extractors_produces_empty_extractors() {
        // given / when
        let (_verifier, request_args) = ForeignChainRequestBuilder::new()
            .with_abstract_tx_id(EvmTxId::from([42; 32]))
            .with_finality(EvmFinality::Latest)
            .with_derivation_path("path".to_string())
            .with_domain_id(DomainId::from(1))
            .build();

        // then
        match &request_args.request {
            ForeignChainRpcRequest::Abstract(req) => {
                assert!(req.extractors.is_empty());
            }
            _ => panic!("Expected Abstract request"),
        }
    }

    fn make_test_log(log_index: u64) -> EvmLog {
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
}
