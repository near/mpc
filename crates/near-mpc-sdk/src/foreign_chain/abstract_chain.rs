use crate::{
    foreign_chain::{
        ForeignChainRequestBuilder,
        evm::{EvmChainVariant, EvmRequest},
    },
    sign::NotSet,
};

pub use crate::foreign_chain::evm::{
    EvmExtractedValue, EvmExtractor, EvmFinality, EvmLog, EvmRpcRequest, EvmTxId,
    ForeignChainRpcRequest,
};
pub use crate::foreign_chain::evm::EvmBlockHash as AbstractBlockHash;

#[derive(Debug, Clone)]
pub struct Abstract;

impl EvmChainVariant for Abstract {
    fn wrap(request: EvmRpcRequest) -> ForeignChainRpcRequest {
        ForeignChainRpcRequest::Abstract(request)
    }
}

pub type AbstractRequest<TxId, Finality> = EvmRequest<Abstract, TxId, Finality>;

impl ForeignChainRequestBuilder<AbstractRequest<NotSet, NotSet>, NotSet> {
    pub fn new_abstract() -> Self {
        Self {
            request: EvmRequest {
                tx_id: NotSet,
                finality: NotSet,
                expected_block_hash: None,
                expected_logs: vec![],
                _chain: std::marker::PhantomData,
            },
            domain_id: NotSet,
        }
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use near_mpc_contract_interface::types::{
        DomainId, Hash160, Hash256, VerifyForeignTransactionRequestArgs,
    };

    use crate::foreign_chain::{DEFAULT_PAYLOAD_VERSION, ForeignChainSignatureVerifier};
    use near_mpc_contract_interface::types::ExtractedValue;

    use super::*;

    #[test]
    fn with_tx_id_sets_expected_value() {
        // given
        let tx_id = EvmTxId::from([123; 32]);

        // when
        let builder = ForeignChainRequestBuilder::new_abstract().with_tx_id(tx_id.clone());

        // then
        assert_eq!(builder.request.tx_id, tx_id);
    }

    #[test]
    fn with_finality_sets_expected_value() {
        // given
        let tx_id = EvmTxId::from([123; 32]);

        // when
        let builder = ForeignChainRequestBuilder::new_abstract()
            .with_tx_id(tx_id)
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
        let builder = ForeignChainRequestBuilder::new_abstract()
            .with_tx_id(tx_id)
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
        let log = test_evm_log(3);

        // when
        let builder = ForeignChainRequestBuilder::new_abstract()
            .with_tx_id(tx_id)
            .with_finality(EvmFinality::Finalized)
            .with_expected_log(3, log.clone());

        // then
        assert_eq!(builder.request.expected_logs.len(), 1);
        assert_eq!(builder.request.expected_logs[0].log_index, 3);
        assert_eq!(builder.request.expected_logs[0].log, log);
    }

    #[test]
    fn with_multiple_expected_logs_produces_correct_extractors_and_values() {
        // given
        let tx_id = EvmTxId::from([123; 32]);
        let log_a = test_evm_log(1);
        let log_b = test_evm_log(2);

        // when
        let (verifier, request_args) = ForeignChainRequestBuilder::new_abstract()
            .with_tx_id(tx_id.clone())
            .with_finality(EvmFinality::Finalized)
            .with_expected_log(1, log_a.clone())
            .with_expected_log(2, log_b.clone())
            .with_domain_id(DomainId::from(1))
            .build();

        // then
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
        // given
        let domain_id = DomainId::from(2);
        let tx_id = EvmTxId::from([123; 32]);
        let expected_hash = [9; 32];
        let log = test_evm_log(5);

        // when
        let (_verifier, request_args) = ForeignChainRequestBuilder::new_abstract()
            .with_tx_id(tx_id.clone())
            .with_finality(EvmFinality::Finalized)
            .with_expected_block_hash(expected_hash)
            .with_expected_log(5, log.clone())
            .with_domain_id(domain_id)
            .build();

        // then
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
        // given
        let tx_id = EvmTxId::from([123; 32]);
        let expected_hash = [9; 32];
        let log = test_evm_log(5);

        // when
        let (verifier, _request_args) = ForeignChainRequestBuilder::new_abstract()
            .with_tx_id(tx_id.clone())
            .with_finality(EvmFinality::Finalized)
            .with_expected_block_hash(expected_hash)
            .with_expected_log(5, log.clone())
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
                extractors: vec![EvmExtractor::BlockHash, EvmExtractor::Log { log_index: 5 }],
            }),
        };

        assert_eq!(verifier, expected_verifier);
    }

    #[test]
    fn verifier_request_matches_request_args() {
        // given
        let (verifier, request_args) = ForeignChainRequestBuilder::new_abstract()
            .with_tx_id(EvmTxId::from([123; 32]))
            .with_finality(EvmFinality::Safe)
            .with_domain_id(DomainId::from(1))
            // when
            .build();

        // then
        assert_eq!(verifier.request, request_args.request);
    }

    #[test]
    fn build_without_extractors_produces_empty_extractors() {
        // given / when
        let (_verifier, request_args) = ForeignChainRequestBuilder::new_abstract()
            .with_tx_id(EvmTxId::from([42; 32]))
            .with_finality(EvmFinality::Latest)
            .with_domain_id(DomainId::from(1))
            .build();

        // then
        assert_matches!(&request_args.request, ForeignChainRpcRequest::Abstract(rpc_request) => {
            assert_eq!(rpc_request.extractors, vec![]);
        });
    }

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
}
