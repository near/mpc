use crate::{
    foreign_chain::{ForeignChainRequestBuilder, ForeignChainRpcRequestWithExpectations},
    sign::NotSet,
};

use contract_interface::types::ExtractedValue;

// API types
pub use contract_interface::types::{
    ForeignChainRpcRequest, StarknetExtractedValue, StarknetExtractor, StarknetFelt,
    StarknetFinality, StarknetRpcRequest, StarknetTxId,
};

/// Type alias with concrete types for when [`StarknetRequest`] is ready to be built
/// as part of the [`ForeignChainRequestBuilder`] builder.
type BuildableStarknetRequest = StarknetRequest<StarknetTxId, StarknetFinality>;

#[derive(Debug, Clone, derive_more::From, derive_more::Deref)]
pub struct StarknetBlockHash([u8; 32]);

#[derive(Debug, Clone)]
pub struct StarknetRequest<TxId, Finality> {
    tx_id: TxId,
    finality: Finality,

    // Extractors
    expected_block_hash: Option<StarknetBlockHash>,
}

impl From<BuildableStarknetRequest> for ForeignChainRpcRequestWithExpectations {
    fn from(built_request: BuildableStarknetRequest) -> Self {
        let mut extractors = vec![];
        let mut expected_values = vec![];

        if let Some(expected_block_hash) = built_request.expected_block_hash {
            extractors.push(StarknetExtractor::BlockHash);
            expected_values.push(ExtractedValue::StarknetExtractedValue(
                StarknetExtractedValue::BlockHash(StarknetFelt(*expected_block_hash)),
            ));
        }

        ForeignChainRpcRequestWithExpectations {
            request: ForeignChainRpcRequest::Starknet(StarknetRpcRequest {
                tx_id: built_request.tx_id,
                finality: built_request.finality,
                extractors,
            }),
            expected_values,
        }
    }
}

impl ForeignChainRequestBuilder<NotSet, NotSet, NotSet> {
    pub fn with_starknet_tx_id(
        self,
        tx_id: impl Into<StarknetTxId>,
    ) -> ForeignChainRequestBuilder<StarknetRequest<StarknetTxId, NotSet>, NotSet, NotSet> {
        ForeignChainRequestBuilder {
            request: StarknetRequest {
                tx_id: tx_id.into(),
                finality: NotSet,
                expected_block_hash: None,
            },
            derivation_path: self.derivation_path,
            domain_id: self.domain_id,
            payload_version: self.payload_version,
        }
    }
}

impl ForeignChainRequestBuilder<StarknetRequest<StarknetTxId, NotSet>, NotSet, NotSet> {
    pub fn with_finality(
        self,
        finality: impl Into<StarknetFinality>,
    ) -> ForeignChainRequestBuilder<BuildableStarknetRequest, NotSet, NotSet> {
        ForeignChainRequestBuilder {
            request: StarknetRequest {
                finality: finality.into(),
                tx_id: self.request.tx_id,
                expected_block_hash: self.request.expected_block_hash,
            },
            derivation_path: self.derivation_path,
            domain_id: self.domain_id,
            payload_version: self.payload_version,
        }
    }
}

impl ForeignChainRequestBuilder<BuildableStarknetRequest, NotSet, NotSet> {
    pub fn with_expected_block_hash(self, block_hash: impl Into<StarknetBlockHash>) -> Self {
        ForeignChainRequestBuilder {
            request: StarknetRequest {
                tx_id: self.request.tx_id,
                finality: self.request.finality,
                expected_block_hash: Some(block_hash.into()),
            },
            derivation_path: self.derivation_path,
            domain_id: self.domain_id,
            payload_version: self.payload_version,
        }
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use contract_interface::types::{DomainId, VerifyForeignTransactionRequestArgs};

    use crate::foreign_chain::{DEFAULT_PAYLOAD_VERSION, ForeignChainSignatureVerifier};

    use super::*;

    #[test]
    fn with_starknet_tx_id_sets_expected_value() {
        // given
        let tx_id = StarknetTxId::from(StarknetFelt([123; 32]));

        // when
        let builder = ForeignChainRequestBuilder::new().with_starknet_tx_id(tx_id.clone());

        // then
        assert_eq!(builder.request.tx_id, tx_id);
    }

    #[test]
    fn with_finality_sets_expected_value() {
        // given
        let tx_id = StarknetTxId::from(StarknetFelt([123; 32]));

        // when
        let builder = ForeignChainRequestBuilder::new()
            .with_starknet_tx_id(tx_id)
            .with_finality(StarknetFinality::AcceptedOnL1);

        // then
        assert_eq!(builder.request.finality, StarknetFinality::AcceptedOnL1);
    }

    #[test]
    fn with_expected_block_hash_sets_expected_value() {
        // given
        let tx_id = StarknetTxId::from(StarknetFelt([123; 32]));
        let expected_hash = [9; 32];

        // when
        let builder = ForeignChainRequestBuilder::new()
            .with_starknet_tx_id(tx_id)
            .with_finality(StarknetFinality::AcceptedOnL1)
            .with_expected_block_hash(expected_hash);

        // then
        assert_eq!(
            builder.request.expected_block_hash.as_deref(),
            Some(&expected_hash)
        );
    }

    #[test]
    fn build_produces_correct_request_args() {
        // given
        let path = "test_path".to_string();
        let domain_id = DomainId::from(2);
        let tx_id = StarknetTxId::from(StarknetFelt([123; 32]));
        let expected_hash = [9; 32];

        // when
        let (_verifier, request_args) = ForeignChainRequestBuilder::new()
            .with_starknet_tx_id(tx_id.clone())
            .with_finality(StarknetFinality::AcceptedOnL1)
            .with_expected_block_hash(expected_hash)
            .with_derivation_path(path.clone())
            .with_domain_id(domain_id)
            .build();

        // then
        let expected = VerifyForeignTransactionRequestArgs {
            request: ForeignChainRpcRequest::Starknet(StarknetRpcRequest {
                tx_id,
                finality: StarknetFinality::AcceptedOnL1,
                extractors: vec![StarknetExtractor::BlockHash],
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
        let tx_id = StarknetTxId::from(StarknetFelt([123; 32]));
        let expected_hash = [9; 32];

        // when
        let (verifier, _request_args) = ForeignChainRequestBuilder::new()
            .with_starknet_tx_id(tx_id.clone())
            .with_finality(StarknetFinality::AcceptedOnL1)
            .with_expected_block_hash(expected_hash)
            .with_derivation_path("path".to_string())
            .with_domain_id(DomainId::from(1))
            .build();

        // then
        let expected_verifier = ForeignChainSignatureVerifier {
            expected_extracted_values: vec![ExtractedValue::StarknetExtractedValue(
                StarknetExtractedValue::BlockHash(StarknetFelt(expected_hash)),
            )],
            request: ForeignChainRpcRequest::Starknet(StarknetRpcRequest {
                tx_id,
                finality: StarknetFinality::AcceptedOnL1,
                extractors: vec![StarknetExtractor::BlockHash],
            }),
        };

        assert_eq!(verifier, expected_verifier);
    }

    #[test]
    fn verifier_request_matches_request_args() {
        // given
        let (verifier, request_args) = ForeignChainRequestBuilder::new()
            .with_starknet_tx_id(StarknetTxId::from(StarknetFelt([123; 32])))
            .with_finality(StarknetFinality::AcceptedOnL2)
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
            .with_starknet_tx_id(StarknetTxId::from(StarknetFelt([42; 32])))
            .with_finality(StarknetFinality::AcceptedOnL2)
            .with_derivation_path("path".to_string())
            .with_domain_id(DomainId::from(1))
            .build();

        // then
        assert_matches!(&request_args.request, ForeignChainRpcRequest::Starknet(rpc_request) => {
            assert_eq!(rpc_request.extractors, vec![]);
        });
    }
}
