use crate::{
    foreign_chain::{ForeignChainRequestBuilder, ForeignChainRpcRequestWithExpectations},
    sign::NotSet,
};

use contract_interface::types::{ExtractedValue, Hash256};

// API types
pub use contract_interface::types::{
    BitcoinExtractedValue, BitcoinExtractor, BitcoinRpcRequest, BitcoinTxId, BlockConfirmations,
    ForeignChainRpcRequest,
};

/// Type alias with concrete types for when [`BitcoinRequest`] is ready to be built
/// as part of the [`ForeignChainRequestBuilder`] builder.
type BuildableBitcoinRequest = BitcoinRequest<BitcoinTxId, BlockConfirmations>;

#[derive(Debug, Clone, derive_more::From, derive_more::Deref)]
pub struct BitcoinBlockHash([u8; 32]);

#[derive(Debug, Clone)]
pub struct BitcoinRequest<TxId, Confirmations> {
    tx_id: TxId,
    confirmations: Confirmations,

    // Extractors
    expected_block_hash: Option<BitcoinBlockHash>,
}

impl From<BuildableBitcoinRequest> for ForeignChainRpcRequestWithExpectations {
    fn from(built_request: BuildableBitcoinRequest) -> Self {
        let mut extractors = vec![];
        let mut expected_values = vec![];

        if let Some(expected_block_hash) = built_request.expected_block_hash {
            extractors.push(BitcoinExtractor::BlockHash);
            expected_values.push(ExtractedValue::BitcoinExtractedValue(
                BitcoinExtractedValue::BlockHash(Hash256::from(*expected_block_hash)),
            ));
        }

        ForeignChainRpcRequestWithExpectations {
            request: ForeignChainRpcRequest::Bitcoin(BitcoinRpcRequest {
                tx_id: built_request.tx_id,
                confirmations: built_request.confirmations,
                extractors,
            }),
            expected_values,
        }
    }
}

impl ForeignChainRequestBuilder<NotSet, NotSet, NotSet> {
    pub fn new_bitcoin()
    -> ForeignChainRequestBuilder<BitcoinRequest<NotSet, NotSet>, NotSet, NotSet> {
        ForeignChainRequestBuilder {
            request: BitcoinRequest {
                tx_id: NotSet,
                confirmations: NotSet,
                expected_block_hash: None,
            },
            derivation_path: NotSet,
            domain_id: NotSet,
        }
    }
}

impl ForeignChainRequestBuilder<BitcoinRequest<NotSet, NotSet>, NotSet, NotSet> {
    pub fn with_tx_id(
        self,
        tx_id: impl Into<BitcoinTxId>,
    ) -> ForeignChainRequestBuilder<BitcoinRequest<BitcoinTxId, NotSet>, NotSet, NotSet> {
        ForeignChainRequestBuilder {
            request: BitcoinRequest {
                tx_id: tx_id.into(),
                confirmations: NotSet,
                expected_block_hash: None,
            },
            derivation_path: self.derivation_path,
            domain_id: self.domain_id,
        }
    }
}

impl ForeignChainRequestBuilder<BitcoinRequest<BitcoinTxId, NotSet>, NotSet, NotSet> {
    pub fn with_block_confirmations(
        self,
        confirmations: impl Into<BlockConfirmations>,
    ) -> ForeignChainRequestBuilder<BuildableBitcoinRequest, NotSet, NotSet> {
        ForeignChainRequestBuilder {
            request: BitcoinRequest {
                confirmations: confirmations.into(),
                tx_id: self.request.tx_id,
                expected_block_hash: self.request.expected_block_hash,
            },
            derivation_path: self.derivation_path,
            domain_id: self.domain_id,
        }
    }
}

impl ForeignChainRequestBuilder<BuildableBitcoinRequest, NotSet, NotSet> {
    pub fn with_expected_block_hash(self, block_hash: impl Into<BitcoinBlockHash>) -> Self {
        ForeignChainRequestBuilder {
            request: BitcoinRequest {
                tx_id: self.request.tx_id,
                confirmations: self.request.confirmations,
                expected_block_hash: Some(block_hash.into()),
            },
            derivation_path: self.derivation_path,
            domain_id: self.domain_id,
        }
    }
}

#[cfg(test)]
mod test {
    use contract_interface::types::{DomainId, VerifyForeignTransactionRequestArgs};

    use crate::foreign_chain::{DEFAULT_PAYLOAD_VERSION, ForeignChainSignatureVerifier};

    use super::*;

    #[test]
    fn with_tx_id_sets_expected_value() {
        // given
        let tx_id = BitcoinTxId::from([123; 32]);

        // when
        let builder = ForeignChainRequestBuilder::new_bitcoin().with_tx_id(tx_id.clone());

        // then
        assert_eq!(builder.request.tx_id, tx_id);
    }

    #[test]
    fn with_block_confirmations_sets_expected_value() {
        // given
        let tx_id = BitcoinTxId::from([123; 32]);

        // when
        let builder = ForeignChainRequestBuilder::new_bitcoin()
            .with_tx_id(tx_id)
            .with_block_confirmations(10);

        // then
        assert_eq!(builder.request.confirmations, BlockConfirmations::from(10));
    }

    #[test]
    fn with_expected_block_hash_sets_expected_value() {
        // given
        let tx_id = BitcoinTxId::from([123; 32]);
        let expected_hash = [9; 32];

        // when
        let builder = ForeignChainRequestBuilder::new_bitcoin()
            .with_tx_id(tx_id)
            .with_block_confirmations(10)
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
        let tx_id = BitcoinTxId::from([123; 32]);
        let expected_hash = [9; 32];

        // when
        let (_verifier, request_args) = ForeignChainRequestBuilder::new_bitcoin()
            .with_tx_id(tx_id.clone())
            .with_block_confirmations(10)
            .with_expected_block_hash(expected_hash)
            .with_derivation_path(path.clone())
            .with_domain_id(domain_id)
            .build();

        // then
        let expected = VerifyForeignTransactionRequestArgs {
            request: ForeignChainRpcRequest::Bitcoin(BitcoinRpcRequest {
                tx_id,
                confirmations: BlockConfirmations::from(10),
                extractors: vec![BitcoinExtractor::BlockHash],
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
        let tx_id = BitcoinTxId::from([123; 32]);
        let expected_hash = [9; 32];

        // when
        let (verifier, _request_args) = ForeignChainRequestBuilder::new_bitcoin()
            .with_tx_id(tx_id.clone())
            .with_block_confirmations(10)
            .with_expected_block_hash(expected_hash)
            .with_derivation_path("path".to_string())
            .with_domain_id(DomainId::from(1))
            .build();

        // then
        let expected_verifier = ForeignChainSignatureVerifier {
            expected_extracted_values: vec![ExtractedValue::BitcoinExtractedValue(
                BitcoinExtractedValue::BlockHash(expected_hash.into()),
            )],
            request: ForeignChainRpcRequest::Bitcoin(BitcoinRpcRequest {
                tx_id,
                confirmations: BlockConfirmations::from(10),
                extractors: vec![BitcoinExtractor::BlockHash],
            }),
        };

        assert_eq!(verifier, expected_verifier);
    }

    #[test]
    fn verifier_request_matches_request_args() {
        // given
        let (verifier, request_args) = ForeignChainRequestBuilder::new_bitcoin()
            .with_tx_id(BitcoinTxId::from([123; 32]))
            .with_block_confirmations(10)
            .with_derivation_path("path".to_string())
            .with_domain_id(DomainId::from(1))
            // when
            .build();

        // then
        assert_eq!(verifier.request, request_args.request);
    }
}
