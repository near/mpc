use crate::{
    foreign_chain::{ForeignChainRequestBuilder, RequestFinishedBuilding},
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
type BuiltBitcoinRequest = BitcoinRequest<BitcoinTxId, BlockConfirmations>;

#[derive(Debug, Clone, derive_more::From, derive_more::Deref)]
pub struct BitcoinBlockHash([u8; 32]);

#[derive(Debug, Clone)]
pub struct BitcoinRequest<TxId, Confirmations> {
    tx_id: TxId,
    confirmations: Confirmations,

    // Extractors
    expected_block_hash: Option<BitcoinBlockHash>,
}

// This means the request can be built
impl RequestFinishedBuilding for BuiltBitcoinRequest {}

impl From<BuiltBitcoinRequest> for (ForeignChainRpcRequest, Vec<ExtractedValue>) {
    fn from(built_request: BuiltBitcoinRequest) -> Self {
        let mut extractors = vec![];
        let mut expected_values = vec![];

        if let Some(expected_block_hash) = built_request.expected_block_hash {
            extractors.push(BitcoinExtractor::BlockHash);
            expected_values.push(ExtractedValue::BitcoinExtractedValue(
                BitcoinExtractedValue::BlockHash(Hash256::from(*expected_block_hash)),
            ));
        }

        (
            ForeignChainRpcRequest::Bitcoin(BitcoinRpcRequest {
                tx_id: built_request.tx_id,
                confirmations: built_request.confirmations,
                extractors,
            }),
            expected_values,
        )
    }
}

impl ForeignChainRequestBuilder<NotSet, NotSet, NotSet> {
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
            derivation_path: NotSet,
            domain_id: NotSet,
            payload_version: self.payload_version,
        }
    }
}

impl ForeignChainRequestBuilder<BitcoinRequest<BitcoinTxId, NotSet>, NotSet, NotSet> {
    pub fn with_block_confirmations(
        self,
        confirmations: impl Into<BlockConfirmations>,
    ) -> ForeignChainRequestBuilder<BuiltBitcoinRequest, NotSet, NotSet> {
        ForeignChainRequestBuilder {
            request: BitcoinRequest {
                tx_id: self.request.tx_id,
                confirmations: confirmations.into(),
                expected_block_hash: None,
            },
            derivation_path: NotSet,
            domain_id: NotSet,
            payload_version: self.payload_version,
        }
    }
}

impl ForeignChainRequestBuilder<BuiltBitcoinRequest, NotSet, NotSet> {
    pub fn with_expected_block_hash(self, block_hash: impl Into<BitcoinBlockHash>) -> Self {
        ForeignChainRequestBuilder {
            request: BitcoinRequest {
                tx_id: self.request.tx_id,
                confirmations: self.request.confirmations,
                expected_block_hash: Some(block_hash.into()),
            },
            derivation_path: NotSet,
            domain_id: NotSet,
            payload_version: self.payload_version,
        }
    }
}

#[cfg(test)]
mod test {
    use contract_interface::types::{DomainId, VerifyForeignTransactionRequestArgs};

    use crate::foreign_chain::{DEFAULT_PAYLOAD_VERSION, ForeignChainSignatureVerifier};

    use super::*;

    #[test]
    fn builder_builds_as_expected() {
        // given
        let path = "test_path".to_string();
        let domain_id = DomainId::from(2);
        let tx_id = BitcoinTxId::from([123; 32]);
        let confirmations = 10;

        let expected_hash = [9; 32];

        // when
        let (verifier, built_sign_request_args) = ForeignChainRequestBuilder::new()
            .with_tx_id(tx_id.clone())
            .with_block_confirmations(10)
            .with_expected_block_hash(expected_hash)
            .with_derivation_path(path.clone())
            .with_domain_id(domain_id)
            .build();

        // then
        let block_hash_extractor = BitcoinExtractor::BlockHash;
        let example_extracted_value = BitcoinExtractedValue::BlockHash(expected_hash.into());

        let expected_rpc_request = ForeignChainRpcRequest::Bitcoin({
            BitcoinRpcRequest {
                tx_id,
                confirmations: BlockConfirmations::from(confirmations),
                extractors: vec![block_hash_extractor],
            }
        });

        let expected_request = VerifyForeignTransactionRequestArgs {
            request: expected_rpc_request,
            derivation_path: path,
            domain_id,
            payload_version: DEFAULT_PAYLOAD_VERSION,
        };

        let expected_verifier = ForeignChainSignatureVerifier {
            expected_extracted_values: vec![ExtractedValue::BitcoinExtractedValue(
                example_extracted_value,
            )],
            request: expected_request.request.clone(),
        };

        assert_eq!(built_sign_request_args, expected_request);
        assert_eq!(verifier, expected_verifier);
    }
}
