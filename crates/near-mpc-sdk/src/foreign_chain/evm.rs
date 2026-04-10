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
