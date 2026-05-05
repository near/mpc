use crate::{
    foreign_chain::{
        ForeignChainRequestBuilder,
        evm::{EvmChainVariant, EvmRequest},
    },
    sign::NotSet,
};

pub use crate::foreign_chain::evm::EvmBlockHash as ArbitrumBlockHash;
pub use crate::foreign_chain::evm::{
    EvmExtractedValue, EvmExtractor, EvmFinality, EvmLog, EvmRpcRequest, EvmTxId,
    ForeignChainRpcRequest,
};

#[derive(Debug, Clone)]
pub struct Arbitrum;

impl EvmChainVariant for Arbitrum {
    fn wrap(request: EvmRpcRequest) -> ForeignChainRpcRequest {
        ForeignChainRpcRequest::Arbitrum(request)
    }
}

pub type ArbitrumRequest<TxId, Finality> = EvmRequest<Arbitrum, TxId, Finality>;

impl ForeignChainRequestBuilder<ArbitrumRequest<NotSet, NotSet>, NotSet> {
    pub fn new_arbitrum() -> Self {
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
    use near_mpc_contract_interface::types::DomainId;

    use crate::foreign_chain::ForeignChainRequestBuilder;

    use super::*;

    #[test]
    fn build_wraps_into_arbitrum_variant() {
        // given / when
        let (_verifier, request_args) = ForeignChainRequestBuilder::new_arbitrum()
            .with_tx_id(EvmTxId::from([1; 32]))
            .with_finality(EvmFinality::Finalized)
            .with_domain_id(DomainId::from(1))
            .build();

        // then
        assert_matches!(request_args.request, ForeignChainRpcRequest::Arbitrum(_));
    }
}
