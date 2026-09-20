use crate::{
    foreign_chain::{
        ForeignChainRequestBuilder,
        evm::{EvmChainVariant, EvmRequest},
    },
    sign::NotSet,
};

pub use crate::foreign_chain::evm::EvmBlockHash as EthereumBlockHash;
pub use crate::foreign_chain::evm::{
    EvmExtractedValue, EvmExtractor, EvmFinality, EvmLog, EvmRpcRequest, EvmTxId,
    ForeignChainRpcRequest,
};

#[derive(Debug, Clone)]
pub struct Ethereum;

impl EvmChainVariant for Ethereum {
    fn wrap(request: EvmRpcRequest) -> ForeignChainRpcRequest {
        ForeignChainRpcRequest::Ethereum(request)
    }
}

pub type EthereumRequest<TxId, Finality> = EvmRequest<Ethereum, TxId, Finality>;

impl ForeignChainRequestBuilder<EthereumRequest<NotSet, NotSet>, NotSet> {
    pub fn new_ethereum() -> Self {
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
    fn build_wraps_into_ethereum_variant() {
        // given / when
        let (_verifier, request_args) = ForeignChainRequestBuilder::new_ethereum()
            .with_tx_id(EvmTxId::from([1; 32]))
            .with_finality(EvmFinality::Finalized)
            .with_domain_id(DomainId::from(1))
            .build()
            .unwrap();

        // then
        assert_matches!(request_args.request, ForeignChainRpcRequest::Ethereum(_));
    }
}
