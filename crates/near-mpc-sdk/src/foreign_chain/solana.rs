use crate::{
    foreign_chain::{
        ForeignChainRequestBuilder,
        svm::{SvmChainVariant, SvmRequest},
    },
    sign::NotSet,
};

pub use crate::foreign_chain::svm::{
    ForeignChainRpcRequest, SvmAccount, SvmAddress, SvmExtractedValue, SvmExtractor, SvmFinality,
    SvmInnerInstruction, SvmRpcRequest, SvmTxId,
};

#[derive(Debug, Clone)]
pub struct Solana;

impl SvmChainVariant for Solana {
    fn wrap(request: SvmRpcRequest) -> ForeignChainRpcRequest {
        ForeignChainRpcRequest::Solana(request)
    }
}

pub type SolanaRequest<TxId, Finality> = SvmRequest<Solana, TxId, Finality>;

impl ForeignChainRequestBuilder<SolanaRequest<NotSet, NotSet>, NotSet> {
    pub fn new_solana() -> Self {
        Self {
            request: SvmRequest {
                tx_id: NotSet,
                finality: NotSet,
                expected_values: vec![],
                _chain: std::marker::PhantomData,
            },
            domain_id: NotSet,
        }
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod test {
    use assert_matches::assert_matches;
    use near_mpc_contract_interface::types::DomainId;

    use crate::foreign_chain::ForeignChainRequestBuilder;

    use super::*;

    #[test]
    fn build__should_wrap_into_solana_variant() {
        // Given
        let builder = ForeignChainRequestBuilder::new_solana()
            .with_tx_id(SvmTxId::from([1; 64]))
            .with_finality(SvmFinality::Finalized)
            .with_domain_id(DomainId::from(1));

        // When
        let (_verifier, request_args) = builder.build().unwrap();

        // Then
        assert_matches!(request_args.request, ForeignChainRpcRequest::Solana(_));
    }
}
