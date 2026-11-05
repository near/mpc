use near_mpc_sdk::foreign_chain::{
    DomainId, ForeignChainRequestBuilder,
    adi::{EvmFinality, EvmTxId, ForeignChainRpcRequest},
};
use std::assert_matches;

#[test]
fn no_extractor_added() {
    // given
    let domain_id = DomainId::from(2);
    let tx_id = EvmTxId::from([123; 32]);

    // when
    let (_verifier, built_sign_request_args) = ForeignChainRequestBuilder::new_adi()
        .with_tx_id(tx_id)
        .with_finality(EvmFinality::Finalized)
        .with_domain_id(domain_id)
        .build()
        .unwrap();

    // then
    assert_matches!(
        built_sign_request_args.request,
        ForeignChainRpcRequest::Adi(rpc_request) if rpc_request.extractors.is_empty()
    );
}
