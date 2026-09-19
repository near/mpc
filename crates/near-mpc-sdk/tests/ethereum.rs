use assert_matches::assert_matches;
use near_mpc_sdk::foreign_chain::{
    DomainId, ForeignChainRequestBuilder,
    ethereum::{EvmFinality, EvmTxId, ForeignChainRpcRequest},
};

#[test]
fn no_extractor_added() {
    // given
    let domain_id = DomainId::from(2);
    let tx_id = EvmTxId::from([123; 32]);

    // when
    let (_verifier, built_sign_request_args) = ForeignChainRequestBuilder::new_ethereum()
        .with_tx_id(tx_id)
        .with_finality(EvmFinality::Finalized)
        .with_domain_id(domain_id)
        .build()
        .unwrap();

    // then
    let no_extractors = vec![];

    assert_matches!(built_sign_request_args.request, ForeignChainRpcRequest::Ethereum(ethereum_rpc_request) => {
        assert_eq!(ethereum_rpc_request.extractors.to_vec(), no_extractors);
    });
}
