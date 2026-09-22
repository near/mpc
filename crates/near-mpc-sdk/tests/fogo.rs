use assert_matches::assert_matches;
use near_mpc_sdk::foreign_chain::{
    DomainId, ForeignChainRequestBuilder,
    fogo::{ForeignChainRpcRequest, SvmFinality, SvmTxId},
};

#[test]
fn no_extractor_added() {
    // given
    let domain_id = DomainId::from(2);
    let tx_id = SvmTxId::from([123; 64]);

    // when
    let (_verifier, built_sign_request_args) = ForeignChainRequestBuilder::new_fogo()
        .with_tx_id(tx_id)
        .with_finality(SvmFinality::Finalized)
        .with_domain_id(domain_id)
        .build()
        .unwrap();

    // then
    let no_extractors = vec![];

    assert_matches!(built_sign_request_args.request, ForeignChainRpcRequest::Fogo(fogo_rpc_request) => {
        assert_eq!(fogo_rpc_request.extractors.to_vec(), no_extractors);
    });
}
