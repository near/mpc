use near_mpc_sdk::foreign_chain::{
    DomainId, ForeignChainRequestBuilder,
    fogo::{ForeignChainRpcRequest, SvmFinality, SvmTxId},
};
use std::assert_matches;

#[test]
#[expect(non_snake_case)]
fn build__should_add_no_extractors_without_expectations() {
    // Given
    let domain_id = DomainId::from(2);
    let tx_id = SvmTxId::from([123; 64]);

    // When
    let (_verifier, built_sign_request_args) = ForeignChainRequestBuilder::new_fogo()
        .with_tx_id(tx_id)
        .with_finality(SvmFinality::Finalized)
        .with_domain_id(domain_id)
        .build()
        .unwrap();

    // Then
    assert_matches!(
        built_sign_request_args.request,
        ForeignChainRpcRequest::Fogo(rpc_request) if rpc_request.extractors.is_empty()
    );
}
