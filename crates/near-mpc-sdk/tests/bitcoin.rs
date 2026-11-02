use near_mpc_sdk::foreign_chain::{
    DomainId, ForeignChainRequestBuilder,
    bitcoin::{BitcoinTxId, ForeignChainRpcRequest},
};
use std::assert_matches;

#[test]
fn no_extractor_added() {
    // given
    let domain_id = DomainId::from(2);
    let tx_id = BitcoinTxId::from([123; 32]);

    // when
    let (_verifier, built_sign_request_args) = ForeignChainRequestBuilder::new_bitcoin()
        .with_tx_id(tx_id)
        .with_block_confirmations(10)
        .with_domain_id(domain_id)
        .build()
        .unwrap();

    // then
    assert_matches!(
        built_sign_request_args.request,
        ForeignChainRpcRequest::Bitcoin(rpc_request) if rpc_request.extractors.is_empty()
    );
}
