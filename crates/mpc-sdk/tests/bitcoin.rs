use assert_matches::assert_matches;
use near_mpc_sdk::foreign_chain::{
    DomainId, ForeignChainRequestBuilder,
    bitcoin::{BitcoinTxId, ForeignChainRpcRequest},
};

#[test]
fn no_extractor_added() {
    // given
    let path = "test_path".to_string();
    let domain_id = DomainId::from(2);
    let tx_id = BitcoinTxId::from([123; 32]);

    // when
    let (_verifier, built_sign_request_args) = ForeignChainRequestBuilder::new_bitcoin()
        .with_tx_id(tx_id)
        .with_block_confirmations(10)
        .with_derivation_path(path)
        .with_domain_id(domain_id)
        .build();

    // then
    let no_extractors = vec![];

    assert_matches!(built_sign_request_args.request, ForeignChainRpcRequest::Bitcoin(bitcoin_rpc_request) => {
        assert_eq!(bitcoin_rpc_request.extractors, no_extractors);
    });
}
