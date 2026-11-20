#![expect(non_snake_case)]

use near_mpc_sdk::foreign_chain::{
    DomainId, ForeignChainRequestBuilder, abstract_chain, adi, arbitrum, avalanche, base, bitcoin,
    bnb, ethereum, fogo, hyper_evm, polygon, solana, starknet,
};
use std::assert_matches;

#[test]
fn build_abstract__should_add_no_extractors_without_expectations() {
    // Given
    let domain_id = DomainId::from(2);
    let builder = ForeignChainRequestBuilder::new_abstract()
        .with_tx_id(abstract_chain::EvmTxId::from([123; 32]))
        .with_finality(abstract_chain::EvmFinality::Finalized)
        .with_domain_id(domain_id);

    // When
    let (_verifier, built_sign_request_args) = builder.build().unwrap();

    // Then
    assert_matches!(
        built_sign_request_args.request,
        abstract_chain::ForeignChainRpcRequest::Abstract(rpc_request)
            if rpc_request.extractors.is_empty()
    );
}

#[test]
fn build_adi__should_add_no_extractors_without_expectations() {
    // Given
    let domain_id = DomainId::from(2);
    let builder = ForeignChainRequestBuilder::new_adi()
        .with_tx_id(adi::EvmTxId::from([123; 32]))
        .with_finality(adi::EvmFinality::Finalized)
        .with_domain_id(domain_id);

    // When
    let (_verifier, built_sign_request_args) = builder.build().unwrap();

    // Then
    assert_matches!(
        built_sign_request_args.request,
        adi::ForeignChainRpcRequest::Adi(rpc_request) if rpc_request.extractors.is_empty()
    );
}

#[test]
fn build_arbitrum__should_add_no_extractors_without_expectations() {
    // Given
    let domain_id = DomainId::from(2);
    let builder = ForeignChainRequestBuilder::new_arbitrum()
        .with_tx_id(arbitrum::EvmTxId::from([123; 32]))
        .with_finality(arbitrum::EvmFinality::Finalized)
        .with_domain_id(domain_id);

    // When
    let (_verifier, built_sign_request_args) = builder.build().unwrap();

    // Then
    assert_matches!(
        built_sign_request_args.request,
        arbitrum::ForeignChainRpcRequest::Arbitrum(rpc_request) if rpc_request.extractors.is_empty()
    );
}

#[test]
fn build_avalanche__should_add_no_extractors_without_expectations() {
    // Given
    let domain_id = DomainId::from(2);
    let builder = ForeignChainRequestBuilder::new_avalanche()
        .with_tx_id(avalanche::EvmTxId::from([123; 32]))
        .with_finality(avalanche::EvmFinality::Finalized)
        .with_domain_id(domain_id);

    // When
    let (_verifier, built_sign_request_args) = builder.build().unwrap();

    // Then
    assert_matches!(
        built_sign_request_args.request,
        avalanche::ForeignChainRpcRequest::Avalanche(rpc_request)
            if rpc_request.extractors.is_empty()
    );
}

#[test]
fn build_base__should_add_no_extractors_without_expectations() {
    // Given
    let domain_id = DomainId::from(2);
    let builder = ForeignChainRequestBuilder::new_base()
        .with_tx_id(base::EvmTxId::from([123; 32]))
        .with_finality(base::EvmFinality::Finalized)
        .with_domain_id(domain_id);

    // When
    let (_verifier, built_sign_request_args) = builder.build().unwrap();

    // Then
    assert_matches!(
        built_sign_request_args.request,
        base::ForeignChainRpcRequest::Base(rpc_request) if rpc_request.extractors.is_empty()
    );
}

#[test]
fn build_bnb__should_add_no_extractors_without_expectations() {
    // Given
    let domain_id = DomainId::from(2);
    let builder = ForeignChainRequestBuilder::new_bnb()
        .with_tx_id(bnb::EvmTxId::from([123; 32]))
        .with_finality(bnb::EvmFinality::Finalized)
        .with_domain_id(domain_id);

    // When
    let (_verifier, built_sign_request_args) = builder.build().unwrap();

    // Then
    assert_matches!(
        built_sign_request_args.request,
        bnb::ForeignChainRpcRequest::Bnb(rpc_request) if rpc_request.extractors.is_empty()
    );
}

#[test]
fn build_ethereum__should_add_no_extractors_without_expectations() {
    // Given
    let domain_id = DomainId::from(2);
    let builder = ForeignChainRequestBuilder::new_ethereum()
        .with_tx_id(ethereum::EvmTxId::from([123; 32]))
        .with_finality(ethereum::EvmFinality::Finalized)
        .with_domain_id(domain_id);

    // When
    let (_verifier, built_sign_request_args) = builder.build().unwrap();

    // Then
    assert_matches!(
        built_sign_request_args.request,
        ethereum::ForeignChainRpcRequest::Ethereum(rpc_request) if rpc_request.extractors.is_empty()
    );
}

#[test]
fn build_hyper_evm__should_add_no_extractors_without_expectations() {
    // Given
    let domain_id = DomainId::from(2);
    let builder = ForeignChainRequestBuilder::new_hyper_evm()
        .with_tx_id(hyper_evm::EvmTxId::from([123; 32]))
        .with_finality(hyper_evm::EvmFinality::Finalized)
        .with_domain_id(domain_id);

    // When
    let (_verifier, built_sign_request_args) = builder.build().unwrap();

    // Then
    assert_matches!(
        built_sign_request_args.request,
        hyper_evm::ForeignChainRpcRequest::HyperEvm(rpc_request)
            if rpc_request.extractors.is_empty()
    );
}

#[test]
fn build_polygon__should_add_no_extractors_without_expectations() {
    // Given
    let domain_id = DomainId::from(2);
    let builder = ForeignChainRequestBuilder::new_polygon()
        .with_tx_id(polygon::EvmTxId::from([123; 32]))
        .with_finality(polygon::EvmFinality::Finalized)
        .with_domain_id(domain_id);

    // When
    let (_verifier, built_sign_request_args) = builder.build().unwrap();

    // Then
    assert_matches!(
        built_sign_request_args.request,
        polygon::ForeignChainRpcRequest::Polygon(rpc_request) if rpc_request.extractors.is_empty()
    );
}

#[test]
fn build_bitcoin__should_add_no_extractors_without_expectations() {
    // Given
    let domain_id = DomainId::from(2);
    let builder = ForeignChainRequestBuilder::new_bitcoin()
        .with_tx_id(bitcoin::BitcoinTxId::from([123; 32]))
        .with_block_confirmations(10)
        .with_domain_id(domain_id);

    // When
    let (_verifier, built_sign_request_args) = builder.build().unwrap();

    // Then
    assert_matches!(
        built_sign_request_args.request,
        bitcoin::ForeignChainRpcRequest::Bitcoin(rpc_request) if rpc_request.extractors.is_empty()
    );
}

#[test]
fn build_starknet__should_add_no_extractors_without_expectations() {
    // Given
    let domain_id = DomainId::from(2);
    let builder = ForeignChainRequestBuilder::new_starknet()
        .with_tx_id(starknet::StarknetTxId::from(starknet::StarknetFelt(
            [123; 32],
        )))
        .with_finality(starknet::StarknetFinality::AcceptedOnL1)
        .with_domain_id(domain_id);

    // When
    let (_verifier, built_sign_request_args) = builder.build().unwrap();

    // Then
    assert_matches!(
        built_sign_request_args.request,
        starknet::ForeignChainRpcRequest::Starknet(rpc_request) if rpc_request.extractors.is_empty()
    );
}

#[test]
fn build_fogo__should_add_no_extractors_without_expectations() {
    // Given
    let domain_id = DomainId::from(2);
    let builder = ForeignChainRequestBuilder::new_fogo()
        .with_tx_id(fogo::SvmTxId::from([123; 64]))
        .with_finality(fogo::SvmFinality::Finalized)
        .with_domain_id(domain_id);

    // When
    let (_verifier, built_sign_request_args) = builder.build().unwrap();

    // Then
    assert_matches!(
        built_sign_request_args.request,
        fogo::ForeignChainRpcRequest::Fogo(rpc_request) if rpc_request.extractors.is_empty()
    );
}

#[test]
fn build_solana__should_add_no_extractors_without_expectations() {
    // Given
    let domain_id = DomainId::from(2);
    let builder = ForeignChainRequestBuilder::new_solana()
        .with_tx_id(solana::SvmTxId::from([123; 64]))
        .with_finality(solana::SvmFinality::Finalized)
        .with_domain_id(domain_id);

    // When
    let (_verifier, built_sign_request_args) = builder.build().unwrap();

    // Then
    assert_matches!(
        built_sign_request_args.request,
        solana::ForeignChainRpcRequest::Solana(rpc_request) if rpc_request.extractors.is_empty()
    );
}
