//! Generates the borsh-encoded base64 argument for `vote_update_foreign_chain_providers`
//! on testnet (issue https://github.com/near/mpc/issues/3622).
//!
//! Run:
//!   cargo run -p mpc-contract --example gen_testnet_rpc_whitelist_vote --features test-utils

use base64::Engine as _;
use near_mpc_bounded_collections::NonEmptyBTreeMap;
use near_mpc_contract_interface::types::{
    AuthScheme, ChainEntry, ChainRouting, ForeignChain, ProviderConfig, ProviderId,
};

fn none(base_url: &str) -> ProviderConfig {
    ProviderConfig {
        base_url: base_url.to_string(),
        auth_scheme: AuthScheme::None,
        chain_routing: ChainRouting::Embedded,
    }
}

fn path_auth(base_url: &str, placeholder: &str) -> ProviderConfig {
    ProviderConfig {
        base_url: base_url.to_string(),
        auth_scheme: AuthScheme::Path { placeholder: placeholder.to_string() },
        chain_routing: ChainRouting::Embedded,
    }
}

fn header_bearer(base_url: &str, header_name: &str) -> ProviderConfig {
    ProviderConfig {
        base_url: base_url.to_string(),
        auth_scheme: AuthScheme::Header {
            name: header_name.to_string(),
            scheme: Some("Bearer".to_string()),
        },
        chain_routing: ChainRouting::Embedded,
    }
}

fn entry(providers: NonEmptyBTreeMap<ProviderId, ProviderConfig>, quorum: u64) -> ChainEntry {
    ChainEntry { providers, quorum }
}

fn id(s: &str) -> ProviderId {
    ProviderId(s.to_string())
}

fn main() {
    // Bitcoin testnet — 1 provider, quorum 1/1
    let bitcoin = entry(
        NonEmptyBTreeMap::new(
            id("public"),
            none("https://bitcoin-testnet-rpc.publicnode.com"),
        ),
        1,
    );

    // Abstract testnet — 3 providers, quorum 3/3
    let mut abstract_providers = NonEmptyBTreeMap::new(
        id("alchemy"),
        path_auth("https://abstract-testnet.g.alchemy.com/v2/", "{API_KEY}"),
    );
    abstract_providers.insert(id("public"), none("https://api.testnet.abs.xyz"));
    // QuickNode subdomain is operator-specific; base_url is a minimal HTTPS prefix
    abstract_providers.insert(id("quicknode"), path_auth("https://", "{api_key}"));
    let abstract_chain = entry(abstract_providers, 3);

    // Starknet testnet (Sepolia) — 3 providers, quorum 3/3
    let mut starknet_providers = NonEmptyBTreeMap::new(
        id("alchemy"),
        path_auth(
            "https://starknet-sepolia.g.alchemy.com/starknet/version/rpc/v0_10/",
            "{API_KEY}",
        ),
    );
    starknet_providers.insert(id("public"), none("https://starknet-sepolia-rpc.publicnode.com"));
    starknet_providers.insert(id("quicknode"), path_auth("https://", "{api_key}"));
    let starknet = entry(starknet_providers, 3);

    // Aptos testnet — 4 providers, quorum 3/4
    let mut aptos_providers = NonEmptyBTreeMap::new(
        id("alchemy"),
        path_auth("https://aptos-testnet.g.alchemy.com/v2/", "{API_KEY}"),
    );
    aptos_providers.insert(
        id("geomi"),
        header_bearer("https://api.testnet.aptoslabs.com/v1", "Authorization"),
    );
    aptos_providers.insert(id("public"), none("https://fullnode.testnet.aptoslabs.com/v1"));
    aptos_providers.insert(id("quicknode"), path_auth("https://", "{api_key}"));
    let aptos = entry(aptos_providers, 3);

    // NonEmptyBTreeMap is sorted by ForeignChain discriminant:
    // Bitcoin=1, Abstract=6, Starknet=7, Aptos=11
    let mut batch = NonEmptyBTreeMap::new(ForeignChain::Abstract, abstract_chain);
    batch.insert(ForeignChain::Aptos, aptos);
    batch.insert(ForeignChain::Bitcoin, bitcoin);
    batch.insert(ForeignChain::Starknet, starknet);

    let bytes = borsh::to_vec(&batch).expect("borsh serialization failed");
    assert_eq!(bytes.len(), 709, "payload size changed — update the ops doc");

    let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
    println!("{b64}");
}
