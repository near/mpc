use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU64;

use crate::common;

use mpc_node_config::{ForeignChainConfig, ForeignChainProviderConfig, ForeignChainsConfig};
use near_mpc_bounded_collections::NonEmptyBTreeMap;
use near_mpc_contract_interface::types::{
    DomainConfig, DomainId, DomainPurpose, ForeignChain, ForeignChainsConfigs, Protocol,
    ReconstructionThreshold,
};

const SOLANA_PROVIDER_NAME: &str = "public";
const SOLANA_RPC_URL: &str = "https://rpc.public.example.com";

fn solana_foreign_chains_config() -> ForeignChainsConfig {
    ForeignChainsConfig {
        solana: Some(ForeignChainConfig {
            timeout_sec: NonZeroU64::new(30).unwrap(),
            max_retries: NonZeroU64::new(3).unwrap(),
            expected_network_fingerprint: None,
            providers: NonEmptyBTreeMap::new(
                SOLANA_PROVIDER_NAME.to_string().into(),
                ForeignChainProviderConfig {
                    rpc_url: SOLANA_RPC_URL.to_string(),
                    auth: Default::default(),
                },
            ),
        }),
        ..Default::default()
    }
}

/// Verify that a chain becomes available only once it is whitelisted and a
/// signing threshold of participants has registered a config covering it.
///
/// 3-node cluster (ForeignTx domain threshold 2): nodes 0 and 1 are configured
/// with the Solana foreign chain, node 2 has no foreign chain config.
///
/// 1. All three nodes auto-register on startup — nodes 0 and 1 with Solana,
///    node 2 with an empty configuration. Solana must NOT be available while
///    it is not whitelisted.
/// 2. After the participants whitelist Solana, two registrations reach the
///    threshold and the chain becomes available.
#[tokio::test]
#[expect(non_snake_case)]
async fn available_foreign_chains__should_require_whitelist_and_threshold_of_registrations() {
    // given — 3-node cluster with a ForeignTx domain; Solana configured on
    // nodes 0 and 1 only, and no chain whitelisted yet.
    let (cluster, _running) =
        common::must_setup_cluster(common::AVAILABLE_FOREIGN_CHAINS_PORT_SEED, |c| {
            c.domains = vec![DomainConfig {
                id: DomainId(0),
                protocol: Protocol::CaitSith,
                reconstruction_threshold: ReconstructionThreshold::new(2),
                purpose: DomainPurpose::ForeignTx,
            }];
            c.foreign_chains.node_configs = vec![
                solana_foreign_chains_config(), // node 0
                solana_foreign_chains_config(), // node 1
                ForeignChainsConfig::default(), // node 2 — no foreign chains
            ];
        })
        .await;

    // when — wait for all three nodes to register (one with an empty
    // configuration) without Solana becoming available.
    let expected_registrations: ForeignChainsConfigs = BTreeMap::from([
        (
            cluster.nodes[0].p2p_public_key(),
            BTreeSet::from([ForeignChain::Solana]).into(),
        ),
        (
            cluster.nodes[1].p2p_public_key(),
            BTreeSet::from([ForeignChain::Solana]).into(),
        ),
        (cluster.nodes[2].p2p_public_key(), BTreeSet::new().into()),
    ])
    .into();
    cluster
        .wait_for_foreign_chains_registrations(&expected_registrations)
        .await
        .expect("timed out waiting for all three registrations with one empty");
    cluster
        .wait_for_available_foreign_chains(&BTreeSet::new())
        .await
        .expect("no chain must be available before whitelisting");

    // when — the participants whitelist Solana.
    cluster
        .whitelist_foreign_chains(
            &[0, 1],
            &BTreeMap::from([(
                ForeignChain::Solana,
                e2e_tests::cluster::placeholder_chain_entry(ForeignChain::Solana),
            )]),
        )
        .await
        .expect("failed to whitelist Solana");

    // then — Solana becomes available with two of three registrations.
    cluster
        .wait_for_available_foreign_chains(&BTreeSet::from([ForeignChain::Solana]))
        .await
        .expect("timed out waiting for Solana to become available");
}
