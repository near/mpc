use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU64;
use std::time::Duration;

use crate::common;

use e2e_tests::cluster::chain_entry_matching;
use mpc_node_config::foreign_chains::{ProviderCredentials, RpcPreset, resolve_with_embedded};
use mpc_node_config::{
    ForeignChainConfig, ForeignChainProviderConfig, ForeignChainsConfig, TokenConfig,
};
use near_mpc_bounded_collections::NonEmptyBTreeMap;
use near_mpc_contract_interface::types::{
    AuthScheme, ChainEntry, ChainRouting, DomainConfig, DomainId, DomainPurpose, ForeignChain,
    ForeignChainsConfigs, Protocol, ProviderConfig, ProviderId, ReconstructionThreshold,
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

/// The Solana whitelist entry every node conforms to, plus one provider nobody runs so that
/// `quorum` 2 is out of reach for a node with one provider.
fn solana_whitelist(quorum: u64) -> BTreeMap<ForeignChain, ChainEntry> {
    let config = solana_foreign_chains_config();
    let mut entry = chain_entry_matching(config.solana.as_ref().expect("solana"), quorum);
    entry.providers.insert(
        ProviderId("other".to_string()),
        ProviderConfig {
            base_url: "https://rpc.other.example.com".to_string(),
            auth_scheme: AuthScheme::None,
            chain_routing: ChainRouting::Embedded,
        },
    );
    BTreeMap::from([(ForeignChain::Solana, entry)])
}

/// Verify that a node registers a chain only once it can reach the voted quorum, and that the
/// chain becomes available once a signing threshold of participants has registered it.
///
/// 3-node cluster (ForeignTx domain threshold 2): nodes 0 and 1 are configured
/// with the Solana foreign chain, node 2 has no foreign chain config.
///
/// 1. All three nodes auto-register an empty configuration on startup, since
///    nothing is whitelisted.
/// 2. The participants vote a quorum the nodes cannot reach. The nodes report it on the
///    quorum gauge, keep their registrations empty, and Solana stays unavailable.
/// 3. The participants lower the quorum to what the nodes have. Nodes 0 and 1 register
///    Solana, and two registrations reach the threshold.
#[tokio::test]
#[expect(non_snake_case)]
async fn available_foreign_chains__should_require_a_reachable_quorum_and_threshold_of_registrations()
 {
    // Given
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

    // When
    let empty_registrations: ForeignChainsConfigs = cluster
        .nodes
        .iter()
        .map(|node| (node.p2p_public_key(), BTreeSet::new().into()))
        .collect::<BTreeMap<_, _>>()
        .into();
    cluster
        .wait_for_foreign_chains_registrations(&empty_registrations)
        .await
        .expect("timed out waiting for the three empty registrations");

    // When
    cluster
        .whitelist_foreign_chains(&[0, 1], &solana_whitelist(2))
        .await
        .expect("failed to whitelist Solana");
    cluster
        .wait_for_metric_on_nodes(
            &[0, 1],
            "mpc_foreign_chain_rpc_quorum_required",
            |required| required == 2,
            Duration::from_secs(60),
        )
        .await
        .expect("nodes 0 and 1 did not pick up the voted quorum");
    assert_eq!(
        cluster
            .foreign_chains_registrations()
            .await
            .expect("failed to read the registrations"),
        empty_registrations,
        "an unreachable quorum must not register the chain"
    );
    cluster
        .wait_for_available_foreign_chains(&BTreeSet::new())
        .await
        .expect("no chain must be available with an unreachable quorum");

    // When
    cluster
        .whitelist_foreign_chains(&[0, 1], &solana_whitelist(1))
        .await
        .expect("failed to whitelist Solana");

    // Then
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
        .expect("timed out waiting for nodes 0 and 1 to register Solana");
    cluster
        .wait_for_available_foreign_chains(&BTreeSet::from([ForeignChain::Solana]))
        .await
        .expect("timed out waiting for Solana to become available");
}

/// Verify that a node resolves its `rpc_preset` at startup and registers the resolved chains.
///
/// 3-node cluster (ForeignTx domain threshold 2): node 0 selects the testnet preset with dummy
/// alchemy, quicknode and tatum credentials, so it registers the keyless chains plus those the
/// credentials enable. Nodes 1 and 2 have no foreign chain config. The whitelist votes an entry
/// every resolved provider conforms to. Node 0's startup probe calls the preset's real
/// endpoints. Its failures are only logged.
#[tokio::test]
#[expect(non_snake_case)]
async fn node_startup__should_register_chains_resolved_from_rpc_preset() {
    // Given
    let keyless_config = ForeignChainsConfig {
        rpc_preset: Some(RpcPreset::Testnet),
        ..Default::default()
    };
    let preset_config = ForeignChainsConfig {
        credentials: BTreeMap::from([
            ("alchemy".to_string().into(), dummy_credentials(None)),
            (
                "quicknode".to_string().into(),
                dummy_credentials(Some("dummy-slug")),
            ),
            ("tatum".to_string().into(), dummy_credentials(None)),
        ]),
        ..keyless_config.clone()
    };
    let keyless_chains = resolved_chains(&keyless_config);
    let preset_chains = resolved_chains(&preset_config);
    let whitelist: BTreeMap<_, _> = resolve_with_embedded(&preset_config)
        .expect("the testnet preset should resolve")
        .config
        .iter_chains()
        .map(|(chain, config)| (chain, chain_entry_matching(config, 1)))
        .collect();
    assert!(
        keyless_chains.is_subset(&preset_chains) && keyless_chains != preset_chains,
        "credentials should enable chains beyond the keyless ones"
    );

    // When
    let (cluster, _running) =
        common::must_setup_cluster(common::RPC_PRESET_REGISTRATION_PORT_SEED, |c| {
            c.domains = vec![DomainConfig {
                id: DomainId(0),
                protocol: Protocol::CaitSith,
                reconstruction_threshold: ReconstructionThreshold::new(2),
                purpose: DomainPurpose::ForeignTx,
            }];
            c.foreign_chains.node_configs = vec![
                preset_config.clone(),          // node 0
                ForeignChainsConfig::default(), // node 1 — no foreign chains
                ForeignChainsConfig::default(), // node 2 — no foreign chains
            ];
            c.foreign_chains.whitelist = whitelist;
        })
        .await;

    // Then
    let expected_registrations: ForeignChainsConfigs = BTreeMap::from([
        (cluster.nodes[0].p2p_public_key(), preset_chains.into()),
        (cluster.nodes[1].p2p_public_key(), BTreeSet::new().into()),
        (cluster.nodes[2].p2p_public_key(), BTreeSet::new().into()),
    ])
    .into();
    cluster
        .wait_for_foreign_chains_registrations(&expected_registrations)
        .await
        .expect("node 0 should register the chains resolved from its preset");
}

fn dummy_credentials(slug: Option<&str>) -> ProviderCredentials {
    ProviderCredentials {
        api_key: TokenConfig::Val {
            val: "dummy-key".to_string(),
        },
        slug: slug.map(str::to_string),
    }
}

fn resolved_chains(config: &ForeignChainsConfig) -> BTreeSet<ForeignChain> {
    resolve_with_embedded(config)
        .expect("the testnet preset should resolve")
        .config
        .iter_chains()
        .map(|(chain, _)| chain)
        .collect()
}
