use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU64;

use crate::common::{self, POLL_INTERVAL};

use backon::{ConstantBuilder, Retryable};
use e2e_tests::CLUSTER_WAIT_TIMEOUT;
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
const SOLANA_NODES: [usize; 2] = [0, 1];
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

/// Waits until every node running Solana reports the voted quorum, so a check that follows
/// runs after the nodes saw the whitelist.
async fn wait_for_solana_quorum_required(
    cluster: &e2e_tests::MpcCluster,
    quorum: i64,
) -> anyhow::Result<()> {
    let max_times = (CLUSTER_WAIT_TIMEOUT.as_millis() / POLL_INTERVAL.as_millis()) as usize;
    (|| async {
        let values = cluster
            .get_metric_all_nodes("mpc_foreign_chain_rpc_quorum_required")
            .await?;
        anyhow::ensure!(
            SOLANA_NODES
                .iter()
                .all(|node| values[*node] == Some(quorum)),
            "quorum {quorum} not reported by the Solana nodes (values: {values:?})"
        );
        Ok(())
    })
    .retry(
        ConstantBuilder::default()
            .with_delay(POLL_INTERVAL)
            .with_max_times(max_times),
    )
    .await
}

/// Whitelists the nodes' Solana provider plus one they do not run, so a quorum of two is
/// valid for the contract yet unreachable for the nodes.
fn solana_chain_entry(quorum: u64) -> BTreeMap<ForeignChain, ChainEntry> {
    let config = solana_foreign_chains_config();
    let mut entry = chain_entry_matching(config.solana.as_ref().unwrap(), quorum);
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

/// Verify that a node registers a chain only once the whitelist makes its RPC quorum
/// reachable, and that the chain becomes available once a signing threshold of
/// participants has registered it.
///
/// 3-node cluster (ForeignTx domain threshold 2): nodes 0 and 1 are configured
/// with the Solana foreign chain, node 2 has no foreign chain config.
///
/// 1. All three nodes register an empty configuration on startup: Solana is
///    not whitelisted, so no node can reach a quorum for it.
/// 2. A whitelist whose quorum exceeds the single configured provider keeps
///    the registrations empty.
/// 3. Once the quorum is reachable, nodes 0 and 1 register Solana, two
///    registrations reach the threshold and the chain becomes available.
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
    let registrations = |solana_nodes: &[usize]| -> ForeignChainsConfigs {
        (0..3)
            .map(|node| {
                let chains = if solana_nodes.contains(&node) {
                    BTreeSet::from([ForeignChain::Solana])
                } else {
                    BTreeSet::new()
                };
                (cluster.nodes[node].p2p_public_key(), chains.into())
            })
            .collect::<BTreeMap<_, _>>()
            .into()
    };

    // when — wait for all three nodes to register without Solana whitelisted.
    cluster
        .wait_for_foreign_chains_registrations(&registrations(&[]))
        .await
        .expect("timed out waiting for three empty registrations");

    // then — nothing is available.
    cluster
        .wait_for_available_foreign_chains(&BTreeSet::new())
        .await
        .expect("no chain must be available before whitelisting");

    // when — Solana is whitelisted with a quorum no node can reach with one provider.
    cluster
        .whitelist_foreign_chains(&[0, 1], &solana_chain_entry(2))
        .await
        .expect("failed to whitelist Solana");

    // then — the registrations stay empty and Solana stays unavailable.
    wait_for_solana_quorum_required(&cluster, 2)
        .await
        .expect("timed out waiting for the Solana nodes to see the quorum of two");
    cluster
        .wait_for_foreign_chains_registrations(&registrations(&[]))
        .await
        .expect("registrations must stay empty while the quorum is unreachable");
    cluster
        .wait_for_available_foreign_chains(&BTreeSet::new())
        .await
        .expect("no chain must be available while the quorum is unreachable");

    // when — the quorum becomes reachable.
    cluster
        .whitelist_foreign_chains(&[0, 1], &solana_chain_entry(1))
        .await
        .expect("failed to whitelist Solana");

    // then — nodes 0 and 1 register Solana and it becomes available.
    cluster
        .wait_for_foreign_chains_registrations(&registrations(&SOLANA_NODES))
        .await
        .expect("timed out waiting for nodes 0 and 1 to register Solana");
    cluster
        .wait_for_available_foreign_chains(&BTreeSet::from([ForeignChain::Solana]))
        .await
        .expect("timed out waiting for Solana to become available");
}

/// Verify that a node resolves its `rpc_preset` at startup and registers the resolved chains
/// once they are whitelisted.
///
/// 3-node cluster (ForeignTx domain threshold 2): node 0 selects the testnet preset with dummy
/// alchemy, quicknode and tatum credentials, so it registers the keyless chains plus those the
/// credentials enable; nodes 1 and 2 have no foreign chain config. Node 0's startup probe calls
/// the preset's real endpoints; its failures are only logged.
#[tokio::test]
#[expect(non_snake_case)]
async fn node_startup__should_register_chains_resolved_from_rpc_preset() {
    // given
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
    assert!(
        keyless_chains.is_subset(&preset_chains) && keyless_chains != preset_chains,
        "credentials should enable chains beyond the keyless ones"
    );
    // Every resolved provider is whitelisted with a quorum of one, so node 0 can register
    // each resolved chain.
    let whitelist: BTreeMap<ForeignChain, ChainEntry> = resolve_with_embedded(&preset_config)
        .expect("the testnet preset should resolve")
        .config
        .iter_chains()
        .map(|(chain, config)| (chain, chain_entry_matching(config, 1)))
        .collect();

    // when
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

    // then
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
