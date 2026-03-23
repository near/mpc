use std::time::{Duration, Instant};

use chain_gateway::state_viewer::ViewMethod;
use chain_gateway::types::{NoArgs, ObservedState};
use chain_gateway_test_contract::VIEW_METHOD;

use super::contract::{Contract, compiled_test_contract_wasm, test_contract};
use super::node::{LocalNode, LocalNodeBuilder};

pub struct Localnet {
    pub validator: LocalNode,
    pub observer: LocalNode,
    pub contract: Contract,
}

impl Localnet {
    /// Two-node setup for sender tests.
    ///
    /// The observer is a non-validator node that syncs from the validator.
    /// Genesis is copied from the validator to ensure both nodes share the same chain.
    pub async fn new() -> Self {
        let validator_home = make_test_home_dir("validator.near");
        let observer_home = make_test_home_dir("observer.near");
        let contract = test_contract();

        // start a validator node (this is what the MPC node calls the "near indexer node")
        let validator = LocalNodeBuilder::new("validator", validator_home)
            .with_consensus_min_peers(1)
            .with_contract(test_contract(), compiled_test_contract_wasm())
            .start()
            .await;

        // start an observer node (non-validator, just like what the MPC node would be running)
        // Copy genesis from validator so both nodes share the same chain
        // (indexer_init_configs embeds genesis_time = Utc::now(), so independent
        // genesis generation produces different genesis hashes).
        let validator_node_pk = validator.read_node_public_key();
        let validator_network_port = validator.ports.network_port;
        let boot_node = format!("{validator_node_pk}@127.0.0.1:{validator_network_port}");
        let observer = LocalNodeBuilder::new("observer", observer_home)
            .with_consensus_min_peers(1)
            .with_genesis_from(&validator)
            .without_validator_key()
            .with_boot_nodes(&boot_node)
            .start()
            .await;

        // Wait for block production: poll until the observer sees a finalized block
        // beyond genesis (height > 0). This ensures the P2P connection is established
        // and the validator has started producing blocks.
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let state: ObservedState<String> = observer
                .chain_gateway
                .view_method(contract.account_id.clone(), VIEW_METHOD, &NoArgs {})
                .await
                .expect("view call should succeed during startup wait");
            if u64::from(state.observed_at) > 0 {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "Timed out waiting for block production on observer"
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        Localnet {
            validator,
            observer,
            contract,
        }
    }
}

impl Drop for Localnet {
    fn drop(&mut self) {
        self.validator.chain_gateway.stop();
        self.observer.chain_gateway.stop();
        // `stop()` cancels all actor runtimes, but nearcore's background
        // threads (RocksDB compaction, trie prefetch, etc.) wind down
        // asynchronously. RocksDB instances are the last resources to close, so
        // blocking on them acts as a fence that all background work has finished.
        // This is the same shutdown sequence nearcore uses in its own integration
        // tests - see `NodeCluster::run_and_then_shutdown` in
        // nearcore/integration-tests/src/tests/nearcore/node_cluster.rs.
        // it is important that all background tasks have closed before dropping the temporary
        // directories of the validator and observer nodes.
        near_store::db::RocksDB::block_until_all_instances_are_dropped();
    }
}

/// Returns a fresh temp directory under `target/chain-gateway-test-nodes/`.
/// The returned `TempDir` is automatically deleted when dropped.
fn make_test_home_dir(account_id: &str) -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix(&format!("{account_id}-"))
        .tempdir()
        .expect("create temp home dir")
}
