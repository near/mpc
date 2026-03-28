use std::time::{Duration, Instant};

use chain_gateway::event_subscriber::block_events::BlockUpdate;
use chain_gateway::event_subscriber::subscriber::BlockEventSubscriber;
use chain_gateway::state_viewer::ViewMethod;
use chain_gateway::types::{NoArgs, ObservedState};
use chain_gateway_test_contract::consts::VIEW;
use ed25519_dalek::SigningKey;

use super::accounts::{Contract, TestAccount, compiled_test_contract_wasm, test_contract};
use super::node::{LocalNode, LocalNodeBuilder};

pub struct Localnet {
    pub validator: LocalNode,
    pub observer: LocalNode,
    pub contract: Contract,
}

impl Localnet {
    /// Takes the block update receiver from the observer, panics if already taken.
    pub fn take_block_update_receiver(&mut self) -> tokio::sync::mpsc::Receiver<BlockUpdate> {
        self.observer
            .block_update_receiver
            .take()
            .expect("block_update_receiver already taken")
    }

    pub async fn new() -> Self {
        LocalnetBuilder::new().build().await
    }
}

pub struct LocalnetBuilder {
    contract_id: Option<near_account_id::AccountId>,
    test_account: Option<TestAccount>,
    event_subscriber: Option<BlockEventSubscriber>,
}

impl LocalnetBuilder {
    pub fn new() -> Self {
        LocalnetBuilder {
            contract_id: None,
            event_subscriber: None,
            test_account: None,
        }
    }
    pub fn with_contract_id(mut self, contract_id: near_account_id::AccountId) -> Self {
        self.contract_id = Some(contract_id);
        self
    }

    pub fn with_event_subscriber(mut self, subscriber: BlockEventSubscriber) -> Self {
        self.event_subscriber = Some(subscriber);
        self
    }

    pub fn with_test_account(
        mut self,
        test_account_id: near_account_id::AccountId,
    ) -> (Self, TestAccount) {
        let signing_key = SigningKey::from_bytes(&[3u8; 32]);
        let test_account = TestAccount::new(test_account_id, signing_key);
        self.test_account = Some(test_account.clone());
        (self, test_account)
    }

    /// Build and start the two-node localnet.
    ///
    /// The observer is a non-validator node that syncs from the validator.
    /// Genesis is copied from the validator to ensure both nodes share the same chain.
    pub async fn build(self) -> Localnet {
        let validator_home = make_test_home_dir("validator.near");
        let observer_home = make_test_home_dir("observer.near");
        let contract = test_contract(
            self.contract_id
                .unwrap_or("default-contract-name.near".parse().unwrap()),
        );

        // Start a validator node (this is what the MPC node calls the "near indexer node").
        let mut validator = LocalNodeBuilder::new("validator", validator_home)
            .with_consensus_min_peers(1)
            .with_contract(contract.clone(), compiled_test_contract_wasm());

        if let Some(test_account) = self.test_account {
            validator = validator.with_account(test_account);
        }

        let validator = validator.start(None).await;

        // Start an observer node (non-validator, just like what the MPC node would be running).
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
            .start(self.event_subscriber)
            .await;

        let localnet = Localnet {
            validator,
            observer,
            contract,
        };

        // Wait for block production: poll until the observer sees a finalized block
        // beyond genesis (height > 0). This ensures the P2P connection is established
        // and the validator has started producing blocks.
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            localnet.assert_nodes_alive();
            let state: ObservedState<String> = localnet
                .observer
                .chain_gateway
                .view_method(localnet.contract.account_id.clone(), VIEW, &NoArgs {})
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

        localnet
    }
}

impl Localnet {
    /// Panics with a clear message if either node's background thread has crashed.
    pub fn assert_nodes_alive(&self) {
        assert!(
            self.validator.node_handle.is_node_alive(),
            "Validator node crashed"
        );
        assert!(
            self.observer.node_handle.is_node_alive(),
            "Observer node crashed"
        );
    }

    pub async fn shutdown(mut self) {
        self.validator.node_handle.send_shutdown();
        self.observer.node_handle.send_shutdown();
        // RocksDB cleanup happens asynchronously after the actor system stops;
        // block until all instances are dropped to avoid test interference.
        tokio::task::spawn_blocking(|| {
            near_store::db::RocksDB::block_until_all_instances_are_dropped();
        })
        .await
        .unwrap();
    }
}

/// Returns a temp directory.
/// The returned `TempDir` is automatically deleted when dropped.
fn make_test_home_dir(account_id: &str) -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix(&format!("{account_id}-"))
        .tempdir()
        .expect("create temp home dir")
}
