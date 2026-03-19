use assert_matches::assert_matches;
use base64::Engine;
use chain_gateway::errors::ChainGatewayError;
use chain_gateway::state_viewer::WatchContractState;
use chain_gateway::state_viewer::{SubscribeToContractMethod, ViewMethod};
use chain_gateway::types::NoArgs;
use chain_gateway::types::ObservedState;
use near_indexer::near_primitives::hash::hash;
use near_indexer::near_primitives::types::Finality;
use std::path::Path;

const TEST_CONTRACT_ACCOUNT: &str = "test-contract.near";
const TEST_STRING: &str = "hello from test";
const TEST_METHOD: &str = "get_greeting";

/// spawns a local neard node, inserts a test contract and checks if viewing a valid contract method succeeds
#[tokio::test]
async fn test_view_method_contract_state() {
    let (gw, _dir) = setup_chain_gateway().await;

    let value: ObservedState<String> = gw
        .view_method(
            TEST_CONTRACT_ACCOUNT.parse().unwrap(),
            TEST_METHOD,
            &NoArgs {},
        )
        .await
        .expect("view call should succeed");

    assert_eq!(value.value, TEST_STRING);
}

/// spawns a local neard node, inserts a test contract and checks if viewing an invalid contract method fails
#[tokio::test]
async fn test_view_method_nonexistent_method_returns_error() {
    let (gw, _dir) = setup_chain_gateway().await;

    let result = gw
        .view_method::<NoArgs, String>(
            TEST_CONTRACT_ACCOUNT.parse().unwrap(),
            "nonexistent",
            &NoArgs {},
        )
        .await;

    let err = result.expect_err("calling a nonexistent method should fail");
    assert_matches!(err, ChainGatewayError::ViewError { .. });
}

/// Spawns a local neard node, inserts a test contract and checks if subscribing to the state
/// succeeds
#[tokio::test]
async fn test_subscription_receives_initial_value() {
    let (gw, _dir) = setup_chain_gateway().await;

    let mut sub = gw
        .subscribe_to_contract_method::<String>(TEST_CONTRACT_ACCOUNT.parse().unwrap(), TEST_METHOD)
        .await;

    let res = sub.latest().expect("subscription latest should succeed");
    assert_eq!(res.value, TEST_STRING);
}

async fn setup_chain_gateway() -> (
    chain_gateway::chain_gateway::ChainGateway,
    tempfile::TempDir,
) {
    let dir = tempfile::tempdir().unwrap();

    near_indexer::indexer_init_configs(
        &dir.path().to_path_buf(),
        near_indexer::InitConfigArgs {
            chain_id: Some("localnet".to_string()),
            account_id: Some("test.near".to_string()),
            test_seed: Some("test.near".to_string()),
            num_shards: 1,
            fast: true,
            genesis: None,
            download_genesis: false,
            download_genesis_url: None,
            download_records_url: None,
            download_config: None,
            download_config_url: None,
            boot_nodes: None,
            max_gas_burnt_view: None,
        },
    )
    .expect("indexer_init_configs should succeed");

    inject_test_contract(dir.path(), TEST_CONTRACT_ACCOUNT);
    randomize_config_ports(dir.path());

    let indexer_config = near_indexer::IndexerConfig {
        home_dir: dir.path().to_path_buf(),
        sync_mode: near_indexer::SyncModeEnum::LatestSynced,
        await_for_node_synced: near_indexer::AwaitForNodeSyncedEnum::WaitForFullSync,
        finality: Finality::Final,
        validate_genesis: true,
    };

    let gw = chain_gateway::chain_gateway::ChainGateway::start(indexer_config)
        .await
        .expect("chain_gateway::start should succeed");

    (gw, dir)
}

// TODO(#2343): Once we have transactions, add a method that changes the contract state. Then verify that
// the viewer sees it correctly

/// Minimal WASM contract: `get_greeting` returns `TEST_STRING`.
fn test_contract_wasm() -> Vec<u8> {
    let wat = format!(
        r#"(module
            (import "env" "value_return" (func $value_return (param i64 i64)))
            (memory (export "memory") 1)
            (data (i32.const 0) "\"{}\"")
            (func (export "{}")
                (call $value_return (i64.const {}) (i64.const 0))
            )
        )"#,
        TEST_STRING,
        TEST_METHOD,
        TEST_STRING.len() + 2, // adjust for quotes
    );

    wat::parse_str(&wat).expect("WAT should compile to valid WASM")
}

/// Inject a contract account into genesis.json before the node starts.
///
/// Adds three state records: Account (with code_hash), Contract (base64 WASM),
/// and AccessKey (FullAccess). This embeds the contract directly in genesis so
/// we don't need to deploy via transaction.
fn inject_test_contract(home_dir: &Path, account_id: &str) {
    let genesis_path = home_dir.join("genesis.json");
    let genesis_text = std::fs::read_to_string(&genesis_path).expect("read genesis.json");
    let mut genesis: serde_json::Value =
        serde_json::from_str(&genesis_text).expect("parse genesis.json");
    *genesis.get_mut("total_supply").unwrap() =
        serde_json::json!("2050000010000000000000000000000000");

    let wasm = test_contract_wasm();
    let code_hash = hash(&wasm).to_string();
    let code_base64 = base64::engine::general_purpose::STANDARD.encode(&wasm);

    let records = genesis
        .get_mut("records")
        .expect("genesis should have records")
        .as_array_mut()
        .expect("records should be an array");

    // Account record
    records.push(serde_json::json!({
        "Account": {
            "account_id": account_id,
            "account": {
                "amount": "10000000000000000000000000",
                "locked": "0",
                "code_hash": code_hash,
                "storage_usage": 0,
                "version": "V1"
            }
        }
    }));

    // Contract record (code field uses base64 encoding, matching StateRecord serde)
    records.push(serde_json::json!({
        "Contract": {
            "account_id": account_id,
            "code": code_base64
        }
    }));

    // AccessKey record (not strictly required for view calls, but mirrors real accounts)
    records.push(serde_json::json!({
        "AccessKey": {
            "account_id": account_id,
            "public_key": "ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp",
            "access_key": {
                "nonce": 0,
                "permission": "FullAccess"
            }
        }
    }));

    let updated = serde_json::to_string_pretty(&genesis).expect("serialize genesis.json");
    std::fs::write(&genesis_path, updated).expect("write genesis.json");
}

/// Find an available TCP port by binding to port 0 and reading the assigned port.
fn find_available_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind to port 0");
    listener.local_addr().unwrap().port()
}

/// Rewrite config.json to use unique free ports for network and RPC
/// so that multiple test nodes don't collide.
fn randomize_config_ports(home_dir: &Path) {
    let config_path = home_dir.join("config.json");
    let config_text = std::fs::read_to_string(&config_path).expect("read config.json");
    let mut config: serde_json::Value =
        serde_json::from_str(&config_text).expect("parse config.json");

    let network_port = find_available_port();
    let rpc_port = find_available_port();

    config["network"]["addr"] = serde_json::json!(format!("127.0.0.1:{network_port}"));
    config["rpc"]["addr"] = serde_json::json!(format!("127.0.0.1:{rpc_port}"));

    let updated = serde_json::to_string_pretty(&config).expect("serialize config.json");
    std::fs::write(&config_path, updated).expect("write config.json");
}
