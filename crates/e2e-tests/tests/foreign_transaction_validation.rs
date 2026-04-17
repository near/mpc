use crate::common;

use std::io::{BufRead, BufReader, Write as _};
use std::net::TcpListener;
use std::time::Duration;

use backon::{ConstantBuilder, Retryable};
use mpc_node_config::ForeignChainsConfig;
use mpc_node_config::foreign_chains::{
    AbstractApiVariant, AbstractChainConfig, AbstractProviderConfig, BitcoinApiVariant,
    BitcoinChainConfig, BitcoinProviderConfig, BnbApiVariant, BnbChainConfig, BnbProviderConfig,
    StarknetApiVariant, StarknetChainConfig, StarknetProviderConfig,
};
use near_mpc_bounded_collections::NonEmptyBTreeMap;
use near_mpc_contract_interface::types::{Curve, DomainConfig, DomainId, DomainPurpose};

const MOCK_BLOCK_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const MOCK_TX_ID: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

// ---------------------------------------------------------------------------
// Mock JSON-RPC servers
// ---------------------------------------------------------------------------

/// Start a mock JSON-RPC HTTP server on an OS-assigned port.
/// Each incoming connection is handled in its own thread so concurrent
/// requests from the MPC nodes don't block each other.
fn start_mock_server(handler: fn(&serde_json::Value) -> serde_json::Value) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind mock server");
    let port = listener.local_addr().unwrap().port();

    std::thread::spawn(move || {
        for stream_result in listener.incoming() {
            let stream = match stream_result {
                Ok(s) => s,
                Err(_) => continue,
            };
            std::thread::spawn(move || {
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(10)))
                    .ok();

                let mut reader = BufReader::new(&stream);
                let mut content_length = 0usize;

                // Read HTTP headers line by line until blank line.
                loop {
                    let mut line = String::new();
                    match reader.read_line(&mut line) {
                        Ok(0) | Err(_) => return,
                        _ => {}
                    }
                    if line == "\r\n" {
                        break;
                    }
                    if line.to_ascii_lowercase().starts_with("content-length:") {
                        if let Some(val) = line.split(':').nth(1) {
                            content_length = val.trim().parse().unwrap_or(0);
                        }
                    }
                }

                // Read exactly Content-Length bytes of body.
                let mut body = vec![0u8; content_length];
                if content_length > 0 {
                    use std::io::Read;
                    if reader.read_exact(&mut body).is_err() {
                        return;
                    }
                }

                let request: serde_json::Value =
                    serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
                let response = handler(&request);
                let response_body = serde_json::to_string(&response).unwrap();
                let http_response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    response_body.len(),
                    response_body
                );
                let mut writer = stream;
                let _ = writer.write_all(http_response.as_bytes());
                let _ = writer.flush();
            });
        }
    });

    port
}

fn bitcoin_rpc_handler(request: &serde_json::Value) -> serde_json::Value {
    let request_id = request
        .get("id")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let method = request.get("method").and_then(|m| m.as_str()).unwrap_or("");

    if method == "getrawtransaction" {
        serde_json::json!({
            "jsonrpc": "2.0",
            "result": {
                "blockhash": MOCK_BLOCK_HASH,
                "confirmations": 10,
            },
            "id": request_id,
        })
    } else {
        serde_json::json!({
            "jsonrpc": "2.0",
            "error": {
                "code": -32601,
                "message": format!("Method not found: {method}"),
            },
            "id": request_id,
        })
    }
}

fn evm_rpc_handler(request: &serde_json::Value) -> serde_json::Value {
    let request_id = request
        .get("id")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let method = request.get("method").and_then(|m| m.as_str()).unwrap_or("");

    if method == "eth_getBlockByNumber" {
        serde_json::json!({
            "jsonrpc": "2.0",
            "result": { "number": "0x16740f3" },
            "id": request_id,
        })
    } else if method == "eth_getTransactionReceipt" {
        serde_json::json!({
            "jsonrpc": "2.0",
            "result": {
                "blockHash": format!("0x{MOCK_BLOCK_HASH}"),
                "blockNumber": "0xa",
                "status": "0x1",
                "logs": [{
                    "address": "0x000000000000000000000000000000000000800a",
                    "topics": [
                        "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
                        "0x000000000000000000000000edaf4083f29753753d0cd6c3c50aceb08c87b5bd",
                        "0x0000000000000000000000000000000000000000000000000000000000008001",
                    ],
                    "data": "0x000000000000000000000000000000000000000000000000000006e4b5898a00",
                    "blockHash": "0x4c93dd4a8f347e6480b0a44f8c2b7eecdfb31d711e8d542fd60112ea5d98fb02",
                    "blockNumber": "0xfbf4b1",
                    "l1BatchNumber": "0x4f3c",
                    "transactionHash": "0x497fc5f5b5d81d6bc15cccc6d4d8be8ef6ad19376233b944a60dc435593f7234",
                    "transactionIndex": "0x0",
                    "logIndex": "0x0",
                    "transactionLogIndex": "0x0",
                    "removed": false,
                    "blockTimestamp": "0x69864dd4",
                }],
            },
            "id": request_id,
        })
    } else {
        serde_json::json!({
            "jsonrpc": "2.0",
            "error": {
                "code": -32601,
                "message": format!("Method not found: {method}"),
            },
            "id": request_id,
        })
    }
}

fn starknet_rpc_handler(request: &serde_json::Value) -> serde_json::Value {
    let request_id = request
        .get("id")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let method = request.get("method").and_then(|m| m.as_str()).unwrap_or("");

    if method == "starknet_getTransactionReceipt" {
        serde_json::json!({
            "result": {
                "type": "INVOKE",
                "transaction_hash": "0x52a6c2b9d1d1b77dbc322b298fd91f39e3cca9bf1db4a7aa79f14a90efa633e",
                "actual_fee": { "amount": "0xe97d3e61059940", "unit": "FRI" },
                "execution_status": "SUCCEEDED",
                "finality_status": "ACCEPTED_ON_L1",
                "block_hash": format!("0x{MOCK_BLOCK_HASH}"),
                "block_number": 6868546,
                "messages_sent": [],
                "events": [
                    {
                        "from_address": "0x377c2d65debb3978ea81904e7d59740da1f07412e30d01c5ded1c5d6f1ddc43",
                        "keys": [
                            "0x99cd8bde557814842a3121e8ddfd433a539b8c9f14bf31ebf108d12e6196e9",
                            "0x0",
                            "0x42ec39c9e6f0598af2f3e94f9f94e32710af47921da7989875d6fe1a6bebdf4",
                            "0xa890956905f240e4b50eccc026d6f5ed",
                            "0x0",
                        ],
                        "data": [],
                    },
                    {
                        "from_address": "0x42ec39c9e6f0598af2f3e94f9f94e32710af47921da7989875d6fe1a6bebdf4",
                        "keys": [
                            "0x1dcde06aabdbca2f80aa51392b345d7549d7757aa855f7e37f5d335ac8243b1",
                            "0x29ccfaa9597a35ee361a95470a8df3ec7e817bcb0ce264ef6c903d295c47757",
                        ],
                        "data": ["0x1", "0x0"],
                    },
                    {
                        "from_address": "0x127021a1b5a52d3174c2ab077c2b043c80369250d29428cee956d76ee51584f",
                        "keys": [
                            "0x2495e87dbfae534a775dc432ffb2b4c64cd5b8e42a9dd1984ee7f424e46feb9"
                        ],
                        "data": [
                            "0x42ec39c9e6f0598af2f3e94f9f94e32710af47921da7989875d6fe1a6bebdf4",
                            "0x1",
                            "0x1e8ad5efb5efdbd97f9f5ce49e5efb6279b5e05bb79b488edd836ce614e2ef4",
                        ],
                    },
                    {
                        "from_address": "0x7c183208cf2fc08503ed1edb44694295a07d0adc25bb6dad1b40f4540a427fa",
                        "keys": [
                            "0x1dcde06aabdbca2f80aa51392b345d7549d7757aa855f7e37f5d335ac8243b1",
                            "0x52a6c2b9d1d1b77dbc322b298fd91f39e3cca9bf1db4a7aa79f14a90efa633e",
                        ],
                        "data": ["0x1", "0x1", "0x1"],
                    },
                    {
                        "from_address": "0x4718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d",
                        "keys": [
                            "0x99cd8bde557814842a3121e8ddfd433a539b8c9f14bf31ebf108d12e6196e9"
                        ],
                        "data": [
                            "0x7c183208cf2fc08503ed1edb44694295a07d0adc25bb6dad1b40f4540a427fa",
                            "0x1176a1bd84444c89232ec27754698e5d2e7e1a7f1539f12027f28b23ec9f3d8",
                            "0xe97d3e61059940",
                            "0x0",
                        ],
                    },
                ],
                "execution_resources": {
                    "l1_gas": 0,
                    "l2_gas": 3159360,
                    "l1_data_gas": 512,
                },
            },
            "jsonrpc": "2.0",
            "id": request_id,
        })
    } else {
        serde_json::json!({
            "jsonrpc": "2.0",
            "error": {
                "code": -32601,
                "message": format!("Method not found: {method}"),
            },
            "id": request_id,
        })
    }
}

// ---------------------------------------------------------------------------
// Cluster setup helper
// ---------------------------------------------------------------------------

struct MockServers {
    bitcoin_url: String,
    abstract_url: String,
    bnb_url: String,
    starknet_url: String,
}

fn start_all_mock_servers() -> MockServers {
    let bitcoin_port = start_mock_server(bitcoin_rpc_handler);
    let abstract_port = start_mock_server(evm_rpc_handler);
    let bnb_port = start_mock_server(evm_rpc_handler);
    let starknet_port = start_mock_server(starknet_rpc_handler);

    MockServers {
        bitcoin_url: format!("http://127.0.0.1:{bitcoin_port}"),
        abstract_url: format!("http://127.0.0.1:{abstract_port}"),
        bnb_url: format!("http://127.0.0.1:{bnb_port}"),
        starknet_url: format!("http://127.0.0.1:{starknet_port}"),
    }
}

fn build_foreign_chains_config(servers: &MockServers) -> ForeignChainsConfig {
    ForeignChainsConfig {
        bitcoin: Some(BitcoinChainConfig {
            timeout_sec: 30,
            max_retries: 3,
            providers: NonEmptyBTreeMap::new(
                "mock".to_string(),
                BitcoinProviderConfig {
                    rpc_url: servers.bitcoin_url.clone(),
                    api_variant: BitcoinApiVariant::Standard,
                    auth: Default::default(),
                },
            ),
        }),
        abstract_chain: Some(AbstractChainConfig {
            timeout_sec: 30,
            max_retries: 3,
            providers: NonEmptyBTreeMap::new(
                "mock".to_string(),
                AbstractProviderConfig {
                    rpc_url: servers.abstract_url.clone(),
                    api_variant: AbstractApiVariant::Standard,
                    auth: Default::default(),
                },
            ),
        }),
        bnb: Some(BnbChainConfig {
            timeout_sec: 30,
            max_retries: 3,
            providers: NonEmptyBTreeMap::new(
                "mock".to_string(),
                BnbProviderConfig {
                    rpc_url: servers.bnb_url.clone(),
                    api_variant: BnbApiVariant::Standard,
                    auth: Default::default(),
                },
            ),
        }),
        starknet: Some(StarknetChainConfig {
            timeout_sec: 30,
            max_retries: 3,
            providers: NonEmptyBTreeMap::new(
                "mock".to_string(),
                StarknetProviderConfig {
                    rpc_url: servers.starknet_url.clone(),
                    api_variant: StarknetApiVariant::Standard,
                    auth: Default::default(),
                },
            ),
        }),
        ..Default::default()
    }
}

async fn setup_foreign_tx_cluster() -> (e2e_tests::MpcCluster, MockServers) {
    let servers = start_all_mock_servers();
    let fc_config = build_foreign_chains_config(&servers);

    let (cluster, _running) = common::setup_cluster(common::FOREIGN_TX_VALIDATION_PORT_SEED, |c| {
        c.num_nodes = 2;
        c.threshold = 2;
        // Only Secp256k1 ForeignTx domain
        c.domains = vec![DomainConfig {
            id: DomainId(0),
            curve: Curve::Secp256k1,
            purpose: DomainPurpose::ForeignTx,
        }];
        c.node_foreign_chains_configs = vec![fc_config.clone(), fc_config];
    })
    .await;

    // Wait for the foreign chain policy to be applied (unanimous auto-vote).
    let policy_timeout = Duration::from_secs(60);
    (|| async {
        let policy = cluster
            .view_foreign_chain_policy()
            .await
            .expect("failed to view policy");
        anyhow::ensure!(
            !policy.chains.is_empty(),
            "foreign chain policy not yet applied"
        );
        Ok(())
    })
    .retry(
        ConstantBuilder::default()
            .with_delay(common::POLL_INTERVAL)
            .with_max_times(
                (policy_timeout.as_millis() / common::POLL_INTERVAL.as_millis()) as usize,
            ),
    )
    .await
    .expect("timed out waiting for foreign chain policy to be applied");

    (cluster, servers)
}

// ---------------------------------------------------------------------------
// Response verification
// ---------------------------------------------------------------------------

fn verify_foreign_tx_response(outcome: &near_kit::FinalExecutionOutcome) {
    assert!(
        outcome.is_success(),
        "verify_foreign_transaction failed: {:?}",
        outcome.failure_message()
    );

    // Extract and parse the SuccessValue from the outcome
    let response: serde_json::Value = outcome
        .json()
        .expect("failed to parse verify_foreign_transaction response");

    tracing::info!(?response, "verify_foreign_transaction response");

    // Verify payload_hash is present and is 64 hex chars
    let payload_hash = response["payload_hash"]
        .as_str()
        .expect("expected payload_hash string");
    assert_eq!(
        payload_hash.len(),
        64,
        "expected 64 hex chars in payload_hash, got {}",
        payload_hash.len()
    );

    // Verify signature is present and is Secp256k1
    let signature = &response["signature"];
    assert_eq!(
        signature["scheme"].as_str().unwrap(),
        "Secp256k1",
        "expected Secp256k1 signature scheme"
    );
    assert!(
        signature.get("big_r").is_some(),
        "expected big_r in signature"
    );
    assert!(signature.get("s").is_some(), "expected s in signature");
    assert!(
        signature.get("recovery_id").is_some(),
        "expected recovery_id in signature"
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Verify foreign transaction signing for Bitcoin, Abstract, and Starknet.
///
/// Sets up a single 2-node cluster with mock RPC servers for all chains,
/// then submits verify_foreign_transaction requests for each chain and
/// verifies the MPC nodes return valid signed responses.
#[tokio::test]
#[expect(non_snake_case)]
async fn verify_foreign_transaction__should_sign_bitcoin_abstract_and_starknet() {
    let (cluster, _servers) = setup_foreign_tx_cluster().await;

    let state = cluster
        .get_contract_state()
        .await
        .expect("failed to get contract state");
    let running = match &state {
        near_mpc_contract_interface::types::ProtocolContractState::Running(r) => r,
        _ => panic!("expected Running state"),
    };
    let secp_domain = running
        .domains
        .domains
        .iter()
        .find(|d| d.curve == Curve::Secp256k1)
        .expect("no Secp256k1 domain");

    // Bitcoin
    let request = serde_json::json!({
        "request": {
            "Bitcoin": {
                "tx_id": MOCK_TX_ID,
                "confirmations": 1,
                "extractors": ["BlockHash"],
            }
        },
        "domain_id": secp_domain.id,
        "payload_version": 1,
    });
    let outcome = cluster
        .send_verify_foreign_transaction(request)
        .await
        .expect("verify_foreign_transaction (Bitcoin) call failed");
    verify_foreign_tx_response(&outcome);
    tracing::info!("Bitcoin verify_foreign_transaction passed");

    // Abstract (EVM)
    let request = serde_json::json!({
        "request": {
            "Abstract": {
                "tx_id": MOCK_TX_ID,
                "finality": "Finalized",
                "extractors": ["BlockHash", { "Log": { "log_index": 0 } }],
            }
        },
        "domain_id": secp_domain.id,
        "payload_version": 1,
    });
    let outcome = cluster
        .send_verify_foreign_transaction(request)
        .await
        .expect("verify_foreign_transaction (Abstract) call failed");
    verify_foreign_tx_response(&outcome);
    tracing::info!("Abstract verify_foreign_transaction passed");

    // Starknet
    let request = serde_json::json!({
        "request": {
            "Starknet": {
                "tx_id": MOCK_TX_ID,
                "finality": "AcceptedOnL1",
                "extractors": ["BlockHash"],
            }
        },
        "domain_id": secp_domain.id,
        "payload_version": 1,
    });
    let outcome = cluster
        .send_verify_foreign_transaction(request)
        .await
        .expect("verify_foreign_transaction (Starknet) call failed");
    verify_foreign_tx_response(&outcome);
    tracing::info!("Starknet verify_foreign_transaction passed");
}
