//! Mock JSON-RPC servers for foreign chain e2e tests.
//!
//! Uses [`httpmock`] to set up lightweight mock servers that mimic Bitcoin, EVM,
//! and Starknet JSON-RPC endpoints, returning hardcoded responses for the methods
//! the MPC nodes call during `verify_foreign_transaction`.

use httpmock::prelude::*;
use httpmock::{HttpMockRequest, HttpMockResponse};

/// A [`MockServer`] paired with the id of a registered [`httpmock::Mock`], so
/// tests can recover the `Mock<'_>` (which borrows from the server) on demand
/// and read its hit count. Storing the `Mock` directly would make this struct
/// self-referential.
pub struct MockServerExt {
    pub server: MockServer,
    pub mock_id: usize,
}

impl MockServerExt {
    pub fn new(server: MockServer, mock_id: usize) -> Self {
        Self { server, mock_id }
    }

    /// Number of HTTP requests the registered mock has matched so far.
    pub fn calls(&self) -> usize {
        httpmock::Mock::new(self.mock_id, &self.server).calls()
    }
}

pub const MOCK_BLOCK_HASH: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
pub const MOCK_TX_ID: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn jsonrpc_error(id: serde_json::Value, method: &str) -> HttpMockResponse {
    let response_body = serde_json::json!({
        "jsonrpc": "2.0",
        "error": { "code": -32601, "message": format!("method not found: {method}") },
        "id": id,
    });
    HttpMockResponse::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(serde_json::to_string(&response_body).unwrap())
        .build()
}

pub fn setup_bitcoin_mock(server: &MockServer) -> usize {
    server
        .mock(|when, then| {
            when.method(POST).path("/");
            then.respond_with(move |req: &HttpMockRequest| {
                let body: serde_json::Value =
                    serde_json::from_slice(req.body().as_ref()).expect("valid json-rpc request");
                let id = body["id"].clone();
                let method = body["method"].as_str().expect("method field");

                if method != "getrawtransaction" {
                    return jsonrpc_error(id, method);
                }

                let response_body = serde_json::json!({
                    "jsonrpc": "2.0",
                    "result": {
                        "blockhash": MOCK_BLOCK_HASH,
                        "confirmations": 10,
                    },
                    "id": id,
                });

                HttpMockResponse::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(serde_json::to_string(&response_body).unwrap())
                    .build()
            });
        })
        .id
}

pub fn setup_evm_mock(server: &MockServer) -> usize {
    server.mock(|when, then| {
        when.method(POST).path("/");
        then.respond_with(move |req: &HttpMockRequest| {
            let body: serde_json::Value =
                serde_json::from_slice(req.body().as_ref()).expect("valid json-rpc request");
            let id = body["id"].clone();
            let method = body["method"].as_str().expect("method field");

            let result = match method {
                "eth_getBlockByNumber" => {
                    // First param is either a finality tag (e.g. "finalized") for the
                    // finality-head lookup, or a `0x`-prefixed block number for the
                    // canonical-chain lookup. Return a hash matching the receipt's
                    // blockHash for the canonical lookup so the check passes.
                    let block_id = body["params"][0].as_str().expect("block id param");
                    if block_id.starts_with("0x") {
                        serde_json::json!({
                            "number": block_id,
                            "hash": format!("0x{MOCK_BLOCK_HASH}"),
                        })
                    } else {
                        serde_json::json!({
                            "number": "0x16740f3",
                            "hash": format!("0x{MOCK_BLOCK_HASH}"),
                        })
                    }
                }
                "eth_getTransactionReceipt" => {
                    serde_json::json!({
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
                    })
                }
                other => return jsonrpc_error(id, other),
            };

            let response_body = serde_json::json!({
                "jsonrpc": "2.0",
                "result": result,
                "id": id,
            });

            HttpMockResponse::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(serde_json::to_string(&response_body).unwrap())
                .build()
        });
    })
    .id
}

pub fn setup_starknet_mock(server: &MockServer) -> usize {
    server.mock(|when, then| {
        when.method(POST).path("/");
        then.respond_with(move |req: &HttpMockRequest| {
            let body: serde_json::Value =
                serde_json::from_slice(req.body().as_ref()).expect("valid json-rpc request");
            let id = body["id"].clone();
            let method = body["method"].as_str().expect("method field");

            if method != "starknet_getTransactionReceipt" {
                return jsonrpc_error(id, method);
            }

            let response_body = serde_json::json!({
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
                "id": id,
            });

            HttpMockResponse::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(serde_json::to_string(&response_body).unwrap())
                .build()
        });
    })
    .id
}
