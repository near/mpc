#!/usr/bin/env python3
"""
End-to-end system test for the foreign transaction validation flow.

Exercises: user submits verify_foreign_transaction() -> MPC nodes fetch from
a mock Bitcoin/Abstract JSON-RPC server -> nodes collaboratively sign -> response
returned to caller.
"""

import base64
import json
import pathlib
import sys
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

from cluster import atexit
import pytest

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))

from common_lib import shared
from common_lib.constants import (
    GAS_FOR_VERIFY_FOREIGN_TX_CALL,
    TGAS,
    VERIFY_FOREIGN_TX_DEPOSIT,
)
from common_lib.contract_state import ProtocolState
from common_lib.contracts import load_mpc_contract
from common_lib.shared import MpcCluster
from common_lib.shared import foreign_chains
from common_lib.shared import utils

MOCK_BLOCK_HASH = "aa" * 32  # 64 hex chars, 32 bytes
MOCK_TX_ID = "bb" * 32  # 64 hex chars, 32 bytes
JSONRPC_METHOD_NOT_FOUND = -32601


class _BitcoinRpcHandler(BaseHTTPRequestHandler):
    """Handles JSON-RPC 2.0 requests pretending to be a Bitcoin node."""

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        request = json.loads(body)

        request_id = request.get("id")
        method = request.get("method")

        if method == "getrawtransaction":
            response = {
                "jsonrpc": "2.0",
                "result": {
                    "blockhash": MOCK_BLOCK_HASH,
                    "confirmations": 10,
                },
                "id": request_id,
            }
        else:
            response = {
                "jsonrpc": "2.0",
                "error": {
                    "code": JSONRPC_METHOD_NOT_FOUND,
                    "message": f"Method not found: {method}",
                },
                "id": request_id,
            }

        payload = json.dumps(response).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    # Silence per-request log lines
    def log_message(self, format, *args):
        pass


class _EvmRpcHandler(BaseHTTPRequestHandler):
    """Handles JSON-RPC 2.0 requests pretending to be a Evm compatible node."""

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        request = json.loads(body)

        request_id = request.get("id")
        method = request.get("method")

        if method == "eth_getBlockByNumber":
            response = {
                "jsonrpc": "2.0",
                "result": {
                    "number": "0x16740f3",
                },
                "id": request_id,
            }
        elif method == "eth_getTransactionReceipt":
            response = {
                "jsonrpc": "2.0",
                "result": {
                    "blockHash": "0x" + MOCK_BLOCK_HASH,
                    "blockNumber": "0xa",
                    "status": "0x1",
                    "logs": [
                        {
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
                            "removed": False,
                            "blockTimestamp": "0x69864dd4",
                        },
                    ],
                },
                "id": request_id,
            }
        else:
            response = {
                "jsonrpc": "2.0",
                "error": {
                    "code": JSONRPC_METHOD_NOT_FOUND,
                    "message": f"Method not found: {method}",
                },
                "id": request_id,
            }

        payload = json.dumps(response).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    # Silence per-request log lines
    def log_message(self, format, *args):
        pass


def _start_mock_rpc(_RpcHandler) -> tuple[HTTPServer, int]:
    """Start a mock Bitcoin RPC server on an OS-assigned port. Returns (server, port)."""
    server = HTTPServer(("127.0.0.1", 0), _RpcHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port


@pytest.fixture(scope="module")
def foreign_tx_validation_cluster():
    """
    Spin up a 2-node MPC cluster with a mock Bitcoin RPC provider,
    wait for the foreign chain policy to be applied, and yield.
    """
    bitcoin_mock_server, bitcoin_mock_port = _start_mock_rpc(_BitcoinRpcHandler)
    bitcoin_mock_rpc_url = f"http://127.0.0.1:{bitcoin_mock_port}"

    abstract_mock_server, abstract_mock_port = _start_mock_rpc(_EvmRpcHandler)
    abstract_mock_rpc_url = f"http://127.0.0.1:{abstract_mock_port}"

    contract = load_mpc_contract()
    cluster, mpc_nodes = shared.start_cluster_with_mpc(
        2, 1, contract, start_mpc_nodes=False
    )

    foreign_chains_config = {
        "bitcoin": {
            "timeout_sec": 30,
            "max_retries": 3,
            "providers": {
                "mock": {
                    "api_variant": "standard",
                    "rpc_url": bitcoin_mock_rpc_url,
                    "auth": {
                        "kind": "none",
                    },
                }
            },
        },
        "abstract": {
            "timeout_sec": 30,
            "max_retries": 3,
            "providers": {
                "mock": {
                    "api_variant": "standard",
                    "rpc_url": abstract_mock_rpc_url,
                    "auth": {
                        "kind": "none",
                    },
                }
            },
        },
    }

    for node in mpc_nodes:
        foreign_chains.set_foreign_chains_config(node, foreign_chains_config)

    for node in mpc_nodes:
        node.run()

    cluster.init_cluster(participants=mpc_nodes, threshold=2, domains=["Secp256k1"])
    assert cluster.wait_for_state(ProtocolState.RUNNING), "expected running state"

    # Wait for the foreign chain policy to be applied (unanimous auto-vote).
    expected_policy = foreign_chains.normalize_policy(
        {
            "chains": [
                {
                    "chain": "Bitcoin",
                    "providers": [{"rpc_url": bitcoin_mock_rpc_url}],
                },
                {
                    "chain": "Abstract",
                    "providers": [{"rpc_url": abstract_mock_rpc_url}],
                },
            ]
        }
    )

    def policy_applied() -> bool:
        policy = cluster.view_contract_function("get_foreign_chain_policy")
        return foreign_chains.normalize_policy(policy) == expected_policy

    utils.wait_until(
        policy_applied,
        description="foreign chain policy applied after unanimous voting",
        timeout_sec=30,
    )

    yield cluster, mpc_nodes

    cluster.kill_all()
    bitcoin_mock_server.shutdown()
    abstract_mock_server.shutdown()
    atexit._run_exitfuncs()


@pytest.mark.no_atexit_cleanup
def test_verify_foreign_transaction_bitcoin(
    foreign_tx_validation_cluster: tuple[MpcCluster, list],
):
    """
    Submit a verify_foreign_transaction request for Bitcoin and verify
    the MPC nodes return a valid signed response with the expected payload.
    """
    cluster, _mpc_nodes = foreign_tx_validation_cluster

    # Find the Secp256k1 domain
    contract_state = cluster.contract_state()
    domains = contract_state.get_running_domains()
    secp_domain = next(d for d in domains if d.scheme == "Secp256k1")

    # Build the verify_foreign_transaction args
    args = {
        "request": {
            "request": {
                "Bitcoin": {
                    "tx_id": MOCK_TX_ID,
                    "confirmations": 1,
                    "extractors": ["BlockHash"],
                }
            },
            "derivation_path": "test",
            "domain_id": secp_domain.id,
            "payload_version": 1,
        }
    }

    tx = cluster.request_node.sign_tx(
        cluster.mpc_contract_account(),
        "verify_foreign_transaction",
        args,
        gas=GAS_FOR_VERIFY_FOREIGN_TX_CALL * TGAS,
        deposit=VERIFY_FOREIGN_TX_DEPOSIT,
    )

    # Send, await, and verify response
    def verify_response(res):
        try:
            success_value = res["result"]["status"]["SuccessValue"]
        except KeyError:
            raise AssertionError(
                f"Expected SuccessValue in response: {json.dumps(res, indent=2)}"
            )

        response = json.loads(base64.b64decode(success_value))

        print(
            f"\033[96mVerify Foreign Tx Response: {json.dumps(response, indent=2)}\033[0m"
        )

        # Verify payload_hash is present (full payload is no longer returned, only its hash)
        payload_hash = response["payload_hash"]
        assert isinstance(payload_hash, str), (
            f"Expected hex string payload_hash, got: {type(payload_hash)}"
        )
        assert len(payload_hash) == 64, (
            f"Expected 64 hex chars in payload_hash, got: {len(payload_hash)}"
        )

        # Verify signature is present and is Secp256k1
        signature = response["signature"]
        assert signature["scheme"] == "Secp256k1", (
            f"Expected Secp256k1 signature scheme, got: {signature.get('scheme')}"
        )
        assert "big_r" in signature, "Expected big_r in signature"
        assert "s" in signature, "Expected s in signature"
        assert "recovery_id" in signature, "Expected recovery_id in signature"

        print("\033[96mVerify Foreign Tx Response \u2713\033[0m")

    cluster.request_node.send_await_check_txs_parallel(
        "verify_foreign_transaction", [tx], verify_response
    )


@pytest.mark.no_atexit_cleanup
def test_verify_foreign_transaction_abstract(
    foreign_tx_validation_cluster: tuple[MpcCluster, list],
):
    """
    Submit a verify_foreign_transaction request for Abstract and verify
    the MPC nodes return a valid signed response with the expected payload.
    """
    cluster, _mpc_nodes = foreign_tx_validation_cluster

    # Find the Secp256k1 domain
    contract_state = cluster.contract_state()
    domains = contract_state.get_running_domains()
    secp_domain = next(d for d in domains if d.scheme == "Secp256k1")

    # Build the verify_foreign_transaction args
    args = {
        "request": {
            "request": {
                "Abstract": {
                    "tx_id": MOCK_TX_ID,
                    "finality": "Finalized",
                    "extractors": ["BlockHash", {"Log": {"log_index": 0}}],
                }
            },
            "derivation_path": "test",
            "domain_id": secp_domain.id,
            "payload_version": 1,
        }
    }

    tx = cluster.request_node.sign_tx(
        cluster.mpc_contract_account(),
        "verify_foreign_transaction",
        args,
        gas=GAS_FOR_VERIFY_FOREIGN_TX_CALL * TGAS,
        deposit=VERIFY_FOREIGN_TX_DEPOSIT,
    )

    # Send, await, and verify response
    def verify_response(res):
        try:
            success_value = res["result"]["status"]["SuccessValue"]
        except KeyError:
            raise AssertionError(
                f"Expected SuccessValue in response: {json.dumps(res, indent=2)}"
            )

        response = json.loads(base64.b64decode(success_value))

        print(
            f"\033[96mVerify Foreign Tx Response: {json.dumps(response, indent=2)}\033[0m"
        )

        # Verify payload_hash is present (full payload is no longer returned, only its hash)
        payload_hash = response["payload_hash"]
        assert isinstance(payload_hash, str), (
            f"Expected hex string payload_hash, got: {type(payload_hash)}"
        )
        assert len(payload_hash) == 64, (
            f"Expected 64 hex chars in payload_hash, got: {len(payload_hash)}"
        )

        # Verify signature is present and is Secp256k1
        signature = response["signature"]
        assert signature["scheme"] == "Secp256k1", (
            f"Expected Secp256k1 signature scheme, got: {signature.get('scheme')}"
        )
        assert "big_r" in signature, "Expected big_r in signature"
        assert "s" in signature, "Expected s in signature"
        assert "recovery_id" in signature, "Expected recovery_id in signature"

        print("\033[96mVerify Foreign Tx Response \u2713\033[0m")

    cluster.request_node.send_await_check_txs_parallel(
        "verify_foreign_transaction", [tx], verify_response
    )
