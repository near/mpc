#!/usr/bin/env python3
"""
End-to-end system test for the foreign transaction validation flow.

Exercises: user submits verify_foreign_transaction() -> MPC nodes fetch from
a mock Bitcoin JSON-RPC server -> nodes collaboratively sign -> response
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
from common_lib.constants import TGAS
from common_lib.contract_state import ProtocolState
from common_lib.contracts import load_mpc_contract
from common_lib.shared import MpcCluster
from common_lib.shared import foreign_chains
from common_lib.shared import utils

MOCK_BLOCK_HASH = "aa" * 32  # 64 hex chars, 32 bytes
MOCK_TX_ID = "bb" * 32  # 64 hex chars, 32 bytes



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
                "error": {"code": -32601, "message": f"Method not found: {method}"},
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


def _start_mock_bitcoin_rpc() -> tuple[HTTPServer, int]:
    """Start a mock Bitcoin RPC server on an OS-assigned port. Returns (server, port)."""
    server = HTTPServer(("127.0.0.1", 0), _BitcoinRpcHandler)
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
    mock_server, mock_port = _start_mock_bitcoin_rpc()
    mock_rpc_url = f"http://127.0.0.1:{mock_port}"

    contract = load_mpc_contract()
    cluster, mpc_nodes = shared.start_cluster_with_mpc(
        2, 1, contract, start_mpc_nodes=False
    )

    bitcoin_config = {
        "bitcoin": {
            "timeout_sec": 30,
            "max_retries": 3,
            "providers": {
                "mock": {
                    "api_variant": "standard",
                    "rpc_url": mock_rpc_url,
                    "auth": {
                        "kind": "none",
                    },
                }
            },
        }
    }

    for node in mpc_nodes:
        foreign_chains.set_foreign_chains_config(node, bitcoin_config)

    for node in mpc_nodes:
        node.run()

    cluster.init_cluster(participants=mpc_nodes, threshold=2)
    assert cluster.wait_for_state(ProtocolState.RUNNING), "expected running state"

    # Wait for the foreign chain policy to be applied (unanimous auto-vote).
    expected_policy = foreign_chains.normalize_policy(
        {
            "chains": [
                {
                    "chain": "Bitcoin",
                    "providers": [{"rpc_url": mock_rpc_url}],
                }
            ]
        }
    )

    def policy_applied() -> bool:
        policy = cluster.view_contract_function("get_foreign_chain_policy")
        return foreign_chains.normalize_policy(policy) == expected_policy

    utils.wait_until(
        policy_applied,
        description="foreign chain policy applied after unanimous voting",
        timeout_sec=60,
    )

    yield cluster, mpc_nodes

    cluster.kill_all()
    mock_server.shutdown()
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
        gas=15 * TGAS,
        deposit=1,
    )

    # Send, await, and verify response
    def verify_response(res):
        try:
            success_value = res["result"]["status"]["SuccessValue"]
        except KeyError:
            raise AssertionError(
                f"Expected SuccessValue in response: {json.dumps(res, indent=2)}"
            )

        # Decode the base64-encoded JSON response
        padded = success_value + "=" * ((4 - len(success_value) % 4) % 4)
        response = json.loads(base64.b64decode(padded))

        print(f"\033[96mVerify Foreign Tx Response: {json.dumps(response, indent=2)}\033[0m")

        # Verify payload structure
        payload = response["payload"]
        assert "V1" in payload, f"Expected V1 payload, got: {payload}"

        v1 = payload["V1"]

        # Verify extracted values contain the mock block hash
        values = v1["values"]
        assert len(values) > 0, "Expected at least one extracted value"
        block_hash_value = values[0]
        assert "Hash256" in block_hash_value, f"Expected Hash256, got: {block_hash_value}"
        assert block_hash_value["Hash256"] == MOCK_BLOCK_HASH, (
            f"Expected block hash {MOCK_BLOCK_HASH}, got {block_hash_value['Hash256']}"
        )

        # Verify the request in the payload matches what we submitted
        assert "Bitcoin" in v1["request"], f"Expected Bitcoin request, got: {v1['request']}"

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
