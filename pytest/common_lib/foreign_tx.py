"""
Helper functions for foreign chain transaction verification tests.
"""

import base64
import json
import requests
import time
from typing import Optional

# Default Solana RPC endpoints for testing
SOLANA_MAINNET_RPC = "https://api.mainnet-beta.solana.com"

# Default provider name for testing
DEFAULT_PROVIDER_NAME = "mainnet"


def get_solana_rpc_config(
    rpc_url: str = SOLANA_MAINNET_RPC,
    backup_rpc_urls: Optional[list[str]] = None,
    timeout_sec: int = 30,
    max_retries: int = 3,
    provider_name: str = DEFAULT_PROVIDER_NAME,
) -> dict:
    """
    Generate Solana RPC configuration for MPC node config.yaml.

    Uses the new provider-based format required for foreign chain policy voting.
    """
    return {
        "solana": {
            "providers": {
                provider_name: {
                    "rpc_url": rpc_url,
                    "backup_urls": backup_rpc_urls or [],
                }
            },
            "timeout_sec": timeout_sec,
            "max_retries": max_retries,
        }
    }


def generate_vote_foreign_chain_policy_args(
    provider_names: list[str],
    chain: str = "Solana",
) -> dict:
    """
    Generate arguments for the vote_foreign_chain_policy contract call.

    Args:
        provider_names: List of provider names (e.g., ["mainnet", "alchemy"]).
        chain: The foreign chain (currently only "Solana" is supported).

    Returns:
        Dictionary suitable for passing to the contract's vote_foreign_chain_policy method.
    """
    return {
        "proposal": {
            "chains": [
                {
                    "chain": chain,
                    "required_providers": [{"0": name} for name in provider_names],
                }
            ]
        }
    }


def get_foreign_chain_policy(cluster) -> dict:
    """
    Get the current foreign chain policy from the contract using a view call.

    Returns:
        The foreign chain policy as a dict, or empty dict if not set.
    """
    # Use the contract node's near_node to make a view call
    result = cluster.contract_node.near_node.call_function(
        cluster.mpc_contract_account(),
        "get_foreign_chain_policy",
        base64.b64encode(b"{}").decode("utf-8"),
    )

    if "error" in result:
        raise Exception(f"Error calling get_foreign_chain_policy: {result['error']}")

    # Decode the result
    result_bytes = bytes(result["result"]["result"])
    return json.loads(result_bytes.decode("utf-8"))


def wait_for_foreign_chain_policy(
    cluster,
    expected_chain: str = "Solana",
    timeout_sec: int = 60,
) -> bool:
    """
    Wait for the foreign chain policy to be established (non-empty).

    Args:
        cluster: The MpcCluster instance.
        expected_chain: The chain that should be in the policy.
        timeout_sec: Maximum time to wait.

    Returns:
        True if policy was established within timeout, False otherwise.
    """
    start_time = time.time()
    last_policy_print = 0
    while time.time() - start_time < timeout_sec:
        try:
            policy = get_foreign_chain_policy(cluster)
            # Print policy every 5 seconds for debugging
            if time.time() - last_policy_print > 5:
                print(f"Current policy: {policy}")
                last_policy_print = time.time()
            if policy and "chains" in policy and len(policy["chains"]) > 0:
                # Check if expected chain is in policy
                for chain_entry in policy["chains"]:
                    if chain_entry.get("chain") == expected_chain:
                        print(f"\033[92mForeign chain policy established: {policy}\033[0m")
                        return True
        except Exception as e:
            print(f"Error getting policy: {e}")

        time.sleep(1)

    print(f"\033[91mTimeout waiting for foreign chain policy\033[0m")
    return False


def fetch_recent_finalized_transaction(rpc_url: str = SOLANA_MAINNET_RPC) -> str:
    """
    Fetch a recent finalized transaction signature from Solana mainnet.

    This is needed because Solana RPC doesn't keep infinite history,
    so we need to use a recent transaction for verification tests.

    Returns:
        A base58-encoded transaction signature.
    """
    headers = {"Content-Type": "application/json"}

    # Get current finalized slot
    get_slot_request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getSlot",
        "params": [{"commitment": "finalized"}]
    }

    response = requests.post(rpc_url, headers=headers, json=get_slot_request, timeout=30)
    current_slot = response.json()["result"]

    # Try recent slots to find one with transactions
    for offset in range(0, 100, 5):
        slot = current_slot - offset

        get_block_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getBlock",
            "params": [
                slot,
                {
                    "encoding": "json",
                    "transactionDetails": "signatures",
                    "rewards": False,
                    "maxSupportedTransactionVersion": 0,
                }
            ]
        }

        response = requests.post(rpc_url, headers=headers, json=get_block_request, timeout=30)
        result = response.json().get("result")

        if result and result.get("signatures"):
            # Return the first transaction signature
            return result["signatures"][0]

    raise RuntimeError("Could not find a recent finalized transaction on Solana")


def generate_verify_foreign_tx_args(
    tx_signature: str,
    chain: str = "Solana",
    finality: str = "Final",
    path: str = "test",
    domain_id: Optional[int] = None,
) -> dict:
    """
    Generate arguments for the verify_foreign_transaction contract call.

    Args:
        tx_signature: Base58-encoded Solana transaction signature.
        chain: The foreign chain (currently only "Solana" is supported).
        finality: Finality level - "Final" or "Optimistic".
        path: Key derivation path.
        domain_id: Optional domain ID (defaults to legacy ECDSA).

    Returns:
        Dictionary suitable for passing to the contract's verify_foreign_transaction method.
    """
    args = {
        "request": {
            "chain": chain,
            "tx_id": {"SolanaSignature": tx_signature},
            "finality": finality,
            "path": path,
        }
    }

    if domain_id is not None:
        args["request"]["domain_id"] = domain_id

    return args


def assert_verify_foreign_tx_success(res) -> dict:
    """
    Assert that a verify_foreign_transaction call succeeded and return the response.

    Args:
        res: The transaction result from NEAR RPC.

    Returns:
        The decoded response containing verified_at_block and signature.

    Raises:
        AssertionError: If the transaction failed.
    """
    try:
        result_base64 = res["result"]["status"]["SuccessValue"]
    except KeyError:
        raise AssertionError(f"verify_foreign_transaction failed: {json.dumps(res, indent=1)}")

    # Pad base64 string if necessary
    result_base64 += "=" * ((4 - len(result_base64) % 4) % 4)
    result = json.loads(base64.b64decode(result_base64))

    print("\033[96mVerify Foreign Tx Response ✓\033[0m")
    print(f"  Verified at block: {result.get('verified_at_block')}")

    return result
