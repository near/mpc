"""
Helper functions for foreign chain transaction verification tests.
"""

import base64
import json
import requests
from typing import Optional

# Default Solana RPC endpoints for testing
SOLANA_MAINNET_RPC = "https://api.mainnet-beta.solana.com"


def get_solana_rpc_config(
    rpc_url: str = SOLANA_MAINNET_RPC,
    backup_rpc_urls: Optional[list[str]] = None,
    timeout_sec: int = 30,
    max_retries: int = 3,
) -> dict:
    """
    Generate Solana RPC configuration for MPC node config.yaml.
    """
    return {
        "solana": {
            "rpc_url": rpc_url,
            "backup_rpc_urls": backup_rpc_urls or [],
            "timeout_sec": timeout_sec,
            "max_retries": max_retries,
        }
    }


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
