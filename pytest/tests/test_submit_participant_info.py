#!/usr/bin/env python3
"""
Tests that MPC nodes successfully call the submit_participant_info endpoint.
"""

import sys
import pathlib
import time
import json
import base64

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
from common_lib import shared
from common_lib.contracts import load_mpc_contract


def get_tee_accounts(cluster):
    """
    Call the get_tee_accounts method on the MPC contract to retrieve registered TEE accounts.
    Returns the TEE accounts data.
    """
    tx = cluster.contract_node.sign_tx(
        cluster.mpc_contract_account(), "get_tee_accounts", {}
    )
    return cluster.contract_node.send_txn_and_check_success(tx)


def test_submit_participant_info_endpoint():
    """
    Test that MPC nodes successfully call submit_participant_info endpoint during startup.

    This test:
    1. Starts a cluster with MPC nodes
    2. Lets nodes call submit_participant_info during their initialization
    3. Uses get_tee_accounts to verify the calls succeeded
    """
    # Start cluster with 2 validators and 2 MPC nodes
    cluster, mpc_nodes = shared.start_cluster_with_mpc(2, 2, 1, load_mpc_contract())

    # Initialize the cluster - this triggers node startup process
    cluster.deploy_contract(load_mpc_contract())
    cluster.init_cluster(mpc_nodes, 2)

    startup_time = 30  # seconds
    print(
        f"Waiting {startup_time} seconds for nodes to complete startup and submit participant info..."
    )
    time.sleep(startup_time)

    # Check if submit_participant_info calls succeeded by querying get_tee_accounts
    tee_accounts_result = get_tee_accounts(cluster)

    print("=== Raw contract response ===")
    print(tee_accounts_result)
    print("===============================")

    # Assert valid contract response format
    assert "result" in tee_accounts_result, (
        "Invalid contract response format - missing 'result' field"
    )

    # Assert successful transaction
    success_value = tee_accounts_result["result"]["status"].get("SuccessValue")
    assert success_value, "No SuccessValue found in contract response"

    # Decode and parse the result
    decoded_result = base64.b64decode(success_value).decode("utf-8")
    print(f"Decoded result: {decoded_result}")
    tee_accounts = json.loads(decoded_result)
    tee_account_count = len(tee_accounts) if isinstance(tee_accounts, list) else 0

    print(f"   📊 Contract shows {tee_account_count} registered TEE accounts")

    # Assert that submit_participant_info calls succeeded
    assert tee_account_count > 0, (
        f"Expected successful submit_participant_info calls with registered TEE accounts, "
        f"but found {tee_account_count}. This indicates the submit_participant_info calls failed."
    )

    print("   ✅ TEE accounts found - submit_participant_info calls succeeded!")
