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
    1. Starts a cluster with initial participants and additional nodes
    2. Initializes only the initial participants (they get mock attestations)
    3. Starts additional nodes that must submit their own attestations
    4. Verifies the additional nodes successfully submitted attestations
    """
    # Start cluster with 2 validators and 4 MPC nodes total
    # We'll only initialize 2 nodes, leaving 2 additional nodes to test attestation submission
    initial_participants = 2
    total_nodes = 4
    cluster, mpc_nodes = shared.start_cluster_with_mpc(
        2, total_nodes, 1, load_mpc_contract()
    )

    # Initialize the cluster with only the first 2 nodes - these get mock attestations
    cluster.deploy_contract(load_mpc_contract())
    cluster.init_cluster(mpc_nodes[:initial_participants], 2)

    print(
        f"✅ Initialized cluster with {initial_participants} participants (they have mock attestations)"
    )

    # Start the additional nodes that are NOT part of initial participants
    # These nodes will need to submit their own attestations to be registered
    additional_nodes = mpc_nodes[initial_participants:]
    print(
        f"🚀 Starting {len(additional_nodes)} additional nodes that must submit attestations..."
    )

    for i, node in enumerate(additional_nodes):
        print(
            f"   Starting additional node {i + 1}/{len(additional_nodes)}: {node.p2p_public_key}"
        )
        node.run()

    startup_time = 30  # seconds
    print(
        f"⏳ Waiting {startup_time} seconds for additional nodes to submit attestations..."
    )
    time.sleep(startup_time)

    # Get the current TEE accounts from contract
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

    # Expected count: initial participants + additional nodes that submitted attestations
    expected_tee_account_count = initial_participants + len(additional_nodes)

    print(
        f"   🎯 Expected: {initial_participants} initial + {len(additional_nodes)} additional = {expected_tee_account_count} total"
    )

    # Assert that additional nodes successfully submitted attestations
    assert tee_account_count == expected_tee_account_count, (
        f"Expected exactly {expected_tee_account_count} TEE accounts "
        f"({initial_participants} initial + {len(additional_nodes)} additional nodes), "
        f"but found {tee_account_count}. This indicates a mismatch in attestation submissions."
    )

    print(
        f"   ✅ Success! All {len(additional_nodes)} additional nodes submitted attestations!"
    )
