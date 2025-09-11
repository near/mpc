#!/usr/bin/env python3
"""
Tests that MPC nodes successfully call the submit_participant_info endpoint.
This test ensures that nodes can properly submit their TEE attestation information to the 
contract, avoiding API mismatches.
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
    Returns the TEE accounts data or None if the call fails.
    """
    try:
        # Make a view call to get_tee_accounts using the same pattern as other contract methods
        tx = cluster.contract_node.sign_tx(
            cluster.mpc_contract_account(),
            "get_tee_accounts",
            {}
        )
        result = cluster.contract_node.send_txn_and_check_success(tx)
        return result
    except Exception as e:
        print(f"Failed to call get_tee_accounts: {e}")
        return None


def test_submit_participant_info_endpoint():
    """
    Test that MPC nodes successfully call submit_participant_info endpoint during startup.
    
    This test:
    1. Starts a cluster with MPC nodes
    2. Lets nodes naturally call submit_participant_info during their initialization
    3. Uses get_tee_accounts to verify the calls succeeded
    4. Ensures no API mismatches prevent nodes from submitting their info
    """
    # Start cluster with 2 validators and 2 MPC nodes
    cluster, mpc_nodes = shared.start_cluster_with_mpc(
        2, 2, 1, load_mpc_contract()
    )
    
    # Initialize the cluster - this triggers node startup process
    cluster.deploy_contract(load_mpc_contract())
    cluster.init_cluster(mpc_nodes, 2)
    
    print("\n=== MPC Nodes Starting Up ===")
    print("Nodes will automatically call submit_participant_info during initialization...")
    
    # Give nodes time to start up and make their submit_participant_info calls
    startup_time = 30  # seconds
    print(f"Waiting {startup_time} seconds for nodes to complete startup and submit participant info...")
    time.sleep(startup_time)

    print("\n=== Checking TEE Account Registration ===")

    # Check if submit_participant_info calls succeeded by querying get_tee_accounts
    tee_accounts_result = get_tee_accounts(cluster)

    print("=== Raw contract response ===")
    print(tee_accounts_result)
    print("===============================")
    
    # Extract the actual result from the SuccessValue field
    if tee_accounts_result and "result" in tee_accounts_result:
        success_value = tee_accounts_result["result"]["status"].get("SuccessValue")
        if success_value:
            # Decode base64 result
            decoded_result = base64.b64decode(success_value).decode('utf-8')
            print(f"Decoded result: {decoded_result}")
            
            # Parse the JSON result
            tee_accounts = json.loads(decoded_result)
            tee_account_count = len(tee_accounts) if isinstance(tee_accounts, list) else 0
            
            print(f"   📊 Contract shows {tee_account_count} registered TEE accounts")
            
            if tee_account_count > 0:
                print("   ✅ TEE accounts found - submit_participant_info calls succeeded!")
                success = True
            else:
                print("   ❌ No TEE accounts registered - submit_participant_info calls failed")
                success = False
        else:
            print("   ❌ No SuccessValue found in contract response")
            success = False
    else:
        print("   ❌ Invalid contract response format")
        success = False

    # Assert that submit_participant_info calls succeeded
    assert success, (
        "Expected successful submit_participant_info calls with registered TEE accounts, but found none. "
        "This indicates an API mismatch or startup failure preventing nodes from submitting participant info."
    )

    print("\n🎉 TEST PASSED: submit_participant_info endpoint is working correctly!")