#!/usr/bin/env python3
"""
Tests that when a participant's TEE attestation expires, verify_tee() triggers
resharing and the participant is removed from the set.

This test covers the full flow:
1. Start 3 nodes with valid attestations
2. Replace one node's attestation with a short expiry
3. Wait for attestation to expire
4. Call verify_tee() to trigger resharing
5. Wait for resharing to complete
6. Assert participant count is reduced from 3 to 2
"""

import pathlib
import sys
import time
from datetime import datetime

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
from common_lib import shared
from common_lib.contract_state import ProtocolState, RunningProtocolState
from common_lib.contracts import ContractMethod, load_mpc_contract
from common_lib.shared.mpc_node import MpcNode


def get_block_timestamp_seconds(cluster) -> int:
    """Get the current block timestamp in seconds from the blockchain."""
    sync_info = cluster.contract_node.near_node.get_status()["sync_info"]
    # Format: "2024-01-08T12:34:56.123456789Z" - truncate nanoseconds to microseconds
    latest_block_time = sync_info["latest_block_time"][:26] + "Z"
    return int(
        datetime.fromisoformat(latest_block_time.replace("Z", "+00:00")).timestamp()
    )


def test_verify_tee_expired_attestation_triggers_resharing():
    """
    Tests that verify_tee() kicks out a participant with an expired attestation
    and completes resharing with reduced participant count.

    Steps:
    1. Start 3 MPC nodes and initialize contract
    2. Wait for all nodes to submit attestations
    3. Submit a new attestation with short expiry for node[0]
    4. Wait for attestation to expire
    5. Call verify_tee() to detect expired attestation and trigger resharing
    6. Wait for contract to transition through Resharing → Running
    7. Assert final participant count is 2 (node[0] was kicked out)
    """
    # Start cluster with 3 nodes
    cluster, mpc_nodes = shared.start_cluster_with_mpc(3, 1, load_mpc_contract())

    # Initialize with all 3 nodes, threshold 2
    cluster.init_cluster(participants=mpc_nodes[:3], threshold=2)

    # Verify initial state: 3 participants
    state = cluster.contract_state()
    assert isinstance(state.protocol_state, RunningProtocolState)
    initial_participant_count = len(
        state.protocol_state.parameters.participants.participants
    )
    assert initial_participant_count == 3, (
        f"Expected 3 participants initially, got {initial_participant_count}"
    )
    print(f"✓ Initial participant count: {initial_participant_count}")

    # Wait for all nodes to have attestations submitted
    attestations_submitted = cluster.wait_for_nodes_to_have_attestation(mpc_nodes[:3])
    assert attestations_submitted, "All nodes should have attestations"
    print("✓ All nodes have attestations submitted")

    # Replace node[0]'s attestation with one that will expire shortly
    target_node = mpc_nodes[0]
    print(f"Target node for expiry: {target_node.account_id()}")

    # Set expiry to 5 seconds in the future (just enough time to submit)
    attestation_expiry_seconds = 5
    current_timestamp = get_block_timestamp_seconds(cluster)
    expiry_timestamp = current_timestamp + attestation_expiry_seconds

    attestation_with_expiry = {
        "Mock": {
            "WithConstraints": {
                "mpc_docker_image_hash": None,
                "launcher_docker_compose_hash": None,
                "expiry_time_stamp_seconds": expiry_timestamp,
            }
        }
    }

    tx = target_node.sign_tx(
        cluster.mpc_contract_account(),
        ContractMethod.SUBMIT_PARTICIPANT_INFO,
        {
            "proposed_participant_attestation": attestation_with_expiry,
            "tls_public_key": target_node.p2p_public_key,
        },
    )
    target_node.send_txn_and_check_success(tx)
    print(
        f"✓ Submitted attestation with expiry at {expiry_timestamp} for {target_node.account_id()}"
    )

    # Wait for expiry time plus equal buffer for blockchain to produce blocks and advance timestamp
    wait_seconds = attestation_expiry_seconds * 2
    print(f"Waiting {wait_seconds} seconds for attestation to expire...")
    time.sleep(wait_seconds)

    # Verify blockchain time has passed expiry
    current_timestamp = get_block_timestamp_seconds(cluster)
    print(
        f"Current block timestamp: {current_timestamp}, expiry was: {expiry_timestamp}"
    )
    assert current_timestamp > expiry_timestamp, (
        f"Blockchain time {current_timestamp} should be past expiry {expiry_timestamp}"
    )
    print("✓ Block timestamp is past attestation expiry")

    # Call verify_tee() from one of the other participants to trigger TEE validation
    caller_node = mpc_nodes[1]
    print(f"Calling verify_tee() from {caller_node.account_id()}...")

    tx = caller_node.sign_tx(
        cluster.mpc_contract_account(), ContractMethod.VERIFY_TEE, {}
    )
    verify_result = caller_node.send_txn_and_check_success(tx)
    print(f"verify_tee result: {verify_result}")

    # The contract should transition to Resharing state
    print("Waiting for contract to enter Resharing state...")
    assert cluster.wait_for_state(ProtocolState.RESHARING), (
        "Contract should transition to Resharing state after verify_tee detects expired attestation"
    )
    print("✓ Contract is in Resharing state")

    # Wait for resharing to complete
    print("Waiting for resharing to complete...")
    assert cluster.wait_for_state(ProtocolState.RUNNING), (
        "Contract should complete resharing and return to Running state"
    )
    print("✓ Contract completed resharing")

    # Verify final participant count is reduced to 2
    final_state = cluster.contract_state()
    assert isinstance(final_state.protocol_state, RunningProtocolState)
    final_participant_count = len(
        final_state.protocol_state.parameters.participants.participants
    )

    print(f"Final participant count: {final_participant_count}")
    assert final_participant_count == 2, (
        f"Expected 2 participants after resharing (kicked out node with expired attestation), "
        f"got {final_participant_count}"
    )
    print("✓ Participant count reduced from 3 to 2")

    # Verify the kicked-out node is no longer a participant
    participant_account_ids = (
        final_state.protocol_state.parameters.participants.account_ids()
    )
    assert target_node.account_id() not in participant_account_ids, (
        f"Node {target_node.account_id()} should have been kicked out but is still a participant"
    )
    print(f"✓ Node {target_node.account_id()} was successfully kicked out")

    # Verify signature requests still work with the remaining 2 participants
    cluster.send_and_await_signature_requests(1)
    print("✓ Signature requests work with remaining participants")

    print(
        "\n✅ Test passed: Expired attestation triggered resharing and reduced participant count"
    )
