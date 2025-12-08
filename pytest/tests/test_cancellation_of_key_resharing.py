#!/usr/bin/env python3
import pathlib
import sys


sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))

from common_lib.shared.transaction_status import assert_txn_execution_error
from common_lib import shared
from common_lib.contracts import load_mpc_contract
from common_lib.contract_state import (
    ProtocolState,
    RunningProtocolState,
)


def test_cancellation_of_key_resharing():
    """
    Tests the flow of cancellation of key resharing by calling the `vote_cancel_resharing` method on the contract.

    This test verifies:
    1. Votes for cancellation of key resharing by new participants are rejected by the contract.
    2. Cancellation of key resharing requires threshold number of votes from previous running set.
    3. Cancellation of key resharing reverts the contract state back to the previous running state.
    4. When a key resharing is cancelled, the contract stores the cancelled epoch ID
       in `previously_cancelled_resharing_epoch_id`.
    5. Network can serve sign requests after cancelling.
    6. After successful resharing completion, `previously_cancelled_resharing_epoch_id`
       is cleared (set to None).
    """
    # Start cluster with:
    initial_threshold = 2
    initial_running_nodes = 3
    number_of_mpc_nodes = 5

    cluster, mpc_nodes = shared.start_cluster_with_mpc(
        number_of_mpc_nodes,
        1,
        load_mpc_contract(),
    )
    initial_running_nodes = mpc_nodes[:initial_running_nodes]
    cluster.init_cluster(
        participants=initial_running_nodes, threshold=initial_threshold
    )

    state = cluster.contract_state()
    initial_prospective_epoch_id = 1

    # Two new nodes join, increase threshold to 3
    cluster.do_resharing(
        mpc_nodes,
        new_threshold=3,
        prospective_epoch_id=initial_prospective_epoch_id,
        wait_for_running=False,
    )

    # Kill the last one of the new nodes to make resharing stall
    killed_node = mpc_nodes[-1]
    killed_node.kill()

    # Cancel resharing
    print("\033[91mVoting on cancellation of resharing\033[0m")

    # Vote with nodes that were not in the previous running state.
    # These votes should be reject by the contract.
    for node in mpc_nodes:
        # Our pytest setup will not allow us to run voting commands
        # on nodes that are killed. Thus skip voting with this node.
        node_is_killed = node == killed_node
        node_is_participant = node in initial_running_nodes

        if node_is_killed or node_is_participant:
            continue

        tx = node.sign_tx(cluster.mpc_contract_account(), "vote_cancel_resharing", {})
        response = node.near_node.send_tx_and_wait(tx, timeout=20)
        assert_txn_execution_error(response, expected_error_msg="Not a participant")

    # Vote with a threshold number of the running nodes
    for running_node in initial_running_nodes[:initial_threshold]:
        tx = running_node.sign_tx(
            cluster.mpc_contract_account(), "vote_cancel_resharing", {}
        )
        running_node.send_txn_and_check_success(tx)

    # Assert cancellation works.
    assert cluster.wait_for_state(ProtocolState.RUNNING), (
        "Contract should transition to running state after threshold running nodes voted for cancellation."
    )

    state = cluster.contract_state()
    assert isinstance(state.protocol_state, RunningProtocolState), (
        "State must be running after cancellation"
    )

    # Check that `previously_cancelled_resharing_epoch_id` is set correctly
    previously_cancelled_resharing_epoch_id = (
        state.protocol_state.previously_cancelled_resharing_epoch_id
    )
    assert isinstance(previously_cancelled_resharing_epoch_id, int), (
        "`previously_cancelled_resharing_epoch_id` must be set after cancelling a resharing"
    )
    assert initial_prospective_epoch_id == previously_cancelled_resharing_epoch_id, (
        f"Contract stored wrong epoch ID: expected {initial_prospective_epoch_id}, got {previously_cancelled_resharing_epoch_id}"
    )

    # Verify that network can handle requests after cancellation
    cluster.send_and_await_signature_requests(3)
    cluster.send_and_await_ckd_requests(3)

    # Retry resharing with the previously killed node back online
    killed_node.run()

    cluster.do_resharing(
        mpc_nodes,
        new_threshold=3,
        prospective_epoch_id=previously_cancelled_resharing_epoch_id + 1,
        wait_for_running=True,
    )

    state = cluster.contract_state()
    assert isinstance(state.protocol_state, RunningProtocolState), (
        "State must be running after completed resharing"
    )

    # Verify that previously_cancelled_resharing_epoch_id is cleared
    previously_cancelled_resharing_epoch_id = (
        state.protocol_state.previously_cancelled_resharing_epoch_id
    )
    assert previously_cancelled_resharing_epoch_id is None, (
        "`previously_cancelled_resharing_epoch_id` must be None after completing a resharing"
    )

    # Verify that network can handle requests after resharing
    cluster.send_and_await_signature_requests(3)
    cluster.send_and_await_ckd_requests(3)
