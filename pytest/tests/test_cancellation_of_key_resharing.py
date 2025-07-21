#!/usr/bin/env python3
import pathlib
import sys

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
from common_lib import shared
from common_lib.contracts import load_mpc_contract
from common_lib.contract_state import (
    RunningProtocolState,
)


def test_cancellation_of_key_resharing():
    """
    Tests the flow of cancellation of key resharing by calling the `vote_cancel_resharing` method on the contract.

    This test verifies:
    1. When a key resharing is cancelled, the contract stores the cancelled epoch ID
       in `previously_cancelled_resharing_epoch_id`.
    2. Network can serve sign requests after cancelling and transitions to the running state.
    3. After successful resharing completion, `previously_cancelled_resharing_epoch_id`
       is cleared (set to None).
    """
    # Start cluster with 2 active nodes out of 4 total
    cluster, mpc_nodes = shared.start_cluster_with_mpc(2, 4, 1, load_mpc_contract())
    initial_participants = mpc_nodes[:2]
    all_participants = mpc_nodes[:4]
    cluster.init_cluster(participants=initial_participants, threshold=2)

    state = cluster.contract_state()
    initial_prospective_epoch_id = 1

    # Two new nodes join, increase threshold to 3
    cluster.do_resharing(
        all_participants,
        new_threshold=3,
        prospective_epoch_id=initial_prospective_epoch_id,
        wait_for_running=False,
    )

    # Kill one of the new nodes to make resharing stall
    mpc_nodes[3].kill()

    # Cancel resharing
    cluster.do_cancellation(initial_participants)
    state = cluster.contract_state()
    assert isinstance(
        state.protocol_state, RunningProtocolState
    ), "State must be running after cancellation"

    # Check that `previously_cancelled_resharing_epoch_id` is set correctly
    previously_cancelled_resharing_epoch_id = (
        state.protocol_state.previously_cancelled_resharing_epoch_id
    )
    assert isinstance(
        previously_cancelled_resharing_epoch_id, int
    ), "`previously_cancelled_resharing_epoch_id` must be set after cancelling a resharing"
    assert (
        initial_prospective_epoch_id == previously_cancelled_resharing_epoch_id
    ), f"Contract stored wrong epoch ID: expected {initial_prospective_epoch_id}, got {previously_cancelled_resharing_epoch_id}"

    # Verify that network can handle signature requests after cancellation
    cluster.send_and_await_signature_requests(3)

    # Retry resharing with the previously killed node back online
    mpc_nodes[3].run()

    cluster.do_resharing(
        all_participants,
        new_threshold=3,
        prospective_epoch_id=previously_cancelled_resharing_epoch_id + 1,
        wait_for_running=True,
    )

    state = cluster.contract_state()
    assert isinstance(
        state.protocol_state, RunningProtocolState
    ), "State must be running after completed resharing"

    # Verify that previously_cancelled_resharing_epoch_id is cleared
    previously_cancelled_resharing_epoch_id = (
        state.protocol_state.previously_cancelled_resharing_epoch_id
    )
    assert (
        previously_cancelled_resharing_epoch_id is None
    ), "`previously_cancelled_resharing_epoch_id` must be None after completing a resharing"

    # Verify that network can handle signature requests after resharing
    cluster.send_and_await_signature_requests(3)
