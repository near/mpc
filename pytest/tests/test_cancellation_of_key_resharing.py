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
    Tests that flow of cancellation of key resharing by calling the `vote_cancel_resharing` on the contract.

    This test verifies:
    1. When a key resharing is cancelled, the contract stores the cancelled epoch ID
       in `previously_cancelled_resharing_epoch_id`.
    2. Network canc serve sign requests after cancelling and transitions to the running state.
    3. After successful resharing completion, `previously_cancelled_resharing_epoch_id`
       is cleared (set to None)
    """

    # Have the nodes disabled
    cluster, mpc_nodes = shared.start_cluster_with_mpc(2, 4, 1, load_mpc_contract())
    initial_participants = mpc_nodes[:2]
    all_participants = mpc_nodes[:4]
    cluster.init_cluster(participants=initial_participants, threshold=2)

    state = cluster.contract_state()

    initial_prospective_epoch_id = 1

    # Two new nodes join, increase threshold to 4
    cluster.do_resharing(
        all_participants,
        new_threshold=3,
        prospective_epoch_id=initial_prospective_epoch_id,
        wait_for_running=False,
    )

    # Kill one node such that resharing stalls.
    mpc_nodes[3].kill()

    # Cancel resharing
    cluster.do_cancellation(initial_participants)
    state = cluster.contract_state()
    assert isinstance(
        state.protocol_state, RunningProtocolState
    ), "state must be running after cancellation"

    # Check that `previously_cancelled_resharing_epoch_id` is set.
    previously_cancelled_resharing_epoch_id = (
        state.protocol_state.previously_cancelled_resharing_epoch_id
    )
    assert isinstance(
        previously_cancelled_resharing_epoch_id, int
    ), "`previously_cancelled_resharing_epoch_id` must be set after cancelling a resharing."
    assert (
        initial_prospective_epoch_id == previously_cancelled_resharing_epoch_id
    ), "Contract stored the wrong epoch id for the field `previously_cancelled_resharing_epoch_id`"

    # check that network can handle signature requests after a cancellation
    cluster.send_and_await_signature_requests(3)

    # retry resharing.
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
    ), "state must be running after completed resharing."

    previously_cancelled_resharing_epoch_id = (
        state.protocol_state.previously_cancelled_resharing_epoch_id
    )
    assert (
        previously_cancelled_resharing_epoch_id == None
    ), "`previously_cancelled_resharing_epoch_id` must be set to None after completing a resharing."

    # check that network can handle signature requests after resharing
    cluster.send_and_await_signature_requests(3)
