#!/usr/bin/env python3
"""
Tests that signature/ckd requests are still processed while performing key resharing, when
the new threshold is higher than available nodes from the previous running state.

Test scenario:
    1. Start with:
        a. 2 nodes
        b. threshold set to 2.
        c. 1 domain for ECDSA and EdDSA each.
    2. Add 2 more, and increase threshold to 4 participants to start a key resharing.
    3. While in resharing, kill one node such that the nodes are stuck in resharing.
    4. Send a signature/ckd request to assert that it is processed while the network is in resharing state,
        even if less nodes than the new treshold are online.
"""

import pathlib
import sys

from common_lib.contract_state import ProtocolState

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
from common_lib import shared
from common_lib.contracts import load_mpc_contract


def test_threshold_from_previous_running_state_is_maintained():
    # Have the nodes disabled
    cluster, mpc_nodes = shared.start_cluster_with_mpc(4, 1, load_mpc_contract())

    cluster.init_cluster(participants=mpc_nodes[:2], threshold=2)

    # Two new nodes join, increase threshold to 4
    cluster.do_resharing(
        new_participants=mpc_nodes[:4],
        new_threshold=4,
        prospective_epoch_id=1,
        wait_for_running=False,
    )

    # Kill one node such that resharing does not finish.
    mpc_nodes[3].kill()

    # sanity check
    assert cluster.wait_for_state(ProtocolState.RESHARING), (
        "State should still be in resharing. 4th node was killed."
    )

    cluster.send_and_await_signature_requests(3)
    # sanity check
    assert cluster.wait_for_state(ProtocolState.RESHARING), (
        "State should still be in resharing. 4th node was killed."
    )

    cluster.send_and_await_ckd_requests(3)
    # sanity check
    assert cluster.wait_for_state(ProtocolState.RESHARING), (
        "State should still be in resharing. 4th node was killed."
    )


def test_threshold_from_previous_running_state_is_maintained_robust_ecdsa_only():
    number_of_nodes = 6
    threshold = 5

    cluster, mpc_nodes = shared.start_cluster_with_mpc(
        number_of_nodes,
        1,
        load_mpc_contract(),
        triples_to_buffer=0,
    )

    cluster.init_cluster(
        participants=mpc_nodes[:-1], threshold=threshold, domains=["V2Secp256k1"]
    )

    # One more node join, increase threshold
    cluster.do_resharing(
        new_participants=mpc_nodes[:],
        new_threshold=threshold + 1,
        prospective_epoch_id=1,
        wait_for_running=False,
    )

    # Kill one node such that resharing does not finish.
    mpc_nodes[-1].kill()

    # sanity check
    assert cluster.wait_for_state(ProtocolState.RESHARING), (
        "State should still be in resharing. last node was killed."
    )

    cluster.send_and_await_signature_requests(3)
    # sanity check
    assert cluster.wait_for_state(ProtocolState.RESHARING), (
        "State should still be in resharing. last node was killed."
    )
