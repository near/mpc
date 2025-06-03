#!/usr/bin/env python3
import pathlib
import sys

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
from common_lib import shared
from common_lib.contracts import load_mpc_contract


def test_single_domain():
    """
    Tests that signature requests are still processed while performing key resharing.

    Test scenario:
        1. Start with 2 nodes and 1 domain for Ecdsa as well as Eddsa.
        2. Add 2 more nodes and start a key resharing.
        3. While in resharing, kill one node such that the nodes are stuck in resharing.
        4. Send a signature request to assert that it is processed while the network is in resharing state.
    """
    # Have the nodes disabled
    cluster, mpc_nodes = shared.start_cluster_with_mpc(2,
                                                       4,
                                                       1,
                                                       load_mpc_contract(),
                                                       start_mpc_nodes=True)

    cluster.init_cluster(participants=mpc_nodes[:2], threshold=2)

    # Two new nodes join, increase threshold
    cluster.do_resharing(
        new_participants=mpc_nodes[:4],
        new_threshold=3,
        prospective_epoch_id=1,
        wait_for_running=False,
    )

    # Kill one node such that resharing does not finish.
    mpc_nodes[3].kill()

    # sanity check
    assert cluster.wait_for_state(
        "Resharing"
    ), "State should still be in resharing. 4th node was killed."

    cluster.send_and_await_signature_requests(3)

    # sanity check
    assert cluster.wait_for_state(
        "Resharing"
    ), "State should still be in resharing. 4th node was killed."
