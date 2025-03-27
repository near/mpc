#!/usr/bin/env python3
"""
Tests key resharing (adding and removing nodes).
Starts 2 nodes, have node #3 join, then #4 join,
then #1 leaves, and finally #2 leaves.
At every step we check that signatures can still be produced.
"""

import sys
import pathlib

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
from common_lib import shared
from common_lib.contracts import load_mpc_contract


def test_key_resharing():
    cluster, mpc_nodes = shared.start_cluster_with_mpc(2, 4, 1,
                                                       load_mpc_contract())
    # start with 2 nodes
    cluster.init_cluster(participants=mpc_nodes[:2], threshold=2)
    cluster.send_and_await_signature_requests(1)

    # third node joins
    cluster.do_resharing(new_participants=mpc_nodes[:3],
                         new_threshold=3,
                         prospective_epoch_id=1)
    cluster.send_and_await_signature_requests(1)

    # fourth node joins
    cluster.do_resharing(new_participants=mpc_nodes,
                         new_threshold=3,
                         prospective_epoch_id=2)
    cluster.send_and_await_signature_requests(1)

    # first node gets kicked
    cluster.do_resharing(new_participants=mpc_nodes[1:],
                         new_threshold=2,
                         prospective_epoch_id=3)
    cluster.send_and_await_signature_requests(1)

    # second node gets kicked
    cluster.do_resharing(new_participants=mpc_nodes[2:],
                         new_threshold=2,
                         prospective_epoch_id=4)
    cluster.send_and_await_signature_requests(1)

    # bring down first two nodes; the cluster should still be able to sign
    mpc_nodes[0].near_node.kill()
    mpc_nodes[1].near_node.kill()
    assert cluster.wait_for_state('Running'), "require running"
    cluster.send_and_await_signature_requests(1)
