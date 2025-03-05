#!/usr/bin/env python3
"""
Tests key resharing (adding and removing nodes).
Starts 2 nodes, have node #3 join, then #4 join,
then #1 leaves, and finally #2 leaves.
At every step we check that signatures can still be produced.
"""

import sys
import pathlib
import time

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
from common_lib import shared
from common_lib.contracts import load_mpc_contract


def test_key_resharing():
    cluster = shared.start_cluster_with_mpc(2, 4, 1, load_mpc_contract())

    # start with 2 nodes
    all_mpc_nodes = cluster.mpc_nodes
    cluster.mpc_nodes = all_mpc_nodes[:2]

    cluster.init_contract(threshold=2)
    cluster.send_and_await_signature_requests(1)

    # third node joins
    cluster.propose_join(all_mpc_nodes[2])
    cluster.vote_join(0, all_mpc_nodes[2].account_id())
    cluster.vote_join(1, all_mpc_nodes[2].account_id())
    cluster.mpc_nodes = all_mpc_nodes[:3]

    time.sleep(2)
    cluster.send_and_await_signature_requests(1)

    # fourth node joins
    # only two votes are needed due to threshold
    cluster.propose_join(all_mpc_nodes[3])
    cluster.vote_join(0, all_mpc_nodes[3].account_id())
    cluster.vote_join(1, all_mpc_nodes[3].account_id())
    cluster.mpc_nodes = all_mpc_nodes

    time.sleep(2)
    cluster.send_and_await_signature_requests(1)

    # first node gets kicked
    cluster.vote_leave(1, all_mpc_nodes[0].account_id())
    cluster.vote_leave(2, all_mpc_nodes[0].account_id())
    cluster.mpc_nodes = all_mpc_nodes[1:]

    time.sleep(2)
    cluster.send_and_await_signature_requests(1)

    # second node gets kicked (indexes passed to vote_leave are shifted by 1)
    cluster.vote_leave(1, all_mpc_nodes[1].account_id())
    cluster.vote_leave(2, all_mpc_nodes[1].account_id())
    cluster.mpc_nodes = all_mpc_nodes[2:]

    time.sleep(2)
    cluster.send_and_await_signature_requests(1)

    # bring down first two nodes; the cluster should still be able to sign
    all_mpc_nodes[0].near_node.kill()
    all_mpc_nodes[1].near_node.kill()

    cluster.send_and_await_signature_requests(1)



