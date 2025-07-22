#!/usr/bin/env python3
"""
Starts 2 near validators and 3 mpc nodes.
Allows assets to be generated, then stops one node and wipes its database.
Restarts the node and verifies that signature requests succeed.
"""

import sys
import time
import pathlib
from typing import List
import requests

from common_lib.shared import MpcCluster, MpcNode, metrics

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
from common_lib import shared
from common_lib.contracts import load_mpc_contract
from common_lib.constants import TIMEOUT

PRESIGNATURES_TO_BUFFER = 8


def wait_for_presignatures_to_buffer(cluster: MpcCluster):
    started = time.time()
    while True:
        assert time.time() - started < TIMEOUT, "Waiting for presignatures"
        try:
            presignature_count = cluster.get_int_metric_value(
                metrics.IntMetricName.MPC_OWNED_NUM_PRESIGNATURES_AVAILABLE
            )
            print("Owned presignatures:", presignature_count)
            if all(x and x == PRESIGNATURES_TO_BUFFER for x in presignature_count):
                break
        except requests.exceptions.ConnectionError:
            pass
        time.sleep(1)


def wait_for_asset_cleanup(mpc_nodes: List[MpcNode]):
    started = time.time()
    while True:
        assert time.time() - started < TIMEOUT, "Waiting for asset cleanup"
        try:

            cleanup_done = True
            for node in mpc_nodes:
                available = node.get_int_metric_value(
                    metrics.IntMetricName.MPC_OWNED_NUM_PRESIGNATURES_AVAILABLE
                )
                online = node.get_int_metric_value(
                    metrics.IntMetricName.MPC_OWNED_NUM_PRESIGNATURES_ONLINE
                )
                offline = node.get_int_metric_value(
                    metrics.IntMetricName.MPC_OWNED_NUM_PRESIGNATURES_WITH_OFFLINE_PARTICIPANT
                )
                print(
                    f"node {node.print()} has owned presignatures available={available} online={online} with_offline_participant={offline}"
                )
                peers_indexer_block_heights = node.get_peers_block_height_metric_value()
                print(
                    f"node {node.print()} has following peer block heights: {peers_indexer_block_heights}"
                )
                if not (online == PRESIGNATURES_TO_BUFFER and offline == 0):
                    cleanup_done = False
            if cleanup_done:
                break
        except requests.exceptions.ConnectionError:
            pass
        time.sleep(1)


def test_lost_assets():
    cluster, mpc_nodes = shared.start_cluster_with_mpc(
        2,
        3,
        1,
        load_mpc_contract(),
        presignatures_to_buffer=PRESIGNATURES_TO_BUFFER,
    )
    cluster.init_cluster(participants=mpc_nodes, threshold=2)
    cluster.wait_for_state("Running")

    # Wait for nodes to have assets with everyone else
    wait_for_presignatures_to_buffer(cluster)

    # Stop mpc node 0 and wipe its database. Any assets generated before this point
    # which included node 0 are now unusable because node 0 has lost its share.
    cluster.mpc_nodes[0].kill(gentle=True)
    cluster.mpc_nodes[0].reset_mpc_data()

    # Let the other nodes notice that node 0 is offline;
    # we don't want to check the presignature metrics too early
    cluster.mpc_nodes[1].wait_for_connection_count(2)
    cluster.mpc_nodes[2].wait_for_connection_count(2)

    # Wait for nodes 1 and 2 to clean up assets involving node 0
    wait_for_asset_cleanup(cluster.mpc_nodes[1:])

    # Start node 0 again
    cluster.mpc_nodes[0].run()
    cluster.mpc_nodes[1].wait_for_connection_count(3)
    cluster.mpc_nodes[2].wait_for_connection_count(3)

    # Send some signature requests as a sanity check. Ideally we would like the entire
    # presignature stores in nodes 1 and 2 to be used up here.
    # However, it is tricky to guarantee because we cannot control which nodes
    # are assigned as leaders for the requests.

    presignatures_available = sum(
        cluster.get_int_metric_value(
            metrics.IntMetricName.MPC_OWNED_NUM_PRESIGNATURES_AVAILABLE
        )
    )
    cluster.send_and_await_signature_requests(presignatures_available // 4)


def test_signature_pause_block_ingestion():
    """
    This test requires the MPC binary to be compiled with the feature flag "network-hardship-simulation"
    """
    cluster, mpc_nodes = shared.start_cluster_with_mpc(
        2,
        3,
        1,
        load_mpc_contract(),
        presignatures_to_buffer=PRESIGNATURES_TO_BUFFER,
    )
    cluster.init_cluster(mpc_nodes, 2)
    cluster.wait_for_state("Running")

    # Wait for nodes to have assets with everyone else
    wait_for_presignatures_to_buffer(cluster)

    # Simulate node 0's indexer falling behind
    mpc_nodes[0].set_block_ingestion(False)

    started = time.time()
    while True:
        peers_indexer_block_heights = mpc_nodes[0].get_peers_block_height_metric_value()
        print(
            f"node {mpc_nodes[0].print()} has following peer block heights = {peers_indexer_block_heights}"
        )
        assert time.time() - started < 120, "Waiting for presignatures"
        try:

            block_heights = cluster.get_int_metric_value(
                metrics.IntMetricName.MPC_INDEXER_LATEST_BLOCK_HEIGHT
            )
            print("block heights:", block_heights)
            if (block_heights[0] + 10 < block_heights[1]) and (
                block_heights[0] + 10 < block_heights[2]
            ):
                break
        except requests.exceptions.ConnectionError:
            pass
        time.sleep(5)

    # we wait for the other nodes to cleanup
    wait_for_asset_cleanup(cluster.mpc_nodes[1:])

    cluster.send_and_await_signature_requests(5)

    # re-enable block ingestion, in case any tests run afterwards
    mpc_nodes[0].set_block_ingestion(True)
