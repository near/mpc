#!/usr/bin/env python3
"""
Starts 2 near validators and 3 mpc nodes.
Allows assets to be generated, then stops one node and wipes its database.
Restarts the node and verifies that signature requests succeed.
"""

import sys
from cluster import atexit
import pytest
import time
import random
import pathlib
from typing import List
import requests

from common_lib.contract_state import ContractState, ProtocolState
from common_lib.shared import MpcCluster, metrics

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
from common_lib import shared
from common_lib.contracts import load_mpc_contract
from common_lib.constants import TIMEOUT

PRESIGNATURES_TO_BUFFER = 8


@pytest.fixture(scope="module")
def lost_assets_cluster():
    """
    Spins up a cluster with three nodes, initializes contract and adds domains. Retuns the cluster in a running state.
    """
    cluster, mpc_nodes = shared.start_cluster_with_mpc(
        2,
        3,
        1,
        load_mpc_contract(),
        presignatures_to_buffer=PRESIGNATURES_TO_BUFFER,
    )
    cluster.init_cluster(mpc_nodes, 2)
    cluster.wait_for_state(ProtocolState.RUNNING)

    yield cluster

    atexit._run_exitfuncs()


def assert_num_presignatures_available(
    cluster: MpcCluster, expected_num_presignatures_available: int, timeout: int
):
    """
    Asserts that each node owns `expected_number_of_presignatures` presignatures.
    Panics in case of a timeout
    """
    started = time.time()
    while True:
        assert time.time() - started < timeout, "Waiting for presignatures"
        try:
            presignature_count: List[int] = cluster.require_int_metric_values(
                metrics.IntMetricName.MPC_OWNED_NUM_PRESIGNATURES_AVAILABLE
            )
            print("Owned presignatures:", presignature_count)
            if all(
                x == expected_num_presignatures_available for x in presignature_count
            ):
                break
        except requests.exceptions.ConnectionError:
            pass
        time.sleep(1)


def assert_num_offline_online_presignatures(
    cluster: MpcCluster,
    node_idxs_alive: List[int],
    expected_num_presignatures_online: int,
    expected_num_presignaturse_offline: int,
    verbose: bool = True,
):
    """
    ensures that
    """
    started = time.time()
    while True:
        assert time.time() - started < TIMEOUT, "Waiting for asset cleanup"

        try:
            cleanup_done = all(
                (
                    node.require_int_metric_value(
                        metrics.IntMetricName.MPC_OWNED_NUM_PRESIGNATURES_ONLINE
                    )
                    == expected_num_presignatures_online
                    and node.require_int_metric_value(
                        metrics.IntMetricName.MPC_OWNED_NUM_PRESIGNATURES_WITH_OFFLINE_PARTICIPANT
                    )
                    == expected_num_presignaturse_offline
                )
                for node in (cluster.active_mpc_nodes[i] for i in node_idxs_alive)
            )
            if verbose:
                for node in (cluster.active_mpc_nodes[i] for i in node_idxs_alive):
                    node_name = node.print()
                    peers_block_heights = node.get_peers_block_height_metric_value()
                    print(f"node {node_name} peer block heights: {peers_block_heights}")

                    online = node.require_int_metric_value(
                        metrics.IntMetricName.MPC_OWNED_NUM_PRESIGNATURES_ONLINE
                    )
                    offline = node.require_int_metric_value(
                        metrics.IntMetricName.MPC_OWNED_NUM_PRESIGNATURES_WITH_OFFLINE_PARTICIPANT
                    )
                    available = node.require_int_metric_value(
                        metrics.IntMetricName.MPC_OWNED_NUM_PRESIGNATURES_AVAILABLE
                    )
                    print(
                        f"node {node_name} available={available} online={online} offline_participant={offline}"
                    )
            if cleanup_done:
                print(f"time for cleanup: {time.time() - started:.2f} s")
                return
        except requests.exceptions.ConnectionError:
            pass
        time.sleep(1)


def assert_num_live_connections(
    cluster: MpcCluster, node_idxs: List[int], expected_num_connected: int, timeout: int
):
    """
    Asserts that each node in node_idx is connected to exactly `expected_num_connected` peers.
    """
    for node_idx in node_idxs:
        cluster.active_mpc_nodes[node_idx].assert_num_live_connections(
            expected_num_connected, timeout
        )


def assert_indexer_lag(
    cluster: MpcCluster,
    faulty_node_idx: int,
    active_node_idxs: List[int],
    min_lag: int = 10,
    timeout: int = 120,
    verbose: bool = True,
):
    """
    This function:
        - asserts that the nodes correctly expose the `metrics.IntMetricName.MPC_INDEXER_LATEST_BLOCK_HEIGHT` metric
        - returns only after the indexer of the node with `faulty_node_idx` lags at least `min_lag` behind every active nodes.
    Raises an exception if the timeout is exceeded or if there is no valid metric
    """
    started = time.time()
    while True:
        assert time.time() - started < timeout, "Waiting for indexer lag"
        try:
            block_heights: List[int] = cluster.require_int_metric_values(
                metrics.IntMetricName.MPC_INDEXER_LATEST_BLOCK_HEIGHT
            )
            if verbose:
                print(f"Block heights: {block_heights}")
            stalled_node_height: int = block_heights[faulty_node_idx]
            if all(
                [
                    stalled_node_height + min_lag < block_heights[active_node_idx]
                    for active_node_idx in active_node_idxs
                ]
            ):
                break
        except requests.exceptions.ConnectionError:
            pass
        time.sleep(1)


@pytest.mark.no_atexit_cleanup
def test_cleanup_dead_node(lost_assets_cluster: MpcCluster):
    """
    Expect an initialized cluster of at least 3 nodes running.
    This function tests if the asset cleanup mechanism works if a node is dead.
    """
    assert len(lost_assets_cluster.active_mpc_nodes) == 3, (
        "expected cluster with three nodes"
    )
    contract: ContractState = lost_assets_cluster.contract_state()
    assert contract.is_state(ProtocolState.RUNNING), "expect cluster in running state"
    assert len(contract.get_running_domains()) > 0, (
        "expect cluster with at least one domain"
    )

    # Wait for nodes to have assets with everyone else
    assert_num_presignatures_available(
        lost_assets_cluster, PRESIGNATURES_TO_BUFFER, TIMEOUT
    )

    # Stop mpc node 0 and wipe its database. Any assets generated before this point
    # which included node 0 are now unusable because node 0 has lost its share.
    faulty_node_idx = random.randint(0, 2)
    node_idxs_alive = [i for i in range(0, 3) if i != faulty_node_idx]
    lost_assets_cluster.kill_nodes([faulty_node_idx])
    lost_assets_cluster.reset_mpc_data([faulty_node_idx])

    # Assert that node is noticed as offline
    assert_num_live_connections(lost_assets_cluster, node_idxs_alive, 2, TIMEOUT)

    # Wait for alive nodes to clean up assets involving dead node
    assert_num_offline_online_presignatures(
        lost_assets_cluster,
        node_idxs_alive,
        expected_num_presignatures_online=PRESIGNATURES_TO_BUFFER,
        expected_num_presignaturse_offline=0,
    )

    # Start node 0 again
    lost_assets_cluster.run_nodes([faulty_node_idx])
    assert_num_live_connections(lost_assets_cluster, node_idxs_alive, 3, TIMEOUT)

    # Send some signature requests as a sanity check.
    presignatures_available = sum(
        lost_assets_cluster.require_int_metric_values(
            metrics.IntMetricName.MPC_OWNED_NUM_PRESIGNATURES_AVAILABLE
        )
    )
    lost_assets_cluster.send_and_await_signature_requests(presignatures_available // 4)


# requires network network-hardship-simulation
@pytest.mark.no_atexit_cleanup
def test_cleanup_lagging_node(lost_assets_cluster: MpcCluster):
    """
    This test requires the MPC binary to be compiled with the feature flag "network-hardship-simulation"
    """
    assert len(lost_assets_cluster.active_mpc_nodes) == 3, (
        "expected cluster with three nodes"
    )
    contract: ContractState = lost_assets_cluster.contract_state()
    assert contract.is_state(ProtocolState.RUNNING), "expect cluster in running state"
    assert len(contract.get_running_domains()) > 0, (
        "expect cluster with at least one domain"
    )
    # Wait for nodes to have assets with everyone else
    assert_num_presignatures_available(
        lost_assets_cluster, PRESIGNATURES_TO_BUFFER, TIMEOUT
    )

    # Simulate node 0's indexer falling behind
    faulty_node_idx = random.randint(0, 2)
    node_idxs_alive = [i for i in range(0, 3) if i != faulty_node_idx]
    lost_assets_cluster.set_block_ingestion([faulty_node_idx], False)

    assert_indexer_lag(lost_assets_cluster, faulty_node_idx, node_idxs_alive, 50)

    # we wait for the other nodes to cleanup
    assert_num_offline_online_presignatures(
        lost_assets_cluster,
        node_idxs_alive,
        expected_num_presignatures_online=PRESIGNATURES_TO_BUFFER,
        expected_num_presignaturse_offline=0,
    )

    lost_assets_cluster.send_and_await_signature_requests(5)

    # re-enable block ingestion, in case any tests run afterwards
    lost_assets_cluster.set_block_ingestion([faulty_node_idx], True)
