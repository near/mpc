#!/usr/bin/env python3
"""
Starts 2 near validators and 3 mpc nodes.
Allows assets to be generated, then stops one node and wipes its database.
Restarts the node and verifies that signature requests succeed.
"""

import sys
import atexit
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
from common_lib.constants import INDEXER_MAX_HEIGHT_DIFF, TIMEOUT

PRESIGNATURES_TO_BUFFER = 8


@pytest.fixture(scope="module")
def lost_assets_cluster():
    """
    Spins up a cluster with three nodes, initializes the contract and adds domains. Returns the cluster in a running state.
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
    cluster: MpcCluster, expected_num_presignatures_available: int, timeout_seconds: int
):
    """
    Asserts that the number of presignatures available for each node in the cluster is exactly `expected_num_presignatures_available`.
    Does so by comparing the metric value `MPC_OWNED_NUM_PRESIGNATURES_AVAILABLE` with the expected value.
    Panics in case any of the metrics is unreachable or does not match the expected value before timeout is reached.
    """
    started = time.time()
    while True:
        elapsed = time.time() - started
        assert elapsed < timeout_seconds, (
            "Nodes did not reach expected MPC presignature counts (available) before timeout."
        )
        try:
            presignature_count: List[int] = cluster.require_int_metric_values(
                metrics.IntMetricName.MPC_OWNED_NUM_PRESIGNATURES_AVAILABLE
            )
            if int(elapsed) % 2:
                print("Available presignatures:", presignature_count)
            if all(
                x == expected_num_presignatures_available for x in presignature_count
            ):
                print(
                    f"time for reaching expected asset count (available): {time.time() - started:.2f} s"
                )
                return
        except requests.exceptions.ConnectionError:
            pass
        time.sleep(0.1)


def assert_num_offline_online_presignatures(
    cluster: MpcCluster,
    nodes_idxs_to_verify: List[int],
    expected_num_presignatures_online: int,
    expected_num_presignatures_offline: int,
    timeout_seconds: int,
):
    """
    Asserts that each node with index in `nodes_idxs_to_verify`:
        - owns exactly `expected_num_presignatures_online` with online participants (by comparing the expected value with the metric `MPC_OWNED_NUM_PRESIGNATURES_ONLINE`)
        - owns exactly `expected_num_presignatures_offline` with offline participants (by comparing the expected value with the metric `MPC_OWNED_NUM_PRESIGNATURES_WITH_OFFLINE_PARTICIPANT`)

    Fails in case any of the metrics is not reachable or does not match the expected value before `timeout`
    """
    started = time.time()
    last_print = -5
    while True:
        elapsed = time.time() - started
        assert elapsed < timeout_seconds, (
            "Nodes did not reach expected MPC presignature counts (online | offline) before timeout."
        )

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
                    == expected_num_presignatures_offline
                )
                for node in (cluster.mpc_nodes[i] for i in nodes_idxs_to_verify)
            )
            if elapsed - last_print >= 5:
                last_print = elapsed
                for node in (cluster.mpc_nodes[i] for i in nodes_idxs_to_verify):
                    node_name = node.print()
                    peers_block_heights = node.get_peers_block_height_metric_value()
                    print(f"node {node_name} peer block heights: {peers_block_heights}")

                    online = node.require_int_metric_value(
                        metrics.IntMetricName.MPC_OWNED_NUM_PRESIGNATURES_ONLINE
                    )
                    offline = node.require_int_metric_value(
                        metrics.IntMetricName.MPC_OWNED_NUM_PRESIGNATURES_WITH_OFFLINE_PARTICIPANT
                    )
                    print(
                        f"Asset count node {node_name}: (online {online} | offline {offline})"
                    )
            if cleanup_done:
                print(
                    f"time for reaching expected asset count (online | offline): {time.time() - started:.2f} s"
                )
                return
        except requests.exceptions.ConnectionError:
            pass
        time.sleep(0.5)


def assert_num_live_connections(
    cluster: MpcCluster,
    node_idxs: List[int],
    expected_num_connected: int,
    timeout_seconds: int,
):
    """
    Asserts that each node in node_idx is connected to exactly `expected_num_connected` peers.
    """
    for node_idx in node_idxs:
        cluster.mpc_nodes[node_idx].assert_num_live_connections(
            expected_num_connected, timeout_seconds
        )


def assert_indexer_lag(
    cluster: MpcCluster,
    faulty_node_idx: int,
    active_node_idxs: List[int],
    min_lag_blocks: int = 10,
    timeout_seconds: int = 120,
):
    """
    This function:
        - asserts that the nodes correctly expose the `metrics.IntMetricName.MPC_INDEXER_LATEST_BLOCK_HEIGHT` metric
        - returns only after the indexer of the node with `faulty_node_idx` lags at least `min_lag_blocks` behind every active nodes.
    Raises an exception if the timeout is exceeded or if there is no valid metric
    """
    started = time.time()
    last_print = -5
    while True:
        elapsed = time.time() - started
        assert elapsed < timeout_seconds, (
            f"Timed out waiting for node {faulty_node_idx} to lag {min_lag_blocks} behind {active_node_idxs}."
        )
        try:
            block_heights: List[int] = cluster.require_int_metric_values(
                metrics.IntMetricName.MPC_INDEXER_LATEST_BLOCK_HEIGHT
            )
            if elapsed - last_print >= 5:
                print(f"Block heights: {block_heights}")
                last_print = elapsed
            faulty_node_height: int = block_heights[faulty_node_idx]
            node_considered_stalled = all(
                [
                    faulty_node_height + min_lag_blocks
                    <= block_heights[active_node_idx]
                    for active_node_idx in active_node_idxs
                ]
            )
            if node_considered_stalled:
                break
        except requests.exceptions.ConnectionError:
            pass
        time.sleep(0.5)


@pytest.mark.no_atexit_cleanup
def test_cleanup_dead_node(lost_assets_cluster: MpcCluster):
    """
    Expect an initialized cluster of at least 3 nodes running.
    This function tests if the asset cleanup mechanism works if a node is dead.
    Specifically, it ensures that MPC nodes delete any owned assets involving dead participants (participants without a live connection).
    """
    assert len(lost_assets_cluster.mpc_nodes) == 3, "expected cluster with three nodes"
    contract: ContractState = lost_assets_cluster.contract_state()
    assert contract.is_state(ProtocolState.RUNNING), "expect cluster in running state"
    assert len(contract.get_running_domains()) > 0, (
        "expect cluster with at least one domain"
    )

    # Wait for nodes to have assets with everyone else
    assert_num_presignatures_available(
        lost_assets_cluster, PRESIGNATURES_TO_BUFFER, TIMEOUT
    )

    # Stop one of the mpc nodes and wipe its database. Any assets generated before this point
    # which included that node are now unusable because node 0 has lost its share.
    faulty_node_idx = random.randint(0, 2)
    node_idxs_alive = [i for i in range(0, 3) if i != faulty_node_idx]
    lost_assets_cluster.kill_nodes([faulty_node_idx])
    lost_assets_cluster.reset_mpc_data([faulty_node_idx])

    # Assert that node is noticed as offline
    assert_num_live_connections(lost_assets_cluster, node_idxs_alive, 2, TIMEOUT)

    # Ensure alive nodes clean up assets involving dead node (the key behavior we want to test)
    assert_num_offline_online_presignatures(
        lost_assets_cluster,
        node_idxs_alive,
        expected_num_presignatures_online=PRESIGNATURES_TO_BUFFER,
        expected_num_presignatures_offline=0,
        timeout_seconds=TIMEOUT,
    )

    # Ensure the remaining nodes can handle signature requests. (We deplete the buffer here).
    lost_assets_cluster.send_and_await_signature_requests(PRESIGNATURES_TO_BUFFER * 2)

    # Start node 0 again
    lost_assets_cluster.run_nodes([faulty_node_idx])
    node_idxs_alive.append(faulty_node_idx)
    # Wait for nodes to connect
    assert_num_live_connections(lost_assets_cluster, node_idxs_alive, 3, TIMEOUT)

    # Send some signature requests as a sanity check.
    presignatures_available = sum(
        lost_assets_cluster.require_int_metric_values(
            metrics.IntMetricName.MPC_OWNED_NUM_PRESIGNATURES_AVAILABLE
        )
    )
    lost_assets_cluster.send_and_await_signature_requests(presignatures_available)


# Todo: [(#791)](https://github.com/near/mpc/issues/791) requires MPC node binary with enabled network-hardship-simulation feature
@pytest.mark.no_atexit_cleanup
def test_cleanup_lagging_node(lost_assets_cluster: MpcCluster):
    """
    This test requires the MPC binary to be compiled with the feature flag "network-hardship-simulation"
    """
    # Ensure cluster meets needs of this test
    assert len(lost_assets_cluster.mpc_nodes) == 3, "expected cluster with three nodes"
    contract: ContractState = lost_assets_cluster.contract_state()
    assert contract.is_state(ProtocolState.RUNNING), "expect cluster in running state"
    assert len(contract.get_running_domains()) > 0, (
        "expect cluster with at least one domain"
    )

    # Wait for nodes to have assets with everyone else
    assert_num_presignatures_available(
        lost_assets_cluster, PRESIGNATURES_TO_BUFFER, TIMEOUT
    )

    # Disable block ingestion on one of the nodes
    faulty_node_idx = random.randint(0, 2)
    node_idxs_alive = [i for i in range(0, 3) if i != faulty_node_idx]
    lost_assets_cluster.set_block_ingestion([faulty_node_idx], False)

    # Ensure the node falls the required number of blocks behind to be considered offline
    assert_indexer_lag(
        lost_assets_cluster, faulty_node_idx, node_idxs_alive, INDEXER_MAX_HEIGHT_DIFF
    )

    # Ensure the asset cleanup mechanism kicks in
    assert_num_offline_online_presignatures(
        lost_assets_cluster,
        node_idxs_alive,
        expected_num_presignatures_online=PRESIGNATURES_TO_BUFFER,
        expected_num_presignatures_offline=0,
        timeout_seconds=TIMEOUT,
    )
    # Ensure the nodes can handle signature requests. We deplete their asset stores
    lost_assets_cluster.send_and_await_signature_requests(2 * PRESIGNATURES_TO_BUFFER)

    # re-enable block ingestion, in case any tests run afterwards
    lost_assets_cluster.set_block_ingestion([faulty_node_idx], True)
