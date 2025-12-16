#!/usr/bin/env python3
"""
Starts 2 near validators and 3 mpc nodes.
Allows assets to be generated, then stops one node and wipes its database.
Restarts the node and verifies that signature requests succeed.
"""

import sys
from cluster import atexit
import pytest
import random
import pathlib

from common_lib.contract_state import ContractState, ProtocolState
from common_lib.shared import MpcCluster, metrics

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
from common_lib import shared
from common_lib.shared import mpc_cluster_metrics
from common_lib.contracts import load_mpc_contract
from common_lib.constants import INDEXER_MAX_HEIGHT_DIFF, TIMEOUT

PRESIGNATURES_TO_BUFFER = 8


@pytest.fixture(scope="module")
def lost_assets_cluster():
    """
    Spins up a cluster with three nodes, initializes the contract and adds domains. Returns the cluster in a running state.
    """
    cluster, mpc_nodes = shared.start_cluster_with_mpc(
        3,
        1,
        load_mpc_contract(),
        presignatures_to_buffer=PRESIGNATURES_TO_BUFFER,
    )
    cluster.init_cluster(mpc_nodes, 2)
    cluster.wait_for_state(ProtocolState.RUNNING)

    yield cluster

    cluster.kill_all()

    atexit._run_exitfuncs()


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
    mpc_cluster_metrics.assert_num_presignatures_available(
        lost_assets_cluster, PRESIGNATURES_TO_BUFFER, TIMEOUT
    )

    # Stop one of the mpc nodes and wipe its database. Any assets generated before this point
    # which included that node are now unusable because node 0 has lost its share.
    faulty_node_idx = random.randint(0, 2)
    node_idxs_alive = [i for i in range(0, 3) if i != faulty_node_idx]
    lost_assets_cluster.kill_nodes([faulty_node_idx])
    lost_assets_cluster.reset_mpc_data([faulty_node_idx])

    # Assert that node is noticed as offline
    mpc_cluster_metrics.assert_num_live_connections(
        lost_assets_cluster, node_idxs_alive, 2, TIMEOUT
    )

    # Ensure alive nodes clean up assets involving dead node (the key behavior we want to test)
    mpc_cluster_metrics.assert_num_offline_online_presignatures(
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
    mpc_cluster_metrics.assert_num_live_connections(
        lost_assets_cluster, node_idxs_alive, 3, TIMEOUT
    )

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
    mpc_cluster_metrics.assert_num_presignatures_available(
        lost_assets_cluster, PRESIGNATURES_TO_BUFFER, TIMEOUT
    )

    # Disable block ingestion on one of the nodes
    faulty_node_idx = random.randint(0, 2)
    node_idxs_alive = [i for i in range(0, 3) if i != faulty_node_idx]
    lost_assets_cluster.set_block_ingestion([faulty_node_idx], False)

    # Ensure the node falls the required number of blocks behind to be considered offline
    mpc_cluster_metrics.assert_indexer_lag(
        lost_assets_cluster, faulty_node_idx, node_idxs_alive, INDEXER_MAX_HEIGHT_DIFF
    )

    # Ensure the asset cleanup mechanism kicks in
    mpc_cluster_metrics.assert_num_offline_online_presignatures(
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
