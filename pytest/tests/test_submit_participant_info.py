#!/usr/bin/env python3
"""
Tests that MPC nodes successfully call the submit_participant_info endpoint.
"""

import sys
import pathlib

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
from common_lib import shared
from common_lib.contracts import load_mpc_contract


def test_submit_participant_info_endpoint():
    initial_participants = 2
    total_mpc_nodes = 4
    cluster, mpc_nodes = shared.start_cluster_with_mpc(
        total_mpc_nodes,
        1,
        load_mpc_contract(),
    )
    cluster.init_cluster(mpc_nodes[:initial_participants], 2)

    attestations_submitted = cluster.wait_for_nodes_to_have_attestation(mpc_nodes)

    assert attestations_submitted, (
        f"Timeout: Not all {len(mpc_nodes) - initial_participants} additional nodes submitted attestations within the timeout period. "
        f"Check the debug output above for which nodes failed to submit."
    )
