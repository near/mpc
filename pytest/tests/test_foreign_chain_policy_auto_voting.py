#!/usr/bin/env python3
"""
Tests automatic registration of supported foreign chains from node-local config.
"""

import pathlib
import sys

from cluster import atexit
import pytest

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))

from common_lib import shared
from common_lib.contract_state import ProtocolState
from common_lib.contracts import load_mpc_contract
from common_lib.shared import MpcCluster
from common_lib.shared import foreign_chains
from common_lib.shared import utils


FOREIGN_CHAINS_CONFIG = {
    "solana": {
        "timeout_sec": 30,
        "max_retries": 3,
        "providers": {
            "public": {
                "api_variant": "standard",
                "rpc_url": "https://rpc.public.example.com",
                "auth": {
                    "kind": "none",
                },
            }
        },
    }
}

FOREIGN_CHAINS_CONFIG_DTO = {
    "Solana": [
        {
            "rpc_url": "https://rpc.public.example.com",
        }
    ],
}


@pytest.fixture(scope="module")
def foreign_chain_registration_cluster():
    cluster, mpc_nodes = shared.start_cluster_with_mpc(
        3, 1, load_mpc_contract(), start_mpc_nodes=False
    )

    foreign_chains.set_foreign_chains_config(mpc_nodes[0], FOREIGN_CHAINS_CONFIG)
    foreign_chains.set_foreign_chains_config(mpc_nodes[1], FOREIGN_CHAINS_CONFIG)
    foreign_chains.set_foreign_chains_config(mpc_nodes[2], None)

    for node in mpc_nodes:
        node.run()

    cluster.init_cluster(participants=mpc_nodes, threshold=2)
    assert cluster.wait_for_state(ProtocolState.RUNNING), "expected running state"

    yield cluster, mpc_nodes

    cluster.kill_all()
    atexit._run_exitfuncs()


@pytest.mark.no_atexit_cleanup
def test_supported_foreign_chains_requires_all_participants(
    foreign_chain_registration_cluster: tuple[MpcCluster, list],
):
    cluster, mpc_nodes = foreign_chain_registration_cluster

    # Wait for all three nodes to auto-register on startup: nodes 0 and 1 with
    # Solana, node 2 with an empty configuration. Solana should not yet appear
    # as supported because node 2's configuration does not include it.
    def all_nodes_registered_with_one_empty() -> bool:
        registrations = cluster.view_contract_function(
            "get_foreign_chain_configurations"
        )["foreign_chain_configuration_by_node"]
        supported = cluster.view_contract_function("get_supported_foreign_chains")
        empty_count = sum(1 for config in registrations.values() if not config)
        return (
            len(registrations) == 3 and empty_count == 1 and "Solana" not in supported
        )

    utils.wait_until(
        all_nodes_registered_with_one_empty,
        description="all three registrations with one empty and Solana unsupported",
    )

    supported = cluster.view_contract_function("get_supported_foreign_chains")
    assert "Solana" not in supported, (
        "Solana should not be supported when not all participants registered it"
    )

    # Have node 3 register Solana support directly on the contract.
    cluster.call_contract_function_with_account_assert_success(
        mpc_nodes[2],
        "register_foreign_chain_config",
        {
            "foreign_chain_configuration": FOREIGN_CHAINS_CONFIG_DTO,
        },
    )

    def solana_supported() -> bool:
        supported = cluster.view_contract_function("get_supported_foreign_chains")
        return "Solana" in supported

    utils.wait_until(
        solana_supported,
        description="Solana supported after all participants registered it",
        timeout_sec=30,
    )
