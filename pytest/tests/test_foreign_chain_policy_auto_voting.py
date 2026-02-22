#!/usr/bin/env python3
"""
Tests automatic voting of foreign chain policy from node-local config.
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

EXPECTED_POLICY = {
    "chains": {
        "Solana": [
            {
                "rpc_url": "https://rpc.public.example.com",
            }
        ],
    }
}


@pytest.fixture(scope="module")
def foreign_chain_policy_cluster():
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
def test_foreign_chain_policy_auto_voting_requires_unanimity(
    foreign_chain_policy_cluster: tuple[MpcCluster, list],
):
    cluster, mpc_nodes = foreign_chain_policy_cluster

    def partial_votes_visible() -> bool:
        votes = cluster.view_contract_function("get_foreign_chain_policy_proposals")[
            "proposal_by_account"
        ]
        policy = cluster.view_contract_function("get_foreign_chain_policy")
        return len(votes) == 2 and foreign_chains.normalize_policy(policy) == []

    utils.wait_until(
        partial_votes_visible,
        description="two policy votes without policy application",
    )

    votes = cluster.view_contract_function("get_foreign_chain_policy_proposals")[
        "proposal_by_account"
    ]
    assert len(votes) == 2, "expected exactly two votes before unanimity"
    assert (
        foreign_chains.normalize_policy(
            cluster.view_contract_function("get_foreign_chain_policy")
        )
        == []
    ), "policy should not be applied before unanimous voting"

    cluster.call_contract_function_with_account_assert_success(
        mpc_nodes[2],
        "vote_foreign_chain_policy",
        {"policy": EXPECTED_POLICY},
    )

    expected_normalized_policy = foreign_chains.normalize_policy(EXPECTED_POLICY)

    def policy_applied() -> bool:
        votes = cluster.view_contract_function("get_foreign_chain_policy_proposals")[
            "proposal_by_account"
        ]
        policy = cluster.view_contract_function("get_foreign_chain_policy")
        return (
            len(votes) == 0
            and foreign_chains.normalize_policy(policy) == expected_normalized_policy
        )

    utils.wait_until(
        policy_applied,
        description="policy application after unanimous voting",
        timeout_sec=30,
    )
