#!/usr/bin/env python3
"""
Tests automatic voting of foreign chain policy from node-local config.
"""

import pathlib
import re
import sys
import time
from typing import Any

from cluster import atexit
import pytest
import yaml

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))

from common_lib import shared
from common_lib.contract_state import ProtocolState
from common_lib.contracts import load_mpc_contract
from common_lib.shared import MpcCluster


def _node_config_path(node) -> pathlib.Path:
    return pathlib.Path(node.home_dir) / "config.yaml"


def _set_foreign_chains_config(node, foreign_chains: dict[str, Any] | None) -> None:
    config_path = _node_config_path(node)

    config_text = config_path.read_text(encoding="utf-8")
    # Keep generated YAML tags intact by editing only the trailing `foreign_chains` section.
    config_text = (
        re.sub(r"\nforeign_chains:\n[\s\S]*\Z", "\n", config_text).rstrip() + "\n"
    )

    if foreign_chains is not None:
        foreign_chains_text = yaml.safe_dump(
            {"foreign_chains": foreign_chains}, sort_keys=False
        )
        config_text += "\n" + foreign_chains_text

    config_path.write_text(config_text, encoding="utf-8")


def _normalize_policy(policy: dict[str, Any]) -> list[tuple[str, tuple[str, ...]]]:
    chains = policy.get("chains", [])
    normalized = []
    for chain_cfg in chains:
        chain_name = chain_cfg["chain"]
        providers = tuple(sorted(p["rpc_url"] for p in chain_cfg["providers"]))
        normalized.append((chain_name, providers))
    return sorted(normalized)


def _wait_until(
    predicate, description: str, timeout_sec: float = 30, poll_interval_sec: float = 0.5
) -> None:
    deadline = time.monotonic() + timeout_sec
    last_error = None
    while time.monotonic() < deadline:
        try:
            if predicate():
                return
        except Exception as err:
            last_error = err
        time.sleep(poll_interval_sec)

    raise AssertionError(f"timed out waiting for {description}") from last_error


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
    "chains": [
        {
            "chain": "Solana",
            "providers": [
                {
                    "rpc_url": "https://rpc.public.example.com",
                }
            ],
        }
    ]
}


@pytest.fixture(scope="module")
def foreign_chain_policy_cluster():
    cluster, mpc_nodes = shared.start_cluster_with_mpc(
        3, 1, load_mpc_contract(), start_mpc_nodes=False
    )

    _set_foreign_chains_config(mpc_nodes[0], FOREIGN_CHAINS_CONFIG)
    _set_foreign_chains_config(mpc_nodes[1], FOREIGN_CHAINS_CONFIG)
    _set_foreign_chains_config(mpc_nodes[2], None)

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
        return len(votes) == 2 and _normalize_policy(policy) == []

    _wait_until(
        partial_votes_visible,
        description="two policy votes without policy application",
    )

    votes = cluster.view_contract_function("get_foreign_chain_policy_proposals")[
        "proposal_by_account"
    ]
    assert len(votes) == 2, "expected exactly two votes before unanimity"
    assert (
        _normalize_policy(cluster.view_contract_function("get_foreign_chain_policy"))
        == []
    ), "policy should not be applied before unanimous voting"

    cluster.call_contract_function_with_account_assert_success(
        mpc_nodes[2],
        "vote_foreign_chain_policy",
        {"policy": EXPECTED_POLICY},
    )

    expected_normalized_policy = _normalize_policy(EXPECTED_POLICY)

    def policy_applied() -> bool:
        votes = cluster.view_contract_function("get_foreign_chain_policy_proposals")[
            "proposal_by_account"
        ]
        policy = cluster.view_contract_function("get_foreign_chain_policy")
        return (
            len(votes) == 0 and _normalize_policy(policy) == expected_normalized_policy
        )

    _wait_until(
        policy_applied,
        description="policy application after unanimous voting",
        timeout_sec=30,
    )
