"""Shared helpers for foreign chain configuration and policy tests."""

from typing import Any


def set_foreign_chains_config(node, foreign_chains: dict[str, Any] | None) -> None:
    if foreign_chains is not None:
        node.node_config["foreign_chains"] = foreign_chains
    else:
        node.node_config["foreign_chains"] = {}


def normalize_policy(policy: dict[str, Any]) -> list[tuple[str, tuple[str, ...]]]:
    chains = policy.get("chains", {})
    normalized = []
    for chain_name, providers in chains.items():
        rpcs = tuple(sorted(p["rpc_url"] for p in providers))
        normalized.append((chain_name, rpcs))
    return sorted(normalized)
