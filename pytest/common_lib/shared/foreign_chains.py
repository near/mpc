"""Shared helpers for foreign chain configuration and policy tests."""

from typing import Any


def set_foreign_chains_config(node, foreign_chains: dict[str, Any] | None) -> None:
    if foreign_chains is not None:
        node.node_config["foreign_chains"] = foreign_chains
    else:
        node.node_config["foreign_chains"] = {}
