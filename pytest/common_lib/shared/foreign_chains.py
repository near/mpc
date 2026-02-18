"""Shared helpers for foreign chain configuration and policy tests."""

import pathlib
import re
from typing import Any

import yaml


def node_config_path(node) -> pathlib.Path:
    return pathlib.Path(node.home_dir) / "config.yaml"


def set_foreign_chains_config(node, foreign_chains: dict[str, Any] | None) -> None:
    config_path = node_config_path(node)

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


def normalize_policy(policy: dict[str, Any]) -> list[tuple[str, tuple[str, ...]]]:
    chains = policy.get("chains", {})
    normalized = []
    for chain_name, providers in chains.items():
        rpcs = tuple(sorted(p["rpc_url"] for p in providers))
        normalized.append((chain_name, rpcs))
    return sorted(normalized)
