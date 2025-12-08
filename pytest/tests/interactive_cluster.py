#!/usr/bin/env python3
"""
Interactive integration test for signature requests using a local NEAR cluster.

This script:
- Starts 2 NEAR validators and 6 MPC (multi-party computation) nodes.
- Deploys the MPC contract.
- Initializes the cluster with multiple access keys for the responder account.
- Enters an interactive REPL loop where you can:
    - Send signature requests with 'sign <n>'.
    - Query in-process metrics with 'metric <name>'.
    - Exit with 'quit'.

Note:
- This test is marked as skipped by default (`@pytest.mark.skip`) because it's meant
  for manual experimentation or debugging only.
- It will fail if responses are not received within an internal timeout.

Usage:
    Run with `INTERACTIVE_PYTEST=1 pytest -s` to enable interactive input:
        $ INTERACTIVE_PYTEST=1 pytest -s path/to/this_file.py
"""

import sys
import pathlib
import pytest
import os

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
from common_lib import shared, signature
from common_lib.contracts import load_mpc_contract


def test_interactive_cluster():
    if os.environ.get("INTERACTIVE_PYTEST") != "1":
        pytest.skip(
            "Only used for manual interactive testing. Set INTERACTIVE_PYTEST=1 to run."
        )
    num_respond_access_keys = 5
    cluster, mpc_nodes = shared.start_cluster_with_mpc(
        6, num_respond_access_keys, load_mpc_contract()
    )
    cluster.init_cluster(mpc_nodes, 4)
    print(
        "Interactive mode started. Type 'sign <num_signatures>' to send signature requests or 'quit' to exit."
    )
    while True:
        try:
            cmd = input(">> ").strip()
            if cmd == "quit":
                print("Quitting interactive mode.")
                break
            elif cmd.startswith("sign"):
                try:
                    n_signatures = int(cmd.split()[1])
                    cluster.send_and_await_signature_requests(
                        n_signatures,
                        signature.print_signature_outcome,
                    )
                except (IndexError, ValueError):
                    print("Invalid command. Use: sign <int>")
            elif cmd.startswith("metric"):
                try:
                    _, metric_name = cmd.split(maxsplit=1)
                    value = cluster.get_int_metric_value(metric_name)
                    print(f"{metric_name} = {value}")
                except Exception as e:
                    print(f"error: {e}")
            else:
                print("Unknown command. Use 'sign <num_signatures>' or 'quit'.")
        except EOFError:
            break  # e.g., if piped input ends
