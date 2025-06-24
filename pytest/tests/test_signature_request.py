#!/usr/bin/env python3
"""
Starts 2 near validators and 2 mpc nodes.
Deploys mpc contract in 'libs/chain-signatures/res/mpc_contract.wasm'
Sends signature requests.
Verifies that the mpc nodes index the signature request.
Waits for the signature responses. Fails if timeout is reached.
"""

from datetime import datetime
import sys
import pathlib
import argparse
from time import sleep
import pytest

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
from common_lib import shared
from common_lib.contracts import load_mpc_contract


@pytest.mark.parametrize("num_requests, num_respond_access_keys", [(10, 1)])
def test_signature_pause_block_ingestion(num_requests,
                                         num_respond_access_keys):
    cluster, mpc_nodes = shared.start_cluster_with_mpc(
        2, 6, num_respond_access_keys, load_mpc_contract())
    cluster.init_cluster(mpc_nodes, 4)
    # removing one node should not be a problem.

    mpc_nodes[0].set_block_ingestion(False)
    mpc_nodes[1].set_block_ingestion(False)
    # we pause
    for _ in range(0, 120):
        print(
            "owned and online:\n",
            cluster.get_int_metric_value("mpc_owned_num_presignatures_online"))
        print(
            "owned and offline:\n",
            cluster.get_int_metric_value(
                "mpc_owned_num_presignatures_with_offline_participant"))
        print("block height:\n",
              cluster.get_int_metric_value("mpc_indexer_latest_block_height"))
        sleep(1)
    t0 = datetime.now()
    cluster.send_and_await_signature_requests(num_requests)
    t1 = datetime.now()
    delay = t1 - t0
    print(f"time passed: {delay}")

    cluster.send_and_await_signature_requests(num_requests)
    t2 = datetime.now()
    delay = t2 - t1
    print(f"time passed: {delay}")
    # we would expect to get faster
    cluster.send_and_await_signature_requests(num_requests)
    t3 = datetime.now()
    delay = t3 - t2
    print(f"time passed: {delay}")
    # we would expect to get faster


@pytest.mark.parametrize("num_requests, num_respond_access_keys", [(10, 1)])
def test_signature_lifecycle(num_requests, num_respond_access_keys):
    cluster, mpc_nodes = shared.start_cluster_with_mpc(
        2, 3, num_respond_access_keys, load_mpc_contract())
    cluster.init_cluster(mpc_nodes, 2)
    # removing one node should not be a problem.

    mpc_nodes[0].kill(False)
    cluster.send_and_await_signature_requests(num_requests)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--num-requests",
                        type=int,
                        default=10,
                        help="Number of signature requests to make")
    parser.add_argument(
        "--num-respond-access-keys",
        type=int,
        default=1,
        help="Number of access keys to provision for the respond signer account"
    )
    args = parser.parse_args()

    test_signature_lifecycle(args.num_requests, args.num_respond_access_keys)
