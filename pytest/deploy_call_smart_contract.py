#!/usr/bin/env python3
"""Deploy a smart contract on one node and call it on another."""

import sys
import json
import time
import pathlib

sys.path.append(str(pathlib.Path(__file__).resolve()
                    .parents[1] / 'libs' / 'nearcore' / 'pytest' / 'lib'))
from cluster import start_cluster
from transaction import sign_deploy_contract_tx, sign_function_call_tx
from utils import load_binary_file

GGAS = 10**9

def load_mpc_contract() -> bytearray:
    repo_dir = pathlib.Path(__file__).resolve().parents[1]
    path = repo_dir / 'libs/mpc/chain-signatures/res/mpc_contract.wasm'
    return load_binary_file(path)

def test_deploy_contract():
    nodes = start_cluster(
        2, 0, 1, None,
        [["epoch_length", 10], ["block_producer_kickout_threshold", 80]], {})

    last_block_hash = nodes[0].get_latest_block().hash_bytes
    tx = sign_deploy_contract_tx(nodes[0].signer_key, load_mpc_contract(), 10,
                                 last_block_hash)
    res = nodes[0].send_tx_and_wait(tx, 20)
    print(json.dumps(res, indent=2))

if __name__ == '__main__':
    test_deploy_contract()
