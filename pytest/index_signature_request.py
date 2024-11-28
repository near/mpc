#!/usr/bin/env python3
"""
Starts near validators and an mpc node.
Deploys mpc contract and sends a signature request.
Verifies that the mpc node indexes the request.
"""


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

def test_index_signature_request():
    nodes = start_cluster(
        2, 0, 1, None,
        [["epoch_length", 10], ["block_producer_kickout_threshold", 80]], {})

    # Deploy the mpc contract
    last_block_hash = nodes[0].get_latest_block().hash_bytes
    tx = sign_deploy_contract_tx(nodes[0].signer_key, load_mpc_contract(), 10, last_block_hash)
    res = nodes[0].send_tx_and_wait(tx, 20)
    assert('SuccessValue' in res['result']['status'])
    print(json.dumps(res, indent=2))

    # Send a signature request
    payload = [ 12, 1, 2, 0, 4, 5, 6, 8, 8, 9, 10, 11, 12, 13, 14, 44]
    sign_args= {
        'payload': payload,
        'path': 'test',
        'key_version': 0,
    }
    tx = sign_function_call_tx(
        nodes[1].signer_key,
        nodes[0].signer_key.account_id,
        'sign',
        json.dumps(sign_args).encode('utf-8'),
        150 * GGAS, 1, 20, last_block_hash)
    res = nodes[1].send_tx_and_wait(tx, 20)
    print(json.dumps(res, indent=2))

if __name__ == '__main__':
    test_deploy_contract()
