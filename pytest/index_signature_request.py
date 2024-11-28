#!/usr/bin/env python3
"""
Starts 2 near validators and 2 mpc nodes.
Deploys mpc contract and sends a signature request.
Verifies that the mpc nodes index the signature request.
"""

import os
import sys
import json
import time
import pathlib
import subprocess

sys.path.append(str(pathlib.Path(__file__).resolve()
                    .parents[1] / 'libs' / 'nearcore' / 'pytest' / 'lib'))
from cluster import start_cluster, session
from transaction import sign_deploy_contract_tx, sign_function_call_tx
from utils import load_binary_file

GGAS = 10**9

repo_dir = pathlib.Path(__file__).resolve().parents[1]

def load_mpc_contract() -> bytearray:
    path = repo_dir / 'libs/mpc/chain-signatures/res/mpc_contract.wasm'
    return load_binary_file(path)

def start_cluster_with_mpc(num_validators, num_mpc_nodes):
    # Start a near network with extra observer nodes; we will use their
    # config.json, genesis.json, etc. to configure the mpc nodes' indexers
    nodes = start_cluster(
        num_validators, num_mpc_nodes, 1, None,
        [["epoch_length", 10], ["block_producer_kickout_threshold", 80]], {})
    for i in range(0, num_mpc_nodes):
        nodes[num_validators + i].kill(gentle=True)

    # Generate the mpc configs
    binary_path = os.path.join(repo_dir / 'target' / 'debug', 'mpc-node')
    dot_near = pathlib.Path.home() / '.near'
    subprocess.run((binary_path, 'generate-test-configs',
                    '--output-dir', dot_near, '--num-participants', '2', '--threshold', '1'))

    # Finish configuring the nodes and start them
    for i in range(0, num_mpc_nodes):
        node = nodes[num_validators + i]

        mpc_config_dir = dot_near / str(i)
        for fname in os.listdir(mpc_config_dir):
            subprocess.run(('mv', os.path.join(mpc_config_dir, fname), node.node_dir))

        # Indexer requires tracked shard
        fname = os.path.join(node.node_dir, 'config.json')
        with open(fname) as fd:
            config_json = json.load(fd)
        config_json['tracked_shards'] = [0]
        with open(fname, 'w') as fd:
            json.dump(config_json, fd, indent=2)

        secret_key_hex = '0123456789ABCDEF0123456789ABCDEF'
        node.run_cmd(cmd=(binary_path, 'start', '--home-dir', node.node_dir, secret_key_hex))

    return nodes

def test_index_signature_request():
    nodes = start_cluster_with_mpc(2, 2)

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

    # Check MPC node metrics
    with session() as s:
        r = s.get("http://127.0.0.1:20000/metrics")
        r.raise_for_status()
        print(r.content)

if __name__ == '__main__':
    test_index_signature_request()
