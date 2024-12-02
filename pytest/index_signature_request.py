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
from prometheus_client.parser import text_string_to_metric_families
from multiprocessing import Pool

sys.path.append(str(pathlib.Path(__file__).resolve()
                    .parents[1] / 'libs' / 'nearcore' / 'pytest' / 'lib'))
from cluster import start_cluster, session
from transaction import sign_deploy_contract_tx, sign_function_call_tx
from utils import load_binary_file, MetricsTracker

TIMEOUT = 60
TGAS = 10**12

mpc_repo_dir = pathlib.Path(__file__).resolve().parents[1]
mpc_binary_path = os.path.join(mpc_repo_dir / 'target' / 'debug', 'mpc-node')

def load_mpc_contract() -> bytearray:
    path = mpc_repo_dir / 'libs/mpc/chain-signatures/res/mpc_contract.wasm'
    return load_binary_file(path)

def start_cluster_with_mpc(num_validators, num_mpc_nodes):
    # Start a near network with extra observer nodes; we will use their
    # config.json, genesis.json, etc. to configure the mpc nodes' indexers
    nodes = start_cluster(
        num_validators, num_mpc_nodes, 1, None,
        [["epoch_length", 10], ["block_producer_kickout_threshold", 80]], {})
    mpc_nodes = range(num_validators, num_validators + num_mpc_nodes)
    for i in mpc_nodes:
        nodes[i].kill(gentle=True)
        nodes[i].reset_data()

    # Generate the mpc configs
    dot_near = pathlib.Path.home() / '.near'
    subprocess.run((mpc_binary_path, 'generate-test-configs',
                    '--output-dir', dot_near, '--num-participants', '2', '--threshold', '1'))

    # Set up the node's home directories
    for i in mpc_nodes:
        # Move the generated mpc configs
        mpc_config_dir = dot_near / str(i - num_validators)
        for fname in os.listdir(mpc_config_dir):
            subprocess.run(('mv', os.path.join(mpc_config_dir, fname), nodes[i].node_dir))

        # Indexer config must explicitly specify tracked shard
        fname = os.path.join(nodes[i].node_dir, 'config.json')
        with open(fname) as fd:
            config_json = json.load(fd)
        config_json['tracked_shards'] = [0]
        with open(fname, 'w') as fd:
            json.dump(config_json, fd, indent=2)

    secret_key_hex = '0123456789ABCDEF0123456789ABCDEF'

    # Generate the root keyshares
    commands = [(mpc_binary_path, 'generate-key',
                 '--home-dir', nodes[i].node_dir, secret_key_hex) for i in mpc_nodes]
    with Pool() as pool:
        pool.map(subprocess.run, commands)

    # Start the mpc nodes
    for i in mpc_nodes:
        nodes[i].run_cmd(cmd=(mpc_binary_path, 'start', '--home-dir', nodes[i].node_dir, secret_key_hex))

    # Deploy the mpc contract
    last_block_hash = nodes[0].get_latest_block().hash_bytes
    tx = sign_deploy_contract_tx(nodes[0].signer_key, load_mpc_contract(), 10, last_block_hash)
    res = nodes[0].send_tx_and_wait(tx, 20)
    assert('SuccessValue' in res['result']['status'])

    # Initialize the mpc contract
    # TODO: initialize the contract properly with the MPC nodes as the participants
    init_args = {
        'threshold': 0,
        'candidates': {},
    }
    tx = sign_function_call_tx(
        nodes[0].signer_key,
        nodes[0].signer_key.account_id,
        'init',
        json.dumps(init_args).encode('utf-8'),
        150 * TGAS, 0, 20, last_block_hash)
    res = nodes[0].send_tx_and_wait(tx, 20)
    assert('SuccessValue' in res['result']['status'])

    return nodes

def test_index_signature_request():
    started = time.time()
    nodes = start_cluster_with_mpc(2, 2)

    metrics2 = MetricsTracker(nodes[2])
    metrics3 = MetricsTracker(nodes[3])

    # Send a signature request
    payload = [12,1,2,0,4,5,6,8,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,44]
    sign_args= {
        'request': {
            'key_version': 0,
            'path': 'test',
            'payload': payload,
        }
    }
    last_block_hash = nodes[0].get_latest_block().hash_bytes
    tx = sign_function_call_tx(
        nodes[1].signer_key,
        nodes[0].signer_key.account_id,
        'sign',
        json.dumps(sign_args).encode('utf-8'),
        150 * TGAS, 1, 20, last_block_hash)
    res = nodes[1].send_tx(tx)

    # Wait for the indexers to observe the signature request
    while True:
        assert time.time() - started < TIMEOUT, "Waiting for mpc indexers"
        res2 = metrics2.get_int_metric_value('mpc_num_signature_requests')
        res3 = metrics3.get_int_metric_value('mpc_num_signature_requests')
        if res2 == 1 and res3 == 1:
            break
        time.sleep(1)

    print('EPIC')

if __name__ == '__main__':
    test_index_signature_request()
