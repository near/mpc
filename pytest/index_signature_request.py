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
import re
import yaml
import pathlib
import requests
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
mpc_binary_path = os.path.join(mpc_repo_dir / 'target' / 'release', 'mpc-node')

# Some boilerplate to make pyyaml ignore unknown fields
def ignore_unknown(loader, tag_suffix, node):
    return None
class SafeLoaderIgnoreUnknown(yaml.SafeLoader):
    pass
SafeLoaderIgnoreUnknown.add_multi_constructor('!', ignore_unknown)

def load_mpc_contract() -> bytearray:
    path = mpc_repo_dir / 'libs/mpc/chain-signatures/res/mpc_contract.wasm'
    return load_binary_file(path)

def run_cmd_capturing_output(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)

def start_cluster_with_mpc(num_validators, num_mpc_nodes):
    # Start a near network with extra observer nodes; we will use their
    # config.json, genesis.json, etc. to configure the mpc nodes' indexers
    node_config = {
        # make debugging easier.
        # 'archive': True,
        # 'gc_num_epochs_to_keep': 1000,
    }
    nodes = start_cluster(
        num_validators, num_mpc_nodes, 1, None,
        [["epoch_length", 10], ["block_producer_kickout_threshold", 80]], {i: node_config for i in range(num_validators + num_mpc_nodes)})
    mpc_nodes = range(num_validators, num_validators + num_mpc_nodes)
    for i in mpc_nodes:
        nodes[i].kill(gentle=True)
        nodes[i].reset_data()

    # Generate the mpc configs
    dot_near = pathlib.Path.home() / '.near'
    subprocess.run((mpc_binary_path, 'generate-test-configs',
                                    '--output-dir', dot_near,
                                    '--num-participants', str(num_mpc_nodes),
                                    '--threshold', str(num_mpc_nodes),
                                    '--enable-indexer'))

    # Get the participant set from the mpc configs
    participants = {}
    account_id_to_participant_id = {}
    config_file_path = pathlib.Path(dot_near / '0' / 'config.yaml')
    with open(config_file_path) as file:
        mpc_config = yaml.load(file, Loader=SafeLoaderIgnoreUnknown)
    for i, p in enumerate(mpc_config['participants']['participants']):
        assert p['near_account_id'] == f"test{i}", f"This test only works with account IDs 'test0', 'test1', etc; expected 'test{i}', got {p['near_account_id']}"
        my_pk = p['p2p_public_key']
        my_addr = p['address']
        my_port = p['port']
            
        participants[f"test{i}"] = {
            "account_id": f"test{i}",
            "cipher_pk": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "sign_pk": my_pk,
            "url": f"http://{my_addr}:{my_port}",
        }
        account_id_to_participant_id[f"test{i}"] = p['id']

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
        print(f"Wrote {fname} as config for node {i}")

    def secret_key_hex(i):
        return str(chr(ord('A') + i) * 32)
    
    def p2p_private_key(i):
        return open(pathlib.Path(nodes[i].node_dir) / 'p2p_key').read()
    
    def near_secret_key(i):
        validator_key = json.loads(open(pathlib.Path(nodes[i].node_dir) / 'validator_key.json').read())
        return validator_key['secret_key']

    # Generate the root keyshares
    commands = [(mpc_binary_path, 'generate-key',
                 '--home-dir', nodes[i].node_dir, secret_key_hex(i), p2p_private_key(i)) for i in mpc_nodes]
    with Pool() as pool:
        keygen_results = pool.map(run_cmd_capturing_output, commands)

    # grep for "Public key: ..." in the output from the first keygen command
    # to extract the public key
    public_key = None
    for line in keygen_results[0].stdout.split('\n'):
        m = re.match(r'Public key: (.*)', line)
        if m:
            public_key = m.group(1)
            break
    assert public_key is not None, "Failed to extract public key from keygen output"
    print(f"Public key: {public_key}")

    # Deploy the mpc contract
    last_block_hash = nodes[0].get_latest_block().hash_bytes
    tx = sign_deploy_contract_tx(nodes[0].signer_key, load_mpc_contract(), 10, last_block_hash)
    res = nodes[0].send_tx_and_wait(tx, 20)
    assert('SuccessValue' in res['result']['status'])

    # Initialize the mpc contract
    init_args = {
        'epoch': 0,
        'threshold': num_mpc_nodes,
        'participants': {
            'participants': participants,
            'next_id': 0,  # not used
            'account_to_participant_id': account_id_to_participant_id,
        },
        'public_key': public_key,
    }

    # Start the mpc nodes
    for i in mpc_nodes:
        cmd = (mpc_binary_path, 'start', '--home-dir', nodes[i].node_dir)
        # mpc-node produces way too much output if we run with debug logs
        nodes[i].run_cmd(cmd=cmd, extra_env={
            'RUST_LOG':'INFO',
            'MPC_SECRET_STORE_KEY': secret_key_hex(i),
            'MPC_P2P_PRIVATE_KEY': p2p_private_key(i),
            'MPC_ACCOUNT_SK': near_secret_key(i),
        })

    tx = sign_function_call_tx(
        nodes[0].signer_key,
        nodes[0].signer_key.account_id,
        'init_running',
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
    tx_hash = nodes[1].send_tx(tx)['result']

    # Wait for the indexers to observe the signature request
    while True:
        assert time.time() - started < TIMEOUT, "Waiting for mpc indexers"
        try:
            res2 = metrics2.get_int_metric_value('mpc_num_signature_requests')
            res3 = metrics3.get_int_metric_value('mpc_num_signature_requests')
            if res2 == 1 and res3 == 1:
                break
        except requests.exceptions.ConnectionError:
            pass
        time.sleep(1)

    for _ in range(20):
        try:
            res = nodes[1].get_tx(tx_hash, nodes[0].signer_key.account_id)
            print(res)
            break
        except Exception as e:
            print(e)
        time.sleep(1)

    print('EPIC')

if __name__ == '__main__':
    test_index_signature_request()
