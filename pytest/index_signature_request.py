#!/usr/bin/env python3
"""
Starts 2 near validators and 2 mpc nodes.
Deploys mpc contract and sends a signature request.
Verifies that the mpc nodes index the signature request.
"""

import base64
import base58
import os
import sys
import json
import time
import re
import yaml
import pathlib
import argparse
import requests
import subprocess
from prometheus_client.parser import text_string_to_metric_families
from multiprocessing import Pool
from concurrent.futures import ThreadPoolExecutor

sys.path.append(
    str(
        pathlib.Path(__file__).resolve().parents[1] / 'libs' / 'nearcore' /
        'pytest' / 'lib'))
from cluster import start_cluster, session
from utils import load_binary_file, MetricsTracker
from transaction import create_create_account_action, create_payment_action, \
                        create_full_access_key_action, sign_deploy_contract_tx, \
                        sign_transaction, serialize_transaction, sign_function_call_tx
from key import Key

TIMEOUT = 60
NEAR_BASE = 10**24
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
    path = mpc_repo_dir / 'libs/chain-signatures/res/mpc_contract.wasm'
    return load_binary_file(path)


# Output is deserializable into the rust type near_crypto::SecretKey
def serialize_key(key):
    full_key = bytes(key.decoded_sk()) + bytes(key.decoded_pk())
    return 'ed25519:' + base58.b58encode(full_key).decode('ascii')


def sign_create_account_with_multiple_access_keys_tx(creator_key, new_account_id, keys,
                                                     nonce, block_hash):
    create_account_action = create_create_account_action()
    payment_action = create_payment_action(100 * NEAR_BASE)
    access_key_actions = [create_full_access_key_action(key.decoded_pk()) for key in keys]
    actions = [create_account_action, payment_action] + access_key_actions
    signed_tx = sign_transaction(new_account_id, nonce, actions, block_hash,
                              creator_key.account_id, creator_key.decoded_pk(),
                              creator_key.decoded_sk())
    return serialize_transaction(signed_tx)


def start_cluster_with_mpc(num_validators, num_mpc_nodes, num_respond_aks):
    # Start a near network with extra observer nodes; we will use their
    # config.json, genesis.json, etc. to configure the mpc nodes' indexers
    nodes = start_cluster(
        num_validators, num_mpc_nodes, 1, None,
        [["epoch_length", 1000], ["block_producer_kickout_threshold", 80]], {})
    mpc_nodes = range(num_validators, num_validators + num_mpc_nodes)
    for i in mpc_nodes:
        nodes[i].kill(gentle=True)
        nodes[i].reset_data()

    # Generate the mpc configs
    dot_near = pathlib.Path.home() / '.near'
    subprocess.run(
        (mpc_binary_path, 'generate-test-configs', '--output-dir', dot_near,
         '--participants', ','.join(f'test{i + num_validators}'
                                    for i in range(num_mpc_nodes)),
         '--threshold', str(num_mpc_nodes)))

    # Get the participant set from the mpc configs
    participants = {}
    account_id_to_participant_id = {}
    config_file_path = pathlib.Path(dot_near / '0' / 'config.yaml')
    with open(config_file_path) as file:
        mpc_config = yaml.load(file, Loader=SafeLoaderIgnoreUnknown)
    for i, p in enumerate(mpc_config['participants']['participants']):
        near_account = p['near_account_id']
        assert near_account == f"test{i + num_validators}", \
            f"This test only works with account IDs 'testX' where X is the node index; expected 'test{i + num_validators}', got {near_account}"
        my_pk = p['p2p_public_key']
        my_addr = p['address']
        my_port = p['port']

        participants[near_account] = {
            "account_id":
            near_account,
            "cipher_pk": [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ],
            "sign_pk":
            my_pk,
            "url":
            f"http://{my_addr}:{my_port}",
        }
        account_id_to_participant_id[near_account] = p['id']

    last_block_hash = nodes[0].get_latest_block().hash_bytes

    def near_secret_key(i):
        validator_key = json.loads(
            open(pathlib.Path(nodes[i].node_dir) /
                 'validator_key.json').read())
        return validator_key['secret_key']

    def send_and_confirm_tx(tx):
        res = nodes[0].send_tx_and_wait(tx, 20)
        assert ('SuccessValue' in res['result']['status']), res

    # Set up the node's home directories
    for i in mpc_nodes:
        # Move the generated mpc configs
        mpc_config_dir = dot_near / str(i - num_validators)
        for fname in os.listdir(mpc_config_dir):
            subprocess.run(('mv', os.path.join(mpc_config_dir,
                                               fname), nodes[i].node_dir))

        # Indexer config must explicitly specify tracked shard
        fname = os.path.join(nodes[i].node_dir, 'config.json')
        with open(fname) as fd:
            config_json = json.load(fd)
        config_json['tracked_shards'] = [0]
        with open(fname, 'w') as fd:
            json.dump(config_json, fd, indent=2)
        print(f"Wrote {fname} as config for node {i}")

        # Create respond.yaml with credentials for sending responses
        account_id = f"respond.test{i}"
        access_keys = [Key.from_seed_testonly(account_id, seed=f"{s}")
                       for s in range(0, num_respond_aks)]
        tx = sign_create_account_with_multiple_access_keys_tx(
                nodes[i].signer_key, account_id, access_keys, 1, last_block_hash)
        send_and_confirm_tx(tx)
        respond_cfg = {
            'account_id': account_id,
            'access_keys': list(map(serialize_key, access_keys)),
        }
        fname = os.path.join(nodes[i].node_dir, 'respond.yaml')
        with open(fname, "w") as file:
            yaml.dump(respond_cfg, file, default_flow_style=False)

    def secret_key_hex(i):
        return str(chr(ord('A') + i) * 32)

    def p2p_private_key(i):
        return open(pathlib.Path(nodes[i].node_dir) / 'p2p_key').read()

    # Generate the root keyshares
    commands = [(mpc_binary_path, 'generate-key', '--home-dir',
                 nodes[i].node_dir, secret_key_hex(i), p2p_private_key(i))
                for i in mpc_nodes]
    with Pool() as pool:
        keygen_results = pool.map(subprocess.check_output, commands)

    # grep for "Public key: ..." in the output from the first keygen command
    # to extract the public key
    public_key = None
    for line in keygen_results[0].decode('utf-8', 'ignore').split('\n'):
        m = re.match(r'Public key: (.*)', line)
        if m:
            public_key = m.group(1)
            break
    assert public_key is not None, "Failed to extract public key from keygen output"
    print(f"Public key: {public_key}")

    # Deploy the mpc contract
    tx = sign_deploy_contract_tx(nodes[0].signer_key, load_mpc_contract(), 10,
                                 last_block_hash)
    send_and_confirm_tx(tx)

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
        nodes[i].run_cmd(cmd=cmd,
                         extra_env={
                             'RUST_LOG': 'INFO',
                             'MPC_SECRET_STORE_KEY': secret_key_hex(i),
                             'MPC_P2P_PRIVATE_KEY': p2p_private_key(i),
                             'MPC_ACCOUNT_SK': near_secret_key(i),
                         })

    tx = sign_function_call_tx(nodes[0].signer_key,
                               nodes[0].signer_key.account_id, 'init_running',
                               json.dumps(init_args).encode('utf-8'),
                               150 * TGAS, 0, 20, last_block_hash)
    res = nodes[0].send_tx_and_wait(tx, 20)
    assert ('SuccessValue' in res['result']['status'])

    return nodes


def test_index_signature_request(num_requests, num_respond_access_keys):
    started = time.time()
    nodes = start_cluster_with_mpc(2, 2, num_respond_access_keys)

    metrics2 = MetricsTracker(nodes[2])
    metrics3 = MetricsTracker(nodes[3])

    tx_recipient_id = nodes[0].signer_key.account_id
    last_block_hash = nodes[0].get_latest_block().hash_bytes

    # Construct signature requests
    txs = []
    for i in range(0, num_requests):
        payload = [
            i, 1, 2, 0, 4, 5, 6, 8, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
            19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 44
        ]
        sign_args = {
            'request': {
                'key_version': 0,
                'path': 'test',
                'payload': payload,
            }
        }
        nonce = 20 + i
        tx = sign_function_call_tx(nodes[1].signer_key, tx_recipient_id,
                                   'sign',
                                   json.dumps(sign_args).encode('utf-8'),
                                   150 * TGAS, 1, nonce, last_block_hash)
        txs.append(tx)

    def send_tx(tx):
        return nodes[1].send_tx(tx)['result']

    tx_sent = time.time()
    with ThreadPoolExecutor() as executor:
        tx_hashes = list(executor.map(send_tx, txs))
    print("Sent signature requests, tx_hashes:", tx_hashes)

    # Wait for the indexers to observe the signature requests
    # In case num_requests > 1, some txs may not be included due to nonce conflicts
    while True:
        assert time.time() - started < TIMEOUT, "Waiting for mpc indexers"
        try:
            res2 = metrics2.get_int_metric_value('mpc_num_signature_requests')
            res3 = metrics3.get_int_metric_value('mpc_num_signature_requests')
            print("Indexers num_signature_requests:", res2, res3)
            if res2 and res2 >= 1 and res3 and res3 >= 1:
                tx_indexed = time.time()
                print("Indexer latency: ", tx_indexed - tx_sent)
                break
        except requests.exceptions.ConnectionError:
            pass
        time.sleep(1)

    # Wait for all of the transactions to have results
    for _ in range(20):
        try:
            results = []
            for tx_hash in tx_hashes:
                res = nodes[1].get_tx(tx_hash, tx_recipient_id)
                results.append(res)
                time.sleep(0.1)
            break
        except Exception as e:
            print(e)
        time.sleep(1)

    for res in results:
        try:
            signature_base64 = res['result']['status']['SuccessValue']
            while len(signature_base64) % 4 != 0:
                signature_base64 += '='
            signature = base64.b64decode(signature_base64)
            signature = json.loads(signature)
            print("SUCCESS! Signature:", signature)
        except Exception as e:
            print("Failed to get signature:", e)
            print("Response:", res)
            assert False

    res2 = metrics2.get_int_metric_value('mpc_num_sign_responses_timed_out')
    res3 = metrics2.get_int_metric_value('mpc_num_sign_responses_timed_out')
    print("Number of nonce conflicts which occurred:", res2, res3)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--num-requests",
                        type=int,
                        default=1,
                        help="Number of signature requests to make")
    parser.add_argument("--num-respond-access-keys",
                        type=int,
                        default=1,
                        help="Number of access keys to provision for the respond signer account")
    args = parser.parse_args()

    test_index_signature_request(args.num_requests, args.num_respond_access_keys)
