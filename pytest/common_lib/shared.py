import base64
import base58
import os
import sys
import json
import re
import yaml
import pathlib
import subprocess
from prometheus_client.parser import text_string_to_metric_families
from multiprocessing import Pool
from concurrent.futures import ThreadPoolExecutor

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))

from cluster import BaseNode
from typing import List

from cluster import start_cluster
from utils import MetricsTracker

from transaction import create_create_account_action, create_payment_action, \
                        create_full_access_key_action, sign_deploy_contract_tx, \
                        sign_transaction, serialize_transaction, sign_function_call_tx

from key import Key

#from .contracts import load_mpc_contract
from .constants import NEAR_BASE, mpc_binary_path, TGAS, TIMEOUT
from .contracts import ProposeUpdateArgs

import time

import requests


# Some boilerplate to make pyyaml ignore unknown fields
def ignore_unknown(loader, tag_suffix, node):
    return None


class SafeLoaderIgnoreUnknown(yaml.SafeLoader):
    pass


SafeLoaderIgnoreUnknown.add_multi_constructor('!', ignore_unknown)

import hashlib


class MpcCluster:
    """Helper class"""

    def __init__(self, nodes, num_mpc_nodes):
        self.nodes: List[BaseNode] = nodes
        self.num_mpc_nodes: int = num_mpc_nodes

    def contract_account(self):
        return self.nodes[0].signer_key.account_id

    def get_nonce(self, node_id):
        return self.nodes[node_id].get_nonce_for_pk(
            self.nodes[node_id].signer_key.account_id,
            self.nodes[node_id].signer_key.pk)

    """
    creates on signature transaction for each payload in payloads.
    returns a list of signed transactions
    """

    def sign_request(self, payloads, signing_node_id, nonce_offset=0):
        contract_account = self.contract_account()
        last_block_hash = self.nodes[0].get_latest_block().hash_bytes
        nonce = self.get_nonce(signing_node_id) + nonce_offset
        txs = []
        for payload in payloads:
            sign_args = {
                'request': {
                    'key_version': 0,
                    'path': 'test',
                    'payload': payload,
                }
            }
            nonce += 1

            tx = sign_function_call_tx(self.nodes[signing_node_id].signer_key,
                                       contract_account, 'sign',
                                       json.dumps(sign_args).encode('utf-8'),
                                       150 * TGAS, 1, nonce, last_block_hash)
            txs.append(tx)
        return txs

    def send_txs(self, signing_node_id, txs):

        def send_tx(tx):
            return self.nodes[signing_node_id].send_tx(tx)['result']

        with ThreadPoolExecutor() as executor:
            tx_hashes = list(executor.map(send_tx, txs))
        return tx_hashes

    def participants(self):
        return self.nodes[len(self.nodes) - self.num_mpc_nodes:]

    def send_and_await_signature_requests(self, num_requests):
        started = time.time()
        metrics = [MetricsTracker(node) for node in self.participants()]
        contract_account = self.contract_account()

        # Construct signature requests
        payloads = [[
            i, 1, 2, 0, 4, 5, 6, 8, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
            19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 44
        ] for i in range(num_requests)]
        node_id = 1
        txs = self.sign_request(payloads, node_id, 0)
        tx_sent = time.time()
        tx_hashes = self.send_txs(node_id, txs)
        print("Sent signature requests, tx_hashes:", tx_hashes)

        # Wait for the indexers to observe the signature requests
        # In case num_requests > 1, some txs may not be included due to nonce conflicts
        while True:
            assert time.time() - started < TIMEOUT, "Waiting for mpc indexers"
            try:
                res = [
                    metric.get_int_metric_value('mpc_num_signature_requests')
                    for metric in metrics
                ]
                print("Indexers num_signature_requests:", res)
                if all(x and x >= 1 for x in res):
                    #if res2 and res2 >= 1 and res3 and res3 >= 1:
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
                    res = self.nodes[node_id].get_tx(tx_hash, contract_account)
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

        res = [
            metric.get_int_metric_value('mpc_num_sign_respnses_timed_out')
            for metric in metrics
        ]
        print("Number of nonce conflicts which occurred:", res)

    def propose_update(self, code):
        participants = self.participants()
        contract_account = self.contract_account()
        participant = participants[0]
        last_block_hash = participant.get_latest_block().hash_bytes

        args = ProposeUpdateArgs.build({
            'code': code,
            'config': None,
        })
        ak_nonce = participant.get_nonce_for_pk(
            participant.signer_key.account_id, participant.signer_key.pk)
        tx = sign_function_call_tx(participant.signer_key, contract_account,
                                   'propose_update', args, 150 * TGAS,
                                   8024860000000000000000000, ak_nonce + 1,
                                   last_block_hash)
        res = participant.send_tx_and_wait(tx, 20)
        assert ('SuccessValue' in res['result']['status'])

    def get_deployed_contract_hash(self, finality='optimistic'):
        account_id = self.contract_account()
        node = self.nodes[0]
        query = {
            "request_type": "view_code",
            "account_id": account_id,
            "finality": finality
        }
        response = node.json_rpc('query', query)
        assert 'error' not in response, f"Error fetching contract code: {response['error']}"
        code_b64 = response.get('result', {}).get('code_base64', '')
        contract_code = base64.b64decode(code_b64)
        sha256_hash = hashlib.sha256(contract_code).hexdigest()
        return sha256_hash

    def vote_update(self, node_id, update_id):
        vote_update_args = {'id': update_id}
        contract_account = self.contract_account()
        nodes = self.nodes
        last_block_hash = nodes[node_id].get_latest_block().hash_bytes
        ak_nonce = nodes[node_id].get_nonce_for_pk(
            nodes[node_id].signer_key.account_id, nodes[node_id].signer_key.pk)
        tx = sign_function_call_tx(
            nodes[node_id].signer_key, contract_account, 'vote_update',
            json.dumps(vote_update_args).encode('utf-8'), 150 * TGAS, 0,
            ak_nonce + 1, last_block_hash)
        res = nodes[node_id].send_tx_and_wait(tx, 20)
        assert ('SuccessValue' in res['result']['status'])

    def assert_is_deployed(self, contract):
        hash_expected = hashlib.sha256(contract).hexdigest()
        hash_deployed = self.get_deployed_contract_hash()
        assert (hash_expected == hash_deployed)


# Output is deserializable into the rust type near_crypto::SecretKey
def serialize_key(key):
    full_key = bytes(key.decoded_sk()) + bytes(key.decoded_pk())
    return 'ed25519:' + base58.b58encode(full_key).decode('ascii')


def sign_create_account_with_multiple_access_keys_tx(creator_key,
                                                     new_account_id, keys,
                                                     nonce, block_hash):
    create_account_action = create_create_account_action()
    payment_action = create_payment_action(100 * NEAR_BASE)
    access_key_actions = [
        create_full_access_key_action(key.decoded_pk()) for key in keys
    ]
    actions = [create_account_action, payment_action] + access_key_actions
    signed_tx = sign_transaction(new_account_id, nonce, actions, block_hash,
                                 creator_key.account_id,
                                 creator_key.decoded_pk(),
                                 creator_key.decoded_sk())
    return serialize_transaction(signed_tx)


def start_cluster_with_mpc(num_validators, num_mpc_nodes, num_respond_aks,
                           contract):
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
    with open(pathlib.Path(dot_near / 'participants.json')) as file:
        participants_config = yaml.load(file, Loader=SafeLoaderIgnoreUnknown)
    for i, p in enumerate(participants_config['participants']):
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
        access_keys = [
            Key.from_seed_testonly(account_id, seed=f"{s}")
            for s in range(0, num_respond_aks)
        ]
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

    # Deploy the mpc contract
    tx = sign_deploy_contract_tx(nodes[0].signer_key, contract, 10,
                                 last_block_hash)
    send_and_confirm_tx(tx)

    # Initialize the mpc contract
    init_args = {
        'threshold': num_mpc_nodes,
        'candidates': participants,
    }

    tx = sign_function_call_tx(nodes[0].signer_key,
                               nodes[0].signer_key.account_id, 'init',
                               json.dumps(init_args).encode('utf-8'),
                               150 * TGAS, 0, 20, last_block_hash)
    res = nodes[0].send_tx_and_wait(tx, 20)
    assert ('SuccessValue' in res['result']['status'])

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

    return MpcCluster(nodes, num_mpc_nodes)
