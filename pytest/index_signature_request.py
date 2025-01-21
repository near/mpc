#!/usr/bin/env python3
"""
Starts 2 near validators and 2 mpc nodes.
Deploys mpc contract and sends a signature request.
Verifies that the mpc nodes index the signature request.
"""

import base64
import sys
import json
import time
import pathlib
import argparse
import requests
from concurrent.futures import ThreadPoolExecutor

from lib.cluster import start_cluster_with_mpc

sys.path.append(
    str(
        pathlib.Path(__file__).resolve().parents[1] / 'libs' / 'nearcore' /
        'pytest' / 'lib'))
from transaction import sign_function_call_tx
from utils import MetricsTracker

TIMEOUT = 60
TGAS = 10 ** 12


def test_index_signature_request(num_requests):
    started = time.time()
    nodes = start_cluster_with_mpc(2, 2)

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
    print("Nodes sent responses which failed to be included:", res2, res3)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--num-requests",
                        type=int,
                        default=1,
                        help="Number of signature requests to make")
    args = parser.parse_args()

    test_index_signature_request(args.num_requests)
