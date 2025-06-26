#!/usr/bin/env python3

import base64
import json
import pathlib
import sys
import time
import typing

import pytest

from common_lib.constants import TIMEOUT

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
from common_lib import shared
from common_lib.contracts import load_mpc_contract


def get_tee_state(cluster):
    cn = cluster.contract_node
    txn = cn.sign_tx(cluster.mpc_contract_account(), 'verify_tee', {})
    res = cn.send_txn_and_check_success(txn)
    res = res['result']['status']['SuccessValue']
    res = base64.b64decode(res)
    res = json.loads(res)
    return res


def get_tee_state_failure(cluster):
    cn = cluster.contract_node
    txn = cn.sign_tx(cluster.mpc_contract_account(), 'verify_tee', {})
    res = cn.near_node.send_tx_and_wait(txn, 20)

    assert 'result' in res, json.dumps(res, indent=1)
    assert 'status' in res['result'], json.dumps(res['result'], indent=1)
    assert 'Failure' in res['result']['status'], json.dumps(
        res['result']['status'], indent=1)


# todo: make this modular after merging #508
def get_verify_tee_requests_sent_metrics(
        cluster, expected: typing.List[typing.Optional[int]]):
    started = time.time()
    print("expected:", expected)
    while True:
        assert time.time() - started < TIMEOUT, "Waiting for mpc metric"
        try:
            requests = cluster.get_int_metric_value("verify_tee_requests_sent")
            print("verify_tee_requests_sent:", requests)
            if all((actual is None and expected_val is None) or (
                (actual is not None and expected_val is not None)
                    and int(actual) == int(expected_val))
                   for actual, expected_val in zip(requests, expected)):
                break
        except requests.exceptions.ConnectionError:
            pass
        time.sleep(1)


def test_verify_tee():
    """
    Tests if the contract endpoint `verify_tee` returns a boolean if the contract is in running state and returns an error if the contract is in a non-running state.
    Ensures that the nodes call `verify_tee`.
    """
    cluster, mpc_nodes = shared.start_cluster_with_mpc(1, 3, 1,
                                                       load_mpc_contract())

    participants = mpc_nodes[:2]
    threshold = 2
    cluster.define_candidate_set(participants)
    cluster.update_participant_status(assert_contract=False)
    cluster.init_contract(threshold=threshold)
    tee_state = get_tee_state(cluster)
    assert tee_state == True

    cluster.add_domains(['Secp256k1'],
                        wait_for_running=False,
                        ignore_vote_errors=False)

    get_tee_state_failure(cluster)
    cluster.wait_for_state("Running")
    get_verify_tee_requests_sent_metrics(cluster, [1, 1])

    tee_state = get_tee_state(cluster)
    assert tee_state == True

    cluster.do_resharing(new_participants=mpc_nodes[:3],
                         new_threshold=3,
                         prospective_epoch_id=1,
                         wait_for_running=False)
    get_tee_state_failure(cluster)
    cluster.wait_for_state("Running")
    tee_state = get_tee_state(cluster)
    assert tee_state == True
    cluster.update_participant_status()
    get_verify_tee_requests_sent_metrics(cluster, [3, 3, 1])

    # todo: test with invalid TEE data. Ensure a resharing is entered by one of the nodes (we can trigger a call by entering a running state).
