#!/usr/bin/env python3
"""
Tests key resharing (adding and removing nodes).
Starts 2 nodes, have node #3 join, then #4 join,
then #1 leaves, and finally #2 leaves.
At every step we check that signatures can still be produced.
"""

import pathlib
import sys
from typing import List

import pytest

from common_lib.contract_state import (
    ContractState,
    Domain,
    Keyset,
    ProtocolState,
    SignatureScheme,
)
from common_lib.shared.mpc_cluster import MpcCluster
from common_lib.shared.mpc_node import MpcNode

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
from common_lib import shared
from common_lib.contracts import load_mpc_contract


def assert_key_generation_success(
    cluster: MpcCluster, domains: List[SignatureScheme]
) -> Keyset:
    # Get initial state
    init_state = cluster.contract_state()
    assert init_state.is_state(ProtocolState.RUNNING), "Expected running state"

    init_keyset: Keyset | None = init_state.keyset()
    assert init_keyset != None, "Expected keyset"

    init_domains = init_state.get_running_domains()

    # Add domains
    added_domains: List[Domain] = cluster.add_domains(domains)

    # Get State after key generation
    post_contract_state = cluster.contract_state()
    assert post_contract_state.is_state(ProtocolState.RUNNING), "Expected running state"
    post_keyset: Keyset | None = post_contract_state.keyset()
    assert post_keyset != None, "Expected keyset"
    post_domains: List[Domain] = post_contract_state.get_running_domains()

    # Ensure the correct keys were generated
    for new_domain in added_domains:
        assert new_domain in post_domains, "Could not find new domain"
        assert new_domain not in init_domains, "Expected not having this domain"
        with pytest.raises(KeyError):
            init_keyset.get_key(new_domain.id)
        assert post_keyset.get_key(new_domain.id).key != ""
    return post_keyset


def test_single_domain():
    """
    Tests single-domain key generation and resharing.

    The test starts with 2 nodes and one domain, performs key generation, and verifies
    that the attempt ID is incremented correctly.

    It performs multiple rounds of resharing while changing the participant set.

    Signature requests are sent after each resharing to verify liveness.
    """
    cluster, mpc_nodes = shared.start_cluster_with_mpc(2, 4, 1, load_mpc_contract())
    cluster.init_cluster_no_domains(participants=mpc_nodes[:2], threshold=2)

    # start with 2 nodes
    # test 1: initialize, ensure abort_key_event_instance works for key generation
    mpc_nodes[0].reserve_key_event_attempt(epoch_id=0, domain_id=0, attempt_id=0)
    mpc_nodes[0].reserve_key_event_attempt(epoch_id=0, domain_id=0, attempt_id=1)
    keyset = assert_key_generation_success(
        cluster=cluster, domains=[SignatureScheme.Secp256k1, SignatureScheme.Ed25519]
    )
    assert keyset.get_key(0).attempt_id == 2
    # sanity check
    cluster.send_and_await_signature_requests(1)

    # test 2: reshare, increase threshold, increase number of nodes
    cluster.do_resharing(
        new_participants=mpc_nodes[:4], new_threshold=3, prospective_epoch_id=1
    )
    cluster.update_participant_status()
    cluster.send_and_await_signature_requests(1)

    # test 2: reshare, keep threshold, decrease number of nodes
    cluster.do_resharing(
        new_participants=mpc_nodes[1:4], new_threshold=3, prospective_epoch_id=2
    )

    cluster.update_participant_status()
    cluster.send_and_await_signature_requests(1)
    # test 3: reshare, keep threshold, increase number of nodes
    cluster.do_resharing(
        new_participants=mpc_nodes[0:4],
        new_threshold=3,
        prospective_epoch_id=3,
        wait_for_running=False,
    )

    assert cluster.wait_for_state(ProtocolState.RUNNING), "failed to start running"
    cluster.update_participant_status()
    cluster.send_and_await_signature_requests(1)

    # test for multiple attemps:
    # test 4: key refresh with aborted attempts, ensure multiple key_event_instances / attempts work
    mpc_nodes[0].reserve_key_event_attempt(4, 0, 0)
    mpc_nodes[0].reserve_key_event_attempt(4, 0, 1)
    cluster.do_resharing(
        new_participants=mpc_nodes[0:4], new_threshold=4, prospective_epoch_id=4
    )
    cluster.update_participant_status()
    assert cluster.contract_state().keyset().keyset[0].attempt_id == 2
    cluster.send_and_await_signature_requests(1)


def test_multi_domain():
    """
    Tests multi-domain key generation and resharing.

    The test starts with 2 nodes and one domain, then adds four more domains.
    It performs a resharing of the five domains from 2 to 4 nodes with an increased threshold.

    Afterwards, it adds another domain but cancels the key generation before completion.
    """
    cluster, mpc_nodes = shared.start_cluster_with_mpc(2, 4, 1, load_mpc_contract())

    # start with 2 nodes
    cluster.init_cluster(participants=mpc_nodes[:2], threshold=2)
    cluster.send_and_await_signature_requests(1)

    cluster.add_domains(
        ["Secp256k1", "Ed25519", "Secp256k1", "Ed25519"], wait_for_running=False
    )
    cluster.wait_for_state(ProtocolState.RUNNING)
    ## two new nodes join, increase threshold
    cluster.do_resharing(
        new_participants=mpc_nodes[:4], new_threshold=3, prospective_epoch_id=1
    )
    cluster.update_participant_status()

    mpc_nodes[1].reserve_key_event_attempt(1, 5, 0)
    mpc_nodes[1].reserve_key_event_attempt(1, 5, 1)
    cluster.add_domains(["Secp256k1"], wait_for_running=False)
    mpc_nodes[0].kill(False)
    for node in mpc_nodes[1:4]:
        print(f"{node.print()} voting to cancel domain")
        args = {
            "next_domain_id": 7,
        }
        tx = node.sign_tx(cluster.mpc_contract_account(), "vote_cancel_keygen", args)
        node.send_txn_and_check_success(tx)
    assert cluster.wait_for_state(ProtocolState.RUNNING), "Failed to start running"
    with pytest.raises(KeyError):
        cluster.contract_state().keyset().get_key(6)
    assert cluster.contract_state().protocol_state.next_domain_id() == 7
