#!/usr/bin/env python3
"""
Tests migration service (migrating a node).
Starts 2 nodes, have node #1 migrate to node #3
At every step we check that signatures can still be produced.
"""

import json
import pathlib
import subprocess
import sys
import os
import time
import base58
import pytest

from nacl.signing import SigningKey

from common_lib.constants import BACKUP_SERVICE_BINARY_PATH, MPC_REPO_DIR
from common_lib.contract_state import ProtocolState, RunningProtocolState
from common_lib.migration_state import (
    AccountEntry,
    BackupServiceInfo,
    DestinationNodeInfo,
    MigrationState,
    ParticipantInfo,
)
from common_lib.shared.backup_service import BackupService
from common_lib.shared.mpc_cluster import MpcCluster
from common_lib.shared.mpc_node import MpcNode

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
from common_lib import shared
from common_lib.contracts import load_mpc_contract


def test_migration_service():
    """
    Tests single-domain key generation and resharing.

    The test starts with 2 nodes and one domain, performs key generation, and verifies
    that the attempt ID is incremented correctly.

    It performs multiple rounds of resharing while changing the participant set.

    Signature requests are sent after each resharing to verify liveness.
    """

    PARTING_NODE_ID = 0
    backup_service = BackupService()
    backup_service.generate_keys()

    cluster, mpc_nodes = shared.start_cluster_with_mpc(
        2, 3, 1, load_mpc_contract(), for_migration=True
    )
    assert len(mpc_nodes) == 3

    migrating_node: MpcNode = mpc_nodes[0]
    fixed_node: MpcNode = mpc_nodes[1]
    target_node: MpcNode = mpc_nodes[2]

    assert migrating_node.account_id() == target_node.account_id()
    assert migrating_node.p2p_public_key != target_node.p2p_public_key

    # with the first two nodes
    cluster.init_cluster(participants=[migrating_node, fixed_node], threshold=2)

    contract_state = cluster.contract_state()
    assert isinstance(contract_state.protocol_state, RunningProtocolState)
    migrating_node_info = (
        contract_state.protocol_state.parameters.participants.by_account(
            migrating_node.account_id()
        )
    )
    assert migrating_node_info.sign_pk == migrating_node.p2p_public_key

    cluster.send_and_await_ckd_requests(1)
    cluster.send_and_await_signature_requests(1)

    # 1. submit backup service info
    backup_service_info: BackupServiceInfo = backup_service.info()
    res = cluster.register_backup_service_info(
        PARTING_NODE_ID, backup_service_info=backup_service_info
    )
    print(res)

    # max_attempts: int = 10
    expected_account_entry = AccountEntry(
        backup_service_info, destination_node_info=None
    )
    expected_migrations = MigrationState(
        {migrating_node.account_id(): expected_account_entry}
    )
    migrating_node.wait_for_migration_state(expected_migrations)
    # for attempt in range(max_attempts):
    #    current_state = migrating_node.migration_state_from_web()
    #    print(f"found: {current_state}")
    #    if current_state == expected_migrations:
    #        break
    #    else:
    #        assert attempt + 1 < max_attempts, (
    #            f"Expected {expected_migrations}, found: {current_state}"
    #        )
    #        time.sleep(1)

    ## get keyshares
    contract_state = cluster.get_contract_state()
    backup_service.set_contract_state(contract_state)
    backup_service.get_keyshares(mpc_node=mpc_nodes[PARTING_NODE_ID])

    ## start node migration
    signer_account_pk = target_node._signer_key.pk
    destination_node_participant_info = ParticipantInfo(
        url=target_node.p2p_url, sign_pk=target_node.p2p_public_key
    )
    destination_node = DestinationNodeInfo(
        signer_account_pk=signer_account_pk,
        destination_node_info=destination_node_participant_info,
    )
    cluster.start_node_migration(PARTING_NODE_ID, destination_node)
    # json_path = os.path.join(home_dir, "contract_state.json")
    # with open(json_path, "w", encoding="utf-8") as f:
    #    json.dump(contract_state, f, indent=2, ensure_ascii=False)

    # print(f"Saved contract state to: {json_path}")
    expected_account_entry = AccountEntry(
        backup_service_info, destination_node_info=destination_node
    )
    expected_migrations = MigrationState(
        {migrating_node.account_id(): expected_account_entry}
    )
    migrating_node.wait_for_migration_state(expected_migrations)
    target_node.wait_for_migration_state(expected_migrations)

    contract_state = cluster.get_contract_state()
    backup_service.set_contract_state(contract_state)
    backup_service.put_keyshares(mpc_node=target_node)
    # time.sleep(100)

    expected_account_entry = AccountEntry(
        backup_service_info, destination_node_info=None
    )
    expected_migrations = MigrationState(
        {migrating_node.account_id(): expected_account_entry}
    )
    migrating_node.wait_for_migration_state(expected_migrations)
    target_node.wait_for_migration_state(expected_migrations)
    contract_state = cluster.contract_state()
    assert isinstance(contract_state.protocol_state, RunningProtocolState)
    migrating_node_info = (
        contract_state.protocol_state.parameters.participants.by_account(
            migrating_node.account_id()
        )
    )
    assert migrating_node_info.sign_pk == target_node.p2p_public_key
    # time.sleep(2000)
    # url = mpc_nodes[0].url
    # p2p_key = mpc_nodes[0].p2p_public_key
    # backup_encryption_key = mpc_nodes[0].backup_key
    # home_dir = os.path.join(MPC_REPO_DIR / "pytest" / "backup-service")
    # os.makedirs(home_dir, exist_ok=True)
    # cmd = (
    #    BACKUP_SERVICE_BINARY_PATH,
    #    "--home-dir",
    #    home_dir,
    #    "get-keyshares",
    #    "--mpc-node-url",
    #    url,
    #    "--mpc-node-p2p-key",
    #    p2p_key,
    #    "--backup-encryption-key-hex",
    #    backup_encryption_key.hex(),
    # )
    # print(f"running command:\n{cmd}\n")
    # subprocess.run(cmd)
    # 2. start migration in the contracts

    # 3. call backup service to POST shares

    # 4. ensure migration succeeded by checking the contract values

    ## two new nodes join, increase threshold
    # cluster.do_resharing(
    #    new_participants=mpc_nodes[:4], new_threshold=3, prospective_epoch_id=1
    # )
    # cluster.update_participant_status()
    # cluster.send_and_await_signature_requests(1)
    # cluster.send_and_await_ckd_requests(1)

    # kicked_out_node = mpc_nodes[0]
    # new_participants = mpc_nodes[1:]
    # cluster.do_resharing(
    #    new_participants=new_participants, new_threshold=3, prospective_epoch_id=2
    # )
    # cluster.update_participant_status()
    # cluster.send_and_await_signature_requests(1)

    ## restart node so it re-submits a TEE attestation
    # kicked_out_node.restart()

    # cluster.do_resharing(
    #    new_participants=mpc_nodes,
    #    new_threshold=3,
    #    prospective_epoch_id=3,
    #    wait_for_running=False,
    # )

    # assert cluster.wait_for_state(ProtocolState.RUNNING), "failed to start running"
    # cluster.update_participant_status()
    # cluster.send_and_await_ckd_requests(1)
    # cluster.send_and_await_signature_requests(1)

    ## test for multiple attemps:

    # mpc_nodes[0].reserve_key_event_attempt(4, 0, 0)
    # mpc_nodes[0].reserve_key_event_attempt(4, 0, 1)
    # cluster.do_resharing(
    #    new_participants=mpc_nodes, new_threshold=4, prospective_epoch_id=4
    # )
    # cluster.update_participant_status()
    # assert cluster.contract_state().keyset().keyset[0].attempt_id == 2
    # cluster.send_and_await_signature_requests(1)
    # cluster.send_and_await_ckd_requests(1)
