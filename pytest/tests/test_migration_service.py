#!/usr/bin/env python3
"""
Tests migration service (migrating a node).
Starts 2 nodes, have node #1 migrate to node #3
At every step we check that signatures can still be produced.
"""

import pathlib
import sys
import time


from common_lib.contract_state import RunningProtocolState
from common_lib.migration_state import (
    AccountEntry,
    BackupServiceInfo,
    DestinationNodeInfo,
    MigrationState,
    ParticipantInfo,
)
from common_lib.shared.backup_service import BackupService
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

    time.sleep(20)
    n_try = 0
    while n_try < 50:
        contract_state = cluster.contract_state()
        assert isinstance(contract_state.protocol_state, RunningProtocolState)
        migrating_node_info = (
            contract_state.protocol_state.parameters.participants.by_account(
                migrating_node.account_id()
            )
        )
        if migrating_node_info.sign_pk == target_node.p2p_public_key:
            print("successfully migrated node")
            break
        else:
            print("waiting for migration to conclude")
            time.sleep(1)
            n_try += 1

    expected_account_entry = AccountEntry(
        backup_service_info, destination_node_info=None
    )
    expected_migrations = MigrationState(
        {migrating_node.account_id(): expected_account_entry}
    )
    migrating_node.wait_for_migration_state(expected_migrations)
    target_node.wait_for_migration_state(expected_migrations)
