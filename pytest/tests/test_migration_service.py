#!/usr/bin/env python3
"""
Tests node migrations.
Starts a cluster with 2 participating nodes and two target nodes.
Migrates nodes #0 to #2 and node #1 to #3
Ensures liveness of the network by sending signature and ckd requests
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
from common_lib.shared.mpc_cluster import MpcCluster
from common_lib.shared.mpc_node import MpcNode

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
from common_lib import shared
from common_lib.contracts import load_mpc_contract


def running_state_matches_participant_key_retry(
    cluster: MpcCluster,
    account_id: str,
    expected_pk: str,
    wait_for_s: int = 50,
):
    start = time.time()
    while time.time() - start < wait_for_s:
        if running_state_matches_participant_key(cluster, account_id, expected_pk):
            print("successfully migrated node")
            return True
        else:
            print("waiting for migration to conclude")
            time.sleep(1)

    return False


def running_state_matches_participant_key(
    cluster: MpcCluster, account_id: str, expected_pk: str
) -> bool:
    contract_state = cluster.contract_state()
    if isinstance(contract_state.protocol_state, RunningProtocolState):
        node_info = contract_state.protocol_state.parameters.participants.by_account(
            account_id
        )
        return node_info.sign_pk == expected_pk
    return False


def test_migration_service():
    """
    Spawns a cluster with two nodes.
    Migrates each node one by one to a new node.
    """

    NUM_MPC_NODES = 2
    MIGRATING_NODES = [0, 1]
    NUM_RESPOND_ACC = 1
    cluster, mpc_nodes = shared.start_cluster_with_mpc(
        NUM_MPC_NODES,
        NUM_RESPOND_ACC,
        load_mpc_contract(),
        migrating_nodes=MIGRATING_NODES,
    )
    assert len(mpc_nodes) == NUM_MPC_NODES + len(MIGRATING_NODES)

    expected_migrations = MigrationState({})
    cluster.init_cluster(participants=mpc_nodes[:NUM_MPC_NODES], threshold=2)
    for migrating_node_id in MIGRATING_NODES:
        # set-up a backup service for the migrating node
        backup_service = BackupService()
        backup_service.generate_keys()
        migrating_node: MpcNode = mpc_nodes[migrating_node_id]
        target_node: MpcNode = mpc_nodes[NUM_MPC_NODES + migrating_node_id]

        # sanity check that migrating and target node have different keys
        assert migrating_node.account_id() == target_node.account_id()
        assert migrating_node.p2p_public_key != target_node.p2p_public_key
        # sanity check that the migrating node is an active participant in a running state
        assert running_state_matches_participant_key(
            cluster, migrating_node.account_id(), migrating_node.p2p_public_key
        )

        # ensure signature requests are processed
        cluster.send_and_await_ckd_requests(1)
        cluster.send_and_await_signature_requests(1)

        # 1. submit backup service info
        backup_service_info: BackupServiceInfo = backup_service.info()
        cluster.register_backup_service_info(
            migrating_node_id, backup_service_info=backup_service_info
        )

        # wait on the nodes debug endpoint for the backup service to appear
        expected_migrations.state_by_account[migrating_node.account_id()] = (
            AccountEntry(backup_service_info, destination_node_info=None)
        )
        migrating_node.wait_for_migration_state(expected_migrations)

        # 2. use the backup service cli for a keyshares GET request
        contract_state = cluster.get_contract_state()
        backup_service.set_contract_state(contract_state)
        backup_service.get_keyshares(mpc_node=mpc_nodes[migrating_node_id])

        # 3. node operator initiates node migration
        signer_account_pk = target_node._signer_key.pk
        destination_node_participant_info = ParticipantInfo(
            url=target_node.p2p_url, sign_pk=target_node.p2p_public_key
        )
        destination_node = DestinationNodeInfo(
            signer_account_pk=signer_account_pk,
            destination_node_info=destination_node_participant_info,
        )
        cluster.start_node_migration(migrating_node_id, destination_node)

        # wait for both nodes to register contract change
        expected_migrations.state_by_account[migrating_node.account_id()] = (
            AccountEntry(backup_service_info, destination_node)
        )
        migrating_node.wait_for_migration_state(expected_migrations)
        target_node.wait_for_migration_state(expected_migrations)

        # 4. use the backup service cli to PUT keyshares
        contract_state = cluster.get_contract_state()
        backup_service.set_contract_state(contract_state)
        backup_service.put_keyshares(mpc_node=target_node)

        # 5. assert migration was successful
        assert running_state_matches_participant_key_retry(
            cluster, migrating_node.account_id(), target_node.p2p_public_key
        ), "timed out waiting for migration to conclude"

        # 6. assert migration is removed from contract state
        expected_migrations.state_by_account[migrating_node.account_id()] = (
            AccountEntry(backup_service_info, destination_node_info=None)
        )
        migrating_node.wait_for_migration_state(expected_migrations)
        target_node.wait_for_migration_state(expected_migrations)

        migrating_node.kill(gentle=False)
        # 7. assert signature requests are handled
        cluster.send_and_await_ckd_requests(1)
        cluster.send_and_await_signature_requests(1)
