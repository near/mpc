#!/usr/bin/env python3
"""
Sanity checks that all web endpoints are properly served.
"""

import json
import sys
import pathlib
import time
import requests

sys.path.append(str(pathlib.Path(__file__).resolve().parents[2]))

from common_lib.migration_state import (
    AccountEntry,
    BackupServiceInfo,
    DestinationNodeInfo,
    MigrationState,
    ParticipantInfo,
    parse_migration_state,
)
from common_lib.shared.mpc_cluster import MpcCluster
from common_lib.shared.mpc_node import MpcNode
from common_lib import shared


def test_web_endpoints(shared_cluster: shared.MpcCluster):
    number_nodes = len(shared_cluster.mpc_nodes)
    shared_cluster.send_and_await_signature_requests(1)
    shared_cluster.send_and_await_ckd_requests(1)

    # ports are hardcoded... they come from PortSeed::CLI_FOR_PYTEST.web_port(i)

    expected_migrations = MigrationState(state_by_account={})
    for port in range(20000, 20000 + number_nodes):
        response = requests.get(f"http://localhost:{port}/health")
        assert response.status_code == 200, response.status_code
        assert "OK" in response.text, response.text

        response = requests.get(f"http://localhost:{port}/metrics")
        assert "mpc_num_signature_requests_indexed" in response.text, response.text

        response = requests.get(f"http://localhost:{port}/debug/tasks")
        assert "root:" in response.text, response.text

        response = requests.get(f"http://localhost:{port}/debug/blocks")
        assert "Recent blocks:" in response.text, response.text
        assert "2 reqs:" in response.text, response.text

        response = requests.get(f"http://localhost:{port}/debug/signatures")
        assert "Recent signatures:" in response.text, response.text
        assert "id:" in response.text, response.text

        response = requests.get(f"http://localhost:{port}/debug/ckds")
        assert "Recent ckds:" in response.text, response.text
        assert "id:" in response.text, response.text

        response = requests.get(f"http://localhost:{port}/debug/contract")
        assert "Contract is in Running state" in response.text, response.text

        verify_migration_endpoint(shared_cluster, port, expected_migrations)


def verify_migration_endpoint(
    cluster: MpcCluster, port: int, expected_migrations: MigrationState
):
    contract_migrations = cluster.get_migrations()
    assert contract_migrations == expected_migrations, (
        f"expected {expected_migrations}, found {contract_migrations}"
    )

    response = requests.get(f"http://localhost:{port}/debug/migrations")
    (_, contract_btree_map) = json.loads(response.text)
    res = parse_migration_state(contract_btree_map)
    assert expected_migrations == res, f"expected {expected_migrations}, found {res}"

    # it does not matter which node we take here, as long as we end up taking all of them
    node_id = port - 20000
    node: MpcNode = cluster.mpc_nodes[node_id]
    # we just need a bogus key
    bogus_backup_service = BackupServiceInfo(public_key=node._signer_key.pk)
    node.set_backup_service_info(cluster.mpc_contract_account(), bogus_backup_service)

    expected_migrations.state_by_account[node.account_id()] = AccountEntry(
        backup_service_info=bogus_backup_service, destination_node_info=None
    )
    assert_contract_match(cluster, expected_migrations)
    assert_web_endpiont_match(port, expected_migrations)

    participant_info = ParticipantInfo(url="bogus_url", sign_pk=node.p2p_public_key)
    bogus_destination_node_info = DestinationNodeInfo(
        signer_account_pk=node._signer_key.pk,
        destination_node_info=participant_info,
    )
    node.start_node_migration(
        cluster.mpc_contract_account(), bogus_destination_node_info
    )
    expected_migrations.state_by_account[node.account_id()] = AccountEntry(
        backup_service_info=bogus_backup_service,
        destination_node_info=bogus_destination_node_info,
    )

    assert_contract_match(cluster, expected_migrations)

    assert_web_endpiont_match(port, expected_migrations)


def assert_web_endpiont_match(port: int, expected_migrations: MigrationState):
    max_attempts: int = 10
    for attempt in range(max_attempts):
        response = requests.get(f"http://localhost:{port}/debug/migrations")
        (_, contract_btree_map) = json.loads(response.text)
        res = parse_migration_state(contract_btree_map)
        if res == expected_migrations:
            break
        else:
            assert attempt + 1 < max_attempts, (
                f"Expected {expected_migrations}, found: {response.text}"
            )
            time.sleep(1)


def assert_contract_match(cluster: MpcCluster, expected_migrations: MigrationState):
    max_attempts: int = 10
    for attempt in range(max_attempts):
        contract_migrations = cluster.get_migrations()
        if expected_migrations == contract_migrations:
            break
        else:
            assert attempt + 1 < max_attempts, (
                f"Failed to get expected migrations state expected: {expected_migrations}, found: {contract_migrations}"
            )
            time.sleep(1)
