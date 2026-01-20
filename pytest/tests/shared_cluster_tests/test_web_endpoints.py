#!/usr/bin/env python3
"""
Sanity checks that all web endpoints are properly served.
"""

import json
import sys
import pathlib
import time
import requests
import pytest

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
from common_lib import shared


@pytest.mark.no_atexit_cleanup
def test_web_endpoints(shared_cluster: shared.MpcCluster):
    shared_cluster.send_and_await_signature_requests(1)
    shared_cluster.send_and_await_ckd_requests(1)

    for node in shared_cluster.mpc_nodes:
        socket_address: str = str(node.web_address)
        response = requests.get(f"http://{socket_address}/health")
        assert response.status_code == 200, response.status_code
        assert "OK" in response.text, response.text

        response = requests.get(f"http://{socket_address}/metrics")
        assert "mpc_num_signature_requests_indexed" in response.text, response.text

        response = requests.get(f"http://{socket_address}/debug/tasks")
        assert "root:" in response.text, response.text

        response = requests.get(f"http://{socket_address}/debug/blocks")
        assert "Recent blocks:" in response.text, response.text
        assert "2 reqs:" in response.text, response.text

        response = requests.get(f"http://{socket_address}/debug/signatures")
        assert "Recent signatures:" in response.text, response.text
        assert "id:" in response.text, response.text

        response = requests.get(f"http://{socket_address}/debug/ckds")
        assert "Recent ckds:" in response.text, response.text
        assert "id:" in response.text, response.text

        response = requests.get(f"http://{socket_address}/debug/contract")
        assert "Contract is in Running state" in response.text, response.text

        assert_pprof_endpoint(node.pprof_address)


@pytest.mark.no_atexit_cleanup
def test_migration_endpoint(shared_cluster: shared.MpcCluster):
    expected_migrations = MigrationState(state_by_account={})
    for node in shared_cluster.mpc_nodes:
        socket_address: str = str(node.web_address)
        contract_migrations = shared_cluster.get_migrations()
        assert contract_migrations == expected_migrations, (
            f"expected {expected_migrations}, found {contract_migrations}"
        )

        response = requests.get(f"http://{socket_address}/debug/migrations")
        (_, contract_btree_map) = json.loads(response.text)
        res = parse_migration_state(contract_btree_map)
        assert expected_migrations == res, (
            f"expected {expected_migrations}, found {res}"
        )

        # we just need a bogus key
        bogus_backup_service = BackupServiceInfo(public_key=node._signer_key.pk)
        node.set_backup_service_info(
            shared_cluster.mpc_contract_account(), bogus_backup_service
        )

        expected_migrations.state_by_account[node.account_id()] = AccountEntry(
            backup_service_info=bogus_backup_service, destination_node_info=None
        )

        assert_contract_match(shared_cluster, expected_migrations)
        node.wait_for_migration_state(expected_migrations)

        participant_info = ParticipantInfo(url="bogus_url", sign_pk=node.p2p_public_key)
        bogus_destination_node_info = DestinationNodeInfo(
            signer_account_pk=node._signer_key.pk,
            destination_node_info=participant_info,
        )

        node.start_node_migration(
            shared_cluster.mpc_contract_account(), bogus_destination_node_info
        )
        expected_migrations.state_by_account[node.account_id()] = AccountEntry(
            backup_service_info=bogus_backup_service,
            destination_node_info=bogus_destination_node_info,
        )

        assert_contract_match(shared_cluster, expected_migrations)
        node.wait_for_migration_state(expected_migrations)


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


def assert_pprof_endpoint(pprof_address: str):
    sampling_duration_secs = 1

    response = requests.get(
        f"http://{pprof_address}/profiler/pprof/flamegraph",
        params={"sampling_duration_secs": sampling_duration_secs},
        timeout=10,
    )

    assert response.status_code == 200

    # Content-Type should be SVG
    content_type = response.headers.get("Content-Type", "")
    assert content_type.startswith("image/svg+xml")

    response_body = response.text

    # Accept optional XML declaration / doctype
    assert "<svg" in response_body
    assert "</svg>" in response_body
