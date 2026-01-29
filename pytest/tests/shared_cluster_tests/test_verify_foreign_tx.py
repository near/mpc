#!/usr/bin/env python3
"""
Tests for foreign chain transaction verification with policy enforcement.

These tests verify:
1. verify_foreign_transaction fails when no policy is configured
2. Node operators can configure foreign chain RPC and vote for policy
3. After policy is established, verify_foreign_transaction succeeds
"""

import atexit
import sys
import pathlib
import pytest
import time

sys.path.append(str(pathlib.Path(__file__).resolve().parents[2]))

from common_lib import shared, contracts, contract_state, foreign_tx
from common_lib.constants import TGAS, SIGNATURE_DEPOSIT, TRANSACTION_TIMEOUT


# Gas required for verify_foreign_transaction call (same as sign call)
GAS_FOR_VERIFY_FOREIGN_TX_CALL = 15


@pytest.fixture(scope="module")
def foreign_tx_cluster():
    """
    Spins up a cluster WITHOUT foreign chain configuration initially.
    This allows testing the policy enforcement flow.
    """
    cluster, mpc_nodes = shared.start_cluster_with_mpc(
        num_mpc_nodes=2,
        num_respond_aks=1,
        contract=contracts.load_mpc_contract(),
        triples_to_buffer=200,
        presignatures_to_buffer=100,
        start_mpc_nodes=True,  # Start nodes without foreign chain config
    )

    # Initialize the cluster (no foreign chain config yet)
    cluster.init_cluster(mpc_nodes, threshold=2)
    cluster.wait_for_state(contract_state.ProtocolState.RUNNING)

    # Store references for later use
    cluster._mpc_nodes_list = mpc_nodes

    yield cluster

    cluster.kill_all()
    atexit._run_exitfuncs()


@pytest.mark.ci_excluded  # Relies on Solana mainnet RPC - skip in CI to avoid flakiness
@pytest.mark.no_atexit_cleanup
def test_verify_foreign_tx_fails_with_empty_policy(foreign_tx_cluster: shared.MpcCluster):
    """
    Test that verify_foreign_transaction fails when no policy is configured.

    Initially, the contract has an empty foreign chain policy. Any attempt
    to verify a foreign transaction should fail with PolicyNotConfigured error.
    """
    print("\n\033[93m=== Testing verify_foreign_tx fails with empty policy ===\033[0m")

    # Verify policy is empty
    policy = foreign_tx.get_foreign_chain_policy(foreign_tx_cluster)
    print(f"Current policy: {policy}")
    assert policy.get("chains", []) == [], f"Expected empty policy, got: {policy}"

    # Fetch a real transaction from Solana
    print("\033[93mFetching recent finalized transaction from Solana...\033[0m")
    tx_signature = foreign_tx.fetch_recent_finalized_transaction()
    print(f"\033[92mUsing transaction: {tx_signature}\033[0m")

    # Generate the contract call arguments
    args = foreign_tx.generate_verify_foreign_tx_args(
        tx_signature=tx_signature,
        chain="Solana",
        finality="Final",
        path="test-empty-policy",
    )

    # Create and send the transaction
    tx = foreign_tx_cluster.request_node.sign_tx(
        foreign_tx_cluster.mpc_contract_account(),
        "verify_foreign_transaction",
        args,
        gas=GAS_FOR_VERIFY_FOREIGN_TX_CALL * TGAS,
        deposit=SIGNATURE_DEPOSIT,
    )

    print("\033[93mSending verify_foreign_transaction request (should fail)...\033[0m")
    tx_hash = foreign_tx_cluster.request_node.send_tx(tx)["result"]

    # Wait for the transaction result
    result = foreign_tx_cluster.request_node.near_node.get_tx(
        tx_hash,
        foreign_tx_cluster.mpc_contract_account(),
        timeout=TRANSACTION_TIMEOUT,
    )

    # Verify the transaction failed with policy error
    try:
        foreign_tx.assert_verify_foreign_tx_success(result)
        pytest.fail("Expected verify_foreign_transaction to fail with empty policy")
    except AssertionError as e:
        error_msg = str(e)
        # Check that the error mentions policy
        assert "policy" in error_msg.lower() or "PolicyNotConfigured" in error_msg, \
            f"Expected policy error, got: {error_msg}"
        print(f"\033[92mCorrectly rejected with error: {error_msg[:100]}...\033[0m")


@pytest.mark.ci_excluded  # Relies on Solana mainnet RPC - skip in CI to avoid flakiness
@pytest.mark.no_atexit_cleanup
def test_foreign_chain_policy_voting_and_verification(foreign_tx_cluster: shared.MpcCluster):
    """
    Test the complete foreign chain policy flow:
    1. Add Solana RPC configuration to node configs
    2. Restart nodes (they will automatically vote for the policy)
    3. Wait for unanimous policy agreement
    4. Verify that verify_foreign_transaction now succeeds
    """
    print("\n\033[93m=== Testing policy voting and verification ===\033[0m")

    mpc_nodes = foreign_tx_cluster._mpc_nodes_list
    observers = [node.near_node for node in mpc_nodes]

    # Step 1: Fix boot_nodes and add Solana RPC configuration to MPC node configs
    print("\033[93mStep 1: Fixing boot_nodes and adding Solana RPC config...\033[0m")
    # Fix boot_nodes in the observer nodes' config.json so restarts work correctly
    # (When nodes restart, they use config.json instead of command line args)
    shared.fix_boot_nodes_in_config(observers, foreign_tx_cluster._boot_node)

    solana_config = foreign_tx.get_solana_rpc_config(
        provider_name="mainnet",  # Use a consistent provider name
    )
    shared.add_foreign_chains_config(observers, solana_config)

    # Step 2: Restart MPC nodes (they will vote for the policy on startup)
    print("\033[93mStep 2: Restarting MPC nodes to trigger policy voting...\033[0m")
    for node in mpc_nodes:
        node.kill(gentle=True)

    # Wait a moment for processes to fully stop
    time.sleep(2)

    for node in mpc_nodes:
        node.run()

    # Wait for nodes to sync with the network (check indexer block height)
    print("\033[93mWaiting for MPC nodes to sync with network...\033[0m")
    sync_timeout = 30
    start_time = time.time()
    while time.time() - start_time < sync_timeout:
        try:
            all_synced = True
            for node in mpc_nodes:
                block_height = node.get_int_metric_value(
                    shared.metrics.IntMetricName.MPC_INDEXER_LATEST_BLOCK_HEIGHT
                )
                if block_height is None or block_height < 10:
                    all_synced = False
                    break
            if all_synced:
                print(f"\033[92mAll nodes synced (block height > 10)\033[0m")
                break
        except Exception as e:
            print(f"Waiting for metrics: {e}")
        time.sleep(1)

    # Step 3: Wait for the policy to be established
    print("\033[93mStep 3: Waiting for foreign chain policy to be established...\033[0m")
    assert foreign_tx.wait_for_foreign_chain_policy(
        foreign_tx_cluster,
        expected_chain="Solana",
        timeout_sec=60,
    ), "Foreign chain policy was not established within timeout"

    # Verify the policy details
    policy = foreign_tx.get_foreign_chain_policy(foreign_tx_cluster)
    print(f"Final policy: {policy}")
    assert len(policy.get("chains", [])) > 0, "Policy should have at least one chain"
    solana_entry = next(
        (c for c in policy["chains"] if c.get("chain") == "Solana"),
        None
    )
    assert solana_entry is not None, "Policy should include Solana"
    assert len(solana_entry.get("required_providers", [])) > 0, \
        "Solana entry should have at least one provider"

    print("\033[92mForeign chain policy successfully established!\033[0m")

    # Step 4: Now test that verify_foreign_transaction succeeds
    print("\033[93mStep 4: Testing verify_foreign_transaction with policy...\033[0m")

    # Fetch a recent finalized transaction from Solana
    tx_signature = foreign_tx.fetch_recent_finalized_transaction()
    print(f"\033[92mUsing transaction: {tx_signature}\033[0m")

    args = foreign_tx.generate_verify_foreign_tx_args(
        tx_signature=tx_signature,
        chain="Solana",
        finality="Final",
        path="test-with-policy",
    )

    tx = foreign_tx_cluster.request_node.sign_tx(
        foreign_tx_cluster.mpc_contract_account(),
        "verify_foreign_transaction",
        args,
        gas=GAS_FOR_VERIFY_FOREIGN_TX_CALL * TGAS,
        deposit=SIGNATURE_DEPOSIT,
    )

    print("\033[93mSending verify_foreign_transaction request (should succeed)...\033[0m")
    tx_hash = foreign_tx_cluster.request_node.send_tx(tx)["result"]

    # Wait for the transaction to complete with extended timeout
    result = foreign_tx_cluster.request_node.near_node.get_tx(
        tx_hash,
        foreign_tx_cluster.mpc_contract_account(),
        timeout=TRANSACTION_TIMEOUT * 3,  # 60 seconds
    )

    # Verify the response
    response = foreign_tx.assert_verify_foreign_tx_success(result)

    # Verify response structure
    assert "verified_at_block" in response, "Response should contain verified_at_block"
    assert "signature" in response, "Response should contain signature"

    # Verify the block ID is a Solana slot
    verified_at_block = response["verified_at_block"]
    assert "SolanaSlot" in verified_at_block, f"Expected SolanaSlot, got: {verified_at_block}"

    slot_number = verified_at_block["SolanaSlot"]
    assert isinstance(slot_number, int), f"Slot should be an integer, got: {type(slot_number)}"
    assert slot_number > 0, f"Slot should be positive, got: {slot_number}"

    print(f"\033[92mTransaction verified at Solana slot: {slot_number}\033[0m")
    print(f"\033[92mSignature received successfully!\033[0m")


@pytest.mark.ci_excluded  # Relies on Solana mainnet RPC - skip in CI to avoid flakiness
@pytest.mark.no_atexit_cleanup
def test_verify_foreign_tx_with_optimistic_finality(foreign_tx_cluster: shared.MpcCluster):
    """
    Test verification with Optimistic finality level (Solana "confirmed").
    This test runs after policy is established.

    Note: This test may timeout if Solana RPC is slow due to network conditions.
    The MPC contract has a built-in timeout for signature generation.
    """
    print("\n\033[93mFetching recent transaction for optimistic finality test...\033[0m")
    tx_signature = foreign_tx.fetch_recent_finalized_transaction()
    print(f"\033[92mUsing transaction: {tx_signature}\033[0m")

    args = foreign_tx.generate_verify_foreign_tx_args(
        tx_signature=tx_signature,
        chain="Solana",
        finality="Optimistic",  # Use confirmed instead of finalized
        path="test-optimistic",
    )

    tx = foreign_tx_cluster.request_node.sign_tx(
        foreign_tx_cluster.mpc_contract_account(),
        "verify_foreign_transaction",
        args,
        gas=GAS_FOR_VERIFY_FOREIGN_TX_CALL * TGAS,
        deposit=SIGNATURE_DEPOSIT,
    )

    print("\033[93mSending verify_foreign_transaction with Optimistic finality...\033[0m")
    tx_hash = foreign_tx_cluster.request_node.send_tx(tx)["result"]

    try:
        result = foreign_tx_cluster.request_node.near_node.get_tx(
            tx_hash,
            foreign_tx_cluster.mpc_contract_account(),
            timeout=TRANSACTION_TIMEOUT * 3,
        )

        response = foreign_tx.assert_verify_foreign_tx_success(result)
        assert "signature" in response
        print("\033[92mOptimistic finality verification succeeded!\033[0m")
    except Exception as e:
        error_str = str(e)
        # Contract timeout is expected if Solana RPC is slow
        if "timed out" in error_str.lower() or "timeout" in error_str.lower():
            pytest.skip(f"Test skipped due to network timeout: {error_str[:100]}...")
        raise


@pytest.mark.ci_excluded  # Relies on Solana mainnet RPC - skip in CI to avoid flakiness
@pytest.mark.no_atexit_cleanup
def test_verify_foreign_tx_multiple_requests(foreign_tx_cluster: shared.MpcCluster):
    """
    Test multiple concurrent verify_foreign_transaction requests.
    """
    print("\n\033[93mFetching transaction for multiple request test...\033[0m")
    tx_signature = foreign_tx.fetch_recent_finalized_transaction()
    print(f"\033[92mUsing transaction: {tx_signature}\033[0m")

    num_requests = 3
    txs = []

    for i in range(num_requests):
        args = foreign_tx.generate_verify_foreign_tx_args(
            tx_signature=tx_signature,
            chain="Solana",
            finality="Final",
            path=f"test-multi-{i}",  # Different paths for unique requests
        )

        tx = foreign_tx_cluster.request_node.sign_tx(
            foreign_tx_cluster.mpc_contract_account(),
            "verify_foreign_transaction",
            args,
            gas=GAS_FOR_VERIFY_FOREIGN_TX_CALL * TGAS,
            deposit=SIGNATURE_DEPOSIT,
        )
        txs.append(tx)

    print(f"\033[93mSending {num_requests} verify_foreign_transaction requests...\033[0m")
    foreign_tx_cluster.request_node.send_await_check_txs_parallel(
        "verify_foreign_tx",
        txs,
        foreign_tx.assert_verify_foreign_tx_success,
    )
    print(f"\033[92mAll {num_requests} requests completed successfully!\033[0m")


@pytest.mark.ci_excluded  # Relies on Solana mainnet RPC - skip in CI to avoid flakiness
@pytest.mark.no_atexit_cleanup
def test_verify_foreign_tx_nonexistent_transaction(foreign_tx_cluster: shared.MpcCluster):
    """
    Test that verification of a nonexistent transaction times out.

    When a transaction doesn't exist on Solana, the MPC nodes should fail
    verification and the request should timeout (no signature returned).
    """
    import base58

    # Generate a fake transaction signature (64 bytes of random-ish data)
    # This signature doesn't exist on Solana
    fake_sig_bytes = bytes([0xDE, 0xAD, 0xBE, 0xEF] * 16)
    fake_signature = base58.b58encode(fake_sig_bytes).decode()

    print(f"\n\033[93mTesting with nonexistent transaction: {fake_signature[:20]}...\033[0m")

    args = foreign_tx.generate_verify_foreign_tx_args(
        tx_signature=fake_signature,
        chain="Solana",
        finality="Final",
        path="test-nonexistent",
    )

    tx = foreign_tx_cluster.request_node.sign_tx(
        foreign_tx_cluster.mpc_contract_account(),
        "verify_foreign_transaction",
        args,
        gas=GAS_FOR_VERIFY_FOREIGN_TX_CALL * TGAS,
        deposit=SIGNATURE_DEPOSIT,
    )

    print("\033[93mSending verify_foreign_transaction for nonexistent tx...\033[0m")
    tx_hash = foreign_tx_cluster.request_node.send_tx(tx)["result"]

    # Wait for the transaction - it should timeout (no MPC response)
    # Using a shorter timeout since we expect this to fail
    try:
        result = foreign_tx_cluster.request_node.near_node.get_tx(
            tx_hash,
            foreign_tx_cluster.mpc_contract_account(),
            timeout=TRANSACTION_TIMEOUT * 2,  # 40 seconds
        )

        # The request should have succeeded (NEAR tx succeeded) but returned
        # a timeout/failure because MPC nodes couldn't verify the foreign tx
        try:
            foreign_tx.assert_verify_foreign_tx_success(result)
            # If we get here, the verification somehow succeeded (unexpected)
            print("\033[91mUnexpected: nonexistent tx verification succeeded!\033[0m")
            pytest.fail("Expected verification to fail for nonexistent transaction")
        except AssertionError as e:
            # Expected - the verification failed
            print(f"\033[92mExpected failure for nonexistent tx: {str(e)[:100]}...\033[0m")
            print("\033[92mNonexistent transaction test passed (verification correctly failed)!\033[0m")
    except Exception as e:
        # A timeout or RPC error is also expected - it means the MPC nodes
        # couldn't verify the nonexistent transaction within the timeout
        error_str = str(e)
        if "408" in error_str or "timeout" in error_str.lower():
            print(f"\033[92mExpected timeout for nonexistent tx: {error_str[:100]}...\033[0m")
            print("\033[92mNonexistent transaction test passed (RPC timeout as expected)!\033[0m")
        else:
            # Unexpected error
            raise
