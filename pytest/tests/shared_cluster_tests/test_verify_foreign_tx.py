#!/usr/bin/env python3
"""
Tests for foreign chain transaction verification.

These tests verify that MPC nodes can verify a Solana transaction and sign the
derived payload. The tests use real Solana mainnet RPC to fetch and verify
recent finalized transactions.
"""

import atexit
import sys
import pathlib
import pytest

sys.path.append(str(pathlib.Path(__file__).resolve().parents[2]))

from common_lib import shared, contracts, contract_state, foreign_tx
from common_lib.constants import TGAS, SIGNATURE_DEPOSIT, TRANSACTION_TIMEOUT


# Gas required for verify_foreign_transaction call (same as sign call)
GAS_FOR_VERIFY_FOREIGN_TX_CALL = 15


@pytest.fixture(scope="module")
def foreign_tx_cluster():
    """
    Spins up a cluster with MPC nodes configured for foreign chain verification.
    This fixture adds Solana RPC configuration to the MPC node configs.
    """
    cluster, mpc_nodes = shared.start_cluster_with_mpc(
        num_mpc_nodes=2,
        num_respond_aks=1,
        contract=contracts.load_mpc_contract(),
        triples_to_buffer=200,
        presignatures_to_buffer=100,
        start_mpc_nodes=False,  # Don't start nodes yet
    )

    # Add Solana RPC configuration to MPC node configs
    solana_config = foreign_tx.get_solana_rpc_config()
    observers = [node.near_node for node in mpc_nodes]
    shared.add_foreign_chains_config(observers, solana_config)

    # Now start the MPC nodes
    for node in mpc_nodes:
        node.run()

    # Initialize the cluster
    cluster.init_cluster(mpc_nodes, threshold=2)
    cluster.wait_for_state(contract_state.ProtocolState.RUNNING)

    yield cluster

    cluster.kill_all()
    atexit._run_exitfuncs()


@pytest.mark.no_atexit_cleanup
def test_verify_foreign_tx_success(foreign_tx_cluster: shared.MpcCluster):
    """
    Test that a valid finalized Solana transaction can be verified and signed.

    This test:
    1. Fetches a recent finalized transaction from Solana mainnet
    2. Calls verify_foreign_transaction on the MPC contract
    3. Verifies that the nodes verify the transaction and return a signature
    """
    # Fetch a recent finalized transaction from Solana
    print("\n\033[93mFetching recent finalized transaction from Solana...\033[0m")
    tx_signature = foreign_tx.fetch_recent_finalized_transaction()
    print(f"\033[92mUsing transaction: {tx_signature}\033[0m")

    # Generate the contract call arguments
    args = foreign_tx.generate_verify_foreign_tx_args(
        tx_signature=tx_signature,
        chain="Solana",
        finality="Final",
        path="test",
    )

    # Create and send the transaction
    tx = foreign_tx_cluster.request_node.sign_tx(
        foreign_tx_cluster.mpc_contract_account(),
        "verify_foreign_transaction",
        args,
        gas=GAS_FOR_VERIFY_FOREIGN_TX_CALL * TGAS,
        deposit=SIGNATURE_DEPOSIT,
    )

    print("\033[93mSending verify_foreign_transaction request...\033[0m")
    tx_hash = foreign_tx_cluster.request_node.send_tx(tx)

    # Wait for the transaction to complete with extended timeout
    # Foreign chain verification may take longer than regular signing
    result = foreign_tx_cluster.request_node.near_node.get_tx(
        tx_hash,
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


@pytest.mark.no_atexit_cleanup
def test_verify_foreign_tx_with_optimistic_finality(foreign_tx_cluster: shared.MpcCluster):
    """
    Test verification with Optimistic finality level (Solana "confirmed").
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
    tx_hash = foreign_tx_cluster.request_node.send_tx(tx)

    result = foreign_tx_cluster.request_node.near_node.get_tx(
        tx_hash,
        timeout=TRANSACTION_TIMEOUT * 3,
    )

    response = foreign_tx.assert_verify_foreign_tx_success(result)
    assert "signature" in response
    print("\033[92mOptimistic finality verification succeeded!\033[0m")


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
    tx_hash = foreign_tx_cluster.request_node.send_tx(tx)

    # Wait for the transaction - it should timeout (no MPC response)
    # Using a shorter timeout since we expect this to fail
    result = foreign_tx_cluster.request_node.near_node.get_tx(
        tx_hash,
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
