from concurrent.futures.thread import ThreadPoolExecutor
import json
import pathlib
import sys
import time
from typing import Any, Callable

from key import Key

from common_lib.constants import TGAS
from common_lib.shared.transaction_status import assert_txn_success, verify_txs

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))

from cluster import LocalNode

from transaction import sign_function_call_tx


class NearAccount:
    """
    An interface to an account on a NEAR Blockchain.
    It stores an instance of a NEAR Local Node internally to get the
     latest block hash and send transactions.
    """

    def __init__(
        self,
        near_node: LocalNode,
        signer_key: Key,
        pytest_signer_keys: list[Key],
    ):
        for key in pytest_signer_keys:
            assert signer_key.account_id == key.account_id, "mismatch in account ids"
        self.near_node = near_node
        self._signer_key = signer_key
        self._pytest_signer_keys = pytest_signer_keys
        self._next_signer_key_id = 0

    def account_id(self) -> str:
        return self._signer_key.account_id

    def last_block_hash(self):
        return self.near_node.get_latest_block().hash_bytes

    def send_tx(self, txn):
        return self.near_node.send_tx(txn)

    def send_txs_parallel_returning_hashes(
        self, txns: list[bytes], label: str
    ) -> list[str]:
        print(f"\033[91mSending \033[93m{len(txns)}\033[91m {label} txs.\033[0m")

        def send_tx(tx):
            return self.send_tx(tx)["result"]

        with ThreadPoolExecutor() as executor:
            tx_hashes = list(executor.map(send_tx, txns))

        return tx_hashes

    def send_await_check_txs_parallel(
        self,
        label: str,
        txns: list[bytes],
        verification_callback: Callable[[dict[str, Any]], None],
    ):
        tx_hashes = self.send_txs_parallel_returning_hashes(txns, label)
        results = self.await_txs(tx_hashes)
        verify_txs(results, verification_callback)

    def get_tx(self, tx_hash):
        return self.near_node.get_tx(tx_hash, self.account_id())

    def await_txs(self, tx_hashes):
        """
        sends signature requests without waiting for the result
        """
        for _ in range(20):
            try:
                results = []
                for tx_hash in tx_hashes:
                    res = self.get_tx(tx_hash)
                    results.append(res)
                    time.sleep(0.1)
                return results
            except Exception as e:
                print(e)
            time.sleep(1)

    def send_txn_and_check_success(self, txn, timeout=20):
        res = self.near_node.send_tx_and_wait(txn, timeout)
        assert_txn_success(res)
        return res

    def _get_next_signer_key_id(self) -> int:
        id = self._next_signer_key_id
        self._next_signer_key_id = (id + 1) % len(self._pytest_signer_keys)
        return id

    def get_key_and_nonce(self) -> tuple[Key, int]:
        id = self._get_next_signer_key_id()
        key = self._pytest_signer_keys[id]
        nonce = self.near_node.get_nonce_for_pk(key.account_id, key.pk)
        assert nonce is not None
        return (key, nonce)

    def sign_tx(
        self,
        target_contract,
        function_name,
        args,
        nonce_offset=1,
        gas=150 * TGAS,
        deposit=0,
    ):
        last_block_hash = self.last_block_hash()
        (key, nonce) = self.get_key_and_nonce()
        encoded_args = (
            args if isinstance(args, bytes) else json.dumps(args).encode("utf-8")
        )
        tx = sign_function_call_tx(
            key,
            target_contract,
            function_name,
            encoded_args,
            gas,
            deposit,
            nonce + nonce_offset,
            last_block_hash,
        )
        return tx
