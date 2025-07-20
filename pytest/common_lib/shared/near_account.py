import json
import pathlib
import sys

from key import Key, SigningKey

from common_lib.constants import TGAS

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))

from cluster import LocalNode

from transaction import sign_function_call_tx


def assert_txn_success(res):
    assert 'result' in res, json.dumps(res, indent=1)
    assert 'status' in res['result'], json.dumps(res['result'], indent=1)
    assert 'SuccessValue' in res['result']['status'], json.dumps(
        res['result']['status'])


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

    def get_tx(self, tx_hash):
        return self.near_node.get_tx(tx_hash, self.account_id())

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
        encoded_args = args if type(args) == bytes else json.dumps(args).encode(
            'utf-8')
        tx = sign_function_call_tx(key, target_contract, function_name,
                                   encoded_args, gas, deposit,
                                   nonce + nonce_offset, last_block_hash)
        return tx
