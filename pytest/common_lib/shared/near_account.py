import json
import pathlib
import sys

from key import Key

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

    def __init__(self, near_node: LocalNode):
        self.near_node = near_node

    def signer_key(self) -> Key:
        return self.near_node.signer_key

    def account_id(self) -> str:
        return self.signer_key().account_id

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

    def get_nonce(self):
        nonce = self.near_node.get_nonce_for_pk(
            self.account_id(),
            self.signer_key().pk
        )
        assert nonce is not None
        return nonce

    def sign_tx(self,
                target_contract,
                function_name,
                args,
                nonce_offset=1,
                gas=150 * TGAS,
                deposit=0):
        last_block_hash = self.last_block_hash()
        nonce = self.get_nonce() + nonce_offset
        encoded_args = args if type(args) == bytes else json.dumps(args).encode('utf-8')
        tx = sign_function_call_tx(self.signer_key(), target_contract,
                                   function_name, encoded_args, gas, deposit,
                                   nonce, last_block_hash)
        return tx
