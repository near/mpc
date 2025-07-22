import json
import pathlib
import sys

from key import Key, SigningKey

from common_lib.constants import TGAS

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))

from cluster import LocalNode

from transaction import sign_function_call_tx


def assert_txn_success(res):
    assert "result" in res, json.dumps(res, indent=1)
    assert "status" in res["result"], json.dumps(res["result"], indent=1)
    assert "SuccessValue" in res["result"]["status"], json.dumps(
        res["result"]["status"]
    )


def assert_txn_execution_error(res, expected_error_msg=None):
    """
    Assert that a transaction failed with ExecutionError and contains the expected error message.

    Args:
        res: The transaction response
        expected_error_msg: The error message that should be contained in the ExecutionError
    """
    assert "result" in res, f"No 'result' in response: {json.dumps(res, indent=1)}"
    assert (
        "status" in res["result"]
    ), f"No 'status' in result: {json.dumps(res['result'], indent=1)}"

    status = res["result"]["status"]
    assert (
        "Failure" in status
    ), f"Expected Failure but got: {json.dumps(status, indent=1)}"

    failure = status["Failure"]
    assert (
        "ActionError" in failure
    ), f"Expected ActionError in Failure: {json.dumps(failure, indent=1)}"

    action_error = failure["ActionError"]
    assert (
        "kind" in action_error
    ), f"No 'kind' in ActionError: {json.dumps(action_error, indent=1)}"

    kind = action_error["kind"]
    assert (
        "FunctionCallError" in kind
    ), f"Expected FunctionCallError: {json.dumps(kind, indent=1)}"

    function_call_error = kind["FunctionCallError"]
    assert (
        "ExecutionError" in function_call_error
    ), f"Expected ExecutionError: {json.dumps(function_call_error, indent=1)}"

    execution_error = function_call_error["ExecutionError"]

    if expected_error_msg:
        assert (
            expected_error_msg in execution_error
        ), f"Expected '{expected_error_msg}' in error message but got: {execution_error}"


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
        encoded_args = args if type(args) == bytes else json.dumps(args).encode("utf-8")
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
