import json
from typing import Any

from common_lib.constants import TGAS


def extract_tx_costs(res):
    """
    returns `total_gas_used`, `num_receipts`
    """
    # Extract the gas burnt at transaction level
    total_gas_used = res["result"]["transaction_outcome"]["outcome"]["gas_burnt"]

    # Add the gas burnt for each receipt
    num_receipts = 0
    for receipt in res["result"]["receipts_outcome"]:
        total_gas_used += receipt["outcome"]["gas_burnt"]
        num_receipts += 1
    return total_gas_used, num_receipts


def verify_txs(results, verification_callback, verbose=False):
    max_tgas_used = 0
    total_tgas = 0
    total_receipts = 0
    num_txs = 0
    for res in results:
        num_txs += 1
        gas_tx, n_rcpts_tx = extract_tx_costs(res)
        max_tgas_used = max(max_tgas_used, gas_tx) / TGAS
        total_tgas += gas_tx / TGAS
        total_receipts += n_rcpts_tx
        verification_callback(res)
    if verbose:
        print(
            f"number of txs: {num_txs}\n max gas used (Tgas):{max_tgas_used}\n average receipts: {total_receipts / num_txs}\n average gas used (Tgas): {total_tgas / num_txs}\n"
        )


def assert_txn_success(result: dict[str, Any]):
    assert "result" in result, json.dumps(result, indent=1)
    assert "status" in result["result"], json.dumps(result["result"], indent=1)
    assert "SuccessValue" in result["result"]["status"], json.dumps(
        result["result"]["status"]
    )


def assert_txn_execution_error(result, expected_error_msg=None):
    """
    Assert that a transaction failed with ExecutionError and contains the expected error message.

    Args:
        res: The transaction response
        expected_error_msg: The error message that should be contained in the ExecutionError
    """
    assert "result" in result, (
        f"No 'result' in response: {json.dumps(result, indent=1)}"
    )
    assert "status" in result["result"], (
        f"No 'status' in result: {json.dumps(result['result'], indent=1)}"
    )

    status = result["result"]["status"]
    assert "Failure" in status, (
        f"Expected Failure but got: {json.dumps(status, indent=1)}"
    )

    failure = status["Failure"]
    assert "ActionError" in failure, (
        f"Expected ActionError in Failure: {json.dumps(failure, indent=1)}"
    )

    action_error = failure["ActionError"]
    assert "kind" in action_error, (
        f"No 'kind' in ActionError: {json.dumps(action_error, indent=1)}"
    )

    kind = action_error["kind"]
    assert "FunctionCallError" in kind, (
        f"Expected FunctionCallError: {json.dumps(kind, indent=1)}"
    )

    function_call_error = kind["FunctionCallError"]
    assert "ExecutionError" in function_call_error, (
        f"Expected ExecutionError: {json.dumps(function_call_error, indent=1)}"
    )

    execution_error = function_call_error["ExecutionError"]

    if expected_error_msg:
        assert expected_error_msg in execution_error, (
            f"Expected '{expected_error_msg}' in error message but got: {execution_error}"
        )
