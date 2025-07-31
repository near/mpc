import json


def assert_txn_success(result):
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
    assert (
        "result" in result
    ), f"No 'result' in response: {json.dumps(result, indent=1)}"
    assert (
        "status" in result["result"]
    ), f"No 'status' in result: {json.dumps(result['result'], indent=1)}"

    status = result["result"]["status"]
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
