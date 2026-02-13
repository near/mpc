"""General-purpose shared test utilities."""

import time


def wait_until(
    predicate, description: str, timeout_sec: float = 30, poll_interval_sec: float = 0.5
) -> None:
    """Poll *predicate* until it returns True or *timeout_sec* elapses."""
    deadline = time.monotonic() + timeout_sec
    last_error = None
    while time.monotonic() < deadline:
        try:
            if predicate():
                return
        except Exception as err:
            last_error = err
        time.sleep(poll_interval_sec)

    raise AssertionError(f"timed out waiting for {description}") from last_error
