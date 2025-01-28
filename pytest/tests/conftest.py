# conftest.py
import pytest
import atexit


@pytest.fixture(autouse=True)
def run_atexit_cleanup():
    yield
    atexit._run_exitfuncs()
