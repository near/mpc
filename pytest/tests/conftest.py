# conftest.py
"""
Fixtures for pytest
"""

import pytest
import atexit
import subprocess
import git
import sys
from pathlib import Path
import os
import tempfile

from cluster import CONFIG_ENV_VAR

sys.path.append(str(Path(__file__).resolve().parents[1]))
from common_lib import constants, contracts


@pytest.fixture(autouse=True, scope="function")
def run_atexit_cleanup(request):
    """
    Runs atexit BEFORE the pytest concludes.
    Without the -s flag, pytest redirects the output of stdout and stderr,
    but closes those pipes BEFORE executing atexit,
    resulting in a failed test in case atexit attempts to write to stdout or stderr.
    """
    if "no_atexit_cleanup" in request.keywords:
        yield
        return
    yield
    atexit._run_exitfuncs()


@pytest.fixture(autouse=True, scope="session")
def set_config():
    """
    Sets the environment variable for the nearcore config if not already set.
    """
    if CONFIG_ENV_VAR not in os.environ:
        os.environ[CONFIG_ENV_VAR] = constants.CONFIG_PATH


def pytest_addoption(parser):
    parser.addoption(
        "--non-reproducible",
        action="store_true",
        default=False,
        help="Enable non-reproducible contract build",
    )


@pytest.fixture(scope="session")
def current_contracts():
    with tempfile.TemporaryDirectory() as tmpdir:
        subprocess.run(
            ["cargo", "run", "--bin", "export_contracts", "--", "-t", tmpdir],
            cwd=git_root(),
            check=True,
            stdout=sys.stdout,
            stderr=sys.stderr,
        )

        yield {
            "mainnet": contract_read(tmpdir, "signer_mainnet.wasm"),
            "testnet": contract_read(tmpdir, "signer_testnet.wasm"),
        }


# This function compiles a contract using cargo build
def compile_contract_common(contract_package_name: str):
    repository_root_path = git_root()
    print(f"compiling contract {contract_package_name}")

    subprocess.run(
        [
            "cargo",
            "build",
            "-p",
            contract_package_name,
            "--target=wasm32-unknown-unknown",
            "--profile=release-contract",
        ],
        check=True,
        stdout=sys.stdout,
        stderr=sys.stderr,
    )

    contract_compiled_file_name = contracts.contract_compiled_file_name(
        contract_package_name
    )

    subprocess.run(
        [
            "wasm-opt",
            "-Oz",
            f"target/wasm32-unknown-unknown/release-contract/{contract_compiled_file_name}",
            "-o",
            f"target/wasm32-unknown-unknown/release-contract/{contract_compiled_file_name}",
        ],
        cwd=repository_root_path,
        check=True,
        stdout=sys.stdout,
        stderr=sys.stderr,
    )


@pytest.fixture(scope="session", autouse=True)
def compile_mpc_contract(request):
    """
    This function navigates to the chain-signatures directory, compiles the mpc-contract and moves it in the res folder.
    This ensures that the pytests will always use the source code inside chain-signatures/contract.
    """

    git_root_directory = git_root()
    non_reproducible = request.config.getoption("--non-reproducible")

    if not non_reproducible:
        print("compiling mpc contract")
        subprocess.run(
            [
                "cargo",
                "near",
                "build",
                "reproducible-wasm",
                "--manifest-path",
                contracts.MPC_CONTRACT_MANIFEST_PATH,
                "--out-dir",
                contracts.COMPILED_CONTRACT_DIRECTORY,
            ],
            cwd=git_root_directory,
            check=True,
            stdout=sys.stdout,
            stderr=sys.stderr,
        )

    else:
        compile_contract_common(contracts.MPC_CONTRACT_PACKAGE_NAME)


@pytest.fixture(scope="session")
def compile_parallel_contract(request):
    """
    This function navigates to the tests/tests_contracts/parallel directory,
    compiles the contract and moves it in the res folder.
    """

    compile_contract_common(
        contracts.PARALLEL_CONTRACT_PACKAGE_NAME,
    )


@pytest.fixture(scope="session")
def compile_migration_contract(request):
    """
    This function navigates to the tests/tests_contracts/migration directory,
    compiles the contract and moves it in the res folder.
    """
    compile_contract_common(
        contracts.MIGRATION_CONTRACT_PACKAGE_NAME,
    )


def git_root() -> Path:
    git_repo = git.Repo(".", search_parent_directories=True)
    return Path(git_repo.git.rev_parse("--show-toplevel"))


def contract_read(dir: str, name: str) -> bytearray:
    return bytearray(Path(dir).joinpath(name).read_bytes())
