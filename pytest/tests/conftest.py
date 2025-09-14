# conftest.py
"""
Fixtures for pytest
"""

import pytest
import atexit
import subprocess
import git
import sys
import shutil
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
def compile_contract_common(
    repository_root_path: Path, contract_name: str, contract_output_path: Path
):
    print(f"compiling contract {contract_name}")

    subprocess.run(
        [
            "cargo",
            "build",
            "-p",
            contract_name,
            "--target=wasm32-unknown-unknown",
            "--profile=release-contract",
        ],
        check=True,
        stdout=sys.stdout,
        stderr=sys.stderr,
    )

    contract_bin_name = f"{contract_name.replace('-', '_')}.wasm"

    subprocess.run(
        [
            "wasm-opt",
            "-Oz",
            f"target/wasm32-unknown-unknown/release-contract/{contract_bin_name}",
            "-o",
            f"target/wasm32-unknown-unknown/release-contract/{contract_bin_name}",
        ],
        cwd=repository_root_path,
        check=True,
        stdout=sys.stdout,
        stderr=sys.stderr,
    )
    compiled_contract = (
        repository_root_path
        / "target"
        / "wasm32-unknown-unknown"
        / "release-contract"
        / f"{contract_bin_name}"
    )
    os.makedirs(os.path.dirname(contract_output_path), exist_ok=True)
    shutil.copy(compiled_contract, contract_output_path)


@pytest.fixture(scope="session", autouse=True)
def compile_mpc_contract(request):
    """
    This function navigates to the chain-signatures directory, compiles the mpc-contract and moves it in the res folder.
    This ensures that the pytests will always use the source code inside chain-signatures/contract.
    """

    chain_signatures = git_root() / "libs" / "chain-signatures"
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
                Path("contract") / "Cargo.toml",
                "--out-dir",
                Path("target") / "wasm32-unknown-unknown" / "release-reproducible",
            ],
            cwd=chain_signatures,
            check=True,
            stdout=sys.stdout,
            stderr=sys.stderr,
        )

        os.makedirs(os.path.dirname(contracts.COMPILED_CONTRACT_PATH), exist_ok=True)
        shutil.copy(
            chain_signatures
            / "target"
            / "wasm32-unknown-unknown"
            / "release-reproducible"
            / "mpc_contract.wasm",
            contracts.COMPILED_CONTRACT_PATH,
        )
    else:
        compile_contract_common(
            chain_signatures, "mpc-contract", contracts.COMPILED_CONTRACT_PATH
        )


@pytest.fixture(scope="session")
def compile_parallel_contract(request):
    """
    This function navigates to the tests/tests_contracts/parallel directory,
    compiles the contract and moves it in the res folder.
    """

    compile_contract_common(
        git_root() / "pytest" / "tests" / "test_contracts" / "parallel",
        "parallel-contract",
        contracts.PARALLEL_CONTRACT_PATH,
    )


@pytest.fixture(scope="session")
def compile_migration_contract(request):
    """
    This function navigates to the tests/tests_contracts/migration directory,
    compiles the contract and moves it in the res folder.
    """
    compile_contract_common(
        git_root() / "pytest" / "tests" / "test_contracts" / "migration",
        "migration-contract",
        contracts.MIGRATE_CURRENT_CONTRACT_PATH,
    )


def git_root() -> Path:
    git_repo = git.Repo(".", search_parent_directories=True)
    return Path(git_repo.git.rev_parse("--show-toplevel"))


def contract_read(dir: str, name: str) -> bytearray:
    return bytearray(Path(dir).joinpath(name).read_bytes())
