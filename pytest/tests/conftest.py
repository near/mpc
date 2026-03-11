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

try:
    from filelock import FileLock
except ImportError:
    FileLock = None


def pytest_configure(config):
    """Configure per-worker isolation for pytest-xdist parallel execution."""
    worker_id = os.environ.get("PYTEST_XDIST_WORKER")

    if worker_id is None:
        # Sequential mode or xdist controller: clean up stale build markers
        # so that builds are re-run for this test session.
        lock_dir = Path(tempfile.gettempdir()) / "pytest-xdist-build-locks"
        if lock_dir.exists():
            for f in lock_dir.glob("*.done"):
                f.unlink()
        return

    # Extract worker index: "gw0" -> 0, "gw3" -> 3
    worker_index = int(worker_id[2:])

    # Isolated .near directory per worker
    dot_near = str(Path.home() / f".near-worker-{worker_index}")
    if os.path.exists(dot_near):
        shutil.rmtree(dot_near)
    os.environ['NEAR_DOT_DIR'] = dot_near

    # Non-overlapping NEAR node ports per worker (100-port stride)
    os.environ['NEAR_PORT_OFFSET'] = str(worker_index * 100)

    # Non-overlapping MPC node ports per worker
    # Values 1-20 are used by Rust integration tests; 21+ are safe for pytest workers
    os.environ['MPC_PORT_SEED'] = str(21 + worker_index)


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
        os.environ[CONFIG_ENV_VAR] = str(constants.CONFIG_PATH)


def pytest_addoption(parser):
    parser.addoption(
        "--non-reproducible",
        action="store_true",
        default=False,
        help="Enable non-reproducible contract build",
    )
    parser.addoption(
        "--skip-mpc-node-build",
        action="store_true",
        default=False,
        help="Enable mpc-node build",
    )
    parser.addoption(
        "--skip-nearcore-build",
        action="store_true",
        default=False,
        help="Enable nearcore build",
    )


@pytest.fixture(scope="session")
def current_contracts():
    with tempfile.TemporaryDirectory() as tmpdir:
        subprocess.run(
            ["cargo", "run", "--bin", "copy_contracts", "--", "-t", tmpdir],
            cwd=git_root(),
            check=True,
            stdout=sys.stdout,
            stderr=sys.stderr,
        )

        yield {
            "mainnet": contract_read(tmpdir, "signer_mainnet.wasm"),
            "testnet": contract_read(tmpdir, "signer_testnet.wasm"),
        }


def _build_once(lock_name: str, build_fn):
    """Run a build function exactly once across all xdist workers using a filelock.

    When running with pytest-xdist, multiple workers start concurrently and each
    has its own session. Without coordination, they would all try to compile the
    same cargo target simultaneously, corrupting the output. This helper uses a
    filelock so only the first worker builds; the others wait and skip.
    """
    worker_id = os.environ.get("PYTEST_XDIST_WORKER")
    if worker_id is None or FileLock is None:
        # Sequential mode or filelock not available: just build normally
        build_fn()
        return

    lock_dir = Path(tempfile.gettempdir()) / "pytest-xdist-build-locks"
    lock_dir.mkdir(exist_ok=True)
    lock_file = lock_dir / f"{lock_name}.lock"
    marker_file = lock_dir / f"{lock_name}.done"

    lock = FileLock(str(lock_file), timeout=600)
    with lock:
        if not marker_file.exists():
            build_fn()
            marker_file.touch()
        else:
            print(f"Skipping {lock_name} (already built by another worker)")


@pytest.fixture(scope="session", autouse=True)
def compile_mpc_node(request):
    """
    This function compiles the mpc-node unless `--skip-mpc-node-build` is present
    """
    skip_mpc_node_build = request.config.getoption("--skip-mpc-node-build")

    if not skip_mpc_node_build:
        def _build():
            print("compiling mpc-node")
            subprocess.run(
                [
                    "cargo",
                    "build",
                    "-p",
                    "mpc-node",
                    "--release",
                    "--features",
                    "network-hardship-simulation",
                    "--locked",
                ],
                check=True,
                stdout=sys.stdout,
                stderr=sys.stderr,
            )

        _build_once("compile-mpc-node", _build)


@pytest.fixture(scope="session", autouse=True)
def compile_nearcore(request):
    """
    This function compiles nearcore unless `--skip-nearcore-build` is present
    """
    skip_nearcore_build = request.config.getoption("--skip-nearcore-build")

    if not skip_nearcore_build:
        def _build():
            nearcore_path = git_root() / "libs" / "nearcore"
            current_path = os.getcwd()
            os.chdir(nearcore_path)

            print("compiling nearcore")

            subprocess.run(
                [
                    "cargo",
                    "build",
                    "-p",
                    "neard",
                    "--release",
                    "--locked",
                ],
                check=True,
                stdout=sys.stdout,
                stderr=sys.stderr,
            )

            os.chdir(current_path)

        _build_once("compile-nearcore", _build)


@pytest.fixture(scope="session")
def compile_backup_cli():
    def _build():
        print("compiling backup-cli")
        subprocess.run(
            [
                "cargo",
                "build",
                "-p",
                "backup-cli",
                "--release",
                "--locked",
            ],
            check=True,
            stdout=sys.stdout,
            stderr=sys.stderr,
        )

    _build_once("compile-backup-cli", _build)


def compile_contract_common(contract_package_name: str):
    """
    This function compiles a contract using cargo build and wasm-opt for optimization.
    """
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
            "--locked",
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
    This function compiles the mpc-contract and moves it to the `COMPILED_CONTRACT_DIRECTORY` directory.
    This ensures that the pytests will always use the current source code of the mpc-contract.
    """

    git_root_directory = git_root()
    non_reproducible = request.config.getoption("--non-reproducible")

    if not non_reproducible:
        def _build():
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

        _build_once("compile-mpc-contract-reproducible", _build)
    else:
        def _build():
            compile_contract_common(contracts.MPC_CONTRACT_PACKAGE_NAME)

        _build_once("compile-mpc-contract", _build)


@pytest.fixture(scope="session")
def compile_parallel_contract(request):
    """
    This function compiles the test parallel contract.
    """

    def _build():
        compile_contract_common(
            contracts.PARALLEL_CONTRACT_PACKAGE_NAME,
        )

    _build_once("compile-parallel-contract", _build)


def git_root() -> Path:
    git_repo = git.Repo(".", search_parent_directories=True)
    return Path(git_repo.git.rev_parse("--show-toplevel"))


def contract_read(dir: str, name: str) -> bytearray:
    return bytearray(Path(dir).joinpath(name).read_bytes())
