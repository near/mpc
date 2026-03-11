# Parallel Pytest Execution

## Usage

```bash
# Sequential (unchanged)
pytest -s -x --skip-nearcore-build --non-reproducible --skip-mpc-node-build

# Parallel with N workers
pytest -n 2 --dist=loadscope --skip-nearcore-build --non-reproducible --skip-mpc-node-build
```

`--dist=loadscope` keeps tests sharing a fixture (e.g. `shared_cluster_tests/`) on the same worker.

## Why tests couldn't run in parallel

Three categories of shared global state prevented concurrent execution:

### 1. NEAR node ports (hardcoded in nearcore)

`libs/nearcore/pytest/lib/cluster.py` hardcodes P2P port `24567 + 10 + ordinal` and RPC port `3030 + 10 + ordinal`. Two clusters would bind the same ports.

**Fix:** Read `NEAR_PORT_OFFSET` env var and add it to all port calculations in `spin_up_node()`.

### 2. MPC node ports (hardcoded via PortSeed)

The Rust CLI (`crates/node/src/cli.rs`) uses `PortSeed::CLI_FOR_PYTEST` (a constant) when generating test configs. All test runs get identical MPC p2p/web/migration ports.

**Fix:** Add `--port-seed <N>` CLI argument. Replace `PortSeed::CLI_FOR_PYTEST` with `PortSeed::new(port_seed)` in both `run_generate_test_configs` and `create_file_config`. Python side reads `MPC_PORT_SEED` env var and passes it through.

### 3. Shared `~/.near` directory

`neard localnet` and all test infrastructure write to `~/.near/`. Two concurrent clusters would clobber each other's node configs, genesis, and state.

**Fix:** Read `NEAR_DOT_DIR` env var in three places:
- `cluster.py` `start_cluster()` — sets the base directory for node data
- `cluster.py` `init_cluster()` — passes `--home` flag to `neard localnet`
- `shared/__init__.py` — `_dot_near()` function for MPC config generation/movement

## Worker isolation (conftest.py)

`pytest_configure` hook detects xdist workers via `PYTEST_XDIST_WORKER` env var and sets per-worker values:

| Env var | Worker 0 | Worker 1 | Worker N |
|---|---|---|---|
| `NEAR_DOT_DIR` | `~/.near-worker-0` | `~/.near-worker-1` | `~/.near-worker-N` |
| `NEAR_PORT_OFFSET` | `0` | `100` | `N * 100` |
| `MPC_PORT_SEED` | `21` | `22` | `21 + N` |

MPC port seeds start at 21 because values 1-20 are reserved for Rust integration tests.

## Build serialization

Each xdist worker has its own pytest session, so `autouse` session-scoped build fixtures (`compile_mpc_contract`, `compile_mpc_node`, `compile_nearcore`) run independently per worker. Concurrent `cargo build` invocations targeting the same `target/` directory corrupt WASM output.

**Fix:** `_build_once()` helper uses `filelock` so only the first worker builds; others wait and skip. Marker files in `/tmp/pytest-xdist-build-locks/` track completed builds. The controller process cleans stale markers at session start.

## Changed files

| File | Change |
|---|---|
| `crates/node/src/cli.rs` | `--port-seed` argument, threaded through to `PortSeed::new()` |
| `libs/nearcore/pytest/lib/cluster.py` | `NEAR_PORT_OFFSET` and `NEAR_DOT_DIR` env vars |
| `pytest/common_lib/shared/__init__.py` | `_dot_near()` function (lazy env var read), `--port-seed` passthrough |
| `pytest/tests/conftest.py` | `pytest_configure` worker isolation, `_build_once()` with filelock |
| `pytest/requirements.txt` | `pytest-xdist`, `filelock` |
