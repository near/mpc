# Design Doc: Port TEE Node Launcher from Python to Rust

**Branch**: `2262-port-node-launcher-to-rust-integration-plan`
**Status**: Proof of concept (single commit)
**Scope**: 62 files changed, +2514 / -2134 lines

## 1. Motivation

The TEE node launcher is a security-critical component: it validates Docker image
hashes, extends the RTMR3 trusted measurement register, and constructs the
container environment for the MPC node. The existing Python implementation
(`tee_launcher/launcher.py`, ~870 lines) works but has properties that motivate
a rewrite:

- **No compile-time safety**: Configuration is a bag of string key-value pairs
  parsed from `.conf` files. Typos, missing fields, and type mismatches are only
  caught at runtime (or not at all).
- **Shell-out heavy**: Uses `subprocess` for Docker commands and `curl` for
  dstack socket communication, making error handling fragile.
- **Env-var passthrough risk**: The Python launcher forwards user-supplied
  environment variables into the container with regex-based allow/deny filters.
  This is a large attack surface requiring defense-in-depth (LD_PRELOAD checks,
  control-char rejection, size caps, etc.).
- **No shared types with mpc-node**: The launcher and the MPC node binary define
  TEE configuration independently, so any schema drift requires manual
  coordination.
- **Reproducibility**: Python is harder to build reproducibly compared to a
  statically-linked Rust binary.

## 2. What Changed: Core Design Decisions

### 2.1 Config format: flat env vars -> structured TOML

This is the most architecturally significant change. The old launcher read a flat
`.conf` file of `KEY=VALUE` pairs and forwarded most of them as `--env` flags to
`docker run`. The new launcher reads a structured TOML file with two
clearly-separated sections:

**Old format** (`deployment/testnet/frodo.conf`):
```
MPC_IMAGE_NAME=nearone/mpc-node
MPC_IMAGE_TAGS=main-260e88b
MPC_REGISTRY=registry.hub.docker.com
MPC_ACCOUNT_ID=frodo.test.near
MPC_SECRET_STORE_KEY=AAAA...
MPC_CONTRACT_ID=mpc-contract.test.near
MPC_ENV=testnet
MPC_HOME_DIR=/data
RUST_LOG=info
PORTS=8080:8080,24566:24566
```

**New format** (`deployment/testnet/frodo.toml`):
```toml
[launcher_config]
image_tags = ["main-260e88b"]
image_name = "nearone/mpc-node"
registry = "registry.hub.docker.com"
rpc_request_timeout_secs = 10
rpc_request_interval_secs = 1
rpc_max_attempts = 20
port_mappings = [
    { host = 8080, container = 8080 },
    { host = 24566, container = 24566 },
]

[mpc_node_config]
home_dir = "/data"

[mpc_node_config.log]
filter = "info"

[mpc_node_config.near_init]
chain_id = "testnet"

[mpc_node_config.secrets]
secret_store_key_hex = "AAAA..."

[mpc_node_config.node]
my_near_account_id = "frodo.test.near"
mpc_contract_id = "mpc-contract.test.near"
```

**Why this matters**:

1. **Launcher config is typed**: `LauncherConfig` is a Rust struct with
   `NonEmptyVec<String>` for tags, `NonZeroU16` for ports, `DockerSha256Digest`
   for hashes. Invalid config fails at deserialization, not deep inside runtime
   logic.

2. **MPC node config is opaque to the launcher**: The `mpc_node_config` section
   is deserialized as a generic `toml::Table`. The launcher does *not* interpret
   it -- it writes it to `/mnt/shared/mpc-config.toml` and mounts it into the
   container. The MPC node reads it via `start-with-config-file`. This means the
   launcher never needs to know about MPC node config schema changes.

3. **No env-var passthrough**: The entire category of env-var injection attacks
   disappears. The old launcher needed regex-based key validation, LD_PRELOAD
   scanning, control-char rejection, size caps, and a deny-list for sensitive
   keys. The new launcher simply doesn't pass environment variables to the
   container (except `DSTACK_ENDPOINT` in TEE mode, which is a hardcoded
   constant).

### 2.2 Container launch: `docker run` -> `docker compose`

The old launcher built a `docker run` command by concatenating strings:
```python
cmd = ["docker", "run", "--security-opt", "no-new-privileges:true",
       "-v", "/tapp:/tapp:ro", "-v", "shared-volume:/mnt/shared", ...]
for key, val in env_vars:
    cmd.extend(["--env", f"{key}={val}"])
```

The new launcher renders a docker-compose YAML template and runs
`docker compose up -d`:

```yaml
# mpc-node-docker-compose.template.yml
services:
  mpc-node:
    image: "{{IMAGE_NAME}}@{{IMAGE}}"
    container_name: "{{CONTAINER_NAME}}"
    security_opt:
      - no-new-privileges:true
    ports: {{PORTS}}
    volumes:
      - /tapp:/tapp:ro
      - shared-volume:/mnt/shared
      - mpc-data:/data
    command: ["/app/mpc-node", "start-with-config-file", "{{MPC_CONFIG_SHARED_PATH}}"]
```

There's a separate TEE template that additionally mounts the dstack socket and
sets `DSTACK_ENDPOINT`. Template variables are replaced at runtime. The rendered
file is written to a temp file that's cleaned up after `docker compose up`.

**Why this matters**: The container spec is now a static, auditable template
rather than a dynamically-constructed command string. The only dynamic parts
are the image digest, image name, and port list.

### 2.3 dstack communication: curl subprocess -> native SDK

The old launcher communicated with dstack via shelling out to curl:
```python
subprocess.run(["curl", "--unix-socket", "/var/run/dstack.sock",
                "-X", "POST", "http://dstack/EmitEvent", ...])
```

The new launcher uses the `dstack-sdk` crate directly:
```rust
let client = DstackClient::new(Some(DSTACK_UNIX_SOCKET));
client.emit_event(MPC_IMAGE_HASH_EVENT.to_string(), image_hash.as_ref().to_vec()).await?;
```

### 2.4 Shared types via `launcher-interface` crate

Key types (`DockerSha256Digest`, `ApprovedHashes`, `TeeConfig`,
`TeeAuthorityConfig`) are defined in the `launcher-interface` crate and shared
between the launcher and the MPC node. This eliminates schema drift -- if the
MPC node changes `TeeConfig`, the launcher won't compile until updated.

### 2.5 Docker registry interaction: preserved but strengthened

Both launchers implement the same multi-step image verification:

1. Get bearer token from `auth.docker.io`
2. Iterate through configured tags, requesting manifests from the registry
3. Handle multi-platform OCI image indices by filtering for `amd64/linux`
4. Match the manifest's config digest against the expected image hash
5. `docker pull` by manifest digest (immutable reference)
6. `docker inspect` to verify the pulled image ID matches

The Rust version adds:
- Proper typed deserialization of three manifest formats (OCI index, Docker V2,
  OCI manifest) via a `ManifestResponse` enum with tagged serde
- Exponential backoff with `backon` crate (configurable min delay, factor 1.5,
  max 60s, configurable max attempts)
- Structured error types for every failure mode

## 3. Execution Flow Comparison

```
                     Python                                  Rust
                     ------                                  ----
1. Parse             os.environ["PLATFORM"]                  clap::Parser (env vars)
   CLI args          os.environ["DOCKER_CONTENT_TRUST"]      Type-safe enums
                     os.environ["DEFAULT_IMAGE_DIGEST"]      DockerSha256Digest

2. Load config       parse_env_file("/tapp/user_config")     toml::from_str -> Config
                     -> Dict[str, str]                       -> { LauncherConfig, toml::Table }

3. Select hash       load_and_select_hash()                  select_image_hash()
                     JSON -> approved_hashes list             JSON -> ApprovedHashes
                     Override > newest > default              Same priority

4. Validate          get_manifest_digest() + docker pull     validate_image_hash()
   image             + docker inspect                        Same 3-step verification

5. Extend RTMR3     curl --unix-socket ... EmitEvent         dstack_sdk::emit_event()
   (TEE only)

6. Build config      N/A (env vars passed directly)          intercept_node_config()
   for MPC node                                              Inject [tee] section into TOML
                                                             Write to /mnt/shared/mpc-config.toml

7. Launch            build_docker_cmd() -> docker run        render_compose_file()
   container         60+ env vars as --env flags             -> docker compose up -d
                                                             Config via mounted file
```

## 4. Security Model Changes

| Concern | Python launcher | Rust launcher |
|---------|----------------|---------------|
| Env-var injection | Regex allow-list, deny-list, LD_PRELOAD scan, size caps, control-char rejection | Eliminated -- no env passthrough |
| Port injection | String validation with `is_safe_port_mapping()` | `NonZeroU16` types, structured TOML arrays |
| Config tampering | User can set any `MPC_*` env var | User config is opaque; launcher injects `[tee]` and rejects if user has it |
| Image hash | Same triple-verification (registry + pull + inspect) | Same, with typed error handling |
| Privilege escalation | `--security-opt no-new-privileges:true` | Same, in compose template |
| RTMR3 | curl subprocess (error handling via exit code) | Native SDK (typed errors) |

The key security win is the **elimination of the env-var passthrough surface**.
The Python launcher's `build_docker_cmd()` function was ~90 lines of validation
logic for a feature that the new architecture doesn't need at all.

## 5. What's Deleted

- `tee_launcher/launcher.py` (873 lines) -- the entire Python launcher
- `tee_launcher/test_launcher.py` (32 lines) -- integration test
- `tee_launcher/test_launcher_config.py` (844 lines) -- comprehensive unit tests
- `tee_launcher/launcher.md` (102 lines) -- design doc
- `tee_launcher/requirements.txt`, `__init__.py`, `user-config.conf`
- `tee_launcher/launcher-test-image/Dockerfile`
- All `.conf` config files in `deployment/`

## 6. What's Added

- `crates/tee-launcher/` -- full Rust crate (~1,800 lines across 5 source files)
  - `main.rs` (1,278 lines) -- orchestration, registry interaction, compose
    rendering, container launch, and tests
  - `types.rs` (288 lines) -- CLI args, config structs, validation
  - `docker_types.rs` (150 lines) -- Docker registry API response types
  - `error.rs` (88 lines) -- typed error hierarchy
  - `constants.rs` (8 lines) -- path constants
- Docker compose templates (TEE and non-TEE)
- TOML config files for all deployment environments
- `deployment/cvm-deployment/` -- deployment scripts and compose files (moved
  from `tee_launcher/`)
- CI updates for Rust builds with `repro-env` reproducibility

## 7. Infrastructure Changes

- **CI**: Upgraded machines from 2x to 8x for launcher builds. Added `repro-env`
  for reproducible Rust binary builds. Removed Python pytest job for old launcher
  tests.
- **Dockerfile**: Replaced Python + scripts with a multi-stage build that
  downloads `docker-compose` v2.37.0 (pinned with SHA256) and copies the
  pre-built Rust binary.
- **Build scripts**: `deployment/build-images.sh` now builds the launcher via
  `repro-env build -- cargo build -p tee-launcher --profile reproducible`.
- **Nix**: Minor formatting; no functional changes.

## 8. Test Coverage Gap

The Python launcher had ~844 lines of unit tests covering config parsing,
injection prevention, env-var validation, platform modes, capacity limits, and
end-to-end flows. The Rust launcher has inline tests in `main.rs` covering:

- Image hash selection logic
- Docker compose template rendering
- Config interception (reserved key rejection)
- Docker registry response deserialization

**Missing test coverage** relative to the Python tests:
- Port mapping validation edge cases
- Full end-to-end flow tests (config load -> container launch)
- TOML config parsing error cases
- Platform-specific behavior (TEE vs NONTEE branching)

Many of the Python tests for injection prevention are no longer needed (the
attack surface is gone), but the remaining functional tests should be ported.

---

## 9. Proposed PR Breakdown

The current branch is a single commit with 62 files changed. Here's how to break
it into reviewable, independently-mergeable PRs:

### PR 1: Introduce `tee-launcher` crate with core types and config parsing
**Files**: `Cargo.toml` (workspace), `crates/tee-launcher/Cargo.toml`,
`types.rs`, `error.rs`, `constants.rs`
**Size**: ~400 lines
**Description**: Add the crate skeleton with `CliArgs`, `Config`,
`LauncherConfig`, `Platform`, `PortMapping`, `HostEntry` types, and the
`LauncherError` hierarchy. Include unit tests for config deserialization and
type validation. This PR is pure library code with no binary entry point.
**Reviewable because**: Types and error handling can be reviewed in isolation.
No runtime behavior.

### PR 2: Docker registry interaction and image verification
**Files**: `docker_types.rs`, registry-related functions from `main.rs`
(`get_manifest_digest`, `validate_image_hash`, `select_image_hash`)
**Size**: ~500 lines
**Description**: Add Docker registry API types (`ManifestResponse`,
`DockerTokenResponse`, etc.) and the image verification pipeline: auth token
acquisition, multi-tag manifest resolution with exponential backoff,
multi-platform index handling, and the pull-then-inspect verification. Include
unit tests for manifest deserialization and hash selection logic.
**Reviewable because**: This is the most complex logic and benefits from focused
review. It has an `#[cfg(feature = "external-services-tests")]` integration test
that hits Docker Hub.

### PR 3: Docker compose template rendering and container launch
**Files**: Compose templates (`*.template.yml`), `render_compose_file()`,
`launch_mpc_container()` from `main.rs`
**Size**: ~200 lines
**Description**: Add the two compose templates (TEE and non-TEE), the template
rendering logic, and the container launch function (`docker rm -f` + `docker
compose up -d`). Include tests for template rendering.
**Reviewable because**: The compose templates are the security-auditable
"contract" for how the container is launched.

### PR 4: Main orchestration and `run()` entry point
**Files**: `main.rs` (remaining orchestration: `run()`, `intercept_node_config`,
`insert_reserved`, dstack integration)
**Size**: ~200 lines
**Description**: Wire everything together: config loading -> hash selection ->
image validation -> RTMR3 extension -> config injection -> container launch.
Include the `intercept_node_config` logic that injects `[tee]` into the user
config. This PR depends on PRs 1-3.
**Reviewable because**: The orchestration is now a thin layer over
well-reviewed building blocks.

### PR 5: Config format migration (`.conf` -> `.toml`)
**Files**: All `deployment/**/*.toml` (new), all `deployment/**/*.conf` (deleted),
`deployment/cvm-deployment/user-config.toml`
**Size**: ~400 lines
**Description**: Add TOML config files for all environments (localnet, testnet)
and the cvm-deployment reference config. Delete the old `.conf` files. This is a
pure config change with no code.
**Reviewable because**: Config migration can be reviewed by operators
independently of the code. Easy to verify 1:1 mapping of old values to new
structure.

### PR 6: CI, Dockerfile, and build infrastructure
**Files**: `.github/workflows/ci.yml`, `.github/workflows/docker_build_launcher.yml`,
`deployment/Dockerfile-launcher`, `deployment/build-images.sh`, `flake.nix`,
`scripts/*.sh`
**Size**: ~200 lines
**Description**: Update CI to build the Rust launcher with `repro-env`. Replace
the Python Dockerfile with a multi-stage Rust binary + docker-compose plugin
image. Update scripts to use new paths. Remove old Python pytest CI job.
**Reviewable because**: Infrastructure changes are best reviewed separately from
application logic.

### PR 7: Delete old Python launcher and relocate docs
**Files**: `tee_launcher/` (deleted), `docs/UPDATING_LAUNCHER.md` (moved),
`docs/using-the-launcher-in-nontee-setup.md` (moved), doc updates in
`docs/localnet/`, `localnet/tee/scripts/`, `crates/test-utils/assets/`
**Size**: ~2,000 lines deleted, ~50 lines changed
**Description**: Remove the Python launcher, its tests, and supporting files.
Move documentation to `docs/`. Update cross-references. This is the final
cleanup PR after all Rust infrastructure is in place.
**Reviewable because**: Deletion PRs are easy to review. Keeping this last
ensures the old launcher is only removed after the new one is fully deployed.

### Dependency graph

```
PR 1 (types) ─────┐
                   ├──> PR 4 (orchestration) ──┐
PR 2 (registry) ──┤                            ├──> PR 7 (delete Python)
                   │                            │
PR 3 (compose) ───┘                            │
                                               │
PR 5 (config migration) ──────────────────────>│
                                               │
PR 6 (CI/Docker) ─────────────────────────────>┘
```

PRs 1, 2, 3 can be developed in parallel (they share types from PR 1, but
could use stub types initially). PRs 5 and 6 are independent of the Rust code
PRs. PR 7 is the final cleanup that depends on everything else being merged and
deployed.
