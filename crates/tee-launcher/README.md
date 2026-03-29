# TEE Launcher (Rust)

Secure launcher for initializing and attesting a Docker-based MPC node inside a TEE-enabled environment (e.g., Intel TDX via dstack).

Replaces the previous Python launcher (`tee_launcher/launcher.py`).

## What it does

1. Loads a TOML configuration file from `/tapp/user_config`
2. Selects an approved MPC image hash (from on-disk approved list, override, or default)
3. Validates the image by resolving it through the Docker registry and pulling by digest
4. In TEE mode: extends RTMR3 by emitting the image digest to dstack
5. Writes the MPC node config to a shared volume
6. Launches the MPC container via `docker compose up -d`

## CLI Arguments

All arguments are read from environment variables (set via docker-compose `environment`):

| Variable | Required | Description |
|----------|----------|-------------|
| `PLATFORM` | Yes | `TEE` or `NONTEE` |
| `DOCKER_CONTENT_TRUST` | Yes | Must be `1` |
| `DEFAULT_IMAGE_DIGEST` | Yes | Fallback `sha256:...` digest when the approved-hashes file is absent |

## Configuration (TOML)

The launcher reads its configuration from `/tapp/user_config` as a TOML file. This is a change from the previous Python launcher which used a `.env`-style file.

```toml
[launcher_config]
image_tags = ["latest"]
image_name = "nearone/mpc-node"
registry = "registry.hub.docker.com"
rpc_request_timeout_secs = 10
rpc_request_interval_secs = 1
rpc_max_attempts = 20
# Optional: force selection of a specific digest (must be in approved list)
# mpc_hash_override = "sha256:abcd..."
port_mappings = [
  { host = 11780, container = 11780 },
  { host = 2200, container = 2200 },
]

# Opaque MPC node configuration.
# The launcher does not interpret these fields — they are re-serialized
# to TOML and mounted into the container at /mnt/shared/mpc-config.toml
# for the MPC binary to consume via `start-with-config-file`.
[mpc_node_config]
# ... any fields the MPC node expects
```

### `[launcher_config]`

| Field | Required | Description |
|-------|----------|-------------|
| `image_tags` | Yes | Docker image tags to search, e.g. `["3.7.0"]` |
| `image_name` | Yes | Docker image name, e.g. `"nearone/mpc-node"` |
| `registry` | Yes | Docker registry hostname, e.g. `"registry.hub.docker.com"` |
| `rpc_request_timeout_secs` | Yes | Per-request timeout for registry API calls (seconds) |
| `rpc_request_interval_secs` | Yes | Initial retry interval for registry API calls (seconds) |
| `rpc_max_attempts` | Yes | Maximum registry API retry attempts |
| `mpc_hash_override` | No | Force a specific `sha256:` digest (must appear in approved list) |
| `port_mappings` | Yes | Port mappings forwarded to the MPC container (`{ host, container }` pairs) |

### `[mpc_node_config]`

Arbitrary TOML table passed through to the MPC node. The launcher writes this verbatim to `/mnt/shared/mpc-config.toml`, which the container reads on startup.

## Image Hash Selection

Priority order:
1. If the approved hashes file (`/mnt/shared/image-digest.bin`) exists and `mpc_hash_override` is set: use the override (must be in the approved list)
2. If the approved hashes file exists: use the newest approved hash (first in list)
3. If the file is absent: fall back to `DEFAULT_IMAGE_DIGEST`

## File Locations

| Path | Description |
|------|-------------|
| `/tapp/user_config` | TOML configuration file |
| `/mnt/shared/image-digest.bin` | JSON file with approved image hashes (written by the MPC node) |
| `/mnt/shared/mpc-config.toml` | MPC node config (written by the launcher) |
| `/var/run/dstack.sock` | dstack unix socket (TEE mode only) |

## Key Differences from the Python Launcher

| Aspect | Python (`launcher.py`) | Rust (`tee-launcher`) |
|--------|----------------------|----------------------|
| Config format | `.env` key-value file | TOML |
| MPC node config | Environment variables passed to container | TOML file mounted into container |
| Container launch | `docker run` with flags | `docker compose up -d` with rendered template |
| RTMR3 extension | `curl` to unix socket | `dstack-sdk` native client |

## Building

```bash
cargo build -p tee-launcher --profile=reproducible
```

## Testing

```bash
# Unit tests
cargo nextest run --cargo-profile=test-release -p tee-launcher

# Integration tests (requires network access and Docker Hub)
cargo nextest run --cargo-profile=test-release -p tee-launcher --features external-services-tests
```
