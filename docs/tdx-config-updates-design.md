# Dynamic Configuration Updates in TDX Deployments

**Status:** WIP / Design
**Issue:** #2420
**Authors:** TBD
**Date:** 2026-03-13

## Problem Statement

Today, MPC node configuration in TDX deployments is static: environment variables are passed via the dstack `user-config.conf` at CVM creation time, and the `config.yaml` file is generated once at first boot. There is **no mechanism to update either file while the node is running**.

This is tolerable for settings that rarely change (account IDs, contract IDs, protocol timeouts). It becomes a serious operational bottleneck for **foreign chain validation**, where we expect frequent updates to:

- Add new chains and RPC providers
- Rotate or add API keys for RPC providers
- Update RPC URLs when providers change endpoints

Each such change currently requires a **full CVM restart** (stop CVM, update `user-config.conf`, start CVM), causing downtime for the node and potentially missing signature requests during the restart window.

### Specific Pain Points

1. **`config.yaml` is read once at startup.** The `ConfigFile::from_file()` call in `config.rs` reads the YAML from `$MPC_HOME_DIR/config.yaml` at boot. There is no file watcher or reload mechanism. Changes require a process restart.

2. **`foreign_chains` config lives in `config.yaml`.** Chain definitions, provider URLs, and auth configuration are all part of the static `ConfigFile` struct. They cannot be updated without rewriting `config.yaml` and restarting the node.

3. **API keys are resolved from environment variables at signing time** (via `TokenConfig::Env`), but the environment itself is fixed at container creation. New env vars cannot be injected into a running container.

4. **`user-config.conf` changes require CVM restart.** Dstack's `update-user-config` command followed by stop/start is the only supported mechanism. The launcher re-reads the file only on boot.

5. **No confidential channel for secrets.** The `user-config.conf` is stored in `/tapp/user_config` which is an unmeasured dstack input. While convenient, there is no encrypted or attestation-protected path for delivering API keys to the node.

## Current Architecture

### Configuration Flow

```
Operator writes user-config.conf
        |
        v
  dstack VMM deploys CVM
        |
        v
  Launcher (launcher.py) reads /tapp/user_config
        |
        +--> Launcher-only vars: MPC_IMAGE_NAME, MPC_REGISTRY, MPC_IMAGE_TAGS
        +--> Passthrough vars: MPC_* env vars, RUST_LOG, NEAR_BOOT_NODES
        |
        v
  Launcher starts MPC container with env vars
        |
        v
  MPC node startup (cli.rs -> run.rs):
        +--> Reads $MPC_HOME_DIR/config.yaml (or generates default)
        +--> Reads secrets.json (p2p key, signer key)
        +--> Starts indexer, coordinator, web server
        +--> Starts allowed_image_hashes_watcher (writes to /mnt/shared/)
```

### What CAN Change at Runtime Today

- **MPC Docker image hash**: The `allowed_image_hashes_watcher` monitors the contract for approved image hashes, writes them to `/mnt/shared/image-digest.bin`, and the launcher reads this on next CVM boot. This is the only existing "dynamic update" pattern.

### What CANNOT Change at Runtime

- `config.yaml` contents (all protocol parameters, foreign chains config)
- Environment variables in the MPC container
- API keys for RPC providers
- The set of supported foreign chains

### TEE/Attestation Constraints

Understanding what is and isn't measured is critical for designing a solution:

| Component | Measured in | Can change without breaking attestation? |
|-----------|-------------|------------------------------------------|
| Launcher docker image | RTMR3 (extended by launcher) | No |
| Launcher docker-compose | RTMR3 (extended by launcher) | No |
| MPC docker image hash | RTMR3 (extended by launcher) | No (but approved list is dynamic) |
| vCPU, Memory | RTMR2 | No |
| Guest OS / dstack version | MRTD, RTMR0-2 | No |
| `user-config.conf` | **Unmeasured** | Yes |
| `/mnt/shared/` contents | **Unmeasured** (encrypted at rest) | Yes |
| `config.yaml` | **Unmeasured** (inside encrypted CVM disk) | Yes (if a mechanism exists) |

Key insight: **`config.yaml` and environment variables live inside the CVM's encrypted filesystem, which is not individually measured.** The attestation guarantees that the correct code is running, but the config data itself is not part of the measurement. This means we can update configuration without breaking attestation -- the challenge is getting the data into the running process.

## Proposed Solutions

### Option A: File-Based Config Hot-Reload (Recommended)

Add a file watcher to the MPC node that monitors `config.yaml` for changes, and provide a mechanism to update the file from outside the CVM.

#### Design

1. **Config file watcher in the MPC node:**
   - Add a `tokio::fs::watch` (or `notify` crate) watcher on `config.yaml`
   - On file change, re-parse and validate the new config
   - Apply changes to `foreign_chains` (and potentially other safe-to-reload fields) without restart
   - Reject invalid configs with a warning log, keeping the old config active
   - Follow the existing pattern from `allowed_image_hashes_watcher.rs` for crash-safe atomic file writes

2. **Config update delivery via shared volume:**
   - Extend the `/mnt/shared/` volume pattern already used for `image-digest.bin`
   - The launcher (or a new sidecar) watches for config update files on the shared volume
   - The launcher writes the validated config into the MPC container's data volume
   - Alternatively, the node itself watches a "config overlay" file on `/mnt/shared/`

3. **Operator workflow:**
   - Operator updates `user-config.conf` with new foreign chain settings
   - Operator calls `vmm-cli.py update-user-config` (no CVM restart needed)
   - Launcher detects the change and writes the new config to the shared volume
   - MPC node picks up the change via file watcher

#### What Changes Can Be Hot-Reloaded

| Config field | Hot-reloadable? | Notes |
|-------------|-----------------|-------|
| `foreign_chains` | Yes | Primary use case |
| `triple`, `presignature`, `signature` timeouts | Potentially | Low risk, but needs careful handling of in-flight protocols |
| `my_near_account_id` | No | Fundamental identity, requires restart |
| `indexer` settings | No | Requires indexer restart |
| `web_ui`, `pprof_bind_address` | No | Bound at startup |

#### API Key Delivery

For API keys referenced via `TokenConfig::Env`:
- New env var values can be written to a `.env` file on the shared volume
- The node reads this file when resolving `TokenConfig::Env` tokens at signing time
- This avoids the need to inject env vars into a running container

#### Pros
- Follows existing patterns (`allowed_image_hashes_watcher`)
- No new infrastructure (dstack, contract changes)
- Operator workflow is simple (update file, no restart)
- Gradual rollout: start with `foreign_chains` only, expand later
- API keys stay within the CVM's encrypted filesystem

#### Cons
- Requires MPC node code changes (file watcher, partial config reload)
- Need to carefully define which fields are safe to hot-reload
- Launcher changes needed to relay config updates
- No consensus mechanism: each operator updates independently (but foreign chain policy voting already handles consensus for the chain list)

#### Implementation Sketch

```rust
// New module: crates/node/src/config/watcher.rs
pub async fn watch_config_file(
    config_path: PathBuf,
    foreign_chains_sender: watch::Sender<ForeignChainsConfig>,
    cancellation_token: CancellationToken,
) -> Result<(), ConfigWatchError> {
    // Use notify crate or poll-based approach
    // On change: parse, validate, send update via channel
    // Consumers (coordinator, providers) receive via watch::Receiver
}
```

```rust
// In coordinator.rs, replace static config read with watch channel
let foreign_chains_config = foreign_chains_receiver.borrow().clone();
```

For API key delivery, a separate `.env` file approach:

```rust
// In auth.rs, modify token resolution
impl TokenConfig {
    pub fn resolve(&self) -> Result<String, AuthError> {
        match self {
            TokenConfig::Val { val } => Ok(val.clone()),
            TokenConfig::Env { env } => {
                // First check override file, then fall back to process env
                if let Some(val) = read_env_override_file(env)? {
                    Ok(val)
                } else {
                    std::env::var(env).map_err(|_| AuthError::MissingEnvVar(env.clone()))
                }
            }
        }
    }
}
```

---

### Option B: Contract-Driven Configuration

Store configuration (chain definitions, RPC URLs) on the contract and have nodes read it via the indexer, similar to how `foreign_chain_policy` already works.

#### Design

1. **Extend the contract** with a new `node_config` or `foreign_chains_config` field
2. **Operators vote** on config changes (similar to `vote_foreign_chain_policy`)
3. **Nodes read** the config from the contract via the indexer
4. **API keys** still need a local mechanism (they cannot go on-chain)

#### Pros
- Consensus built-in: all operators must agree on config changes
- Single source of truth for chain definitions
- Already partially implemented: `vote_foreign_chain_policy` exists

#### Cons
- API keys cannot be stored on-chain (secrets must remain local)
- Slow iteration: every config change requires a voting round
- RPC URLs are somewhat operator-specific (different providers, different API tiers)
- Over-engineers the problem: not all config should require consensus
- The existing `foreign_chain_policy` already handles the consensus part (which chains/URLs are accepted); the local config is for operator-specific settings like auth

---

### Option C: Sidecar Config Service

Run a lightweight sidecar container alongside the MPC node that exposes an HTTP API for config updates, protected by mutual TLS or the dstack attestation mechanism.

#### Design

1. **Config sidecar** runs in the same CVM, shares the data volume
2. **Exposes an API** (e.g., `POST /config/foreign_chains`) for config updates
3. **Writes config** atomically to the shared volume
4. **MPC node** watches the config file (same as Option A)
5. **Authentication** via the CVM's TLS certificate or a shared secret

#### Pros
- Clean API for config updates (could integrate with CI/CD)
- Sidecar can validate and merge configs before writing
- Could support encrypted config delivery via TLS

#### Cons
- Additional container to maintain and measure
- New attack surface (API endpoint inside the CVM)
- Launcher compose changes = new attestation measurements
- Over-engineered for the current needs

---

### Option D: Periodic Config Polling from External Source

The MPC node periodically fetches configuration from an external source (S3 bucket, HTTP endpoint, etc.).

#### Design

1. **Node polls** an operator-defined URL for config updates
2. **Config is signed** by the operator's key to prevent tampering
3. **Node applies** validated config changes

#### Pros
- No CVM restart or dstack interaction needed
- Works with existing CI/CD and secret management tools

#### Cons
- Introduces external dependency (what if the config server is down?)
- Needs a signing/verification scheme for config integrity
- Network access from within CVM may be restricted
- Significant new code for a simple problem

## Recommendation

**Option A (File-Based Config Hot-Reload)** is recommended as the primary approach, with the existing contract-based foreign chain policy voting (which is already implemented) providing consensus for the chain/provider list.

### Rationale

1. **Follows existing patterns**: The `allowed_image_hashes_watcher` already demonstrates the file-watch + shared-volume pattern. We'd be extending a proven approach.

2. **Minimal infrastructure changes**: No new containers, no contract changes, no external services. The main work is in the MPC node code.

3. **Separation of concerns**: The contract handles consensus (which chains are accepted), while local config handles operator-specific details (API keys, provider preferences, timeouts).

4. **Incremental delivery**: Start with `foreign_chains` hot-reload only. Expand to other config fields later if needed.

5. **API key handling**: The `.env` override file approach is simple and keeps secrets within the CVM's encrypted filesystem.

### Proposed Implementation Plan

#### Phase 1: Config Hot-Reload in MPC Node
- Add a config file watcher for `config.yaml` (or a dedicated `foreign_chains.yaml`)
- Implement partial config reload for `foreign_chains` section
- Add an env-override file mechanism for API key updates
- Add metrics/logging for config reload events

#### Phase 2: Launcher Support for Config Updates
- Extend the launcher to relay `user-config.conf` changes to the node's config files
- Support writing env override files from `user-config.conf` entries
- Document the operator workflow for config updates without CVM restart

#### Phase 3: Operator Tooling
- Update `deploy-launcher.sh` and `vmm-cli.py` workflows
- Add a dedicated config update command/script
- Update the external operator guide with the new workflow

### Open Questions

1. **Should we use a separate file for hot-reloadable config?** Using a dedicated `foreign_chains.yaml` (or `dynamic_config.yaml`) would make it clearer which fields support hot-reload and avoid the risk of operators editing non-reloadable fields expecting them to take effect.

2. **How should the launcher relay config changes?** The launcher currently only runs at boot. Should it run a background loop watching for `user-config.conf` changes, or should we use a different mechanism (e.g., the node watches a config file on `/mnt/shared/` directly)?

3. **Do we need config change auditing?** Should config changes be logged to an append-only file or reported via the `/public_data` endpoint for observability?

4. **What is the interaction with `vote_foreign_chain_policy`?** Currently, the node votes its local `foreign_chains` config as the foreign chain policy. If the config is hot-reloaded, should the node automatically re-vote? This seems desirable but needs careful handling to avoid vote spam.

5. **Should API keys be deliverable via dstack encrypted env vars?** Dstack supports encrypted environment variables via KMS, but we currently don't use KMS. If we adopt KMS in the future, this could be a cleaner path for secret delivery.
