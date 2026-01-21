# Automatic localnet: feasibility and proposal

## Summary
It is feasible to offer a docker-compose-based localnet that is simple for users to run, but the automation work lives mostly in the bootstrap steps (near CLI key management, account creation, contract deploy/init, and waiting for services). The existing assets already cover a good portion of this:

- `scripts/launch-localnet.sh` has the full bootstrapping logic for a host install.
- `deployment/Dockerfile-node` and `deployment/start.sh` already support running MPC nodes in containers, including an embedded localnet genesis.
- `docs/localnet/docker_localnet.md` shows a partial docker workflow (manual bootstrap on host, nodes in Docker).

A clean compose workflow is achievable by packaging the bootstrap steps into a container (or keeping them on the host) and standardizing configuration/ports/volumes. The main complexity is key management in near CLI and orchestrating the step ordering.

## Current state (relevant pieces)

- The manual guide (`docs/localnet/localnet.md`) and `scripts/launch-localnet.sh` are the authoritative flow.
- The localnet relies on a specific genesis/config from `deployment/localnet`.
- The bootstrap uses near CLI with `save-to-keychain` and `sign-with-keychain` for contract and node accounts, which assumes a host keychain.
- MPC node configs are generated via envsubst using `docs/localnet/mpc-configs/config.yaml.template` and base ports.
- There is already a containerized MPC node entrypoint (`deployment/start.sh`) that handles localnet initialization from an embedded genesis.

## Feasibility conclusion

A docker-compose alternative is feasible and likely the simplest and most maintainable option for the team, as long as we address near CLI key handling and clearly separate “bootstrap” (one-time) from “run” (steady-state) phases. A minimal, workable approach could be:

- Keep the bootstrap on the host (reuse `scripts/launch-localnet.sh` logic with a `--docker` mode).
- Run `neard` and MPC nodes in Docker via compose.

A more complete approach (preferred for reproducibility) is:

- A dedicated `bootstrap` container in compose that runs the near CLI steps, writes keys/configs to shared volumes, and exits.

## Sources of complexity

1. **near CLI keychain usage**
   - The script uses `save-to-keychain` and `sign-with-keychain`. Containers typically do not have the host keychain, so these steps must be changed to use plaintext keys or file-based key storage.

2. **Bootstrap sequencing and readiness**
   - neard must be fully ready before account creation and contract deploy.
   - MPC nodes must be running and exposing `/public_data` before adding their keys and initializing the contract.
   - The existing script uses sleeps + retries; a container version needs health checks or similar wait logic.

3. **Network and port wiring**
   - Each MPC node needs unique RPC/Indexer/Web UI ports.
   - Boot nodes need to be reachable by container name when running inside the Docker network.
   - If multiple localnets run simultaneously, port and data dir namespaces must be isolated.

4. **Genesis and config consistency**
   - Localnet requires the checked-in `deployment/localnet` configs; mismatched genesis will break sync.

5. **Multi-version support**
   - Compose can run different MPC node images per service, but the contract may require allowed image hashes if the TEE path is involved. If localnet is meant to emulate that, the bootstrap needs to vote/allow those hashes.

## Proposal: docker-compose localnet

### Design goals

- One command to start (`docker compose up`) and one to initialize (`docker compose run --rm bootstrap`).
- Configuration is a small YAML file describing the network (node count, port bases, images).
- Ability to run multiple versions simultaneously by specifying per-node image tags and hashes.

### High-level architecture

- `neard`: localnet validator with mounted `deployment/localnet` config and data volume.
- `bootstrap`: one-shot job running near CLI + jq + envsubst, responsible for:
  - create contract account
  - deploy and init contract
  - create node accounts
  - start MPC nodes (or wait for them), add keys, initialize participants, vote domains
- `mpc-node-X`: N services using `deployment/Dockerfile-node` image or a published image.

### Example flow

1. `docker compose up -d neard` (or simply `docker compose up -d`)
2. `docker compose run --rm bootstrap` (creates accounts, deploys, initializes)
3. Nodes are already running and will connect, keys are added, domains are voted, and the network becomes ready.

### Example configuration (conceptual)

```yaml
localnet:
  chain_id: mpc-localnet
  contract_id: mpc-contract.test.near
  node_count: 2
  threshold: 2
  base_ports:
    rpc: 3030
    indexer: 24567
    web_ui: 8080
  nodes:
    - name: mpc-node-1
      account_id: mpc-node-1.test.near
      image: mpc-node:local
      image_hash: 8b40f81f77b8c22d6c777a6e14d307a1d11cb55ab83541fbb8575d02d86a74b0
    - name: mpc-node-2
      account_id: mpc-node-2.test.near
      image: mpc-node:local
      image_hash: 8b40f81f77b8c22d6c777a6e14d307a1d11cb55ab83541fbb8575d02d86a74b0
```

### Example compose sketch (conceptual)

```yaml
services:
  neard:
    image: nearprotocol/neard:local
    volumes:
      - near-data:/root/.near
      - ./deployment/localnet:/seed:ro
    ports:
      - "3030:3030"
    entrypoint: ["/bin/sh", "-c", "cp -rf /seed/. /root/.near/mpc-localnet && neard --home /root/.near/mpc-localnet run"]

  bootstrap:
    image: mpc-localnet-bootstrap:local
    depends_on:
      - neard
    volumes:
      - near-data:/root/.near
      - near-cli:/root/.config/near-cli
      - ./docs/localnet:/work/docs:ro
    environment:
      - NEAR_ENV=mpc-localnet
      - MPC_CONTRACT_ID=mpc-contract.test.near
    command: ["/work/scripts/bootstrap.sh"]

  mpc-node-1:
    image: mpc-node:local
    depends_on:
      - neard
    environment:
      - MPC_ENV=mpc-localnet
      - MPC_ACCOUNT_ID=mpc-node-1.test.near
      - MPC_CONTRACT_ID=mpc-contract.test.near
      - NEAR_BOOT_NODES=${NEAR_BOOT_NODES}
      - MPC_IMAGE_HASH=...
    volumes:
      - mpc-node-1:/data
    ports:
      - "8081:8080"

  mpc-node-2:
    image: mpc-node:local
    ...
```

The above is an example shape, not a final file. The implementation should derive this from a config file to avoid duplication.

## How to deal with near CLI key management

We should avoid `save-to-keychain` in the bootstrap container and instead store keys in a file-backed key directory inside a Docker volume. Two workable options:

- Pre-generate keys in the bootstrap step and use `sign-with-plaintext-private-key` for all account creation and transaction signing.
- Use near CLI’s legacy file-based credentials directory (if supported by the chosen CLI version) and mount it as a persistent volume.

Either approach keeps the flow reproducible and avoids OS-specific keychain dependencies.

## Multi-version support

Compose can run multiple images side-by-side by specifying per-node image tags (and optional image hashes). The bootstrap should:

- Allow listing a per-node `image_hash` in the config file.
- Optionally vote/allow these hashes in the contract if the localnet flow enforces them.

If the contract does not gate local runs on image hashes, this can be skipped for the first iteration.

## Implementation plan (phased)

1. **Refactor bootstrap logic**
   - Extract the near CLI steps from `scripts/launch-localnet.sh` into a reusable `scripts/localnet-bootstrap.sh` that can run on host or in a container.

2. **Compose baseline**
   - Add `deployment/localnet/docker-compose.yml` (or similar) with `neard` + N `mpc-node-*` services.
   - Keep `bootstrap` as a separate step running on host for now.

3. **Bootstrap container**
   - Create a small image with near CLI + jq + envsubst.
   - Run `docker compose run --rm bootstrap` to do all on-chain setup.

4. **Config-driven generation**
   - Introduce a small config file (YAML/JSON) and a script to generate compose and per-node env files.
   - Add support for per-node image versions/hashes.

5. **Quality-of-life**
   - Add health checks and explicit waits (no fixed sleeps).
   - Provide a `down`/cleanup script for volumes and ports.

## Recommended next steps

- Decide whether the bootstrap should run on the host or in a container (container is more reproducible).
- Decide on a small config format for node definitions and port ranges.
- If we want multi-version support immediately, define how image hashes should be voted/allowed in localnet.

## Bottom line

This is doable with moderate effort and should be maintainable if we keep the bootstrapping logic centralized and avoid OS-specific keychains. A compose-based solution also provides a natural path to later k8s support (the bootstrap job maps cleanly to a Kubernetes Job and the nodes to StatefulSets), but compose is the most approachable first step.
