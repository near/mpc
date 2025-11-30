# 🚀 MPC Node Launcher for dstack (TDX Confidential VM)

This repository contains the secure **launcher** used to deploy and upgrade an MPC node inside a **confidential TDX VM**.  
The launcher ensures integrity, validates the MPC image before execution, and interacts with dstack’s attestation agent.

The launcher is a single Python script: **launcher.py**.

---

# 🔐 Features

- Pulls an MPC Docker image from the registry  
- Validates the MPC image digest against an allow-listed set
- Optionally enforces an override digest (`MPC_HASH_OVERRIDE`)
- Extends **RTMR3** with the validated digest via dstack `/var/run/dstack.sock`
- Launches the MPC docker container securely  


---

# 📦 Components

- **launcher.py** — secure attestation + container launcher  
- **launcher-docker-compose.yaml** — Docker Compose example for local development  
- **/tapp/user_config** — dstack-provided configuration file  
- **/mnt/shared/image-digest.bin** — allow-listed approved image hashes (written by MPC node)

---

# 🧩 Mandatory Environment Variables

These must be present **launcher-docker-compose.yaml**:

| Variable | Purpose |
|---------|---------|
| `DOCKER_CONTENT_TRUST=1` | Ensures all docker pulls are content-trusted |
| `DEFAULT_IMAGE_DIGEST` | Allowed image for the first boot.

---

# ⚙️ Optional Launcher Environment Variables (via `/tapp/user_config`)

These configure how the launcher behaves and how the MPC image is selected.

## 🖼️ Image selection

| Variable | Description |
|----------|-------------|
| `MPC_IMAGE_NAME` | Name of the MPC docker image (default: `nearone/mpc-node`) |
| `MPC_REGISTRY` | Registry hostname (default: `registry.hub.docker.com`) |
| `MPC_IMAGE_TAGS` | Comma-separated tags to try (default: `latest`) |
| `RPC_REQUEST_TIMEOUT_SECS` | Per-request timeout | `10` |
| `RPC_REQUEST_INTERVAL_SECS` | Initial retry interval (seconds) | `1.0` |
| `RPC_MAX_ATTEMPTS` | Max attempts before failure | `20` |
| `MPC_HASH_OVERRIDE` | Optional: force a slection of specific sha256 digest (must be in approved list) |

Example:

```bash
MPC_IMAGE_NAME=nearone/mpc-node
MPC_REGISTRY=registry.hub.docker.com
MPC_IMAGE_TAGS=latest,stable
RPC_REQUEST_TIMEOUT_SECS=5
RPC_REQUEST_INTERVAL_SECS=1.0
RPC_MAX_ATTEMPTS=15
MPC_HASH_OVERRIDE=sha256:abc123...
```

These variables **never** propagate into the MPC container.  
They are used only by the launcher.

---


---

# 📁 Important File Locations

| Path | Purpose |
|------|---------|
| `/tapp/user_config` | User-supplied `.env` file read by launcher |
| `/mnt/shared/image-digest.bin` | JSON file containing approved MPC image hashes |
| `/var/run/dstack.sock` | Unix socket to communicate with the dstack agent |
| `/mnt/shared/` | Shared volume between launcher + MPC container |

---

# ▶️ How the Launcher Works (High-Level Flow)

1. Ensure `DOCKER_CONTENT_TRUST=1`
2. Load `/tapp/user_config` (optional)
3. Load RPC timing configuration
4. Load approved image hashes  
   - From `image-digest.bin`, or  
   - From `DEFAULT_IMAGE_DIGEST`
5. Select digest  
   - Use `MPC_HASH_OVERRIDE` if present  
   - Otherwise take newest approved hash
6. Validate digest  
   - Fetch Docker manifests  
   - Confirm digest vs content-trust digest
7. Extend RTMR3 with validated digest
8. Launch MPC container securely using Docker

---

# 🛠️ Building the Launcher (Reproducible Builds)

From `tee_launcher/`, run:

```bash
docker build -t barakeinavnear/launcher:latest -f development/Dockerfile.launcher .
```

Additional reproducible build components:

- **Makefile** — Reproducible build of MPC binary  
- **deployment/Dockerfile** — Fully pinned dependencies  
- **deployment/build-image.sh** — Drives reproducible MPC docker builds  

Example image digest:

```
sha256:dcbd3b8c8ae35d2ba63b25d6b617ce8b7faabb0af96ffa2e35b08a50258ebfa4
```

Example binary digest:

```
5dd1a80f842d08753184334466e97d55e5caa3dbcd93af27097d11e926d7f823
```

To inspect image digest:

```bash
docker image inspect mpc-node-gcp:latest | jq '.[0].Id'
```

To compute binary digest:

```bash
docker run --rm <IMAGE_DIGEST> cat /app/mpc-node | sha256sum
```

---

# 🔄 Upgrading an MPC Node

1. Generate a new MPC docker image (reproducible build)
2. Write the new digest to `/mnt/shared/image-digest.bin`  (with is done by the MPC node)
3. **Optionally** adjust:
   - `MPC_IMAGE_TAGS`
   - `MPC_IMAGE_NAME`
   - `MPC_REGISTRY`
4. Shutdown the CVM
5. Start it again through dstack → launcher validates + launches new image

All node upgrades go through **digest-based verification**, ensuring integrity.

---

# 📌 (Optional) Automating Deployment

You can write a script using `vmm-cli.py` from dstack to:

- Upload `/tapp/user_config`
- Upload new image digest
- Reboot CVM
- Verify attestation logs
- Confirm the newly launched MPC container is running

---

