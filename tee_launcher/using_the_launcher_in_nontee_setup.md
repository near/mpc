# Running the MPC Launcher in Non-TEE Mode

This guide describes the **high-level steps** required to run the MPC launcher **outside of a TEE**, using the same launcher and MPC Docker images as in TEE deployments.

The goal is to allow developers and operators to exercise the **real production launcher flow** (image selection, validation, container launch, upgrades) **without relying on TEE / dstack infrastructure**.

---

## Overview

In non-TEE mode:
- The launcher runs with `PLATFORM=NONTEE`
- No dstack socket or attestation is used
- RTMR extensions are skipped
- Image hash validation and upgrade logic remain unchanged
- The MPC container is launched with DSTACK_ENDPOINT set to dstack.sock

This provides maximum parity with production while keeping the setup simple.

---

## Prerequisites

- Docker installed and running
- Docker Compose (classic `docker-compose` or plugin `docker compose`)
- Network access to pull Docker images
- A valid MPC Docker image digest

---

## Files Used

- **Launcher Docker Compose (non-TEE)**  
  Example:  
  `./launcher_docker_compose_nontee.yaml`

- **User configuration file**  
  Example:  
  `./user-config.conf` (mounted into the launcher container)

---

## Step-by-Step Instructions

### 1. Prepare the non-TEE docker-compose file

Create or use a non-TEE launcher compose file with the following properties:

- Set `PLATFORM=NONTEE`
- Mount `/var/run/docker.sock`
- Do **not** mount `/var/run/dstack.sock`
- Mount the user config file at `/tapp/user_config`
- Provide persistent volumes for shared state and MPC data

See example:
```
./tee_launcher/launcher_docker_compose_nontee.yaml
```

---

### 2. Prepare the user configuration file

Create a `user-config.conf` file containing:
- MPC image selection parameters (`MPC_IMAGE_NAME`, `MPC_IMAGE_TAGS`, `MPC_REGISTRY`)
- MPC runtime configuration (account ID, contract ID, network, logging, etc.)
- Optional port mappings using `PORTS=`

This file is read by the launcher and passed (safely) into the MPC container.

---

### 3. Start the launcher

From the directory containing the non-TEE compose file:

```bash
docker-compose -f launcher_docker_compose_nontee.yaml up -d
```

---

### 4. Monitor launcher logs

```bash
docker logs -f launcher
```

You should see:
- `Launcher platform: NONTEE`
- Image hash selection and validation
- `PLATFORM=NONTEE → skipping RTMR3 extension`
- A `docker run ...` command launching `mpc-node`

---

### 5. Verify the MPC container

Check that the MPC container is running:

```bash
docker ps
```

Inspect the MPC container to confirm:
- No `DSTACK_ENDPOINT` environment variable exists
- No dstack socket is mounted
- Expected ports are published

Example:
```bash
docker inspect mpc-node
```

---



---

## Stopping and Restarting

Stop and remove containers:
```bash
docker-compose -f launcher_docker_compose_nontee.yaml down
```

Stop and remove containers **and volumes** (full reset):
```bash
docker-compose -f launcher_docker_compose_nontee.yaml down -v
```

Restart:
```bash
docker-compose -f launcher_docker_compose_nontee.yaml up -d
```

---

## Notes

- Non-TEE mode is intended for **testing, development, and debugging**
- Security-sensitive behavior for TEE deployments remains unchanged
- The same launcher image and MPC image hashes are used in both modes

---

