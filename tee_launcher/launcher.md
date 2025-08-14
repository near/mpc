# Deploy and Upgrade an MPC Node on dstack

The launcher is a single Python script: [launcher.py](launcher.py)

This is a secure launcher script for initializing and attesting a Docker-based MPC node.  
It is designed to run inside a TEE-enabled environment (e.g., Intel TDX) to add and ensures the integrity and trustworthiness of the image before launching it.


## 🔐 Features

- Pull an MPC docker image.
- Compares the MPC image digest against expected values
- Extends RTMR3 with the verified image digest
- prints remote attestation and quote generation information to log
- Starts the MPC node container with secure mount and network settings

## Usage

The launcher script is designed to run inside a confidential TDX VM managed by dstack VMM.

launcher-docker-compose.yaml — Docker Compose file used to start the launcher and supporting containers.
config.txt — File containing trusted environment variables used by the launcher and MPC node.
It should be uploaded to: /tapp/.host-shared/.user-config

## 🧩 Environment Variables

- `DOCKER_CONTENT_TRUST=1`: Must be enabled
- `DEFAULT_IMAGE_DIGEST`: The expected hash of the Docker image (e.g., `sha256:...`)

## 📁 File Locations

- `/tapp/.host-shared/.user-config`: Optional `.env` file for overriding defaults
- `/mnt/shared/image-digest`: Optional override of image digest (written by external components)
- `/var/run/dstack.sock`: Unix socket used to communicate with `dstack`

## 🔧 Configuration (via user-config)

The launcher supports the following environment variables via `/tapp/.host-shared/.user-config`:

LAUNCHER_IMAGE_NAME=nearone/mpc-node-gcp
LAUNCHER_IMAGE_TAGS=latest
LAUNCHER_REGISTRY=registry.hub.docker.com


## Reproducible builds
from: tee_launcher folder run:
docker build -t barakeinavnear/launcher:latest -f development/Dockerfile.launcher .

- [Makefile](Makefile): use this to build the mpc binary in a reproducible manner
- [deployment/Dockerfile-gcp](deployment/Dockerfile-gcp) Dockerfile with all dependencies pinned to specific versions, e.g., other Dockerfile via sha256 digests and Linux distribution packages via explicit version strings
- [deployment/build-image.sh](deployment/build-image.sh) drives the build process

For example, I ran `deployment/build-image.sh` on the git commit [ef3f1e7...](https://github.com/Near-One/mpc/commit/ef3f1e7f862d447de60e91d32dadf68696eb6a58). The resulting Docker image digest was

```
sha256:dcbd3b8c8ae35d2ba63b25d6b617ce8b7faabb0af96ffa2e35b08a50258ebfa4
```

and the MPC binary digest was

```
5dd1a80f842d08753184334466e97d55e5caa3dbcd93af27097d11e926d7f823
```

The respective commands to find either are

```
docker image inspect mpc-node-gcp:latest | jq '.[0].Id'
```

Note, the image digest used with `docker run` is the output of the `docker image inspect ...` command.

```
docker run --rm dcbd3b8c8ae35d2ba63b25d6b617ce8b7faabb0af96ffa2e35b08a50258ebfa4 cat /app/mpc-node | sha256sum
```

Opens: write a script utilizing `vmm-cli.py` from dstack to deploy an mpc node

- Artifacts to deploy a node
  - Scripts to a) reproducibly build the mpc binary and b) reproducibly build a docker image containing the mpc binary
- Actual upgrade procedure
  - Write new image hash to /mnt/shared/image-digest
  - Shut down cvm
  - Amend LAUNCHER_IMAGE_TAGS if necessary; can be done from host by editing ./meta-dstack/build/run/*/shared/.user-config
