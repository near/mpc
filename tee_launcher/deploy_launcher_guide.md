# 🛠 `deploy-launcher.sh` – Dstack VM Deployment Script

This script automates the deployment of a **Dstack Launcher VM** (`launcher_test_app`) using a templated Docker Compose file and the Dstack VMM CLI.

> **Note:** This script must be run **from within the server that hosts the VMs** (i.e., where `dstack-vmm` is running).

It:

- Loads deployment parameters from a `.env` file (defaults to `default.env`)
- Loads Docker Compose file and user\_config files
- Generates an `app-compose.json` configuration
- Deploys and starts CVM  via `vmm-cli`

---

## 📦 Requirements

- A working Dstack setup and Dstack VMM service (`vmm-server`) accessible at `$VMM_RPC`.
See Phala's [setup guide](https://github.com/Dstack-TEE/dstack).
Also review specific MPC configuration in [running_an_mpc_node_in_tdx_external_guide.md](https://github.com/near/mpc/blob/main/docs/running_an_mpc_node_in_tdx_external_guide.md#mpc-node-setup-and-deployment)
- Python 3.6 or higher installed
- Required Python packages (cryptography, eth_keys, eth_utils)
- `vmm-cli.py` should be located under $basePath/vmm/src/vmm-cli.py
- Docker Compose template (`$DOCKER_COMPOSE_FILE_PATH`)
- Deployment configuration in `*.env` file
- user-config.conf file
- See full CLI documentation here: [vmm-cli-user-guide.md](https://github.com/Dstack-TEE/dstack/blob/master/docs/vmm-cli-user-guide.md)

---

## 📂 Expected Files

Ensure the following files are present in the working directory before running the script:

- `default.env` – default environment configuration
- `$DOCKER_COMPOSE_FILE_PATH` – e.g. `launcher_docker_compose.yaml`
- `$USER_CONFIG_FILE_PATH` – e.g. `user-config.conf`

You can also use the example `.env` files under `tee_deployment/configs/`:

- `configs/kms.env`
- `configs/sgx.env`

---

## 🚀 How to Use

1. **Make the script executable** (if not already):

   ```bash
   chmod +x deploy-launcher.sh
   ```

2. **Run the script**, optionally specifying any of the following:

   ```bash
   ./deploy-launcher.sh \
     --env-file tee_deployment/configs/sgx.env \
     --base-path /project \
     --python-exec /project/.venv/bin/python
   ```

   Or use just the `.env` override:

   ```bash
   ./deploy-launcher.sh --env-file tee_deployment/configs/sgx.env
   ```

   Or use all defaults (`default.env`, default paths):

   ```bash
   ./deploy-launcher.sh
   ```

3. **Follow the prompt** to confirm deployment.

---

## 🔧 Available Options

| Option                | Description                                                               |
| --------------------- | ------------------------------------------------------------------------- |
| `--env-file`, `-e`    | Path to a `.env` file with deployment parameters (default: `default.env`) |
| `--base-path`, `-b`   | Path to the parent directory containing the vmm folder . For example, if your Dstack installation is in /project/meta-dstack/dstack/vmm, then you should set --base-path /project/meta-dstack/dstack/  |
| `--python-exec`, `-p` | Path to the Python executable to use (default: under base path)           |

---

## 💡 Examples

```bash
# Use KMS config from configs directory
./deploy-launcher.sh --env-file tee_deployment/configs/kms.env

# Use SGX config
./deploy-launcher.sh --env-file tee_deployment/configs/sgx.env

# Override Python path only
./deploy-launcher.sh --python-exec python3

# Override both base path (folder above meta-dstack) and Python path
./deploy-launcher.sh \
  --base-path /home/barak/project \
  --python-exec python3
```

---

## 📄 `.env` File Format

Make sure to create and fill in a `.env` file. Example (`default.env`):

```env
APP_NAME=launcher_test_app
VMM_RPC=http://127.0.0.1:16000

# Sealing key type (KMS for deployment, SGX for production)
SEALING_KEY_TYPE=KMS

# Port on the host machine to connect to the dstack guest agent
EXTERNAL_DSTACK_AGENT_PORT=127.0.0.1:9206

# SSH port on the host
EXTERNAL_SSH_PORT=127.0.0.1:9207

# External MPC ports (host machine)
EXTERNAL_MPC_PUBLIC_DEBUG_PORT=0.0.0.0:8080
EXTERNAL_MPC_LOCAL_DEBUG_PORT=127.0.0.1:3030
EXTERNAL_MPC_DECENTRALIZED_STATE_SYNC=0.0.0.0:24567
EXTERNAL_MPC_MAIN_PORT=0.0.0.0:80

# Internal MPC ports (inside CVM)
INTERNAL_MPC_PUBLIC_DEBUG_PORT=8080
INTERNAL_MPC_LOCAL_DEBUG_PORT=3030
INTERNAL_MPC_DECENTRALIZED_STATE_SYNC=24567
INTERNAL_MPC_MAIN_PORT=80

# OS image
OS_IMAGE=dstack-dev-0.5.2

# Path of the launcher docker_compose_file
DOCKER_COMPOSE_FILE_PATH=launcher_docker_compose.yaml
# Path of the user_config file
USER_CONFIG_FILE_PATH=user-config.conf

# Resource configuration (defaults shown):
VCPU=8      # do not change since this is measured in the contract
MEMORY=64G  # do not change since this is measured in the contract
DISK=128G   # can change
```

---

Based on: [Original Dstack deploy script](https://github.com/Dstack-TEE/dstack/blob/be9d0476a63e937eda4c13659547a25088393394/kms/dstack-app/deploy-to-vmm.sh)
