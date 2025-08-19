## 🛠 `deploy-launcher.sh` – Dstack VM Deployment Script

This script automates the deployment of a **Dstack Launcher VM** (`launcher_test_app`) using a templated Docker Compose file and the Dstack VMM CLI.

> **Note:** This script must be run **from within the server that hosts the VMs** (i.e., where `dstack-vmm` is running).

It:

- Loads deployment parameters from a `.env` file (defaults to `default.env`)
- Loads Docker Compose file and user\_config files
- Generates an `app-compose.json` configuration
- Deploys the app via `vmm-cli`

---

### 📦 Requirements

- Python virtual environment with [`vmm-cli.py`](https://github.com/Dstack-TEE/dstack/blob/master/vmm/src/vmm-cli.py)
- A working Dstack VMM service (`vmm-server`) accessible at `$VMM_RPC`
- Docker Compose template (`$DOCKER_COMPOSE_FILE_PATH`)
- Deployment configuration in `.env`
- See full CLI documentation here: [vmm-cli-user-guide.md](https://github.com/Dstack-TEE/dstack/blob/master/vmm-cli-user-guide.md)

---

### 📂 Expected Files

Ensure the following files are present in the working directory before running the script:

- `default.env` – default environment configuration
- `$DOCKER_COMPOSE_FILE_PATH` – e.g. `launcher_docker_compose.yaml`
- `$USER_CONFIG_FILE_PATH` – e.g. `user-config.json`

You can also use the example `.env` files under `tee_deployment/configs/`:

- `configs/kms.env`
- `configs/sgx.env`

---

### 🚀 How to Use

1. **Make the script executable** (if not already):

   ```bash
   chmod +x deploy-launcher.sh
   ```

2. **Run the script**, optionally specifying any of the following:

   ```bash
   ./deploy-launcher.sh \
     --env-file tee_deployment/configs/sgx.env \
     --base-path location of \
     --python-exec /custom/project/.venv/bin/python
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

### 🔧 Available Options

| Option                | Description                                                               |
| --------------------- | ------------------------------------------------------------------------- |
| `--env-file`, `-e`    | Path to a `.env` file with deployment parameters (default: `default.env`) |
| `--base-path`, `-b`   | location of where you have dstack installed (a folder above meta-dstack)  |
| `--python-exec`, `-p` | Path to the Python executable to use (default: under base path)           |

---

### 💡 Examples

```bash
# Use KMS config from configs directory
./deploy-launcher.sh --env-file tee_deployment/configs/kms.env

# Use SGX config
./deploy-launcher.sh --env-file tee_deployment/configs/sgx.env

# Override Python path only
./deploy-launcher.sh --python-exec /home/barak/.venv/bin/python

# Override both base path and Python path
./deploy-launcher.sh \
  --base-path /home/barak/project \
  --python-exec /home/barak/project/.venv/bin/python
```

---

### 📄 `.env` File Format

Make sure to create and fill in a `.env` file. Example (`default.env`):

```env
APP_NAME=launcher_test_app
VMM_RPC=http://127.0.0.1:16000
GUEST_AGENT_ADDR=127.0.0.1:9206
SSH_HOST_PORT=127.0.0.1:9207
MPC_PUBLIC_PORT=0.0.0.0:4444
MPC_VM_PORT=4444
GIT_REV=HEAD
OS_IMAGE=dstack-dev-0.5.0
DOCKER_COMPOSE_FILE_PATH=launcher_docker_compose.yaml
USER_CONFIG_FILE_PATH=user-config.conf
SEALING_KEY_TYPE=SGX  # or 'KMS'

# Resource configuration (defaults shown):
VCPU=8      # do not change since this is measured in the contract
MEMORY=64G  # do not change since this is measured in the contract
DISK=128G   # can change
```

---

Based on: [Original Dstack deploy script](https://github.com/Dstack-TEE/dstack/blob/be9d0476a63e937eda4c13659547a25088393394/kms/dstack-app/deploy-to-vmm.sh)
