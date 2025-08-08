## 🛠 `deploy-launcher.sh` – DStack VM Deployment Script

This script automates the deployment of a **DStack Launcher VM** (`launcher_test_app`) using a templated Docker Compose file and the DStack VMM CLI.

> **Note:** This script must be run **from within the server that hosts the VMs** (i.e., where `dstack-vmm` is running).

It:

- Loads deployment parameters from a `.env` file
- Validates required environment variables
- Substitutes variables into a temporary Docker Compose file
- Generates an `app-compose.json` configuration
- Deploys the app via `vmm-cli`
- Allows selection of sealing key type (`KMS` or `SGX`) via the `SEALING_KEY_TYPE` environment variable

---

### 📦 Requirements

- Python virtual environment with [`vmm-cli.py`](https://github.com/Dstack-TEE/dstack/blob/master/vmm/src/vmm-cli.py)
- A working DStack VMM service (`vmm-server`) accessible at `$VMM_RPC`
- Docker Compose template (`$DOCKER_COMPOSE_FILE_PATH`)
- Deployment configuration in `.env`
- See full CLI documentation here: [vmm-cli-user-guide.md](https://github.com/Dstack-TEE/dstack/blob/master/docs/vmm-cli-user-guide.md)

---

### 📂 Expected Files

Ensure the following files are present in the working directory before running the script:

- `.env` – contains deployment configuration
- `$DOCKER_COMPOSE_FILE_PATH` – e.g. `launcher_docker_compose.yaml`
- `$USER_CONFIG_FILE_PATH` – e.g. `user-config.conf`

---

### 🚀 How to Use

1. **Make the script executable** (if not already):

   ```bash
   chmod +x deploy-launcher.sh
   ```

2. **Run the script**, optionally specifying a custom `.env` file:

   ```bash
   ./deploy-launcher.sh --env-file path/to/your.env
   ```

   Or use the default `.env` file in the current directory:

   ```bash
   ./deploy-launcher.sh
   ```

3. **Follow the prompt** to confirm deployment.

4. The sealing key provider is selected based on the `SEALING_KEY_TYPE` environment variable in the `.env` file. Valid values:

   - `SGX` → uses `--local-key-provider`
   - `KMS` → uses `--kms`

---

### 💡 Examples

```bash
./deploy-launcher.sh --env-file ./env_kms
./deploy-launcher.sh --env-file ./env_sgx
```

---

### 📄 `.env` File Format

Make sure to create and fill in a `.env` file in the same directory as the script. Example:

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
```

---

Based on: [Original DStack deploy script](https://github.com/Dstack-TEE/dstack/blob/be9d0476a63e937eda4c13659547a25088393394/kms/dstack-app/deploy-to-vmm.sh)

