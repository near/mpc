# Setting Up a Local MPC Network Using CVMs

This guide explains how to create and test a **Multi-Party Computation (MPC)** network on a local blockchain (localnet), where each MPC node runs inside a **Confidential Virtual Machine (CVM)**.

It builds upon the [Localnet Setup Guide](https://github.com/near/mpc/blob/main/docs/localnet/localnet.md), which describes how to launch a local blockchain network.  
However, instead of running MPC nodes as local binaries, this setup runs each MPC node inside a CVM, where the MPC node itself runs as a Docker container.

For details on how to set up a TDX-based Confidential VM and prepare the DStack environment, refer to the [Running an MPC Node in TDX External Guide](https://github.com/near/mpc/blob/main/docs/running_an_mpc_node_in_tdx_external_guide.md).

---

## High-Level Steps

1. Prepare a TDX-enabled setup as described in the [TDX Guide](https://github.com/near/mpc/blob/main/docs/running_an_mpc_node_in_tdx_external_guide.md).  
2. Prepare the localnet setup as described in the [Localnet Setup Guide](https://github.com/near/mpc/blob/main/docs/localnet/localnet.md), excluding the startup of the MPC nodes.  
3. Start two MPC nodes that will run inside CVMs.  
4. Extract the public keys from the nodes and add them to the contract and user accounts.  
5. Vote for a new MPC Docker image hash on the contract.  
6. Vote to add a domain to the contract.  
7. Send a `sign` command to the network.

---
## Step 1: Prepare a TDX-enabled setup 
Follow the [TDX Guide](https://github.com/near/mpc/blob/main/docs/running_an_mpc_node_in_tdx_external_guide.md). Up until (but not including **MPC Node Setup and Deployment**
)

Note - You can use the instructions in **MPC Node Setup and Deployment** section - as guidelines on how to configure and manage an MPC node in a CVMs (but the actual configuration values will differ)

## Step 2: Spin Up the Localnet

Follow the [Localnet Setup Guide](https://github.com/near/mpc/blob/main/docs/localnet/localnet.md) up until (but not including) the **“Start MPC nodes”** section.

---

## Step 3: Deploy MPC Nodes

Before proceeding, save the validator key from the network configuration
as a `VALIDATOR_KEY` environment variable.
We will need it in the next step.

```shell
export VALIDATOR_KEY=$(cat ~/.near/mpc-localnet/validator_key.json | jq ".secret_key" | grep -Eo "ed25519:\w+")
```


Create two accounts for the MPC nodes (we’ll call them **Frodo** and **Sam**):


```bash
near account create-account fund-myself frodo.test.near '100 NEAR' autogenerate-new-keypair save-to-keychain sign-as test.near network-config mpc-localnet sign-with-plaintext-private-key "$VALIDATOR_KEY" send
```

```bash
near account create-account fund-myself sam.test.near '100 NEAR' autogenerate-new-keypair save-to-keychain sign-as test.near network-config mpc-localnet sign-with-plaintext-private-key "$VALIDATOR_KEY" send
```

### Configuration Parameters

Note: The files below define several port numbers.
If any of these ports are already in use on your system, you will need to update them.

The most important ports are the Frodo/Sam TLS ports: 13001 / 13002.
These appear in the following files:
- frodo/sam.conf
- frodo/sam.env
- init_tee.json

If you change these ports, make sure to update them in all of the above files.

There are additional ports defined in frodo/sam.env, but you may change those to any values you prefer.

Those are the recommended configuration settings:
you will need the following files:

* [docker-compose.yml](../../tee_launcher/launcher_docker_compose.yaml)
* [frodo.conf](../../deployment/localnet/tee/frodo.conf) / [sam.conf](../../deployment/localnet/tee/sam.conf) 
* [frodo.env](../../deployment/localnet/tee/frodo.env)/ [sam.env](../../deployment/localnet/tee/sam.env)    - if you use the deployment script



create a temp folder for the config files:
```bash
mkdir -p "/tmp/$USER"
```


Concfiguratoin fields in `docker-compose.yml`

Update to use the correct launcher image: (note - this must match the launcher template defined in the MPC contract)

```yaml
image: nearone/mpc-launcher@sha256:bab4577e61bebcbcbed9fff22dd5fa741ded51465671638873af8a43e8f7373b
```

Update to use the correct MPC node image hash:

```yaml
DEFAULT_IMAGE_DIGEST=sha256:abc
```


Define the machine's external IP once  

```bash
export MACHINE_IP=$(curl -4 -s ifconfig.me)  # or use known IP for the machine
```

#### Environment File (`frodo/sam.conf`, `frodo/sam.env`) )

Update Sam/Frodo.conf fields: 


```env
MPC_IMAGE_TAGS=main_3.0.3
```

The MPC_IMAGE_TAGS should match the MPC node image hash used in the docker-compose file.
e.g:

```shell
$Docker inspect nearone/mpc-node:main_3.0.3 | grep "Id"
"Id": "sha256:abc",
```

---
### Node Startup

You can start the nodes **manually** as described in the Operator Guide, or you can start them using the `deploy-launcher.sh` script as shown below.

Once all paths and configuration files (`*.env` and `*.conf`) are prepared, you can launch each MPC node (Frodo and Sam) using the `deploy-launcher.sh` helper script.

#### 1. Move into the `tee_launcher` Directory

```bash
cd tee_launcher
```

#### 2. Ensure the Script Is Executable

```bash
chmod +x deploy-launcher.sh
```
#### 3. Set your env variables 

Set your `BASE_PATH` to the DStack directory that contains the `vmm` folder.

Example:  
`$BASE_PATH/vmm/src/vmm-cli.py` should exist.

```bash
export BASE_PATH="dstask base path"
```

#### 4. Replace ${MACHINE_IP} inside the config files
```bash
envsubst '${MACHINE_IP}' < deployment/localnet/tee/frodo.conf > "/tmp/$USER/frodo.conf"
```

```bash
envsubst '${MACHINE_IP}' < deployment/localnet/tee/sam.conf > "/tmp/$USER/sam.conf"
```

#### 5. Start the Frodo MPC Node

```bash
./deploy-launcher.sh \
  --env-file ../deployment/localnet/tee/frodo.env \
  --base-path $BASE_PATH \
  --python-exec python
```

#### 5. Start the Sam MPC Node

```bash
./deploy-launcher.sh \
  --env-file ../deployment/localnet/tee/sam.env \
  --base-path $BASE_PATH \
  --python-exec python
```

If successful, each command will output an **App ID** and confirm creation of a **CVM instance** (e.g., `Created VM with ID: …`).  
Your MPC nodes are now running inside TDX-backed CVMs and ready to participate in the network.

## Extracting Keys from MPC Nodes

We must delegate the generated account/responder keys from Sam and Frodo as access keys to their NEAR accounts, allowing them to sign transactions requiring authorization on the contract.

> 📝 *Note:* Responder keys are deprecated and can be removed in future revisions.

```bash
export FRODO_PUBKEY=$(curl -s localhost:18081/public_data | jq -r ".near_signer_public_key")
export SAM_PUBKEY=$(curl -s localhost:18082/public_data | jq -r ".near_signer_public_key")

export FRODO_RESPONDER_KEY=$(curl -s localhost:18081/public_data | jq -r ".near_responder_public_keys[0]")
export SAM_RESPONDER_KEY=$(curl -s localhost:18082/public_data | jq -r ".near_responder_public_keys[0]")
```

```bash
export FRODO_P2P_KEY=$(curl -s localhost:18081/public_data | jq -r '.near_p2p_public_key')
export SAM_P2P_KEY=$(curl -s localhost:18082/public_data | jq -r '.near_p2p_public_key')

export MPC_HOST=$MACHINE_IP
```

### Add the Keys to User Accounts

Now, add these keys to the appropriate NEAR accounts using the NEAR CLI:

```bash
near account add-key frodo.test.near grant-full-access use-manually-provided-public-key "$FRODO_PUBKEY" network-config mpc-localnet sign-with-keychain send
near account add-key frodo.test.near grant-full-access use-manually-provided-public-key "$FRODO_RESPONDER_KEY" network-config mpc-localnet sign-with-keychain send

near account add-key sam.test.near grant-full-access use-manually-provided-public-key "$SAM_PUBKEY" network-config mpc-localnet sign-with-keychain send
near account add-key sam.test.near grant-full-access use-manually-provided-public-key "$SAM_RESPONDER_KEY" network-config mpc-localnet sign-with-keychain send
```

### Initialize the MPC Contract

Move to MPC root folder:

```bash
cd ..
```

Initialize the MPC contract with the two participants (using the `P2P_KEY` values retrieved earlier).

Prepare the arguments for the init call:

```bash
envsubst < docs/localnet/args/init_tee.json > "/tmp/$USER/init_args.json"
```

Now call the `init` function on the contract:

```bash
near contract call-function as-transaction mpc-contract.test.near init file-args /tmp/$USER/init_args.json prepaid-gas '300.0 Tgas' attached-deposit '0 NEAR' sign-as mpc-contract.test.near network-config mpc-localnet sign-with-keychain send
```

Verify that initialization succeeded:

```bash
near contract call-function as-read-only mpc-contract.test.near state json-args {} network-config mpc-localnet now
```

---

## Voting for a New MPC Docker Image Hash

Before voting, the contract’s list of valid MPC image hashes is empty.  
Therefor, node attestation submissions will fail.

**Sample Error Log (Expected Before Voting):**

```
mpc_node::indexer::tx_sender: sending tx 381yxJCV5ByYo27oD8fX3BsGwnFpfGSzNCgDpfQtwWoy
..
..
ERROR mpc_node::tee::remote_attestation: failed to submit attestation cause=attestation submission was not executed
```

You can view the trasaction details by calling:

```bash
near transaction view-status <transaction_Id> network-config mpc-localnet
```

```
(ExecutionError("Smart contract panicked: Invalid TEE Remote Attestation.: TeeQuoteStatus is invalid: the allowed mpc image hashes list is empty"
```

### Vote Commands


Set **CODE_HASH** to value you want to vote for.
for example:
```bash
export CODE_HASH=7c0ee6d08f253f7f890883ce4d64c387aab0d1a192a8a827f7db8cdf55a6a3b8
```

Note: this hash should be the same as the one used in the  **launcher_docker_compose.yaml**

```text
DEFAULT_IMAGE_DIGEST=sha256:7c0ee6d08f253f7f890883ce4d64c387aab0d1a192a8a827f7db8cdf55a6a3b8
```

```bash

# Sam votes
near contract call-function as-transaction mpc-contract.test.near vote_code_hash \
  json-args "{\"code_hash\": \"$CODE_HASH\"}" \
  prepaid-gas '100.0 Tgas' attached-deposit '0 NEAR' \
  sign-as sam.test.near network-config mpc-localnet sign-with-keychain send

# Frodo votes
near contract call-function as-transaction mpc-contract.test.near vote_code_hash \
  json-args "{\"code_hash\": \"$CODE_HASH\"}" \
  prepaid-gas '100.0 Tgas' attached-deposit '0 NEAR' \
  sign-as frodo.test.near network-config mpc-localnet sign-with-keychain send
```

Verify the contract state:

```bash
near contract call-function as-read-only mpc-contract.test.near state json-args {} network-config mpc-localnet now
```

Or view the allowed code hashes

```bash
near contract call-function as-transaction mpc-contract.test.near allowed_docker_image_hashes json-args {} prepaid-gas '300.0 Tgas' attached-deposit '0 NEAR' sign-as sam.test.near network-config mpc-localnet sign-with-keychain send
```

### Check That Valid Attestations Are Registered

```bash
near contract call-function as-transaction \
  mpc-contract.test.near \
  get_tee_accounts \
  json-args '{}' \
  prepaid-gas '300 Tgas' \
  attached-deposit '0 NEAR' \
  sign-as sam.test.near \
  network-config mpc-localnet \
  sign-with-keychain send
```

You should see both nodes with valid attestations containing a `tls_public_key` and an `account_public_key`.

> **Note:** If the `account_public_key` is `null`, this means the attestation recorded on the contract is the mock attestation, and the real attestation verification failed.


---

## Add a Domain

Now the contract should be initialized and both nodes should be running.  
To verify that the network is functional, request a signature from it.  
Before that, add a domain.

Both Frodo and Sam should vote to add a **Secp256k1** domain:

```bash
near contract call-function as-transaction mpc-contract.test.near vote_add_domains file-args docs/localnet/args/add_domain.json prepaid-gas '300.0 Tgas' attached-deposit '0 NEAR' sign-as frodo.test.near network-config mpc-localnet sign-with-keychain send

near contract call-function as-transaction mpc-contract.test.near vote_add_domains file-args docs/localnet/args/add_domain.json prepaid-gas '300.0 Tgas' attached-deposit '0 NEAR' sign-as sam.test.near network-config mpc-localnet sign-with-keychain send
```

Check the contract state again. The status should transition from **Running** → **Initializing** → **Running** after DKG completion.

```bash
near contract call-function as-read-only mpc-contract.test.near state json-args {} network-config mpc-localnet now
```

In the MPC node's logs you should see something like this:

```bash
2025-11-16T07:42:09.728557971Z 2025-11-16T07:42:09.728318Z  INFO mpc_node::p2p: Outgoing 1 --> 0 connected
2025-11-16T07:42:09.855900011Z 2025-11-16T07:42:09.855671Z  INFO mpc_node::p2p: Incoming 1 <-- 0 connected
```

> 📝 *Note:* If the contract remains stuck in the *Initializing* state, your nodes may be unable to connect to each other.


---

## Sending a Sign Command to the MPC Network

```bash
near contract call-function as-transaction mpc-contract.test.near sign \
  file-args docs/localnet/args/sign.json \
  prepaid-gas '300.0 Tgas' attached-deposit '100 yoctoNEAR' \
  sign-as frodo.test.near network-config mpc-localnet sign-with-keychain send
```

**Expected Output:**

```
 INFO Function execution return value (printed to stdout):
{
  "big_r": {
    "affine_point": "0266959C2F1A155D38FAB0B15A7E6FAD8DDEB857594FB2F1DFEF323E395949F8E2"
  },
  "recovery_id": 0,
  "s": {
    "scalar": "6C38CCEF118EA86F3A5DB5CC8703E9A2B5289FCD564D3224DC61E374B58ABB8C"
  },
  "scheme": "Secp256k1"
}
 INFO

 |    The "sign" call to <mpc-contract.test.near> on behalf of <frodo.test.near> succeeded.
```


---

## Troubleshooting

You can view trascation using:
```bash
near transaction view-status <transaction_Id>  network-config mpc-localnet
```


### NearD Dashboard

When running a localnet, you can use the **NearD debug dashboard** to inspect the state of the chain and monitor your MPC nodes.

#### Example

In the example below (running on a machine with external IP **57.129.140.254**), the dashboard displays two MPC nodes — one fully synced and the other still catching up:

**Dashboard URL:**
```
http://debug.nearone.org/57.129.140.254:3030/network_info/current
```

**Screenshot:**

![NearD Dashboard](./attachments/dashboard.png)

