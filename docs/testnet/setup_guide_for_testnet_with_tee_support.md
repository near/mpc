# MPC Testnet with TEE Support

This guide describes how to set up a testnet MPC cluster using dstack TDX CVMs.

## Prerequisites
1. Two TDX-enabled machines  
2. dstack installed and configured  
3. MPC repository cloned  
4. NEAR CLI installed  

## High-Level Steps

1. Create a NEAR account that will host the MPC contract.  
2. Deploy the MPC contract.  
3. Start two TDX CVMs: Alice (running MPC node **frodo**) and Bob (running MPC node **sam**).  
4. Get account and TLS keys from each node.  
5. Initialize the contract with node parameters (keys, accounts, IPs).  
6. Workaround for port override issue.  
7. Vote for MPC code hash on the contract.  
8. MPC nodes attestation submission.  
9. Add a domain to the contract.  
10. Submit a signing request to the MPC cluster.  

---

**Note:** These operations assume you start from the MPC root directory and are running on the Alice machine. Otherwise, it will be explicitly noted.

---

## Step 1: Create MPC Account


First, set a unique network name for the MPC cluster:

```bash
# Pick a globally unique name within the team.
# Include your username to avoid collisions.
export MPC_NETWORK_NAME=yourusername-test
```

Define the NEAR accounts to be used:
```bash
export ROOT_ACCOUNT=${MPC_NETWORK_NAME}.testnet
export MPC_CONTRACT_ACCOUNT=${MPC_NETWORK_NAME}_mpc.testnet
export FRODO_ACCOUNT=${MPC_NETWORK_NAME}_frodo.testnet
export SAM_ACCOUNT=${MPC_NETWORK_NAME}_sam.testnet
```


Since the faucet gives only **10 NEAR per account** (and the MPC contract storage costs **15 NEAR**),  
we need to create two accounts and then transfer funds between them.

```bash
near account create-account sponsor-by-faucet-service $ROOT_ACCOUNT \
  autogenerate-new-keypair save-to-legacy-keychain network-config testnet create


near account create-account sponsor-by-faucet-service $MPC_CONTRACT_ACCOUNT \
  autogenerate-new-keypair save-to-legacy-keychain network-config testnet create

```

```bash
export ACCOUNT_ID=$ROOT_ACCOUNT
export RECEIVER_ID=$MPC_CONTRACT_ACCOUNT

near tokens $ACCOUNT_ID send-near $RECEIVER_ID '9 NEAR' network-config testnet sign-with-keychain send
```

After this, **$MPC_CONTRACT_ACCOUNT ** has **19 NEAR**, enough to deploy the MPC contract.

---

## Step 2: Deploy MPC Contract

Build the MPC contract wasm:

```bash
cargo near build non-reproducible-wasm --features abi --manifest-path crates/contract/Cargo.toml --locked
```

Set the path to the built contract:

```bash
export MPC_CONTRACT_PATH="$(pwd)/target/near/mpc_contract/mpc_contract.wasm"
```

Deploy the MPC contract:

```bash
near contract deploy $MPC_CONTRACT_ACCOUNT use-file "$MPC_CONTRACT_PATH" without-init-call network-config testnet sign-with-keychain send
```

Inspect the deployed contract:

```bash
near contract inspect $MPC_CONTRACT_ACCOUNT network-config testnet now
```

---

## Step 3: Start the CVMs with MPC Nodes

Create two accounts for the MPC nodes:

```bash
near account create-account sponsor-by-faucet-service $FRODO_ACCOUNT autogenerate-new-keypair save-to-legacy-keychain network-config testnet create

near account create-account sponsor-by-faucet-service $SAM_ACCOUNT autogenerate-new-keypair save-to-legacy-keychain network-config testnet create
```

### Update Bootnodes

Run this command to get the current testnet bootnodes:

```bash
curl -X POST https://rpc.testnet.near.org \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "method": "network_info", "params": [], "id": "dontcare"}' |
  jq -r '.result.active_peers[] as $p | "\($p.id)@\($p.addr)"' |
  paste -sd',' -
```

Update the resulting bootnodes in:

- `../deployment/testnet/frodo.conf` (Alice)  
- `../deployment/testnet/sam.conf` (Bob)

---

Start the CVMs via `../tee_launcher/deploy-launcher.sh`.

#### 1. Move into the `tee_launcher` directory

```bash
cd tee_launcher
```

#### 2. Ensure the script is executable

```bash
chmod +x deploy-launcher.sh
```

#### 3. Set environment variables

Set your `BASE_PATH` to the dstack directory that contains the `vmm` folder.

Example: `$BASE_PATH/vmm/src/vmm-cli.py` should exist.

```bash
export BASE_PATH="dstack base path"
```

Start the nodes:

**On Alice:**

```bash
./deploy-launcher.sh --env-file ../deployment/testnet/frodo.env --base-path $BASE_PATH --python-exec python
```

**On Bob:**

```bash
./deploy-launcher.sh --env-file ../deployment/testnet/sam.env --base-path $BASE_PATH --python-exec python
```

If successful, each command outputs an **App ID** and confirms creation of a **CVM instance**.

---

## Step 4: Get Account & TLS Keys from Each MPC Node

Define the two server IPs:

```bash
export SERVER_IP_1=${YOUR_ALICE_SERVER_IP}  # e.g., 57.129.140.254
export SERVER_IP_2=${YOUR_BOB_SERVER_IP}    # e.g., 91.134.92.20
```

Each node exposes its keys via:

- Frodo: `http://$SERVER_IP_1:18081/public_data`  
- Sam: `http://$SERVER_IP_2:18082/public_data`

```bash
export FRODO_PUBKEY=$(curl -s http://$SERVER_IP_1:18081/public_data | jq -r ".near_signer_public_key")
export SAM_PUBKEY=$(curl -s http://$SERVER_IP_2:18082/public_data | jq -r ".near_signer_public_key")

export FRODO_RESPONDER_KEY=$(curl -s http://$SERVER_IP_1:18081/public_data | jq -r ".near_responder_public_keys[0]")
export SAM_RESPONDER_KEY=$(curl -s http://$SERVER_IP_2:18082/public_data | jq -r ".near_responder_public_keys[0]")

export FRODO_P2P_KEY=$(curl -s http://$SERVER_IP_1:18081/public_data | jq -r '.near_p2p_public_key')
export SAM_P2P_KEY=$(curl -s http://$SERVER_IP_2:18082/public_data | jq -r '.near_p2p_public_key')
```

Add keys to each NEAR account:

```bash
near account add-key $FRODO_ACCOUNT grant-full-access \
  use-manually-provided-public-key "$FRODO_PUBKEY" network-config testnet sign-with-keychain send

near account add-key $FRODO_ACCOUNT grant-full-access \
  use-manually-provided-public-key "$FRODO_RESPONDER_KEY" network-config testnet sign-with-keychain send
```

```bash
near account add-key $SAM_ACCOUNT grant-full-access \
  use-manually-provided-public-key "$SAM_PUBKEY" network-config testnet sign-with-keychain send

near account add-key $SAM_ACCOUNT grant-full-access \
  use-manually-provided-public-key "$SAM_RESPONDER_KEY" network-config testnet sign-with-keychain send
```

---

## Step 5: Initialize Contract with Node Parameters

Move to the MPC root folder:

```bash
cd ..
```

Prepare arguments for the init call:

```bash
mkdir -p "/tmp/$USER"
envsubst < docs/testnet/args/init_testnet_tee.json > "/tmp/$USER/init_args.json"
```

**Note:** Ensure `/tmp/$USER/init_args.json` has correct IPs, keys, accounts before proceeding.

Example:

```json
{
  "parameters": {
    "threshold": 2,
    "participants": {
      "next_id": 2,
      "participants": [
        [
          "barak_tee_test1_frodo.testnet",
          0,
          {
            "sign_pk": "ed25519:6CeuXPt6qXtXRHVb5C4USZAyQcg65LXJvebPyCJewaN1",
            "url": "https://91.134.92.20:13001"
          }
        ],
        [
          "barak_tee_test1_sam.testnet",
          1,
          {
            "sign_pk": "ed25519:B2pHHn9Kr2GZhDn85VP3vGUccJK7Haekcmy5JRBScUn3",
            "url": "https://57.129.140.254:13002"
          }
        ]
      ]
    }
  }
}
```

Initialize the contract:

```bash
near contract call-function as-transaction $MPC_CONTRACT_ACCOUNT  init \
  file-args /tmp/$USER/init_args.json prepaid-gas '300.0 Tgas' \
  attached-deposit '0 NEAR' sign-as $MPC_CONTRACT_ACCOUNT \
  network-config testnet sign-with-keychain send
```

Verify:

```bash
near contract call-function as-read-only $MPC_CONTRACT_ACCOUNT  state \
  json-args '{}' network-config testnet now
```

---

## Step 6: Workaround for Port Override Issue

Default `port_override = 80`.  
dstack CVMs had issues forwarding port 80, so update the config on both machines.

SSH into each CVM:

```bash
ssh root@localhost -p <CVM-SSH-port>  # 1220 Alice, 1221 Bob
```

Stop the MPC node container:

```bash
docker stop mpc-node
```

Replace port 80 with 2080:

```bash
sed -i 's/port_override: 80/port_override: 2080/' /var/lib/docker/volumes/mpc-data/_data/config.yaml
sed -i 's/port_override: 80/port_override: 2080/' /var/lib/docker/volumes/mpc-data/_data/config.json
```

Restart the container:

```bash
docker start mpc-node
```

---

## Step 7: Vote MPC Hash on Contract

```bash
export CODE_HASH=<hash used to start the nodes>
```

### Frodo votes

```bash
near contract call-function as-transaction $MPC_CONTRACT_ACCOUNT  vote_code_hash \
  json-args "{\"code_hash\": \"$CODE_HASH\"}" prepaid-gas '100.0 Tgas' \
  attached-deposit '0 NEAR' sign-as $FRODO_ACCOUNT \
  network-config testnet sign-with-keychain send
```

### Sam votes

```bash
near contract call-function as-transaction $MPC_CONTRACT_ACCOUNT  vote_code_hash \
  json-args "{\"code_hash\": \"$CODE_HASH\"}" prepaid-gas '100.0 Tgas' \
  attached-deposit '0 NEAR' sign-as $SAM_ACCOUNT \
  network-config testnet sign-with-keychain send
```

Check the hash:

```bash
near contract call-function as-transaction $MPC_CONTRACT_ACCOUNT  allowed_docker_image_hashes \
  json-args '{}' prepaid-gas '300.0 Tgas' attached-deposit '0 NEAR' \
  sign-as $SAM_ACCOUNT network-config testnet sign-with-keychain send
```

---

## Step 8: Check Attestation Submission

```bash
near contract call-function as-transaction $MPC_CONTRACT_ACCOUNT  get_tee_accounts \
  json-args '{}' prepaid-gas '300 Tgas' attached-deposit '0 NEAR' \
  sign-as $SAM_ACCOUNT network-config testnet sign-with-keychain send
```

*Note:* If attestation public key is **null**, the contract uses the default mock attestation.

*Note:* After attestation succeeds, both nodes spam logs aggressively (bug to fix).

---

## Step 9: Add Domain to Contract

```bash
near contract call-function as-transaction $MPC_CONTRACT_ACCOUNT  vote_add_domains \
  file-args docs/localnet/args/add_domain.json prepaid-gas '300.0 Tgas' \
  attached-deposit '0 NEAR' sign-as $FRODO_ACCOUNT network-config testnet sign-with-keychain send

near contract call-function as-transaction $MPC_CONTRACT_ACCOUNT  vote_add_domains \
  file-args docs/localnet/args/add_domain.json prepaid-gas '300.0 Tgas' \
  attached-deposit '0 NEAR' sign-as $SAM_ACCOUNT network-config testnet sign-with-keychain send
```

Check status:

```bash
near contract call-function as-read-only $MPC_CONTRACT_ACCOUNT  state \
  json-args '{}' network-config testnet now
```

If the contract is stuck in **Initializing**, this usually means the MPC nodes failed to connect.

---

## Step 10: Submit Signing Request

```bash
near contract call-function as-transaction $MPC_CONTRACT_ACCOUNT  sign \
  file-args docs/localnet/args/sign.json prepaid-gas '300.0 Tgas' \
  attached-deposit '100 yoctoNEAR' sign-as $FRODO_ACCOUNT \
  network-config testnet sign-with-keychain send
```
