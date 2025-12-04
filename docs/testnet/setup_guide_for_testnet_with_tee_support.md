# MPC Testnet with TEE Support


This guide describes how to set up a testnet an MPC cluster using dstack TDX CVMs.
## Prerequisites
 1. 2 TDX-enabled machines
 2. dstack installed aconfigured
 3. MPC repository cloned
 4. NEAR CLI installed.

## High‑Level Steps

1. Create a near account that will be the MPC contract account  
2. Deploy MPC contract  
3. Start two TDX CVMs: Alice (running MPC node **frodo**) and Bob (running MPC node **sam**)  
4. Get account and TLS keys from each node  
5. Initialize the contract with node parameters (keys, accounts, IPs) 
6. Workaround for Port Override Issue  
7. Vote MPC code hash on the contract
8. MPC nodes attestation submittion  
9. Add domain to the contract  
10. Submit a signing request to the MPC cluster  

---


**Note:** These operations assume you start from the MPC root directory and are running on the Alice machine. Otherwise, it will be explicitly noted.



## Step 1: Create MPC Account

Since the faucet gives only **10 NEAR per account** (and the mpc contract storage costs **15 NEAR**),  
we need to create two accounts and then transfer funds between them.

```bash
near account create-account sponsor-by-faucet-service barak_tee_test1.testnet   autogenerate-new-keypair save-to-legacy-keychain network-config testnet create

near account create-account sponsor-by-faucet-service barak_tee_test1_mpc.testnet   autogenerate-new-keypair save-to-legacy-keychain network-config testnet create
```

```bash
export ACCOUNT_ID=barak_tee_test1.testnet
export RECEIVER_ID=barak_tee_test1_mpc.testnet

near tokens $ACCOUNT_ID send-near $RECEIVER_ID '9 NEAR'   network-config testnet sign-with-keychain send
```

After this, **barak_tee_test1_mpc.testnet** has **19 NEAR**, enough to deploy the MPC contract.

---

## Step 2: Deploy MPC Contract

Buid the MPC contract wasm:
```bash
cargo near build non-reproducible-wasm --features abi --manifest-path crates/contract/Cargo.toml --locked
```

Set the path to the built contract:

```bash
export MPC_CONTRACT_PATH="$(pwd)/target/near/mpc_contract/mpc_contract.wasm"
```

Deploy the MPC contract:

```bash
near contract deploy barak_tee_test1_mpc.testnet use-file "$MPC_CONTRACT_PATH" without-init-call   network-config testnet sign-with-keychain send
```

Inspect the deployed contract:

```bash
near contract inspect barak_tee_test1_mpc.testnet network-config testnet now
```

---

## Step 3: Start the CVMs with MPC Nodes

Create two accounts for the two MPC nodes:

```bash
near account create-account sponsor-by-faucet-service barak_tee_test1_frodo.testnet   autogenerate-new-keypair save-to-legacy-keychain network-config testnet create

near account create-account sponsor-by-faucet-service barak_tee_test1_sam.testnet   autogenerate-new-keypair save-to-legacy-keychain network-config testnet create
```

### Update Bootnodes

Run this command to get the current testnet bootnodes:
```bash
curl -X POST https://rpc.testnet.near.org   -H "Content-Type: application/json"   -d '{"jsonrpc": "2.0", "method": "network_info", "params": [], "id": "dontcare"}' |   jq -r '.result.active_peers[] as $p | "\($p.id)@\($p.addr)"' |   paste -sd',' -
```

Update the resulting bootnodes in your `frodo.conf` located at (alice server)`../deployment/testnet/frodo.conf` and `sam.conf` located at (bob server) `../deployment/testnet/sam.conf`.

---

Start the 2 CVMs via ../tee_launcher/deploy-launcher.sh

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


On Alice run:

```bash
./deploy-launcher.sh --env-file ../deployment/testnet/frodo.env   --base-path $BASE_PATH   --python-exec python3
```

On Bob run:

```bash
./deploy-launcher.sh --env-file ../deployment/testnet/sam.env   --base-path $BASE_PATH  --python-exec python3
```


If successful, each command will output an **App ID** and confirm creation of a **CVM instance** (e.g., `Created VM with ID: …`).  
Your MPC nodes are now running inside TDX-backed CVMs and ready to participate in the network.


## Step 4: Get Account & TLS Keys from each MPC node

Define 2 environment variables for the two server IPs:

```bash
export SERVER_IP_1=${YOUR_ALICE_SERVER_IP} // e.g., 57.129.140.254
export SERVER_IP_2=${YOUR_BOB_SERVER_IP}   // e.g., 91.134.92.20
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


Add each account and responder keys to its corresponding NEAR account:

```bash
near account add-key barak_tee_test1_frodo.testnet grant-full-access   use-manually-provided-public-key "$FRODO_PUBKEY"   network-config testnet sign-with-keychain send

near account add-key barak_tee_test1_frodo.testnet grant-full-access   use-manually-provided-public-key "$FRODO_RESPONDER_KEY"   network-config testnet sign-with-keychain send
```

```bash
near account add-key barak_tee_test1_sam.testnet grant-full-access   use-manually-provided-public-key "$SAM_PUBKEY"   network-config testnet sign-with-keychain send

near account add-key barak_tee_test1_sam.testnet grant-full-access   use-manually-provided-public-key "$SAM_RESPONDER_KEY"   network-config testnet sign-with-keychain send
```

---

## Step 5: Initialize Contract with Node Parameters

Move to MPC root folder:

```bash
cd ..
```

Initialize the MPC contract with the two participants (using the `P2P_KEY` values retrieved earlier).

Prepare the arguments for the init call:

```bash
mkdir -p "/tmp/$USER"
envsubst < docs/testnet/args/init_testnet_tee.json > "/tmp/$USER/init_args.json"
```

note: make sure that the generated file `/tmp/$USER/init_args.json` has the correct IPs,keys, accounts before proceeding

Example format:

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

Now call the `init` function on the contract:

```bash
near contract call-function as-transaction barak_tee_test1_mpc.testnet init file-args /tmp/$USER/init_args.json prepaid-gas '300.0 Tgas' attached-deposit '0 NEAR' sign-as barak_tee_test1_mpc.testnet network-config testnet sign-with-keychain send
```

Verify that initialization succeeded:

```bash
near contract call-function as-read-only barak_tee_test1_mpc.testnet state   json-args '{}' network-config testnet now
```

---

## Step 6: Workaround for Port Override Issue

Default `port_override = 80`.  
Dstack CVMs had issues forwarding port 80, so I manually updated the config:

do the following on both Alice and Bob machines:

SSH into each CVM 

```
ssh root@localhost -p <CVM-SSH-port> // 1220 alice. 1221 bob
```

inside the CVM:
stop the mpc-node container:
```bash
docker stop mpc-node
```

then, replace port 80 with 2080 in both config files:

```bash
sed -i 's/port_override: 80/port_override: 2080/'   /var/lib/docker/volumes/mpc-data/_data/config.yaml

sed -i 's/port_override: 80/port_override: 2080/'   /var/lib/docker/volumes/mpc-data/_data/config.json
```

start the mpc-node container again:

```bash
docker start mpc-node   
```

---

## Step 7: Vote MPC Hash on Contract

```bash
export CODE_HASH=<hash used to start the nodes>
```


### Frodo votes:

```bash
near contract call-function as-transaction barak_tee_test1_mpc.testnet vote_code_hash   json-args "{"code_hash": "$CODE_HASH"}"   prepaid-gas '100.0 Tgas' attached-deposit '0 NEAR'   sign-as barak_tee_test1_frodo.testnet network-config testnet   sign-with-keychain send
```

### Sam votes:

```bash
near contract call-function as-transaction barak_tee_test1_mpc.testnet vote_code_hash   json-args "{"code_hash": "$CODE_HASH"}"   prepaid-gas '100.0 Tgas' attached-deposit '0 NEAR'   sign-as barak_tee_test1_sam.testnet network-config testnet   sign-with-keychain send
```


Check that the hash was added:

```bash
near contract call-function as-transaction barak_tee_test1_mpc.testnet   allowed_docker_image_hashes json-args '{}'   prepaid-gas '300.0 Tgas' attached-deposit '0 NEAR'   sign-as barak_tee_test1_sam.testnet network-config testnet   sign-with-keychain send
```

---

## Step 8: Check Attestation Submission

```bash
near contract call-function as-transaction barak_tee_test1.testnet get_tee_accounts   json-args '{}' prepaid-gas '300 Tgas' attached-deposit '0 NEAR'   sign-as barak_tee_test1_sam.testnet network-config testnet   sign-with-keychain send
```

*Note:* If the attestation public key is **null**, the contract is using the default mock attestation.

*Note:* After attestation succeeds, both nodes spam logs aggressively (bug to fix).

---

## Step 9: Add Domain to Contract

```bash
near contract call-function as-transaction barak_tee_test1_mpc.testnet vote_add_domains   file-args docs/localnet/args/add_domain.json   prepaid-gas '300.0 Tgas' attached-deposit '0 NEAR'   sign-as barak_tee_test1_frodo.testnet network-config testnet sign-with-keychain send

near contract call-function as-transaction barak_tee_test1_mpc.testnet vote_add_domains   file-args docs/localnet/args/add_domain.json   prepaid-gas '300.0 Tgas' attached-deposit '0 NEAR'   sign-as barak_tee_test1_sam.testnet network-config testnet sign-with-keychain send
```

Check the contract status:

```bash
near contract call-function as-read-only barak_tee_test1_mpc.testnet state   json-args '{}' network-config testnet now
```

If the contract is stuck in **Initializing**, this usally means that MPC nodes failed to connect.

---

## Step 10: Submit Signing Request

```bash
near contract call-function as-transaction barak_tee_test1_mpc.testnet sign   file-args docs/localnet/args/sign.json   prepaid-gas '300.0 Tgas' attached-deposit '100 yoctoNEAR'   sign-as barak_tee_test1_frodo.testnet network-config testnet   sign-with-keychain send
```



