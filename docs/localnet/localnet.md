# Localnet - instructions for how to run a local MPC network

## Prerequisites

neard, near CLI, cargo, ripgrep, envsubst, python3-keyring

## Install neard and MPC node binary

### Note about `neard`.

If you skip the installation below, make sure that your `neard` version is compatible with the `near` version with the `near-indexer` version
that is used by the MPC binary defined in the workspace cargo file, `/Cargo.toml`.

```shell
neard --version
```

You should install `neard` from the git submodule:

```shell
git submodule foreach --recursive git reset --hard
git submodule foreach --recursive git clean -fdx
git submodule update --init --recursive --force
```

```shell
cargo install --path libs/nearcore/neard
```

```shell
cargo install --path crates/node
```

## Compile the signer contract
Build the contract from the repository root with:

```shell
cargo near build non-reproducible-wasm --features abi --manifest-path crates/contract/Cargo.toml
```

Now you should have a `mpc_contract.wasm` artifact ready in the target directory.
Let's add an env variable for it. From the workspace root, run the following:

```shell
export MPC_CONTRACT_PATH=$(pwd)/target/near/mpc_contract/mpc_contract.wasm
```

## 1. Run a local NEAR network

To run a local NEAR network, first create the configuration with the following command.

```shell
neard --home ~/.near/mpc-localnet init --chain-id mpc-localnet
```

This will set up the configuration in the `~/.near/mpc-localnet` directory.

Next, start a single validator node for this network with this command.

```shell
NEAR_ENV=mpc-localnet neard --home ~/.near/mpc-localnet run
```

Congratulations, you are now running a local NEAR network.
To see the network status, call

```shell
curl localhost:3030/status | jq
```

Before proceeding, save the validator key from the network configuration
as a `VALIDATOR_KEY` environment variable.
We will need it in the next step.

```shell
export VALIDATOR_KEY=$(cat ~/.near/mpc-localnet/validator_key.json | rg secret_key | rg -o "ed25519:\w+")
```

## 2. Deploy the MPC contract to the network
Now we can deploy the MPC contract with the NEAR CLI.
First, add the mpc-localnet as a network connection in the CLI.

To view existing connections and the location of your CLI config file use;

```shell
near config show-connections
```

In the CLI config file, add the following.

```toml
[network_connection.mpc-localnet]
network_name = "mpc-localnet"
rpc_url = "http://localhost:3030/"
wallet_url = "http://localhost:3030/"
explorer_transaction_url = "http://localhost:3030/"
linkdrop_account_id = "test.near"
```

Now, create an account for the contract with the following command.

```shell
near account create-account fund-myself mpc-contract.test.near '1000 NEAR' autogenerate-new-keypair save-to-keychain sign-as test.near network-config mpc-localnet sign-with-plaintext-private-key $VALIDATOR_KEY send
```

We can verify that the account exists and has 10 NEAR with this command.

```shell
near account view-account-summary mpc-contract.test.near network-config mpc-localnet now
```

Now it's time to deploy the contract.

Now we can deploy the contract with this command.

```shell
near contract deploy mpc-contract.test.near use-file $MPC_CONTRACT_PATH without-init-call network-config mpc-localnet sign-with-keychain send
```

When the contract has been deployed you should be able to see its functions through the CLI.

```shell
near contract inspect mpc-contract.test.near network-config mpc-localnet now
```

Now when the contract has been deployed, the next step is to initialize it.

## 3. Start MPC nodes
In this guide we'll run two MPC nodes. We'll call the nodes "Frodo" and "Sam", and name their accounts accordingly.
Before we're ready to initialize the nodes, we should create the accounts.

```shell
near account create-account fund-myself frodo.test.near '100 NEAR' autogenerate-new-keypair save-to-keychain sign-as test.near network-config mpc-localnet sign-with-plaintext-private-key $VALIDATOR_KEY send
```

```shell
near account create-account fund-myself sam.test.near '100 NEAR' autogenerate-new-keypair save-to-keychain sign-as test.near network-config mpc-localnet sign-with-plaintext-private-key $VALIDATOR_KEY send
```

Next, we need to know the public key of our NEAR validator.

```shell
export NODE_PUBKEY=$(cat ~/.near/mpc-localnet/node_key.json | jq ".public_key" | rg -o "ed25519:\w+")
```

Now we're ready to initialize the nodes.

### Initialize Frodo's node
This commands creates a directory with some initial config for Frodo's node.

```shell
mpc-node init --dir ~/.near/mpc-frodo --chain-id mpc-localnet --genesis ~/.near/mpc-localnet/genesis.json --boot-nodes $NODE_PUBKEY@localhost:3030 --download-config-url https://s3-us-west-1.amazonaws.com/build.nearprotocol.com/nearcore-deploy/testnet/rpc/config.json
```

TODO([#714](https://github.com/near/mpc/issues/714)): Don't download any config.

However, currently the command creates an invalid genesis file.
We need to copy the genesis file from `mpc-localnet`.

```shell
cp ~/.near/mpc-localnet/genesis.json ~/.near/mpc-frodo/genesis.json
```

Now we must update Frodo's to point to correct port for boot nodes as it's currently pointing to localnet's RPC port.
Make sure the `RPC_PORT` and `INDEXER_PORT` is free. The value of these ports are arbitrary, and can be any other port.

```shell
RPC_PORT=3031 BOOT_NODE_PORT=24567 INDEXER_PORT=24568 jq '.network.addr = "0.0.0.0:" + env.INDEXER_PORT | .network.boot_nodes = (.network.boot_nodes | sub("localhost:[0-9]+"; "0.0.0.0:" + env.BOOT_NODE_PORT)) | .rpc.addr = "0.0.0.0:" + env.RPC_PORT' ~/.near/mpc-frodo/config.json > ~/.near/mpc-frodo/temp.json && mv ~/.near/mpc-frodo/temp.json ~/.near/mpc-frodo/config.json
```

Now we must update Frodo's `validator_key.json` to match the `account_id` field to the right account.

```shell
jq '.account_id = "frodo.test.near"' ~/.near/mpc-frodo/validator_key.json > ~/.near/mpc-frodo/temp.json && mv ~/.near/mpc-frodo/temp.json ~/.near/mpc-frodo/validator_key.json
```

Next we'll create a `config.yaml` for the MPC-indexer:

```shell
cat > ~/.near/mpc-frodo/config.yaml << 'EOF'
my_near_account_id: frodo.test.near
near_responder_account_id: frodo.test.near
number_of_responder_keys: 1
web_ui:
  host: localhost
  port: 8081
triple:
  concurrency: 2
  desired_triples_to_buffer: 128
  timeout_sec: 60
  parallel_triple_generation_stagger_time_sec: 1
presignature:
  concurrency: 4
  desired_presignatures_to_buffer: 64
  timeout_sec: 60
signature:
  timeout_sec: 60
indexer:
  validate_genesis: false
  sync_mode: Latest
  concurrency: 1
  mpc_contract_id: mpc-contract.test.near
  finality: optimistic
ckd:
  timeout_sec: 60
cores: 4
EOF
```

### Initialize Sam's node
Now we can do the same steps for Sam.

```shell
mpc-node init --dir ~/.near/mpc-sam --chain-id mpc-localnet --genesis ~/.near/mpc-localnet/genesis.json --boot-nodes $NODE_PUBKEY@localhost:3030 --download-config-url https://s3-us-west-1.amazonaws.com/build.nearprotocol.com/nearcore-deploy/testnet/rpc/config.json
```

```shell
cp ~/.near/mpc-localnet/genesis.json ~/.near/mpc-sam/genesis.json
```

```shell
RPC_PORT=3032 BOOT_NODE_PORT=24567 INDEXER_PORT=24569 jq '.network.addr = "0.0.0.0:" + env.INDEXER_PORT | .network.boot_nodes = (.network.boot_nodes | sub("localhost:[0-9]+"; "0.0.0.0:" + env.BOOT_NODE_PORT)) | .rpc.addr = "0.0.0.0:" + env.RPC_PORT' ~/.near/mpc-sam/config.json > ~/.near/mpc-sam/temp.json && mv ~/.near/mpc-sam/temp.json ~/.near/mpc-sam/config.json
```

```shell
jq '.account_id = "sam.test.near"' ~/.near/mpc-sam/validator_key.json > ~/.near/mpc-sam/temp.json && mv ~/.near/mpc-sam/temp.json ~/.near/mpc-sam/validator_key.json
```

```shell
cat > ~/.near/mpc-sam/config.yaml << 'EOF'
my_near_account_id: sam.test.near
near_responder_account_id: sam.test.near
number_of_responder_keys: 1
web_ui:
  host: localhost
  port: 8082
triple:
  concurrency: 2
  desired_triples_to_buffer: 128
  timeout_sec: 60
  parallel_triple_generation_stagger_time_sec: 1
presignature:
  concurrency: 4
  desired_presignatures_to_buffer: 64
  timeout_sec: 60
signature:
  timeout_sec: 60
indexer:
  validate_genesis: false
  sync_mode: Latest
  concurrency: 1
  mpc_contract_id: mpc-contract.test.near
  finality: optimistic
ckd:
  timeout_sec: 60
cores: 4
EOF
```

### Run the MPC binary

In two separate shells run the MPC binary for frodo and sam. Note the last argument repeating (`11111111111111111111111111111111`) is the encryption key for the secret storage, and can be any arbitrary value.

```shell
mpc-node start --home-dir ~/.near/mpc-sam/ 11111111111111111111111111111111 --image-hash "8b40f81f77b8c22d6c777a6e14d307a1d11cb55ab83541fbb8575d02d86a74b0" --latest-allowed-hash-file /temp/LATEST_ALLOWED_HASH_FILE.txt local
```

```shell
mpc-node start --home-dir ~/.near/mpc-frodo/ 11111111111111111111111111111111 --image-hash "8b40f81f77b8c22d6c777a6e14d307a1d11cb55ab83541fbb8575d02d86a74b0" --latest-allowed-hash-file /temp/LATEST_ALLOWED_HASH_FILE.txt local
```
Note: `8b40f81f77b8c22d6c777a6e14d307a1d11cb55ab83541fbb8575d02d86a74b0` is just an arbitrary hash.

In the shell where you ran the local near node, you should see the peer count change from 0 to 2 as the frodo and sam MPC indexers connect to it.

```log
2025-08-03T14:19:42.179075Z  INFO stats: #  100530 Fe9M4GuFpnTgMJvwZR1uzsxMAp7gKqWp1GAVdm5RY5Rc Validator | 1 validator 0 peers ⬇ 0 B/s ⬆ 0 B/s 1.70 bps 0 gas/s CPU: 3%, Mem: 2.17 GB
2025-08-03T14:19:52.181980Z  INFO stats: #  100546 G9tp5Jwh5pfreNqREKJT75dgq6Zx6w4hXtyecN4r4rWC Validator | 1 validator 0 peers ⬇ 0 B/s ⬆ 0 B/s 1.60 bps 0 gas/s CPU: 3%, Mem: 2.17 GB
2025-08-03T14:20:02.182157Z  INFO stats: #  100563 DqWZMLg9e7Z55u3JxjUBBvjUCJf1T3K4K4XWWbhQfG6a Validator | 1 validator 2 peers ⬇ 69 B/s ⬆ 238 B/s 1.70 bps 0 gas/s CPU: 1%, Mem: 2.17 GB
2025-08-03T14:20:12.183398Z  INFO stats: #  100579 98DQh3yG987rY1pNWKbM4jYjJ5xuFixP4g3MJuVvpiWY Validator | 1 validator 2 peers ⬇ 1.10 kB/s ⬆ 37.4 kB/s 1.60 bps 0 gas/s CPU: 3%, Mem: 2.17 GB
```

### Assign the signer and responder keys as subkeys.

We must delegate the generate signing keys Sam and Frodo generated as access keys to their near accounts such that they
can sign transaction that require authorization on the contract.

First we can get the keys from the `public_data` endpoint:

```shell
export FRODO_P2P_KEY=$(curl -s localhost:8081/public_data | jq -r ".near_signer_public_key")
export SAM_P2P_KEY=$(curl -s localhost:8082/public_data | jq -r ".near_signer_public_key")

export FRODO_RESPONDER_KEY=$(curl -s localhost:8081/public_data | jq -r ".near_responder_public_keys[0]")
export SAM_RESPONDER_KEY=$(curl -s localhost:8082/public_data | jq -r ".near_responder_public_keys[0]")
```

Now we can add these keys to the appropriate NEAR accounts with the NEAR CLI.

```shell
near account add-key frodo.test.near grant-full-access use-manually-provided-public-key "$FRODO_P2P_KEY" network-config mpc-localnet sign-with-keychain send
near account add-key frodo.test.near grant-full-access use-manually-provided-public-key "$FRODO_RESPONDER_KEY" network-config mpc-localnet sign-with-keychain send

near account add-key sam.test.near grant-full-access use-manually-provided-public-key "$SAM_P2P_KEY" network-config mpc-localnet sign-with-keychain send
near account add-key sam.test.near grant-full-access use-manually-provided-public-key "$SAM_RESPONDER_KEY" network-config mpc-localnet sign-with-keychain send
```

```shell
docs/localnet/scripts/assign_access_keys.sh frodo 8081
```

```shell
docs/localnet/scripts/assign_access_keys.sh sam 8082
```

## 4. Initialize the MPC contract

We'll initialize the MPC contract with our two participants.
The first step to achieve this is to get their public keys.

```shell
export FRODO_PUBKEY=$(curl -s localhost:8081/public_data | jq -r '.near_p2p_public_key')
export SAM_PUBKEY=$(curl -s localhost:8082/public_data | jq -r '.near_p2p_public_key')
```

With these set, we can prepare the arguments for the init call.

```shell
envsubst < docs/localnet/args/init.json > /tmp/init_args.json
```

Now, we should be ready to call the `init` function on the contract.

```shell
near contract call-function as-transaction mpc-contract.test.near init file-args /tmp/init_args.json prepaid-gas '300.0 Tgas' attached-deposit '0 NEAR' sign-as mpc-contract.test.near network-config mpc-localnet sign-with-keychain send
```

If this succeeded, you should now be able to query the contract state.

```shell
near contract call-function as-read-only mpc-contract.test.near state json-args {} network-config mpc-localnet now
```

## 5. Add a domain
Now the contract should be initialized and both nodes are running.
To verify that the network is working let's request a singature from it.
To do this, we first need to add a domain.

Let's have Frodo and Sam both vote to add a secp256k1 domain.

```shell
near contract call-function as-transaction mpc-contract.test.near vote_add_domains file-args docs/localnet/args/add_domain.json prepaid-gas '300.0 Tgas' attached-deposit '0 NEAR' sign-as frodo.test.near network-config mpc-localnet sign-with-keychain send

near contract call-function as-transaction mpc-contract.test.near vote_add_domains file-args docs/localnet/args/add_domain.json prepaid-gas '300.0 Tgas' attached-deposit '0 NEAR' sign-as sam.test.near network-config mpc-localnet sign-with-keychain send
```

## 6. Send a sign request to the network
Now we should be able to request a signature from the network.

```shell
near contract call-function as-transaction mpc-contract.test.near sign file-args docs/localnet/args/sign.json prepaid-gas '300.0 Tgas' attached-deposit '100 yoctoNEAR' sign-as frodo.test.near network-config mpc-localnet sign-with-keychain send
```

If this worked, you should see a response like:

```log
INFO Function execution return value (printed to stdout):
{
  "big_r": {
    "affine_point": "036080C3D1CC86EB785F8FBB3E216786D9A9ABAB30CB6D85FC7D5157BB3E8873C5"
  },
  "recovery_id": 1,
  "s": {
    "scalar": "28DC2AB7BC81EB919797FA932632B35B6C3E8B8C037B11EC5F4071F184B3165D"
  },
  "scheme": "Secp256k1"
}
```

Tadaaa! Now you should have a fully functioning MPC network running on your
machine ready to produce signatures.

## Appendix: Further useful commands

### Cancel a key generation

```shell
near contract call-function as-transaction mpc-contract.test.near vote_cancel_keygen json-args '{"next_domain_id": 0}' prepaid-gas '300.0 Tgas' attached-deposit '0 NEAR' sign-as frodo.test.near network-config mpc-localnet sign-with-keychain send
```

### Check allowed image hashes:

```shell
near contract call-function as-transaction mpc-contract.test.near allowed_code_hashes json-args {} prepaid-gas '300.0 Tgas' attached-deposit '0 NEAR' sign-as sam.test.near network-config mpc-localnet sign-with-keychain send
```

### Add more funds to the mpc-contract account

The following command sends 10 NEAR to the mpc-contract.test.near account.

```shell
near transaction construct-transaction test.near mpc-contract.test.near add-action transfer '10 NEAR' skip network-config mpc-localnet sign-with-plaintext-private-key $VALIDATOR_KEY send
```
