# Localnet - instructions for how to run a local MPC network

## Prerequisites

neard, near CLI, cargo, ripgrep, envsubst, python3-keyring

```shell
python3-keyring
```

### Note about `neard`.

Make sure that your `neard` version has is compatible with the `near` version with the `near-indexer` version
that is used by the MPC binary defined in the workspace cargo file, `/Cargo.toml`.

```shell
neard --version
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
near account create-account fund-myself mpc-contract.test.near '10 NEAR' autogenerate-new-keypair save-to-keychain sign-as test.near network-config mpc-localnet sign-with-plaintext-private-key $VALIDATOR_KEY send
```

We can verify that the account exists and has 10 NEAR with this command.

```shell
near account view-account-summary mpc-contract.test.near network-config mpc-localnet now
```

Now it's time to deploy the contract.
First build the contract from the `libs/chain-singatures` folder with:

```shell
cargo build --release --target=wasm32-unknown-unknown
wasm-opt -Oz -o target/wasm32-unknown-unknown/release/mpc_contract.wasm target/wasm32-unknown-unknown/release/mpc_contract.wasm --enable-bulk-memory
```

Now you should have a `mpc_contract.wasm` artifact ready in the target directory.
Let's add an env variable for it. From the workspace root, run the following:

```shell
export MPC_CONTRACT_PATH=$(pwd)/libs/chain-signatures/target/wasm32-unknown-unknown/release/mpc_contract.wasm
```

Now we can deploy the contract with this command.

```shell
near contract deploy mpc-contract.test.near use-file $MPC_CONTRACT_PATH without-init-call network-config mpc-localnet sign-with-keychain send
```

When the contract has been deployed you should be able to see its functions through the CLI.

```shell
near contract inspect mpc-contract.test.near network-config mpc-localnet now
```

Now when the contract has been deployed, the next step is to initialize it.

## 3. Initialize the MPC contract

We'll initialize the MPC contract with two participants. Before we can call the contract, we first need to create accounts for the participants. Let's call them `alice` and `bob`.

```shell
near account create-account fund-myself alice.test.near '10 NEAR' autogenerate-new-keypair save-to-keychain sign-as test.near network-config mpc-localnet sign-with-plaintext-private-key $VALIDATOR_KEY send
```

```shell
near account create-account fund-myself bob.test.near '10 NEAR' autogenerate-new-keypair save-to-keychain sign-as test.near network-config mpc-localnet sign-with-plaintext-private-key $VALIDATOR_KEY send
```

now we can extract their public keys.

```shell
export ALICE_PUBKEY=$(near account get-public-key from-keychain alice.test.near network-config mpc-localnet)
echo "Alice pubkey: $ALICE_PUBKEY"

export BOB_PUBKEY=$(near account get-public-key from-keychain bob.test.near network-config mpc-localnet)
echo "Bob pubkey: $BOB_PUBKEY"
```

With these set, we can prepare the arguments for the init call.

```shell
envsubst < docs/init_args_template.json > /tmp/init_args.json
```

Now, we should be ready to call the `init` function on the contract.

```shell
near contract call-function as-transaction mpc-contract.test.near init file-args /tmp/init_args.json prepaid-gas '300.0 Tgas' attached-deposit '0 NEAR' sign-as mpc-contract.test.near network-config mpc-localnet sign-with-keychain send
```

If this succeeded, you should now be able to query the contract state.

```shell
near contract call-function as-read-only mpc-contract.test.near state json-args {} network-config mpc-localnet now
```

## 4. Start Alice and Bob's MPC nodes

Before we can start the MPC nodes for Alice and Bob, we need to know the public key of our NEAR validator.

```shell
export NODE_PUBKEY=$(cat ~/.near/mpc-localnet/node_key.json | rg public_key | rg -o "ed25519:\w+")
```

### Initialize Alice's node

```shell
mpc-node init --dir ~/.near/mpc-alice --chain-id mpc-localnet --genesis ~/.near/mpc-localnet/genesis.json --boot-nodes $NODE_PUBKEY@localhost:3030 --download-config-url https://s3-us-west-1.amazonaws.com/build.nearprotocol.com/nearcore-deploy/testnet/rpc/config.json
```

TODO([#714](https://github.com/near/mpc/issues/714)): Don't download any config.

#### The following modifications are needed

Fix Alice's genesis file to correspond with the localnet.
TODO: Why do we get a different genesis file from the mpc-node init command when genesis from localnet is passed as argument?.

```shell
cp ~/.near/mpc-localnet/genesis.json cp ~/.near/mpc-alice/genesis.json
```

Update Alice to point to correct port for boot nodes. It is currently pointing to localnet's RPC port. Make sure the `RPC_PORT` and `INDEXER_PORT` is free. The value of these ports are arbitrary, and can be any other port.

```shell
RPC_PORT=3031 BOOT_NODE_PORT=24567 INDEXER_PORT=24568 jq '.network.addr = "0.0.0.0:" + env.INDEXER_PORT | .network.boot_nodes = (.network.boot_nodes | sub("localhost:[0-9]+"; "localhost:" + env.BOOT_NODE_PORT)) | .rpc.addr = "0.0.0.0:" + env.RPC_PORT' ~/.near/mpc-alice/config.json > ~/.near/mpc-alice/temp.json && mv ~/.near/mpc-alice/temp.json ~/.near/mpc-alice/config.json
```

Update Alice's `validator_key.json` to match her `account_id` field to her account.

```shell
jq '.account_id = "alice.test.near"' validator_key.json > temp.json && mv temp.json validator_key.json
```

Create a `config.yaml` for the MPC-indexer:

```bash
cat > ~/.near/mpc-alice/config.yaml << 'EOF'
my_near_account_id: alice.test.near
near_responder_account_id: alice.test.near
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
cores: 4
EOF
```

### Initialize Bob's node

```shell
mpc-node init --dir ~/.near/mpc-bob --chain-id mpc-localnet --genesis ~/.near/mpc-localnet/genesis.json --boot-nodes $NODE_PUBKEY@localhost:3030 --download-config-url https://s3-us-west-1.amazonaws.com/build.nearprotocol.com/nearcore-deploy/testnet/rpc/config.json
```

TODO([#714](https://github.com/near/mpc/issues/714)): Don't download any config.

#### The following modifications are needed

Fix Bob's genesis file to correspond with the localnet.
TODO: Why do we get a different genesis file from the mpc-node init command when genesis from localnet is passed as argument?.

```shell
cp ~/.near/mpc-localnet/genesis.json cp ~/.near/mpc-bob/genesis.json
```

Update Bob to point to correct port for boot nodes. It is currently pointing to localnet's RPC port. Make sure the `RPC_PORT` and `INDEXER_PORT` is free. The value of these ports are arbitrary, and can be any other port.

```shell
RPC_PORT=3032 BOOT_NODE_PORT=24567 INDEXER_PORT=24569 jq '.network.addr = "0.0.0.0:" + env.INDEXER_PORT | .network.boot_nodes = (.network.boot_nodes | sub("localhost:[0-9]+"; "localhost:" + env.BOOT_NODE_PORT)) | .rpc.addr = "0.0.0.0:" + env.RPC_PORT' ~/.near/mpc-bob/config.json > ~/.near/mpc-bob/temp.json && mv ~/.near/mpc-bob/temp.json ~/.near/mpc-bob/config.json
```

Update Bob's `validator_key.json` to match her `account_id` field to her account.

```shell
jq '.account_id = "bob.test.near"' validator_key.json > temp.json && mv temp.json validator_key.json
```

Create a `config.yaml` for the MPC-indexer:

```bash
cat > ~/.near/mpc-bob/config.yaml << 'EOF'
my_near_account_id: bob.test.near
near_responder_account_id: bob.test.near
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
cores: 4
EOF
```

### Run the MPC binary

1.

## Appendix: Further useful command

### Add more funds to the mpc-contract account

The following command sends 10 NEAR to the mpc-contract.test.near account.

```shell
near transaction construct-transaction test.near mpc-contract.test.near add-action transfer '10 NEAR' skip network-config mpc-localnet sign-with-plaintext-private-key $VALIDATOR_KEY send
```
