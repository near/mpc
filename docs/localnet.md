# Localnet - instructions for how to run a local MPC network

## Prerequisites
neard, near CLI, cargo.

## 1. Run a local NEAR network

To run a local NEAR network, first create the configuration with the following command.
```
neard --home ~/.near/mpc-localnet init --chain-id mpc-localnet
```

This will set up the configuration in the `~/.near/mpc-localnet` directory.

Next, start a single validator node for this network with this command.

```
NEAR_ENV=mpc-localnet neard --home ~/.near/mpc-localnet run
```

Congratulations, you are now running a local NEAR network.
To see the network status, call

```
curl localhost:3030/status | jq
```

Before proceeding, save the validator key from the network configuration
as an `VALIDATOR_KEY` environment variable.
We will need it in the next step.

```
export VALIDATOR_KEY=$(cat ~/.near/mpc-localnet/validator_key.json | rg secret_key | rg -o "ed25519:\w+")
```

## 2. Deploy the MPC contract to the network
Now we can deploy the MPC contract with the NEAR CLI.
First, add the mpc-localnet as a network connection in the CLI.

Use `near config show-connections` to view existing connections
and the location of your CLI config file.

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

```
near account create-account fund-myself mpc-contract.test.near '10 NEAR' autogenerate-new-keypair save-to-keychain sign-as test.near network-config mpc-localnet sign-with-plaintext-private-key $VALIDATOR_KEY send
```

We can verify that the account exists and has 10 NEAR with this command.

```
near account view-account-summary mpc-contract.test.near network-config mpc-localnet now
```

Now it's time to deploy the contract.
First build the contract with `cargo build --release` from the `libs/chain-singatures` folder.
Now you should have a `mpc_contract.wasm` artifact ready in the target directory.
Let's add an env variable for it. From the workspace root, run the following:

```
export MPC_CONTRACT_PATH=$(pwd)/libs/chain-signatures/target/wasm32-unknown-unknown/release/mpc_contract.wasm
```

Now we can deploy the contract with this command.
```
near contract deploy mpc-contract.test.near use-file $MPC_CONTRACT_PATH without-init-call network-config mpc-localnet sign-with-keychain send
```

When the contract has been deployed you should be able to see its functions through the CLI.
```
near contract inspect mpc-contract.test.near network-config mpc-localnet now
```

## 3. Initialize the MPC contract
