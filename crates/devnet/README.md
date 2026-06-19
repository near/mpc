# MPC Cluster Testing CLI

This is a comprehensive CLI that provides end-to-end testing
functionality for running MPC nodes in a cluster. It also allows
incrementally making changes to the cluster, as well as sending
load to it.

These instructions are for MPC team members only. These instructions
are currently not applicable to the public, since they rely on a lot of
our internal-specific setup.

## Prerequisites

To be able to use the CLI, make sure to first install [Terraform](https://developer.hashicorp.com/terraform/tutorials/aws-get-started/install-cli) and the [google cloud CLI](https://cloud.google.com/sdk/docs/install).

Once installed you need to authenticate yourself with `gcloud` and get application credentials, which can be done using the following commands.

```shell
gcloud auth login
```

```shell
gcloud auth application-default login
```

You can check you are correctly authenticated by using:

```shell
gcloud auth list
```

## Installation

With the application credentials in place, the next step is to install the CLI.

The CLI can be installed using `cargo install`. Open a terminal in
the devnet directory and run the following.

```shell
cargo install --path . --locked
```

Once completed, you should have the `mpc-devnet` command available in your shell.

## Configuring

Before starting, copy `config.yaml.template` to `config.yaml` and
edit it:

- Add any number of RPC nodes; configuring the QPS rate limit it allows,
  as well as the maximum allowed number of simultaneous outstanding
  requests.
  - The CLI will utilize all available RPC nodes by aggregating their
    available throughput.
- Set the directory of your local clone of the infra-ops repository.
  This is used for Terraform deployment of the test cluster. To avoid any errors, it is advised to ensure the local repo is up to date.
- Configure `rpcs` to point to your RPC endpoint. You can find NEAR testnet RPC providers at [docs](https://docs.near.org/api/rpc/providers#testnet). Use the URL listed under "Endpoint Root" for the url field.
  Here's an example configuration:

```yaml
rpcs:
  - url: https://test.rpc.fastnear.com
    rate_limit: 5
    max_concurrency: 30
    # api_key: your-api-key   # optional, sent as `Authorization: Bearer <key>`
infra_ops_path: path-to-infra-ops-repo
```

The optional `api_key` field is sent as `Authorization: Bearer <value>` on
every request to the corresponding endpoint. Omit it to use the public
endpoint unauthenticated.

- (Optional) Configure a `funding_account` to use a specific account for funding operations:

  ```yaml
  funding_account:
    account_id: your-account.testnet
    access_keys:
      - ed25519:xxxxxx # Your private key
    kind: FundingAccount
  ```

  If not provided, the devnet will create funding accounts as needed from the testnet faucet.

## How the CLI Works

This CLI is somewhat similar to Terraform in spirit. As soon as you
execute any command, it creates a local `devnet_setup.yaml` which stores
all the account keys and network setups it has created. This is
persistent state, which is what allows the CLI to be easy to use across
invocations.

> **NOTE**
> The CLI currently has to be used from the `devnet` directory.
> This is because it uses relative paths to find configuration files.

You may create multiple MPC networks, multiple Loadtest Setups, and
update each of them with bigger parameters. The CLI will automatically
fund any necessary accounts using as many Testnet faucets as needed.

## Creating an MPC Network

First, create an MPC network. Pick a name; here I'll use
"MPC_NETWORK_NAME=yourusername-test", but **ensure that your name is globally unique
within the team**, so include your username in there. It must also be short (less than 15 chars) else
you might get errors when creating and funding accounts.

```shell
export MPC_NETWORK_NAME=yourusername-test
mpc-devnet mpc $MPC_NETWORK_NAME new \
  --num-participants 2 \
  --num-responding-access-keys 8 \
  --near-per-responding-account 1
  [--ssd] # use only if you don't plan to run this for a long period, as it is more expensive
```

Increasing the number of responding access keys can be very helpful in
increasing the throughput of the MPC node, as each key has an
independent nonce.

Then, deploy the contract.

```shell
mpc-devnet mpc $MPC_NETWORK_NAME deploy-contract
```

The path of the contract binary can be overridden via `--path`.

We can now deploy the infra with Terraform:

```shell
mpc-devnet mpc $MPC_NETWORK_NAME deploy-infra
```

This will output the address of the **Nomad UI**. Go there and wait until the
Nomad server UI shows up. Accessing the UI will require a password, which can be
found in the "Nomad MPC UI" entry in the company's password manager. We can then
deploy the MPC nodes:

In addition, You can find the VMs created in GCP under [this link](<https://console.cloud.google.com/compute/instances?referrer=search&inv=1&invt=Ab256A&project=nearone-mpc&pli=1&pageState=(%22instances%22:(%22s%22:%5B(%22i%22:%22creationTimestamp%22,%22s%22:%220%22),(%22i%22:%22name%22,%22s%22:%220%22)%5D,%22r%22:50))>).

```shell
mpc-devnet mpc $MPC_NETWORK_NAME deploy-nomad
```

The docker image to be deployed can be change with the `--docker-image` flag. A
recent docker image can be found in our
[dockerhub](https://hub.docker.com/r/nearone/mpc-node/tags)

Both the `deploy-infra` and `deploy-nomad` commands can be repeated as needed.

The Terraform deployments use the Terraform Workspaces feature, where
the workspace name is the same as the MPC network name. The Terraform
state is stored in S3, which is why this workspace name needs to be
unique in the team.

Now, wait for the nodes to spin-up and start syncing. The node public addresses
can be obtained by:

```shell
mpc-devnet mpc $MPC_NETWORK_NAME describe
```

Once the `public_data` endpoint is accessible in <http://node_address:8080/public_data>, run

```shell
mpc-devnet mpc $MPC_NETWORK_NAME add-keys
```

Finally, initialize the contract

```shell
mpc-devnet mpc $MPC_NETWORK_NAME init-contract --init-participants 2 --threshold 2
```

The `--init-participants` can be fewer than the total number of participants,
if we wish to have fewer participants join the network at the beginning.

### Generating Keys

When first deployed, the contract has no keys. In order to make any signatures,
we must first generate some keys. This example generates one key for each
supported protocol. You can specify duplicate protocols here as well if you
wish to add multiple keys for the same protocol. Use `DamgardEtAl` to add a
Robust ECDSA key on Secp256k1 (distinct from `CaitSith`, which is the classic
ECDSA protocol on the same curve).

```shell
mpc-devnet mpc $MPC_NETWORK_NAME vote-add-domains \
  --protocols CaitSith,Frost,ConfidentialKeyDerivation
```

This triggers the MPC nodes to start performing key generation, after which the
contract will transition into the Running state, ready for signatures.

**NOTE**: This step will only take place when the nodes have already synced, which can
take from around 1 hour (if using SSD) to a few of hours.

### TEE: Setting allowed image hash

Once the contract is deployed, we need to vote for an approved image hash if we want nodes
running in TEE to be authenticated.

You can add approved image hashes with the following command:

```shell
mpc-devnet mpc $MPC_NETWORK_NAME vote-code-hash --mpc-docker-image-hash <IMAGE_DIGEST>
```

### Checking the Network State

You can use the following command to print out the network state:

```shell
mpc-devnet mpc $MPC_NETWORK_NAME describe
```

This will print out the state of the contract as well as some debugging links from
the cluster's nodes, e.g.

```text
MPC contract deployed at: mpc-contract-and-upg-4df70f9abb68.b892843ed20d.testnet
Contract is in Running state
  Epoch: 9
  Keyset:
  Domain 0: Secp256k1, key from attempt 0
  Domain 1: Edwards25519, key from attempt 0
  Domain 2: Secp256k1, key from attempt 0
  Domain 3: Edwards25519, key from attempt 0
  Domain 4: Secp256k1, key from attempt 0
  Domain 5: Edwards25519, key from attempt 0
  Parameters:
  Participants:
    ID 3: mpc-2-and-upg-c4c3bbdf00c0.andrei-devnet.testnet (http://mpc-node-2.service.mpc.consul:3000)
    ID 4: mpc-1-and-upg-5a31c3d4ec91.andrei-devnet.testnet (http://mpc-node-1.service.mpc.consul:3000)
    ID 5: mpc-0-and-upg-26b2094f1da5.andrei-devnet.testnet (http://mpc-node-0.service.mpc.consul:3000)
  Threshold: 3
Nomad server: http://35.203.145.20
Nomad client #0: zone us-west1-b, instance type n2d-standard-8, debug: http://34.169.182.161:8080/debug/tasks
Nomad client #1: zone us-west1-b, instance type n2d-standard-8, debug: http://34.105.100.13:8080/debug/tasks
Nomad client #2: zone us-west1-b, instance type n2d-standard-8, debug: http://34.83.175.21:8080/debug/tasks
```

### Sending Signatures

See the section below on [loadtesting](#creating-a-loadtest-setup)

### Modifying the Network

#### Adding more nodes, add access keys, etc

Any parameter specified via `new` can be overridden here, and the command
will expand the current setup to add any new resources, for example:

```shell
mpc-devnet mpc $MPC_NETWORK_NAME update --num-participants 3
```

**Note**: that it is recommended to create all the participants that we're
going to need upfront, instead of adding one later. The contract can be
initialized with fewer participants and then new participants can join
later, but creating all the machines upfront will save time.

#### Adding or removing participants

Suppose the network currently has 5 nodes, and the contract was initialized with 4 nodes.
That means nodes [0, 1, 2, 3] are currently participating in the network. Suppose then we
want node 4 and 5 to join, node 1 to leave, and to adjust the threshold to 4. We can do this:

```shell
mpc-devnet mpc $MPC_NETWORK_NAME vote-new-parameters --add 4 --add 5 --remove 1 --set-threshold 4
```

This will kick off a resharing operation to reshare all keys.

#### Upgrading the contract

To upgrade the contract, first propose the upgrade (suppose we wish to use the newly compiled
contract code for the upgrade):

```shell
mpc-devnet mpc $MPC_NETWORK_NAME propose-update-contract --path ../../target/near/mpc_contract/mpc_contract.wasm
```

This will print out a command to run for voting for the upgrade:

```shell
mpc-devnet mpc $MPC_NETWORK_NAME vote-update --update-id=0
```

That will trigger a migration to use the new contract.

#### Using a different MPC node binary

If we wish to change the MPC node binary, publish a new docker image and then redeploy
with the docker image tag, e.g.

```shell
mpc-devnet mpc $MPC_NETWORK_NAME deploy-nomad --docker-image nearone/mpc-node:branch-1234567
```

Our docker images are available in [dockerhub](https://hub.docker.com/r/nearone/mpc-node/tags).

### Cleaning up the Infra

After you're done with testing the cluster, please bring down the machines to save resources:

```shell
mpc-devnet mpc $MPC_NETWORK_NAME destroy-infra
```

Also, you need to clear the deployed contract from local state, because the infra contains
locally stored keyshares, and once we clear that, the contract state is effectively useless.

```shell
mpc-devnet mpc $MPC_NETWORK_NAME remove-contract
```

You may resume testing next time by using `deploy-contract` and then `deploy-infra` again.

### Resetting the Contract without Resetting the Cluster

At times, it may be useful to restart the contract from the initial state. We first need to
remove and redeploy the contract like above, but also we need to reset the data for the nodes:

```shell
mpc-devnet mpc $MPC_NETWORK_NAME deploy-nomad --shutdown-and-reset
```

Check the Nomad pages for the reset jobs to complete, and then

```shell
mpc-devnet mpc $MPC_NETWORK_NAME deploy-nomad
```

This will clear all the local data on the nodes except the near blockchain data. That way,
the effect is similar to remaking the cluster, but without having to wait for state sync again.

## Creating a Loadtest Setup

Create a loadtest set of accounts: (The name does **not** need to be
the same as the MPC cluster name, and this name does **not** need to
be globally unique.)

```shell
mpc-devnet loadtest my-test new \
  --num-accounts 1 \
  --keys-per-account 16 \
  --near-per-account 4
```

It is not necessary to create more than 1 account but you may if you
wish to do so. The number of keys is important to increase the
throughput, as the QPS we can send is bounded by the number of
independent nonces we can manage. However, the downside of using a lot
of keys is that we also need more NEAR in the account to buffer the
not-yet-refunded gas fees. (But that isn't solved by having more
accounts, anyway; so I still recommend having a single account.
Also, creating keys takes log(N) rounds; creating accounts is
single-threaded).

Additionally, a parallel signature contract may be deployed.
This can comfortably issue 10 signatures in one transaction.

```shell
mpc-devnet loadtest my-test deploy-parallel-sign-contract
```

### Sending Load

We can point the loadtest setup against the MPC setup:

**Note**: These tests might fail initially when the node is generating triples
and pre-signatures.

```shell
mpc-devnet loadtest my-test run \
  --mpc-network $MPC_NETWORK_NAME \
  --qps 5 \
  --domain-id 0 \
  --duration 10
```

or directly against an already deployed mpc contract (e.g. the testnet contract):

```shell
mpc-devnet loadtest my-test run \
  --mpc-contract v1.signer-prod.testnet \
  --qps 3 \
  --parallel-sign-calls-per-domain 0=2,1=3 \
  --duration 20
```

The `--duration` specifies the duration of the test in seconds. If not specified, the loadtest will run indefinitely, but will not provide any success metric.

The `--parallel-sign-calls-per-domain` parameter is optional; if not
specified, we will send one sign call per transaction. This parameter is useful
if we want to send a high amount of load.

The `--domain-id` parameter specifies which domain to use for the signature
requests. This parameter _may_ be omitted to test compatibility with the legacy API and _will_ be ignored if `--parallel-sign-calls-per-domain` is set.

The output should be something like the following:

```text
Going to run loadtest setup my-test against MPC contract v1.signer-prod.testnet at 3 QPS
Submitted 4 parallel signature requests. Received 0 RPC errors
Collecting Signature Responses
Found 4 parallel signature responses and 0 failures. Encountered 0 rpc errors.
Success Rate: 100
```

### Running predefined load-shape scenarios

`scripts/loadtest-scenarios.sh` drives the `run` command above through a fixed
set of load shapes — sustained baseline, higher steady-state, and a low/burst/
low spike. It is intended for periodic load testing of the testnet contract.

The script uses the parallel-sign helper contract so each RPC transaction
fans out to multiple signature requests (default `--batch 10`); deploy it
once with `mpc-devnet loadtest <name> deploy-parallel-sign-contract` before
running.

```shell
./scripts/loadtest-scenarios.sh my-test                  # all scenarios
./scripts/loadtest-scenarios.sh my-test --scenario spike # just the spike
./scripts/loadtest-scenarios.sh my-test \
    --contract v1.signer-prod.testnet \
    --domain 0
```

Run `./scripts/loadtest-scenarios.sh --help` for the full list of options.

## Deploying against a localnet chain

By default the CLI deploys against **testnet**, so every cluster pays the testnet sync cost. For
benchmarking you can instead deploy against a **localnet** chain (`mpc-localnet`): the cluster runs
a single `neard` validator (on the base-infra machine, off the MPC node machines) and the MPC nodes
peer with it as observers, so a freshly deployed cluster has **no chain sync wait**.

The MPC node, its docker image, and the infra-ops Nomad job already support `mpc-localnet`; the
shared genesis and keys come from the static assets in `deployment/localnet/`. The validator runs a
**stock public `nearprotocol/nearcore` image** — the chain assets are delivered to it at runtime, so
there is no custom image to build or publish. To use it:

Because the chain runs *inside* the cluster, it must be brought up **before** any account/contract
work — so the order differs from the testnet flow: bring up the cluster + validator first, then fund
and deploy. The CLI handles this: on localnet, `new` only registers the network (no funding), and a
`deploy-chain` step starts the validator.

1. **Images — nothing to build or publish.** The MPC nodes run a published image from Docker Hub
   (pass it to `deploy-nomad` with `--docker-image nearone/mpc-node:<tag>`). The validator runs a
   stock public `nearprotocol/nearcore` image, which you pass explicitly via `--neard-docker-image`
   (use the tag matching the nearcore version the node embeds — see `nearcore` in the workspace
   `Cargo.toml`, e.g. `nearprotocol/nearcore:2.12.0`); the CLI feeds it the genesis/config/keys at
   runtime. Note: the published mpc-node image bakes in its own `genesis.json`, which must match
   `deployment/localnet/genesis.json` in your checkout (the CLI sends that one to the validator) or
   the nodes won't peer.

2. **Set `chain_id` in `config.yaml`** (leave the RPC url as a placeholder for now — you'll fill it
   in once the validator is up):

   ```yaml
   chain_id: mpc-localnet
   rpcs:
     - url: http://replace-after-deploy-infra:3030
       rate_limit: 5
       max_concurrency: 30
   infra_ops_path: /path/to/infra-ops
   ```

   No `funding_account` is needed: on localnet the CLI auto-derives the genesis-funded master
   account (`test.near`) from `deployment/localnet/validator_key.json` and funds everything from it —
   no faucet.

3. Pick a globally-unique network name (see [Creating an MPC Network](#creating-an-mpc-network)):

   ```shell
   export MPC_NETWORK_NAME=yourusername-test
   ```

4. `mpc-devnet mpc $MPC_NETWORK_NAME new --num-participants 2 --num-responding-access-keys 8` —
   on localnet this only registers the network; funding is deferred until the chain is up.

5. `mpc-devnet mpc $MPC_NETWORK_NAME deploy-infra` — provisions the cluster (incl. the validator VM)
   and prints the validator's RPC URL. Paste it into `rpcs[0].url` in `config.yaml`.

6. `mpc-devnet mpc $MPC_NETWORK_NAME deploy-chain --neard-docker-image nearprotocol/nearcore:<tag>` —
   starts the `neard` validator. The chain is now live at the RPC URL from step 5.

7. `mpc-devnet mpc $MPC_NETWORK_NAME update` — funds the participant accounts on the live chain (uses
   the count from step 4).

8. `mpc-devnet mpc $MPC_NETWORK_NAME deploy-contract --path ../../target/near/mpc_contract/mpc_contract.wasm`
   (the `--path` is **required** on localnet — there is no testnet contract to fetch).

9. `mpc-devnet mpc $MPC_NETWORK_NAME deploy-nomad --docker-image nearone/mpc-node:<tag>` — deploys the
   MPC node jobs. The validator image is reused from step 6 automatically (override with
   `--neard-docker-image` only if you intend to re-image the validator). Then proceed with the normal
   `add-keys`, `init-contract`, and `vote-add-domains` steps — with no sync wait.

For the single-host equivalent (everything on one machine), see `scripts/launch-localnet.sh`.
