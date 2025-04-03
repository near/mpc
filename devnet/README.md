# MPC Cluster Testing CLI

This is a comprehensive CLI that provides end-to-end testing 
functionality for running MPC nodes in a cluster. It also allows
incrementally making changes to the cluster, as well as sending
load to it.

These instructions are for MPC team members only. These instructions 
are currently not applicable to the public, since they rely on a lot of
our internal-specific setup.

## Configuring
Before starting, copy `config.yaml.template` to `config.yaml` and
edit it:
* Add any number of RPC nodes; configuring the QPS rate limit it allows,
  as well as the maximum allowed number of simultaneous outstanding
  requests.
  * The CLI will utilize all available RPC nodes by aggregating their
    available throughput.
* Set the directory of your local clone of the infra-ops repository.
  This is used for Terraform deployment of the test cluster.
* Set `rpcs` to point to your RPC endpoints
* (Optional) Configure a `funding_account` to use a specific account for funding operations:
  ```yaml
  funding_account:
    account_id: your-account.testnet
    access_keys:
      - ed25519:xxxxxx  # Your private key
    kind: funding_account
  ```
  If not provided, the devnet will create a funding account from the testnet faucet.

## How the CLI Works
This CLI is somewhat similar to Terraform in spirit. As soon as you
execute any command, it creates a local `devnet_setup.yaml` which stores
all the account keys and network setups it has created. This is
persistent state, which is what allows the CLI to be easy to use across
invocations.

You may create multiple MPC networks, multiple Loadtest Setups, and
update each of them with bigger parameters. The CLI will automatically
fund any necessary accounts using as many Testnet faucets as needed.

## Creating an MPC Network

First, create an MPC network. Pick a name; here I'll use "my-test", but
**ensure that your name is globally unique within the team**, so include
your username in there.
```
target/debug/devnet mpc my-test new \
  --num-participants 2 \
  --threshold 2 \
  --num-responding-access-keys 8 \
  --near-per-responding-account 1
```
Increasing the number of responding access keys can be very helpful in
increasing the throughput of the MPC node, as each key has an 
independent nonce.

Then, deploy the contract.
```
target/debug/devnet mpc my-test deploy-contract \
  --init-participants 2
```
The `--init-participants` can be fewer than the total number of participants,
if we wish to have fewer participants join the network at the beginning.

The path of the contract binary can be overridden via `--path`.

We can now deploy the infra with Terraform:
```
target/debug/devnet mpc my-test deploy-infra
```

This will output the address of the Nomad UI. Go there and wait until 
the Nomad server UI shows up, we can then deploy the MPC nodes:
```
target/debug/devnet mpc my-test deploy-nomad
```

Both the `deploy-infra` and `deploy-nomad` commands can be repeated as 
needed.

The Terraform deployments use the Terraform Workspaces feature, where 
the workspace name is the same as the MPC network name. The Terraform
state is stored in S3, which is why this workspace name needs to be
unique in the team.

### Adding or removing nodes

The network can be updated with the following command. Any parameter
specified via `new` can be overridden here, and the command will expand 
the current setup to add any new resources.
```
target/debug/devnet mpc my-test update --num-participants 3
```

This only creates the new participant account. We still need to call join:
```
target/debug/devnet mpc my-test join --account-index 2
```

And then ask everyone else to vote join:
```
target/debug/devnet mpc my-test vote-join --for-account-index 2
```

Once that is all done, we can again run the deployment commands.

Note that it is recommended to create all the participants that we're
going to need upfront, instead of adding one later. The contract can be
initialized with fewer participants and then new participants can join
later, but creating all the machines upfront will save time.

## Creating a Loadtest Setup
Create a loadtest set of accounts: (The name does **not** need to be
the same as the MPC cluster name, and this name does **not** need to
be globally unique.)
```
target/debug/devnet loadtest my-test new \
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
```
target/debug/devnet loadtest my-test deploy-parallel-sign-contract
```

### Sending Load
We can point the loadtest setup against the MPC contract:
```
target/debug/devnet loadtest my-test run \
  --mpc-network my-test \
  --qps 20 \
  --signatures-per-contract-call 10
```
The last parameter is optional; if not specified, we will send one sign
call per transaction.
