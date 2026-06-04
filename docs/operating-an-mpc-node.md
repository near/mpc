# MPC operator expectations

Whether you're already running a node or considering it — thank you. The NEAR MPC network stays secure, reliable, and decentralized only because independent operators like you keep it running. No single party can produce a signature alone; that guarantee rests on you.

This guide lays out what we — the Near One MPC team behind the contract and node code — expect from operators. If anything is unclear, raise it in the operators' Slack channel.

## What you run
All operators are expected to run the following:

1. A TEE **testnet** MPC node
2. A **mainnet** non-TEE MPC node (until the TEE mainnet rollout completes)
3. (once implemented) A TEE-enabled [backup service](./migration-service.md) node

Two things to keep in mind for the setup:

- Run each component on its own machine — don't co-locate them.
- Keep your mainnet and testnet setups as close to identical as possible, so testnet catches bugs before they reach mainnet.

See the [TDX node guide](./running-an-mpc-node-in-tdx-external-guide.md) for how to operate TEE MPC nodes, and the [node migration guide](./node-migration-guide.md) for how to use our backup CLI to migrate nodes between different environments.

> **Note** — As of 2026-06, TEE migration is in progress: testnet runs a mix of TEE and non-TEE nodes, and mainnet does not yet require TEE. Until that changes, operators onboarding now should run a non-TEE node for mainnet and a TEE node for testnet. See [Running the MPC Launcher in Non-TEE Mode](./using-the-launcher-in-nontee-setup.md) for details.

### One node per network per operator
Each operator runs **exactly one** mainnet node and one testnet node — no more. A decentralized set of independently operated nodes is the whole point, so no single party may run more than one node per network, whether directly or by quietly operating several operators' nodes through subcontracting.

Subcontracting the day-to-day operation of *your* node is fine, but the same expectations apply to whoever ends up running it.

### Keep your operator account isolated
Use your MPC operator account only for running the node — don't call other smart contracts with it. This keeps it isolated and adds defense-in-depth against malicious contracts forwarding requests to the signer contract.

## Staying reachable
We have a shared Slack channel for all node operators. We expect you to be available there to coordinate network upgrades and respond to incidents.

## Uptime
You're expected to keep your nodes healthy and participating in their networks. During normal operation we expect 99% uptime. That may sound low for this kind of service, but because the MPC network tolerates individual node failures, it translates to very high uptime for the network as a whole.

### Excused downtime
You're not expected to run hot backup nodes for quick recovery if a node crashes for reasons outside your control. Syncing a recovering node can take a while — that's fine, and won't count against your uptime expectations as long as you responded promptly and took appropriate action.

The same applies if we ask you to turn off your node during incident investigations or similar situations.

## Incident response
When an issue with your node comes up, we expect you to pick it up and start investigating as soon as you reasonably can, and to keep others posted on Slack as you work it. This is essential to the reliability of the network.

We'll move to tighter, formal response times once dedicated alerting is in place; until then, prompt best-effort response is what matters.

When an incident is underway we expect you to be ready to collaborate on actions such as:

- Restarting your node.
- Updating your node.
- Submitting votes or other information to the smart contract.
- Sharing logs for debugging.

## Upgrades
When we publish new MPC versions we typically coordinate node upgrades first, followed by contract upgrades. We coordinate both on Slack. In each case we'd like you to independently verify the code before acting, so you can confirm the expected version is what's actually being run.

### Node upgrades
Follow our [reproducible builds guide](./reproducible-builds.md) to verify the docker image hashes, then upgrade your nodes to the requested version.

### Contract upgrades & voting
Contract upgrades happen through voting. Just like with nodes, reproduce the contract build to verify the code before voting.

For any on-chain vote — upgrades, generating new keys, or changes to the operator set — we expect you to respond within three (3) calendar days of it opening: either approve it, or raise an objection on slack.
