# Configuration of foreign chain RPC providers without full consensus


## Background
For the foreign chain transaction validation feature supported by the MPC network, individual MPC nodes each each query a set of configured RPC providers  to verify the state of a foreign transaction. Each MPC node that partakes in a signing operation for verification of a foreign chain transaction will get an RPC provider randomly assigned with consistent hashing. That means each MPC node only queries 1 RPC provider per verification request.

Currently an RPC provider is only accepted if and only if ALL mpc nodes have their local configuration setup to use that RPC provider on a per chain basis. That is for example if an MPC node wants to use Quiknode RPC provider for Solana, then all other MPC nodes must also add Quiknode in their Solana configuration on their nodes.

## What
As part of [#2648](https://github.com/near/mpc/issues/2648) We would like to be able configure nodes with RPC providers without requiring all other nodes to have the exact same configuration.

### __Requirements__:
1. RPC providers can be whitelisted by being voted into the contract by node operators submitting votes. This will differ in contrast to current solution where the node is the one to submit votes for RPC providers it has in its configuration.

2. Nodes do not need to have local configurations with all RPC providers that are whitelisted, a threshold number of RPC providers is fine.

3. Every node partaking in a foreign signature verification request will query all its locally configured RPC providers independent of other nodes. A quorum of the RPC providers must all agree on the verifications.

Nodes no longer need a view over RPC providers of its peers. Instead of only querying a single RPC provider assigned with consistent hashing, the node with 

## Why
The current setup has many limitations and was implemented as an MVP.

### Availability
Currently, if a single RPC provider is unresponsive, then a foreign chain validation will fail due to the nodes that are mapped to that RPC provider will fail. 
### Security
By requiring every node to have a valid quorum of RPC providers for a verification, each node does not need to trust the other nodes' RPC configurations.
### Flexibility
We want to allow nodes to use newly whitelisted RPC providers, without forcing for all other node operators to also configure RPC accounts for that provider.

## How

### Whitelisting policy for RPC providers on chain

The MPC contract has functionality to vote on a wide set of proposals where node operators cast votes manually, for example for allowed node binary hashes, contract configuration, contract binary upgrade, node participant set, etc.

We can extend the contract to contain a feature for voting on whitelisting of RPC providers.

> NB!
> Currently we are also generalizing these voting structs by creating a generic voting struct [#1573](https://github.com/near/mpc/pull/1573) which we can be used for this purpose.


```rust
struct MpcContractState {
    //..
    //..
    foreign_chain_rpc_policy: RpcPolicies
}

struct RpcPolicies {
    foreign_chains: BtreeMap<ForeignChain, RpcPolicy>,
}

struct RpcPolicy {
    whitelisted_rpc_providers: BtreeSet<RpcProvider>,
    // the minimum number of RPC providers that must verify the foreign
    // tx request for a node to consider the tx as verified.
    quorum_threshold: u8,
}

enum ForeignChain {
    Solana,
    Bitcoin,
    Ethereum,
}

struct RpcProvider {
    // this base url part is what the nodes will check against before using 
    // an RPC provider that the operator has added to its configuration
    base_url: String,
    name: String,
}
```


### Nodes checking if local configuration is valid
On startup, the node will check its [local foreign chain configuration ](https://github.com/near/mpc/blob/4b2e758ee468738579af298f482aa13f9b5d269f/crates/node-config/src/foreign_chains.rs#L23-L37) to assert that all RPC providers are whitelisted on chain.

If an RPC provider with a base url that is not whitelisted is detected, then that RPC entry should be dropped and an error log emitted.
> We can alternatively hard crash the node, so it's obvious when a misconfiguration is done.

Since the nodes are running in a Trusted Execution Environment (TEE), we use this functionality to have the node guard against node operators that might use malicious RPC urls.


### Individual Node quorum of RPC providers for verification requests
When a foreign TX verification request is processed by a set of nodes, every node will each individually query all their respectively configured RPC providers. A node will consider 


### Nodes submit votes for 
Nodes should submit their configuration on chain, to let the network know with chains they have configured and as a consequence support. Functionality for this is already addedon the contract side in [#2784](https://github.com/near/mpc/pull/2784).
