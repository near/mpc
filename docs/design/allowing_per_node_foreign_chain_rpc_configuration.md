# Configuration of foreign chain RPC providers without full consensus


## Background
For the foreign chain transaction validation feature supported by the MPC network, individual MPC nodes each each query a set of configured RPC providers  to verify the state of a foreign transaction. Each MPC node that partakes in a signing operation for verification of a foreign chain transaction will get an RPC provider randomly assigned with consistent hashing. That means each MPC node only queries 1 RPC provider per verification request.

Currently an RPC provider is only accepted if and only if ALL mpc nodes have their local configuration setup to use that RPC provider on a per chain basis. That is for example if an MPC node wants to use Quiknode RPC provider for Solana, then all other MPC nodes must also add Quiknode in their Solana configuration on their nodes.

### What
As part of [#2648](https://github.com/near/mpc/issues/2648) We would like to be able configure nodes with RPC providers without requiring all other nodes to have the exact same configuration.

Requirements:
1. RPC providers can be whitelisted by being voted into the contract by node operators.
2. Nodes do not need to use all RPC providers that are whitelisted, a threshold number is fine.
3. 

### Why
The current setRequiring every node provider


### How

```rust
struct MpcContractState {
    //..
    //..
    foreign_chain_rpc_policy: RpcPolicy
}

struct RpcPolicy {
    foreign_chains: BtreeMap<ForeignChain, ForeignChainRpcPolicy>,
}


struct ForeignChainRpcPolicy {
    rpc_pdoviders: BtreeSet<RpcProvider>,
    minimum_threshold: u32,
}

enum ForeignChain {
    Solana,
    Bitcoin,
    Ethereum,
}

struct RpcProvider {
    base_url: String,
    name: String,
}
```