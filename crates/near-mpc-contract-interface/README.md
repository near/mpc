# MPC Contract interface
This crate defines types for interacting with the MPC contract.

## Purpose
The purpose of this crate is to allow clients of the MPC contract
to construct requests and parse results of contract interactions,
without having to depend on the entire contract crate.

From a development perspective, this crate also helps us in a few ways:

1. It makes it easier to be lean on dependencies to not accidentally include complex types in the interface.
2. It allows us to control how these objects are serialized.

The serialized (JSON/borsh) wire format of these types *is* the public contract.
The MPC contract is free to refactor its internal types — storage layout,
invariant enforcement, `near-sdk` integration — without breaking callers, as
long as the wire format defined here is preserved.

Note that this crate is not intended to hold complicated validation logic that may be shared between the contract and other consumers of this crate. Such logic belongs in `near-mpc-sdk`.

## Feature flags

Two feature flags provide typed helpers for constructing contract calls:

- `call-args` — argument structs for the contract's methods
- `client` (implies `call-args`) — `MpcContractHandle`, a typed client
  generic over the transport traits of `near-contract-transport`. It is the
  single source of each method's wire format: method name, argument struct,
  gas, and deposit.

```rust
# #[cfg(feature = "client")] mod example {
use near_contract_transport::CallContract;
use near_mpc_contract_interface::client::{MpcContractHandle, MpcContractHandleError};
use near_mpc_contract_interface::types::{AccountId, SignRequestArgs};

// `caller` is any backend implementing the `CallContract` trait from
// `near-contract-transport` — e.g. an RPC client or a sandbox account
// submitting the transaction.
async fn sign<C: CallContract>(
    caller: C,
    contract_id: AccountId,
    request: SignRequestArgs,
) -> Result<C::Output, MpcContractHandleError<C::Error>> {
    let mpc_contract_handle = MpcContractHandle::new(caller, contract_id);
    mpc_contract_handle.sign(request).await
}
# }
```

## Design
The contract interface is designed to only be used by the MPC contract
and its callers, decoupling any direct dependencies on the MPC contract.

Moreover, the interface crate's default build should be lean and only depend
on primitive types and serialization utilities. The types here are plain data
carriers: unlike the contract's internal types, they enforce no invariants and
expose their fields directly. Consumers of this crate map between these DTOs and their own types at their own boundaries. Validation should be implemented on the consumer side or, if shared between different consumers, in the `near-mpc-sdk` crate.

Similarly, the `client` feature is not concerned with validating call-data or call-args. Its intention is to ensure a single source of truth for the contract's wire format.

```text
 ┌───────────┐ ┌────────┐ ┌──────────────┐
 │ MPC Node  │ │ Users  │ │ MPC Contract │
 └───────────┘ └────────┘ └──────────────┘
       │           │             │
       └───────┐   │    ┌────────┘
               │   │    │
               ▼   ▼    ▼
          ┌────────────────────┐
          │ Contract Interface │
          └────────────────────┘
                │     │
          ┌─────┘     └───┐
          │               │
          ▼               ▼
 ┌─────────────────┐┌─────────────────────────┐
 │ Primitive types ││ Serialization utilities │
 └─────────────────┘└─────────────────────────┘
```

### Design rules
A couple of conventions keep the crate lean and the wire format robust:

1. **`near-sdk` is not a dependency.** This means that
   consumers (the node, SDKs, external tools) don't need the full contract
   stack. Types that genuinely need `near-sdk` are gated behind the `near`
   feature rather than pulled in unconditionally.
2. **Prefer typed wrappers over bare `String`s.** Use typed wrappers
   instead of raw `String`s (e.g. `Ed25519PublicKey` from `near-mpc-crypto-types`)
   so that malformed values are rejected at deserialization, rather than
   deep in caller logic.

### A note on conversion logic
Currently this crate is intentionally free from any conversion
functions. It is currently up to the dependents of this crate
to define their conversion logic.

However, if we notice that this becomes very repetitive we
may consider extending this crate to contain common conversion helpers
under some feature flag(s).
