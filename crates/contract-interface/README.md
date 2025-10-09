# MPC Contract interface
This is crate defines types for interacting with the MPC contract.

## Purpose
The purpose of this crate is to allow clients of the MPC contract
to construct requests and parse results of contract interactions,
without having to depend on the entire contract crate.

From a development perspective, this crate also helps us in a few ways:

1. It makes it easier to be lean on dependencies to not accidentally include complex types in the interface.
2. It allows us to control how these objects are serialized.

## Vision
While this crate only contains plain data types (or DTOs) at the time of writing,
long term we may want to extend this to also include helper functions to construct
requests and parse responses to the contract.

## Design
The contract interface is designed to only be used by the MPC contract
and its callers, decoupling any direct dependencies on the MPC contract.

Moreover, the interface crate should be lean and only depend on primitive
types and serialization utilities.

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

### A note on conversion logic
Currently this crate is intentionally free from any conversion
functions. It is currently up to the dependents of this crate
to define their conversion logic.

However, if we notice that this becomes very repetitive we
may consider extending this crate to contain common conversion helpers
under some feature flag(s).
