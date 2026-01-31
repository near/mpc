Hey! Can you help draft an initial design doc in `docs/foreign_chain_transactions.md`? Heres a description of the issue:

### Background

In https://github.com/near/mpc/pull/1851 a new feature has been proposed to extend the MPC network to allow MPC nodes to verify foreign chain transactions.

Since this is a big feature, it would be very helpful to compile a design proposal to facilitate effective design conversations and ensure we can make effective progress on getting this merged.

### User Story

As a developer I'd like to have key design decisions documented to ensure we're aligned and allowing us to proceed and focus on implementation details.

### Acceptance Criteria

We have a design doc for the foreign transaction validation feature. The design doc should contain the following:

1. **Motivation.** Why is this feature important? What are the use-cases we want to support?
2. **High level component design.** What are the major components we're implementing, and how are they interacting? How does the flow look end to end when using this feature? Mermaid charts following the c4 model would be helpful here, as well as sequence diagrams for user flows and the voting flows (config updates + proposing new chains) etc.
3. **Risks**. What are the major risks if we implement this feature? Can we migrate pieces of it, or will this cause a big maintenance burden going forward.
4. **Alternatives considered.** Outline some of the alternatives to the design we've considered, and why we chose to proceed with the existing design.

### Resources & Additional Notes

Prototype implementation PR: https://github.com/near/mpc/pull/1851

Meeting notes from a discussion on this:
- We'll start small with only supporting foreign transaction status verification.
  - This is sufficient for the bridge use cases.
  - This will not help us migrate the Hot wallet use case.
  - Hot bridge should be able to work with this, but it would require significant refactors on their end.
- Supported RPC providers should be configured in the MPC contract.
  - We'll require a threshold number of votes to add a new RPC provider.
  - Nodes, not operators, will vote for the RPC providers as soon as they see a proposal they have configured API keys for.
- Each MPC node will call a single RPC provider, determined using consistent hashing similar to how we do leader election.

**Use case: Omnibridge**
See this quote from Bowen - this feature is key to allow using the MPC network to move assets from other chains to near.

> Chain Signatures is used in Omnibridge starting from Day 1. Near → Foreign Chain always uses chain signatures, whether the destination chain is Bitcoin, Zcash, Solana, Ethereum, etc. The other direction (foreign chain to Near) uses a variety of proving mechanisms including light clients and wormhole. However, we are also working on migrating that entirely to chain signatures.

PR description summary
This PR introduces a new MPC signing flow that conditionally signs only after independently verifying that a foreign-chain transaction has succeeded. Users submit a verification request containing a transaction hash, target chain, and finality level. Each MPC node independently verifies the transaction via RPC before participating in signing, with no additional consensus round required—nodes simply abstain if verification fails.

The initial implementation supports Solana and is designed to be easily extensible to additional chains. The contract exposes a new `verify_foreign_transaction` function that derives the signing payload from the transaction ID (SHA-256) and supports ECDSA domains. On-chain policy controls which foreign chains and RPC providers are allowed, with unanimous voting required for policy changes. Nodes automatically validate and synchronize their local configuration against this policy on startup.

Verification uses deterministic RPC provider selection based on participant ID and request ID, ensuring that different nodes query different providers for the same request, reducing reliance on any single RPC endpoint. Fallback to alternate providers is deterministic, improving resilience against faulty or malicious RPC responses.

This design enables secure, trust-minimized cross-chain signing and significantly extends Omnibridge’s multi-chain capabilities, providing a robust foundation for supporting additional foreign chains in the future.

The #1851 PR os on branch `read-foreign-chain`. Please inspect the diff to understand the current idea better. Also please look at key files to understand how the system works around these changes.
