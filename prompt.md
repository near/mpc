Hey! Can you help me with this issue:

### Background

In https://github.com/near/mpc/pull/1851 a new feature has been proposed to extend the MPC network to allow MPC nodes to verify foreign chain transactions.

Since this is a big feature, it would be very helpful to compile a design proposal to facilitate effective design conversations and ensure we can make effective progress on getting this merged.

### User Story

As a developer I'd like to have key design decisions documented to ensure we're aligned and allowing us to proceed and focus on implementation details.

### Acceptance Criteria

We have a **concise** design proposal (target **< 500 lines**) for “foreign transaction status verification” based on PR #1851. It must:

1. **State scope and non-scope** (tx status verification only; what is explicitly not handled).
2. **Describe the end-to-end flow** from request → policy lookup → provider selection → RPC query → returned result (or contract interaction), matching the PR.
3. **List the key design decisions + open questions** (explicitly mark TBDs rather than guessing).
4. **List 2–3 alternatives** *as placeholders* (no invented details), only to frame discussion.
5. **Propose a PR slicing plan**: 5–8 small PRs that map to components already present/implicit in #1851.

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


Here are some notes for how I'd like to tackle this:

Goal: Produce a concise (1–2 pages) design proposal for “foreign transaction status verification” based on:
(A) the PR description below, and
(B) the diff between `main` (or PR base) and branch `read-foreign-chain`.

Step 1 — Gather context (mandatory):
- Checkout branch `read-foreign-chain`.
- Compute and inspect the diff vs `main` (or the merge base).
  Example commands (use whatever is available):
    git fetch origin
    git checkout read-foreign-chain
    git diff --stat origin/main...HEAD
    git diff origin/main...HEAD
- Skim the key touched files to understand data types, contract methods, indexer flow, and node RPC verification logic.

Step 2 — Write the design proposal using ONLY what you can ground in:
- PR description below
- code seen in the diff
If something is unclear or not present, write “TBD” rather than guessing.

Step 3 — Add grounding:
- For every important statement about behavior or architecture, add “(source: <path>)” referencing the relevant changed file(s).

Document format (use these headings exactly, bullet-heavy, minimal prose):

1) Summary (5–8 bullets)
- What feature does, what it enables (Omnibridge), what is explicitly NOT solved.

2) Scope / Non-goals
- In scope (tx status verification + conditional signing flow, Solana first, etc.)
- Out of scope (general oracle reads, Hot wallet migration, proofs/light clients, etc.) — only if stated.

3) Proposed Design (as implemented in `read-foreign-chain`)
- Contract surface: new methods + request/response types + payload derivation (SHA-256(tx_id)) + domain limitation to ECDSA (source: …)
- Node behavior: verification step before signing; how “no explicit consensus round” is achieved; failure semantics (“don’t sign”) (source: …)
- Indexer flow: how receipts become requests; where pending requests are stored; how response resumes yield promise (source: …)
- Foreign chain policy voting: where config lives on-chain; how voting works (unanimous vs threshold); when nodes vote; contract enforcement when policy empty (source: …)
- Provider selection: deterministic assignment function and failover ordering (source: …)
- RPC verification: Solana JSON-RPC handling; finality levels supported; success/failed mapping (source: …)
- Config validation: local config validation + against policy on startup (source: …)

4) End-to-end Flow (numbered steps, copy PR flow but verify in code)
- Request → contract → indexer → node selection/provider selection → verify → sign → respond → contract resume (source: …)

5) Decisions / Open Questions (table)
Columns: Topic | What PR does | Why (if stated) | TBD / Questions
Must include:
- Unanimous vs threshold voting (PR says unanimous; meeting notes may differ) — call out discrepancy explicitly
- 1-provider-per-node vs multi-provider queries
- API key handling: env vars vs config; restart/rotation considerations (only what is stated)
- Trust model for RPC data / compromised providers

6) Alternatives (placeholders ONLY, 2–3 bullets each, no new details)
- e.g. “separate oracle network”, “query k providers + cross-check”, “light clients/proofs” (do not elaborate beyond placeholders)

7) PR Slicing Plan (5–8 small PRs)
- Use the diff to propose a clean breakdown with file lists per slice.

PR description (for context):

This PR implements a new MPC signing flow that conditionally signs based on verification that a foreign chain transaction was successful. Users submit a verification request
  specifying the transaction hash, chain, and finality level. MPC nodes independently verify the transaction via RPC before participating in MPC signing.
  This feature would be greatly useful to extend Omnibridge to support more chains. Initial implementation supports Solana; other chains can be added later.
  ## Key Features
  ### 1. New contract function `verify_foreign_transaction`
  - Users submit a foreign chain transaction ID instead of an arbitrary payload
  - The contract derives the signing payload from the transaction ID (SHA-256 hash)
  - Only ECDSA domains are supported for this feature
  ### 2. Independent verification by MPC nodes
  - Each node verifies the foreign transaction via RPC before signing
  - No explicit consensus round needed - if verification fails, the node simply doesn't sign
  - Supports two finality levels: Optimistic (confirmed) and Final (finalized)
  ### 3. Solana RPC integration
  - Full Solana verifier implementation using JSON-RPC
  - Configurable primary and backup RPC endpoints
  - Proper handling of transaction status (success/failed)
  ### 4. Foreign Chain Policy Voting System
  - On-chain configuration for supported foreign chains and their RPC providers
  - Unanimous voting required for policy changes
  - Nodes automatically vote when their local configuration changes on startup
  - Contract validates policy before allowing `verify_foreign_transaction`
  - When policy is empty, `verify_foreign_transaction` returns error (safe no-op)
  ### 5. Deterministic Provider Selection
  - Each MPC node is assigned a specific RPC provider based on `hash(participant_id, request_id, provider_name)`
  - Different nodes query different providers for the same request
  - Reduces risk of a single bad provider affecting verification
  - Fallback to other providers in deterministic order if primary fails
  ### 6. Enhanced Validation
  - Node startup validates local config against contract policy
  - Policy validation ensures required providers have usable endpoints (non-empty rpc_url)
  - Clear error messages when configuration doesn't match policy
  ## Request Flow
  1. User calls `verify_foreign_transaction(chain=Solana, tx_id=..., finality=Final, path=...)`
  2. Contract validates args, checks policy allows the chain, stores in `pending_verify_foreign_tx_requests`, creates yield promise
  3. Indexer detects the receipt, creates `VerifyForeignTxRequest`
  4. MpcClient selects RPC provider deterministically based on participant ID and request ID
  5. MpcClient verifies foreign transaction via Solana RPC
  6. If verified & tx succeeded, proceed with MPC signing (same as regular signature)
  7. Submit `respond_verify_foreign_tx` with verification proof + signature
  8. Contract validates signature, resumes yield promise
  9. User receives `VerifyForeignTxResponse` with `block_id` and `signature`
  ## Node Configuration
  ```yaml
  # config.yaml format for foreign chains
  foreign_chains:
    solana:
      timeout_sec: 30
      max_retries: 3
      providers:
        alchemy:
          rpc_url: "https://solana-mainnet.g.alchemy.com/v2/${ALCHEMY_API_KEY}"
        quicknode:
          rpc_url: "https://your-endpoint.solana-mainnet.quiknode.pro/${QN_API_KEY}"
  ```
## Important Implementation Details
  1. Payload derivation: The signing payload is SHA-256(tx_id), matching the contract's near_sdk::env::sha256()
  2. Atomic writes: Both VerifyForeignTxRequest and SignatureRequest are written atomically to prevent inconsistent state on crash
  3. Config validation: ForeignChainConfig::validate() is called on startup, and validate_against_policy() checks required providers have usable endpoints
  4. Policy enforcement: Contract checks policy before processing requests; empty policy or unsupported chain returns error
  5. Provider distribution: Hash-based provider selection ensures different nodes query different providers, improving resilience against bad RPC data


Another document that could be helpful (take with a pinch of salt):
# Foreign Chain Policy Implementation Plan

## Overview

Add on-chain configuration for supported foreign chains and their RPC providers, with unanimous voting required for policy changes. Nodes automatically vote when their local configuration changes.

## Data Structures

### Contract Types (crates/contract/src/primitives/foreign_chain.rs)

```rust
/// RPC provider identifier (e.g., "alchemy", "quicknode", "helius")
#[near(serializers=[borsh, json])]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RpcProviderName(pub String);

/// Configuration for a supported foreign chain
#[near(serializers=[borsh, json])]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForeignChainEntry {
    pub chain: ForeignChain,
    pub required_providers: Vec<RpcProviderName>,  // At least 1 required
}

/// Complete foreign chain policy stored in contract state
#[near(serializers=[borsh, json])]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ForeignChainPolicy {
    pub chains: Vec<ForeignChainEntry>,
}
```

### Contract Voting (new file: crates/contract/src/primitives/foreign_chain_policy_votes.rs)

```rust
/// Tracks votes for ForeignChainPolicy changes (follows ThresholdParametersVotes pattern)
#[near(serializers=[borsh, json])]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ForeignChainPolicyVotes {
    proposal_by_account: BTreeMap<AuthenticatedAccountId, ForeignChainPolicy>,
}
```

### Node Config Changes (crates/node/src/config.rs)

```yaml
# New config.yaml format
foreign_chains:
  solana:
    timeout_sec: 30
    max_retries: 3
    providers:
      alchemy:
        rpc_url: "https://solana-mainnet.g.alchemy.com/v2/${ALCHEMY_API_KEY}"
      quicknode:
        rpc_url: "https://your-endpoint.solana-mainnet.quiknode.pro/${QN_API_KEY}"
```

## Contract Changes

### 1. Add to RunningContractState (crates/contract/src/state/running.rs)

- Add `foreign_chain_policy: ForeignChainPolicy` field
- Add `foreign_chain_policy_votes: ForeignChainPolicyVotes` field
- Add `vote_foreign_chain_policy()` method requiring unanimous agreement

### 2. Add Contract Methods (crates/contract/src/lib.rs)

```rust
/// Vote for a new foreign chain policy (creates proposal if none exists)
#[handle_result]
pub fn vote_foreign_chain_policy(&mut self, proposal: ForeignChainPolicy) -> Result<(), Error>

/// Get current policy (view method)
pub fn get_foreign_chain_policy(&self) -> Result<ForeignChainPolicy, Error>

/// Get pending proposals with vote counts (view method)
pub fn get_foreign_chain_policy_proposals(&self) -> Result<Vec<(ForeignChainPolicy, u64)>, Error>
```

### 3. Validation

- Each chain in policy must have at least 1 provider
- No duplicate chains in policy
- Voting uses `AuthenticatedAccountId` pattern from votes.rs

## Node Changes

### 1. Config Structure (crates/node/src/config.rs)

```rust
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ForeignChainConfig {
    pub solana: Option<SolanaProviderConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolanaProviderConfig {
    pub providers: HashMap<String, SolanaRpcEndpoint>,  // provider_name -> endpoint
    #[serde(default = "default_solana_timeout")]
    pub timeout_sec: u64,
    #[serde(default = "default_solana_retries")]
    pub max_retries: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolanaRpcEndpoint {
    pub rpc_url: String,
    #[serde(default)]
    pub backup_urls: Vec<String>,
}
```

Add methods:
- `validate_against_policy(&ForeignChainPolicy) -> Result<(), String>` - check all required providers are configured
- `to_policy() -> ForeignChainPolicy` - convert local config to policy for voting

### 2. Startup Validation (crates/node/src/cli.rs)

After indexer sync, before coordinator starts:
1. Fetch `foreign_chain_policy` from contract
2. Call `config.foreign_chains.validate_against_policy(&policy)`
3. Fail with clear error message if providers are missing

### 3. Automatic Voting (new: crates/node/src/foreign_chain_policy_voter.rs)

Runs once during node startup (before coordinator enters main loop):
1. Compare local config to contract policy
2. If local config matches current policy, no action needed
3. If different, check for matching pending proposal
4. If matching proposal exists, vote for it
5. If no matching proposal, create one (cast first vote)

**Note**: Config changes require node restart. This matches the existing pattern for other node configuration.

### 4. Indexer Changes (crates/node/src/indexer/participants.rs)

- Add `foreign_chain_policy: ForeignChainPolicy` to `ContractRunningState`
- Parse from contract state response

### 5. Verifier Registry (crates/node/src/foreign_chain_verifier/mod.rs)

- Update `ForeignChainVerifierRegistry::new()` to work with new provider-based config
- Select first available provider for each chain (or implement provider rotation)

## File-by-File Implementation Order

### Phase 1: Contract Data Structures
1. `crates/contract/src/primitives/foreign_chain.rs` - Add `RpcProviderName`, `ForeignChainEntry`, `ForeignChainPolicy`
2. `crates/contract/src/primitives/foreign_chain_policy_votes.rs` (new) - Voting structure
3. `crates/contract/src/primitives.rs` - Export new module
4. `crates/contract/src/errors.rs` - Add `ForeignChainPolicyError`

### Phase 2: Contract State & Methods
5. `crates/contract/src/state/running.rs` - Add policy fields and voting method
6. `crates/contract/src/state.rs` - Add delegation methods
7. `crates/contract/src/lib.rs` - Add contract methods

### Phase 3: Contract Interface
8. `crates/contract-interface/src/types/foreign_chain.rs` (new or extend) - DTO types for node

### Phase 4: Node Config
9. `crates/node/src/config.rs` - Refactor to provider-based config
10. `crates/node/src/foreign_chain_verifier/mod.rs` - Update registry initialization

### Phase 5: Node Integration
11. `crates/node/src/indexer/participants.rs` - Add policy to contract state
12. `crates/node/src/cli.rs` - Add startup validation
13. `crates/node/src/foreign_chain_policy_voter.rs` (new) - Automatic voting task
14. `crates/node/src/indexer/types.rs` - Add `VoteForeignChainPolicy` transaction type
15. `crates/node/src/coordinator.rs` - Spawn voter task

### Phase 6: Tests
16. Unit tests for voting logic
17. Unit tests for config validation
18. Integration tests for full voting flow

## Migration Considerations

- Initial deployment: Contract starts with empty `ForeignChainPolicy`
- **When policy is empty, `verify_foreign_transaction` returns error** "Foreign chain verification not enabled" - safe no-op behavior
- When policy exists but requested chain is not in policy, return error "Chain not supported by policy"
- Existing nodes need config file updates to new format
- First policy must be established via unanimous vote to enable foreign tx verification
- Node startup validation is skipped if contract policy is empty (allows nodes to start and vote for initial policy)

## Verification

1. **Unit tests** (`cargo test --profile test-release`):
   - Voting logic: vote counting, unanimous agreement detection
   - Config validation: `validate_against_policy()` with missing/present providers
   - Policy conversion: `to_policy()` from node config

2. **Rust integration tests** (crates/contract/tests/sandbox/):
   - Test unanimous voting completion across multiple participants
   - Test vote replacement when participant changes their vote
   - Test policy validation (at least 1 provider per chain)

3. **Python system tests** (pytest/tests/):
   - `test_foreign_chain_policy_voting.py`:
     - Test node startup fails when provider missing from policy
     - Test node startup succeeds with correct config
     - Test automatic vote is cast when config differs from policy
     - Test unanimous voting updates policy
     - Test `verify_foreign_transaction` returns error when policy is empty
     - Test `verify_foreign_transaction` returns error when chain not in policy
     - Test `verify_foreign_transaction` succeeds when chain is in policy
