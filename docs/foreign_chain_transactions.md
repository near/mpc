# Foreign Chain Transaction Verification (Design Proposal)

Status: Draft (based on PR #1851 / branch `read-foreign-chain`)

## Purpose & Motivation

This feature lets the MPC network sign payloads only after verifying a specific foreign-chain transaction, so NEAR contracts can react to external chain events without a trusted relayer. Primary use cases:

- Omnibridge inbound flow (foreign chain -> NEAR) where Chain Signatures are required to attest that a foreign transaction finalized successfully.
- Broader chain abstraction: a single MPC network verifies foreign chain state and signs conditional payloads.

## Scope

- In scope: contract-level API for verify+sign requests, node-side verification via configured RPC providers, deterministic provider selection, and extensible per-chain verifiers.
- Out of scope: on-chain light clients / cryptographic proofs, multi-round MPC consensus on verification results, and non-ECDSA schemes for verify_foreign_transaction (initially ECDSA only).

## High-Level Design

### System Context Diagram

```mermaid
---
title: Foreign Chain Verification - System Context
---
flowchart TD
    DEV["**Developer / Bridge Service**
      _Submits verify_foreign_transaction requests._"]

    SC["**MPC Signer Contract**
      _On-chain policy + pending requests._"]

    MPC["**MPC Nodes**
      _Verify foreign tx status and sign._"]

    RPC["**RPC Providers**
      _JSON-RPC endpoints._"]

    FC["**Foreign Chain**
      _Solana, future chains._"]

    DEV -->|"1. verify_foreign_transaction()"| SC
    MPC -->|"3. respond_verify_foreign_tx()"| SC
    MPC -->|"2. query tx status"| RPC
    RPC -->|"read chain state"| FC

    DEV@{ shape: manual-input}
    SC@{ shape: db}
    MPC@{ shape: proc}
    RPC@{ shape: proc}
    FC@{ shape: cylinder}
```

### Core Flow: Foreign Chain Policy Updates (New Chains / Providers)

```mermaid
---
title: Foreign Chain Policy Updates - High Level
---
flowchart TD
    NODE["**MPC Node**
      _Local config + API keys._"]

    SC["**MPC Signer Contract**
      _Foreign chain policy._"]

    COMP["**Compare**
      _Local config vs policy._"]

    UPDATED["**Policy Updated**
      _Unanimous vote reached._"]

    NODE -->|"1. read policy"| SC
    NODE -->|"2. compare"| COMP
    COMP -->|"3. vote if different"| SC
    SC -->|"4. update policy on unanimity"| UPDATED

    NODE@{ shape: proc}
    SC@{ shape: db}
    COMP@{ shape: proc}
    UPDATED@{ shape: proc}
```

### Key Components and Responsibilities

**On-chain (mpc-contract)**

- New API:
  - `verify_foreign_transaction(request)` - stores request, yields a callback. Request includes `chain`, `tx_id`, `finality`, `path`, and optional `domain_id`.
  - `respond_verify_foreign_tx(request, response)` - validates signature + resolves the callback. Response includes `verified_at_block` and the signature.
  - `vote_foreign_chain_policy(proposal)` - unanimous vote to update supported chains/providers.
  - `get_foreign_chain_policy()` and `get_foreign_chain_policy_proposals()`.
- Policy gating:
  - If policy is empty, verification is **disabled**.
  - Request chain must be in policy.
  - Policy includes **provider names only** (no secrets).
- Payload derivation:
  - `payload = sha256(tx_id_bytes)` (ECDSA only).
  - For Solana, `tx_id` is a base58 signature in JSON, but the hash uses the raw 64-byte signature bytes.
  - The signed key is derived from the domain key and `tweak`.
- Chain-specific verification parameters (e.g., Solana finality or Bitcoin confirmations).

**Off-chain (mpc-node)**

- **ForeignChainVerifierRegistry**
  - Dispatches to chain-specific verifiers (initially Solana).
  - Uses deterministic provider selection.
- **Foreign Chain Policy Voter**
  - On startup: validates local config vs on-chain policy.
  - Auto-votes if policy differs from local config.
- **MPC Client**
  - Indexes verify_foreign_tx requests.
  - Verifies transaction via RPC, then runs MPC signing.
  - Responds to contract with `verified_at_block` + signature.
- **Storage**
  - `VerifyForeignTxStorage` persists verification requests.
  - Atomic write with `SignRequestStorage` to avoid crash inconsistencies.

### New contract methods
```rust
verify_foreign_transaction(request: VerifyForeignTxRequestArgs) -> VerifyForeignTxResponse // Through a promise
respond_verify_foreign_tx({ request, response }) // Respond method for signers
```

### New contract types

```rust
pub struct VerifyForeignTxRequestArgs {
    pub chain: ForeignChain,
    pub tx_id: TransactionId, // TxID is the payload we're signing
    pub path: String, // Key derivation path
    pub domain_id: Option<DomainId>, // Defaults to 0 (legacy ECDSA)
}

pub struct VerifyForeignTxRequest {
    // Constructed from the args
    pub chain: ForeignChain,
    pub tx_id: TransactionId,
    pub tweak: Tweak,
    pub domain_id: DomainId,
}

pub enum ForeignChain {
    Solana(SolanaConfig),
    Bitcoin(BitcoinConfig),
    // Future chains...
}

pub struct SolanaConfig {
    pub finality: SolanaFinality, // Optimistic or Final
}

pub enum SolanaFinality {
    Optimistic,
    Final,
}

pub struct BitcoinConfig {
    pub confirmations: usize, // required confirmations before considering final
}

pub struct VerifyForeignTxResponse {
    pub verified_at_block: BlockId,
    pub signature: SignatureResponse,
}
```

**What is signed and over what key**

- Payload is `sha256(tx_id_bytes)`, where `tx_id_bytes` are chain-native bytes (e.g., Solana 64-byte signature).
- Signature is ECDSA over that payload using the domain key derived with `tweak` (i.e., the derived key for `domain_id` + `tweak`).
- `tweak` should be derived deterministically (prototype uses `derive_tweak(predecessor_account_id, path)`), unless we explicitly move to passing raw tweaks.

### Failure and Timeout Behavior

- Nodes **abstain** if verification fails (RPC error, tx not found, or not finalized).
- A failed verification does **not** produce an on-chain failure response. The request eventually times out and fails with the standard timeout error.

### Deterministic Provider Selection

Each node selects a provider using a deterministic hash of:

```
hash = sha256(participant_id || request_id || provider_name)
```

Providers are sorted by this hash to build a deterministic ordering:

- **Primary provider** = first in the ordering.
- **Fallback** = subsequent providers in order.
- Each provider can include backup URLs for failover.

This ensures different nodes query different providers for the same request while preserving determinism.

### Configuration (Node)

Example config snippet:

```yaml
foreign_chains:
  solana:
    timeout_sec: 30
    max_retries: 3
    providers:
      alchemy:
        rpc_url: "https://solana-mainnet.g.alchemy.com/v2/${ALCHEMY_API_KEY}"
      quicknode:
        rpc_url: "https://your-endpoint.solana-mainnet.quiknode.pro/${QN_API_KEY}"
        backup_urls:
          - "https://backup.solana.quiknode.pro/${QN_API_KEY}"
```

The contract policy references providers by **name**, and nodes must have matching
provider entries in config (including API keys) to satisfy the policy.

## Risks

- **RPC trust and correctness**: Verification relies on centralized RPC providers. A malicious
  or faulty provider could return incorrect status for a subset of nodes.
- **No additional consensus**: Nodes independently verify and abstain on failure. If a threshold
  of nodes are misled by providers, the network could sign invalid payloads.
- **Provider availability**: Outages or rate limits can cause verification failures and reduced
  signing availability.
- **Finality semantics**: Finality definitions differ across chains; mapping them correctly is critical.
- **Operational friction**: Unanimous voting for policy updates may slow rollouts and hot fixes.
- **Config drift**: Nodes missing required provider keys will fail startup validation.

## Discussion points
- Finality interface right now diverges from the original PR. Are we okay with this new structure?
- Should the policy vote threshold stay **unanimous**, or be configurable (e.g., threshold)?
- Startup validation: when policy is empty, nodes skip config validation and can still boot/vote an initial policy. Is this the desired operational behavior?
