# Domain Separation: Protocol & Governance Configuration Design

The addition of Robust ECDSA (aka DamgardEtAl) invalidates three assumptions in the current design:

✗ There is one protocol per curve (now: both CaitSith and DamgardEtAl operate over Secp256k1).

✗ All domains share a single cryptographic threshold. The node already has a `translate_threshold()` hack to bridge this gap.

✗ Governance voting threshold and cryptographic reconstruction threshold are the same value. The threshold of how many participants must vote to change parameters is currently the same `Threshold` value as the cryptographic reconstruction threshold.

Orthogonally, first trials of adding Robust ECDSA revealed an unecessary (a tech-dept) entanglement between the smart contract and the node which makes it difficult to update the Smart Contract "independently" of the node.

Goals:

- Split cryptographic and governance thresholds of the MPC network by which allows determining such info simply by reading the contract state.
- Allow flexibility and ease in adding new protocol schemes with different configurations without requiring major contract refactors.
- Disentangle the SC from the node.


## Table of Contents

1. [Current State Analysis](#1-current-state-analysis)
2. [Proposed Design](#2-proposed-design)
3. [Validation Logic](#3-validation-logic)
4. [Backwards-Compatible Migration Strategy](#4-backwards-compatible-migration-strategy)
5. [Shared Types Between Contract and Node](#5-shared-types-between-contract-and-node)
6. [Impact on State Machine](#6-impact-on-state-machine)
7. [Open Questions](#7-open-questions)


## 1. Current State Analysis

### 1.1 Contract Types (internal)

**`crates/contract/src/primitives/domain.rs`**:
```rust
pub struct DistributedKeyId(pub u64);

pub enum SignatureScheme {
    Secp256k1,
    Ed25519,
    Bls12381,
}

pub struct DistributedKeyConfig {
    pub id: DistributedKeyId,
    pub scheme: SignatureScheme,
    pub purpose: KeyPurpose,
}
```

**`crates/contract/src/primitives/thresholds.rs`**:
```rust
pub struct Threshold(u64);  // single global threshold

pub struct ThresholdParameters {
    participants: Participants,
    threshold: Threshold,  // applies to ALL domains uniformly
}
```

### 1.2 Contract-Interface DTOs

**`crates/near-mpc-contract-interface/src/types/state.rs`** mirrors the internal types:
```rust
pub enum SignatureScheme { Secp256k1, Ed25519, Bls12381 }
pub struct DistributedKeyConfig { pub id: DistributedKeyId, pub scheme: SignatureScheme, pub purpose: Option<KeyPurpose> }
pub struct ThresholdParameters { pub participants: Participants, pub threshold: Threshold }
```

### 1.3 Node Usage

The node (`crates/node/`) imports types from **both** the internal contract crate and the contract-interface DTO crate:

| Import source | Count | Used for |
|---|---|---|
| `mpc_contract::primitives::domain::{DistributedKeyId, SignatureScheme, DistributedKeyConfig}` | ~30 files | Routing to providers, keyshare storage, key events |
| `mpc_contract::primitives::key_state::{EpochId, KeyEventId, Keyset, ...}` | ~20 files | Key lifecycle, storage, coordination |
| `mpc_contract::primitives::thresholds::{Threshold, ThresholdParameters}` | ~5 files | Threshold extraction for crypto protocols |
| `mpc_contract::primitives::signature::{Payload, SignRequest, ...}` | ~8 files | Request handling, signing |
| `mpc_contract::state::ProtocolContractState` | ~5 files | State machine transitions |
| `near_mpc_contract_interface::types` | ~10 files | Indexer queries, public key types, config |

### 1.4 Threshold Flow Through the System

```
Contract ThresholdParameters.threshold (Threshold(u64))
  → Coordinator extracts: threshold: usize = mpc_config.participants.threshold.try_into()?
  → Converts to: ReconstructionLowerBound::from(threshold)
  → For CaitSith/FROST: passed directly to keygen/sign
  → For DamgardEtAl: translate_threshold() → MaxMalicious::from((n_signers - 1) / 2)
```

The `translate_threshold()` function in `crates/node/src/providers/robust_ecdsa.rs` is an explicit workaround for the mismatch between the contract's single threshold and DamgardEtAl's `MaxMalicious` semantics. The code itself documents this as a hack:
> "This function translates the current threshold from the contract to the threshold expected by the robust-ecdsa scheme, which is semantically different."

### 1.5 Current Curve-Protocol Pairings

| Curve | Protocol | Purpose | Deployed |
|---|---|---|---|
| Secp256k1 | CaitSith | Sign, ForeignTx | Yes |
| Ed25519 | FROST | Sign | Yes |
| Bls12381 | CKD | CKD | Yes |
| Secp256k1 | DamgardEtAl | Sign | Ongoing |


## 2. Proposed Design

### 2.1 New Contract Types

```rust
/// Distributed key configuration. Specifies the protocol, threshold,
/// and purpose for a single distributed key managed by the MPC network.
pub struct DistributedKeyConfig {
    pub id: DistributedKeyId,
    pub protocol: Protocol,
    pub reconstruction_threshold: ReconstructionThreshold,
    pub purpose: KeyPurpose,
}

/// Governs the participant set and voting rules for governance
/// decisions (adding domains, changing parameters).
/// Decoupled from cryptographic thresholds: `governance_threshold`
/// controls how many participants must agree on a governance action,
/// independent of any distributed key's `ReconstructionThreshold`.
pub struct GovernanceBody {
    pub participants: Participants,
    pub governance_threshold: GovernanceThreshold,
}

/// Minimum number of participant votes required to approve a
/// governance action (resharing, adding domains, etc.).
pub struct GovernanceThreshold(pub u64);

/// Number of shares required to reconstruct the secret key.
/// This is the "t" in a t-of-n threshold scheme: the minimum number of
/// key shares that must be combined to recover the secret.
/// The inner value is private; construction goes through `new()`.
pub struct ReconstructionThreshold(u64);

impl ReconstructionThreshold {
    pub fn new(value: u64) -> Self;
    pub fn inner(&self) -> u64;
}

/// Identifies the elliptic curve. Used by the contract to verify
/// signature responses and derive public keys.
pub enum Curve {
    Secp256k1,
    Edwards25519,  // renamed from Ed25519 for clarity
    Bls12381,
}

/// Identifies the threshold signature protocol.
/// Each variant is parameterized with a `Curve`, making it possible
/// for any protocol to operate over different curves in the future.
pub enum Protocol {
    CaitSith(Curve),
    Frost(Curve),
    ConfidentialKeyDerivation(Curve),
    DamgardEtAl(Curve),
}

impl Protocol {
    /// Extracts the curve from any protocol variant.
    pub fn curve(&self) -> Curve {
        match self {
            Self::CaitSith(c)
            | Self::Frost(c)
            | Self::ConfidentialKeyDerivation(c)
            | Self::DamgardEtAl(c) => *c,
        }
    }

    /// Convenience constructors for current default pairings.
    pub fn cait_sith() -> Self { Self::CaitSith(Curve::Secp256k1) }
    pub fn frost() -> Self { Self::Frost(Curve::Edwards25519) }
    pub fn ckd() -> Self { Self::ConfidentialKeyDerivation(Curve::Bls12381) }
    pub fn damgard_et_al() -> Self { Self::DamgardEtAl(Curve::Secp256k1) }
}
```

### 2.2 Design Rationale

#### Why `Curve` is embedded in `Protocol`, not stored separately

Every `Protocol` variant carries its `Curve` as data. This makes the curve-protocol relationship explicit and type-safe — there is no separate `curve` field to validate or keep in sync. The `Protocol::curve()` method provides uniform access via a single match arm with `|` binding.

Today each protocol uses exactly one curve, so convenience constructors (`Protocol::cait_sith()`, etc.) encode the current defaults. If a protocol later supports multiple curves, call sites simply use the variant directly — e.g. `Protocol::Frost(Curve::Secp256k1)` — with no structural changes needed.

#### Why no separate `KeyConfig` / `ProtocolConfig` struct

Earlier iterations of this design had a separate `KeyConfig` struct containing `protocol` and `reconstruction_threshold`, nested inside `DistributedKeyConfig`. Since `DistributedKeyConfig` is the only consumer of these fields, the extra indirection adds no value — it just means an extra `.key_config.` in every access path. Flattening `protocol` and `reconstruction_threshold` directly into `DistributedKeyConfig` is simpler and equally extensible.

Distributed keys sharing the same protocol/threshold (e.g., Sign and ForeignTx both using CaitSith/Secp256k1/threshold=6) will have duplicate field values. This is acceptable — the duplication is trivial in storage cost, and validation during resharing simply iterates all distributed keys.


### 2.3 Relationship to Existing Types

| Current | Proposed | Change |
|---|---|---|
| `SignatureScheme` | `Protocol(Curve)` | Protocol is the primary identifier; curve is embedded in each variant |
| `DomainConfig` | `DistributedKeyConfig` | Renamed; `protocol` and `reconstruction_threshold` inlined directly (no separate `KeyConfig`) |
| `DomainId` | `DistributedKeyId` | Renamed to match `DistributedKeyConfig` |
| `DomainPurpose` | `KeyPurpose` | Renamed to match `DistributedKeyConfig` |
| `DomainRegistry` | `DistributedKeyRegistry` | Renamed (with serde alias for compat) |
| `ThresholdParameters` | `GovernanceBody` (governance) + `DistributedKeyConfig.reconstruction_threshold` (crypto) | Split into two concerns |
| `Threshold` | `GovernanceThreshold` + `ReconstructionThreshold` (`ActiveParticipantsThreshold` can be indirectly derived from `ReconstructionThreshold`) | Distinct newtypes for distinct purposes |

### 2.4 State Structure

```rust
pub struct RunningContractState {
    #[serde(alias = "domains")]  // compat: accept old field name
    pub distributed_keys: DistributedKeyRegistry,
    pub keyset: Keyset,
    pub governance: GovernanceBody,     // RENAMED from parameters, threshold is voting-only
    pub governance_votes: GovernanceVotes,  // RENAMED from parameters_votes
    pub add_domains_votes: AddDomainsVotes,
    pub previously_cancelled_resharing_epoch_id: Option<EpochId>,
}
```

Note: `DistributedKeyRegistry` is renamed from `DomainRegistry`. Use `#[serde(alias = "DomainRegistry")]` on the type (or `#[serde(alias = "domains")]` on the field) for wire compatibility.

### 2.5 KeyEvent Changes

`KeyEvent` currently carries `ThresholdParameters` to know the participant set and threshold for key generation. With the split:

```rust
pub struct KeyEvent {
    pub epoch_id: EpochId,
    pub distributed_key: DistributedKeyConfig,  // protocol + reconstruction threshold + purpose
    pub governance: GovernanceBody,              // participant set
    pub instance: Option<KeyEventInstance>,
    pub next_attempt_id: AttemptId,
}
```

The `KeyEvent` needs both: `GovernanceBody` for who participates, and `DistributedKeyConfig` for the protocol and cryptographic threshold to enforce during generation/resharing.

---

## 3. Validation Logic

### 3.1 Threshold Validation

#### 3.1.1 Threshold Validation per Protocol

Each protocol has different constraints on `ReconstructionThreshold` relative to the participant count:

```rust
/// Validates that the reconstruction threshold is achievable
/// given the number of participants.
pub fn validate_threshold(config: &DistributedKeyConfig, num_participants: u64) -> Result<(), Error> {
    let t = config.reconstruction_threshold.inner();

    // Universal constraints
    if t < 2 {
        return Err(Error::ThresholdTooLow);
    }
    if t > num_participants {
        return Err(Error::ThresholdExceedsParticipants);
    }

    // Protocol-specific constraints
    match config.protocol {
        Protocol::DamgardEtAl(_) => {
            // DamgardEtAl works in honest majority setting
            // i.e. requires t < n/2
            if 2 * t - 1 > num_participants {
                return Err(Error::InsufficientParticipantsForProtocol {
                    required: 2 * t - 1,
                    available: num_participants,
                });
            }
            Ok(())
        }
        _ => Ok(()),
    }
}
```

#### 3.1.2 Resharing Validation

When resharing (changing participants/threshold), we need to validate that:
1. The new governance threshold is valid for the new participant count.
2. **Every** existing distributed key's `reconstruction_threshold` remains achievable with the new participant set.
3. Enough old participants are retained to meet both governance and cryptographic thresholds.

```rust
/// Validates that all distributed keys remain valid under a new participant count.
pub fn validate_for_participant_count(
    keys: &DistributedKeyRegistry,
    num_participants: u64,
) -> Result<(), Error> {
    for key in keys.iter() {
        validate_threshold(key, num_participants).map_err(|e| {
            Error::ThresholdIncompatibleWithNewParticipants { distributed_key_id: key.id, inner: e }
        })?;
    }
    Ok(())
}

/// Returns the minimum number of participants required across all distributed keys.
pub fn min_participants_required(domains: &DistributedKeyRegistry) -> u64 {
    domains.iter().map(|d| {
        min_active_participants(&d.protocol, &d.reconstruction_threshold)
    }).max().unwrap_or(0)
}

/// Returns the minimum number of active participants needed to run the
/// given protocol at the specified reconstruction threshold.
pub fn min_active_participants(
    protocol: &Protocol,
    reconstruction_threshold: &ReconstructionThreshold,
) -> u64 {
    let t = reconstruction_threshold.inner();
    match protocol {
        // DamgardEtAl requires honest majority: n >= 2t - 1
        Protocol::DamgardEtAl(_) => 2 * t - 1,
        // All other protocols need at least t participants
        _ => t,
    }
}

/// Returns the valid range of reconstruction thresholds for a new distributed key
/// given the protocol and current participant count.
pub fn threshold_range(
    protocol: &Protocol,
    num_participants: u64,
) -> Option<(u64, u64)> {
    let min = 2u64;
    let max = match protocol {
        Protocol::DamgardEtAl(_) => (num_participants + 1) / 2,
        _ => num_participants,
    };
    if min > max { None } else { Some((min, max)) }
}
```

### 3.2 Governance Validation

```rust
pub fn validate_governance(governance: &GovernanceBody) -> Result<(), Error> {
    let n = governance.participants.len() as u64;
    let t = governance.governance_threshold.0;
    if t < 2 { return Err(Error::GovernanceThresholdTooLow); }
    if t > n { return Err(Error::GovernanceThresholdExceedsParticipants); }
    // Governance minimum: >= 60% (same policy as current)
    let min_relative = (3 * n).div_ceil(5);
    if t < min_relative {
        return Err(Error::GovernanceThresholdBelowMinimumRelative);
    }
    Ok(())
}
```

---

## 4. Backwards-Compatible Migration Strategy

### 4.1 Guiding Principles

Every PR in the sequence must satisfy:

1. **No on-chain breakage**: The deployed contract's Borsh-serialized state must remain deserializable after each upgrade. If a struct layout changes, a `migrate()` function converts old to new.
2. **No external API breakage**: View methods used by external consumers (block explorers, SDK clients, monitoring) — such as `state()`, `public_key()`, `sign()` — must remain backward-compatible. This is achieved by keeping the existing `state()` view method unchanged and adding `state_v2()` when the DTO shape changes.
3. **Partner-node functions can break**: Functions only called by partner nodes (`vote_*`, `respond*`, `start_keygen_instance`, `start_reshare_instance`, etc.) may introduce breaking JSON changes without compat shims on the contract side. The upgrade order is nodes first, then contract (see §4.5), so new nodes must handle both old and new contract, but the contract does not need to accept old-format calls from nodes.
4. **Each PR is independently deployable**: The system must be functional after each PR lands, even if subsequent PRs are delayed.

### 4.2 Step-by-Step PR Plan

Below is the proposed PR sequence. PRs marked **[DONE]** have already landed. PRs that can be parallelized are noted.

---

#### PR 1 — Rename `SignatureScheme` to `Curve` (internal contract types) **[DONE]**

**Scope**: `crates/contract/src/primitives/domain.rs`, `dto_mapping.rs`, affected call sites.

**Changes**:
- Rename enum `SignatureScheme` to `Curve` and field `.scheme` to `.curve` in internal `DistributedKeyConfig`.
- Add `#[serde(rename = "scheme")]` on `DistributedKeyConfig.curve` to keep JSON wire format identical.
- `DistributedKeyConfigCompat` uses `#[serde(alias = "scheme")]` so both old and new JSON deserialize.
- contract-interface DTO keeps `SignatureScheme` and `scheme` field unchanged.
- `dto_mapping.rs` bridges `Curve` <-> `dtos::SignatureScheme`.

**Borsh compat**: Renaming a Rust type/field does not change Borsh encoding (Borsh uses positional encoding). No migration needed.

**JSON compat**: `#[serde(rename)]` ensures serialization still emits `"scheme"`. Deserialization accepts both via alias.

---

#### PR 2 — Rename `Curve::Ed25519` to `Curve::Edwards25519` **[DONE]**

**Scope**: `crates/contract/src/primitives/domain.rs`, affected match arms.

**Changes**:
- Rename variant `Curve::Ed25519` to `Curve::Edwards25519`.
- Add `#[serde(rename = "Ed25519")]` on the variant for full wire compat (both ser and deser use old name).
- contract-interface DTO untouched (`SignatureScheme::Ed25519` stays).

**Borsh compat**: Same variant index, no migration.

**JSON compat**: `#[serde(rename)]` on variant.

---

#### PR 3 — Delete `V2Secp256k1` and add `Protocol` enum

**Scope**: `crates/contract/src/primitives/domain.rs`, `crates/near-mpc-contract-interface/src/types/state.rs`, node provider routing.

**Precondition**: `V2Secp256k1` is not deployed to mainnet. No on-chain state references this variant.

**Changes (delete V2Secp256k1)**:
- Remove `V2Secp256k1` from internal `Curve` enum.
- Remove `V2Secp256k1` from DTO `SignatureScheme` enum.
- Remove `is_valid_scheme_for_purpose` entry for `V2Secp256k1`.
- Remove the `KeyshareData::V2Secp256k1` variant in the node (or gate behind a feature flag if reshare data exists in dev/testnet).
- Update `coordinator.rs` routing: the `V2Secp256k1` match arm is removed; robust ECDSA will be routed via `Protocol::DamgardEtAl(_)` (added below).

**Changes (add Protocol enum)**:
- Add new enum:
  ```rust
  #[near(serializers=[borsh, json])]
  pub enum Protocol {
      CaitSith(Curve),                    // OT-based ECDSA (default: Secp256k1)
      Frost(Curve),                       // Threshold Schnorr (default: Edwards25519)
      ConfidentialKeyDerivation(Curve),   // BLS-based CKD (default: Bls12381)
      DamgardEtAl(Curve),                 // Robust ECDSA (default: Secp256k1)
  }
  ```
- `Protocol` variants carry `Curve` as data; `Protocol::curve()` extracts it (see §2.1).
- Add convenience constructors for current default pairings (`Protocol::cait_sith()`, etc.).
- **No changes to `DistributedKeyConfig` yet** — `Protocol` exists but is not wired into state.
- No changes to contract-interface DTO.

**Borsh compat**: Removing `V2Secp256k1` (last variant, index 3) does not shift other variant indices. No stored state references it. `Protocol` is a new type, not stored yet. No migration needed.

**JSON compat**: No deployed contract emits `V2Secp256k1`. `Protocol` is not exposed yet. No impact.

**Risk**: If any testnet/devnet deployment has `V2Secp256k1` domains, those nodes will fail to deserialize. Acceptable if coordinated with testnet reset.

---

#### PR 4 — Add `Protocol`, `ReconstructionThreshold`, update `DistributedKeyConfig`

**Scope**: `crates/contract/src/primitives/domain.rs`, `crates/contract/src/dto_mapping.rs`, `crates/near-mpc-contract-interface/src/types/state.rs`.

This is the most complex PR. It wires `Protocol` and `Curve` together and changes `DistributedKeyConfig`'s shape. `protocol` and `reconstruction_threshold` are flattened directly into `DistributedKeyConfig` (see §2.2 rationale — no separate `KeyConfig` struct).

**Changes (contract internals)**:
- Add `ReconstructionThreshold(u64)` newtype.
- Update `DistributedKeyConfig`:
  ```rust
  // Before:
  pub struct DistributedKeyConfig { pub id: DistributedKeyId, pub curve: Curve, pub purpose: KeyPurpose }
  // After:
  pub struct DistributedKeyConfig { pub id: DistributedKeyId, pub protocol: Protocol, pub reconstruction_threshold: ReconstructionThreshold, pub purpose: KeyPurpose }
  ```
- `DistributedKeyConfigCompat` no longer needs to handle the old `{ "scheme": "Secp256k1" }` format for `vote_add_domains` — partner nodes will use the new format directly. `DistributedKeyConfigCompat` can be simplified or removed.

**Changes (contract-interface DTO)**:
- Add new DTO types: `dtos::Protocol`, `dtos::ReconstructionThreshold`.
- Update `dtos::DistributedKeyConfig` to include `protocol` and `reconstruction_threshold`.
- Add new view method `state_v2()` that returns the new DTO structure (for nodes).
- Existing `state()` continues to return old DTO format via `dto_mapping.rs` (for external consumers: block explorers, SDK clients).

**Changes (dto_mapping.rs)**:
- Map internal `DistributedKeyConfig` to old `dtos::DistributedKeyConfig` (for `state()`) by deriving `curve` from `protocol`.
- Map internal `DistributedKeyConfig` to new `dtos::DistributedKeyConfig` (for `state_v2()`).

**Borsh compat**: `DistributedKeyConfig`'s Borsh layout changes (from `(DistributedKeyId, Curve, KeyPurpose)` to `(DistributedKeyId, Protocol, ReconstructionThreshold, KeyPurpose)`). Requires `migrate()`:
```rust
fn migrate(old: OldDistributedKeyConfig) -> DistributedKeyConfig {
    DistributedKeyConfig {
        id: old.id,
        protocol: protocol_from_legacy_curve(old.curve),  // infer protocol + curve from old curve
        // Use global threshold as default for all existing distributed keys
        reconstruction_threshold: ReconstructionThreshold(old_global_threshold),
        purpose: old.purpose,
    }
}
```

Note: Migration needs a `protocol_from_legacy_curve(Curve) -> Protocol` helper to infer the protocol (with its curve) from legacy curve values. This is unambiguous for existing distributed keys since each deployed curve maps to exactly one protocol (e.g., `Curve::Secp256k1` → `Protocol::CaitSith(Curve::Secp256k1)`).

**JSON compat**:
- External consumers calling `state()` see unchanged JSON.
- `vote_add_domains` uses the new `DistributedKeyConfig` JSON format directly (breaking change OK — partner-node-only function).

**Node changes**: Minimal in this PR — node can continue using `state()`. Full node migration happens in PR 7.

**Tests**: Borsh migration roundtrip tests (old state → migrate → new state → serialize → deserialize). Verify `state()` output is unchanged. Verify `state_v2()` returns new structure. Verify `vote_add_domains` accepts new `DistributedKeyConfig` JSON.

---

#### PR 5 — Add per-domain threshold validation

**Scope**: `crates/contract/src/primitives/thresholds.rs`, `crates/contract/src/state/running.rs`, `crates/contract/src/state/key_event.rs`.

**Precondition**: PR 4 landed. `DistributedKeyConfig.reconstruction_threshold` exists but is populated from the global threshold during migration.

**Changes**:
- Add `validate_threshold(config: &DistributedKeyConfig, num_participants)` with protocol-specific rules:
  - CaitSith/Frost/CKD: `t <= n` (same as current).
  - DamgardEtAl: `2t - 1 <= n`.
- Add `min_active_participants(protocol, reconstruction_threshold)` helper (see §3.1).
- Update `vote_add_domains` to validate each new distributed key's `reconstruction_threshold` against the current participant count.
- Update `KeyEvent` to pass per-key threshold (from `DistributedKeyConfig.reconstruction_threshold`) instead of the global threshold.
- Update resharing validation: `validate_incoming_proposal` must check that ALL existing distributed keys' thresholds remain achievable under the proposed new participant count.
- Existing distributed keys continue to have `reconstruction_threshold == global_threshold` (set during PR 4 migration). New keys can choose a different value.

**Borsh compat**: No struct layout changes (threshold is already in `DistributedKeyConfig` from PR 4). No migration.

**Key behavioral change**: This is where `DistributedKeyConfig` gains real per-key threshold semantics. Before this PR, the `reconstruction_threshold` was always the global value.

**Tests**: Unit tests for `validate_threshold` edge cases: DamgardEtAl with `2t-1 == n` (boundary), `2t-1 > n` (reject), `t < 2` (reject). Resharing validation tests: propose new participant set that violates one domain's threshold. Verify `vote_add_domains` rejects invalid thresholds.

---

#### PR 6 — Separate governance threshold from signing thresholds

**Scope**: `crates/contract/src/primitives/thresholds.rs`, `crates/contract/src/state/`.

**Changes**:
- Add `GovernanceThreshold(u64)` newtype.
- Add `GovernanceBody` struct:
  ```rust
  pub struct GovernanceBody {
      pub participants: Participants,
      pub governance_threshold: GovernanceThreshold,
  }
  ```
- In `RunningContractState`, replace `parameters: ThresholdParameters` with `governance: GovernanceBody`.
- Update all vote-counting logic to use `governance.governance_threshold` instead of `parameters.threshold()`.
- `KeyEvent` retains its per-key `DistributedKeyConfig.reconstruction_threshold` for crypto operations.
- Keep `ThresholdParameters` as a private type or remove it if no longer needed.

**Borsh compat**: `RunningContractState` layout changes. Requires `migrate()`:
```rust
fn migrate(old: OldRunningContractState) -> RunningContractState {
    RunningContractState {
        governance: GovernanceBody {
            participants: old.parameters.participants().clone(),
            governance_threshold: GovernanceThreshold(old.parameters.threshold().value()),
        },
        // ... other fields unchanged
    }
}
```

**JSON compat**:
- `state()` view method continues to emit old format (maps `GovernanceBody` back to `ThresholdParameters` DTO) for external consumers.
- `state_v2()` emits the new `GovernanceBody` structure.
- `vote_new_parameters` accepts the new `GovernanceBody` JSON directly (breaking change OK — partner-node-only function).

**Behavioral change**: After this PR, governance votes and crypto thresholds are fully decoupled. Changing participants (`vote_new_parameters`) updates the `GovernanceBody` but does not automatically change any domain's `reconstruction_threshold`.

**Tests**: Borsh migration roundtrip for `RunningContractState`. Verify `state()` maps `GovernanceBody` back to `ThresholdParameters` DTO. Verify vote-counting uses `governance_threshold`. Verify resharing still validates all per-domain thresholds.

---

#### PR 7 — Update node to consume new contract types

**Scope**: `crates/node/src/coordinator.rs`, `crates/node/src/key_events.rs`, `crates/node/src/providers/`.

**Changes**:
- Node switches from `state()` to `state_v2()` for contract queries, with fallback to `state()` when `state_v2()` is not available (during Phase A of the rolling upgrade, before the contract is deployed). The fallback path constructs a synthetic `DistributedKeyConfig` from the old state:
  ```rust
  // Fallback: old contract, state() only
  let distributed_key = DistributedKeyConfig {
      id: old_domain_id,
      protocol: protocol_from_legacy_curve(old_scheme),  // infer protocol + curve from old curve
      reconstruction_threshold: ReconstructionThreshold(global_threshold),
      purpose: old_purpose,
  };
  ```
- Coordinator reads per-key `DistributedKeyConfig` from contract state instead of using global threshold.
- Replace `translate_threshold()` hack in `robust_ecdsa.rs` with the `min_active_participants()` helper:
  ```rust
  // Node computes required active signers from DistributedKeyConfig
  let active_signers = min_active_participants(&dk.protocol, &dk.reconstruction_threshold);
  ```
  Note: `translate_threshold()` is still needed on the `state()` fallback path (it's effectively moved into the synthetic `DistributedKeyConfig` construction above). It can be fully removed once the old contract is guaranteed gone.
- Provider routing uses `Protocol` enum instead of pattern-matching on `SignatureScheme`/`Curve`:
  ```rust
  match dk.protocol {
      Protocol::CaitSith(_) => EcdsaSignatureProvider,
      Protocol::Frost(_) => EddsaSignatureProvider,
      Protocol::ConfidentialKeyDerivation(_) => CKDProvider,
      Protocol::DamgardEtAl(_) => RobustEcdsaSignatureProvider,
  }
  ```

**No contract changes in this PR** — purely a node-side consumer update.

**Tests**: Integration tests with both old contract (fallback to `state()`) and new contract (`state_v2()`). Verify DamgardEtAl active-signers derivation produces correct values. Verify provider routing for all protocol types.

---

#### PR 8 — Move shared primitives to `mpc-primitives` crate

**Scope**: `crates/primitives/src/`, `crates/contract/`, `crates/node/`, `crates/near-mpc-contract-interface/`.

**Changes**:
- Move pure data types to `mpc-primitives`:
  - Identity newtypes: `DistributedKeyId`, `EpochId`, `AttemptId`, `KeyEventId`, `ParticipantId`.
  - Enums: `Curve`, `Protocol`, `KeyPurpose`.
  - Request types: `Payload`, `Tweak`, `SignRequest`, `SignRequestArgs`.
  - Threshold newtypes: `ReconstructionThreshold`, `GovernanceThreshold`.
- `mpc-primitives` is `no_std` compatible, depends only on `borsh` + `serde`.
- Both `mpc-contract` and `near-mpc-contract-interface` depend on `mpc-primitives` and re-export its types.
- Update all imports across contract and node.

**This is a large but mechanical refactor** — only import paths change, no logic changes.

---

#### PR 9 — Remove node's direct dependency on `mpc-contract`

**Scope**: `crates/node/Cargo.toml`, all `use mpc_contract::` imports in node.

**Precondition**: PR 8 landed. All types the node needs are available from `mpc-primitives` or `near-mpc-contract-interface`.

**Changes**:
- Replace remaining `use mpc_contract::` imports with `use mpc_primitives::` or `use near_mpc_contract_interface::types::`.
- Move `BackupServiceInfo`, `DestinationNodeInfo`, `NodeMigrations` out of `mpc-contract` (to a shared crate or `node-types`).
- Move TEE types to dedicated crate or `mpc-primitives`.
- Move `protocol_state_to_string` to node (trivial utility).
- Remove `mpc-contract` from `crates/node/Cargo.toml`.

**Result**: Clean dependency graph where the node never imports contract internals.

---

### 4.3 PR Dependency Graph

```
PR 1 [DONE] --> PR 2 [DONE] --+--> PR 3 (delete V2Secp256k1 + add Protocol)
                               |         |
                               |         v
                               |    PR 4 (Protocol + ReconstructionThreshold + DistributedKeyConfig update + state_v2())
                               |         |
                               |         +---> PR 5 (per-domain threshold validation)
                               |         |       |
                               |         |       v
                               |         |    PR 6 (GovernanceBody separation)
                               |         |       |
                               |         |       v
                               |         +--> PR 7 (node consumes new types)
                               |
                               +--> PR 8 (move types to mpc-primitives)
                                         |
                                         v
                                    PR 9 (remove node -> contract dep)
                                         [depends on PR 7 + PR 8]
```

**Parallelization notes**:
- PR 3 and PR 8 can start in parallel after PR 2. PR 8 (move existing types to `mpc-primitives`) only moves existing, unchanged types and doesn't depend on new types being added.
- PR 4 depends on PR 3.
- PRs 5 and 7 can be developed in parallel after PR 4, though PR 7 should land after PR 6 to consume the final type shapes.
- PR 9 depends on both PR 7 and PR 8.

**Consolidation option**: Since partner-node compat shims are no longer needed (§4.1 principle 3), PRs 4+5+6 could be combined into a single contract PR with one Borsh `migrate()`. This reduces deployment overhead (one contract upgrade instead of two) at the cost of a larger PR to review. See open question §7.6.

### 4.4 Backwards Compatibility Techniques Reference

Each technique used in the PR plan, summarized:

| Technique | What it achieves | Example |
|---|---|---|
| `#[serde(rename = "old")]` on field/variant | Serializes using old name, deserializes old name | `Curve::Edwards25519` serializes as `"Ed25519"` |
| `#[serde(alias = "old")]` on field | Deserializes both old and new name, serializes new name | `DistributedKeyConfigCompat.curve` accepts `"scheme"` |
| `migrate()` in contract | Converts Borsh-stored old state to new layout on upgrade | `OldRunningContractState` to `RunningContractState` |
| `state()` + `state_v2()` view methods | External consumers see old DTO via `state()`, nodes see new DTO via `state_v2()` | Block explorers continue to work unchanged |
| `dto_mapping.rs` | Decouples internal type evolution from public API | Internal `GovernanceBody` maps to DTO `ThresholdParameters` |
| Borsh variant index preservation | Adding/removing enum variants at the end is safe | Remove `V2Secp256k1` (last variant) without shifting others |
| Breaking change on node-facing functions | Partner nodes upgrade with the contract, no compat needed | `vote_add_domains` uses new `DistributedKeyConfig` JSON directly |

### 4.5 Upgrade Scenario

Node-facing functions (`vote_*`, `respond*`, etc.) are only called by partner nodes, but nodes don't all upgrade at the exact same time — there is a rolling window where old and new nodes coexist. The recommended upgrade order is **nodes first, then contract**:

**Phase A — Roll out new node binary**:
1. New nodes are backwards-compatible: they can work with the old contract (no `state_v2()` yet, old JSON formats for `vote_*` calls).
2. Gradually upgrade all partner nodes. During this window, all nodes — old and new — still talk to the old contract.

**Phase B — Deploy new contract**:
1. Once all nodes are running the new binary, deploy the new contract with `migrate()`.
2. On-chain state is converted to new Borsh layout.
3. Nodes switch to `state_v2()` and the new JSON formats for `vote_*` calls.
4. `state()` continues to emit old JSON format for external consumers (block explorers, SDK clients).

This "nodes first" approach avoids the need for the contract to accept both old and new JSON formats on node-facing functions. New nodes handle both old and new contract, but the old contract never sees new-format calls.

---

## 5. Shared Types Between Contract and Node

### 5.1 Current Problem: Tight Coupling

The node currently depends directly on `mpc-contract` internal types:

```
mpc-node → mpc-contract::primitives::{domain, key_state, thresholds, signature, ...}
mpc-node → mpc-contract::state::ProtocolContractState
mpc-node → mpc-contract::tee::*
mpc-node → mpc-contract::node_migrations::*
mpc-node → mpc-contract::crypto_shared::*
mpc-node → mpc-contract::utils::*
```

This means the node depends on the contract's **internal** representation, which:
- Creates a circular design concern (the node should consume the contract's *public* interface).
- Forces the node to recompile on internal contract refactors.
- Makes it unclear which types are part of the public API vs. implementation details.
- Pulls in `near-sdk` and WASM-related dependencies into the node build.

### 5.2 Profiling: Types Used by Both Contract and Node

The following types are imported by the node from the contract's internals:

**Identity types (pure newtypes, no logic)**:
| Type | Contract location | Node usage |
|---|---|---|
| `DistributedKeyId(u64)` | `primitives::domain` | ~20 files: routing, storage, providers |
| `EpochId(u64)` | `primitives::key_state` | ~15 files: keyshare storage, coordination |
| `AttemptId(u64)` | `primitives::key_state` | ~8 files: key events |
| `KeyEventId { epoch_id, domain_id, attempt_id }` | `primitives::key_state` | ~15 files: key generation, resharing |

**Enum types (no methods, pure data)**:
| Type | Contract location | Node usage |
|---|---|---|
| `SignatureScheme` | `primitives::domain` | ~12 files: provider routing, domain matching |
| `KeyPurpose` | `primitives::domain` | ~6 files: test setup, domain creation |

**Composite types (data + some logic)**:
| Type | Contract location | Node usage |
|---|---|---|
| `DistributedKeyConfig` | `primitives::domain` | ~8 files: key events, test setup |
| `Keyset` | `primitives::key_state` | ~6 files: keyshare storage, migration |
| `KeyForDomain` | `primitives::key_state` | ~5 files: keyshare management |
| `Threshold` | `primitives::thresholds` | ~3 files: coordinator, assets |
| `ThresholdParameters` | `primitives::thresholds` | ~3 files: coordinator, assets |
| `Payload`, `SignRequest`, `SignRequestArgs` | `primitives::signature` | ~8 files: request handling |
| `Tweak` | `primitives::signature` | ~4 files: signing |

**State types (complex, with methods)**:
| Type | Contract location | Node usage |
|---|---|---|
| `ProtocolContractState` | `state` | ~5 files: coordinator, indexer, web |

**Other contract internals used by node**:
| Type | Contract location | Node usage |
|---|---|---|
| `BackupServiceInfo`, `DestinationNodeInfo` | `node_migrations` | migration service |
| `NodeMigrations` | `node_migrations` | migration service |
| `CKDRequest`, `CKDRequestArgs` | `primitives::ckd` | indexer handler |
| `derive_tweak`, `CKDResponse` | `crypto_shared` | mpc_client |
| `protocol_state_to_string` | `utils` | web server |
| TEE types | `tee::*` | attestation, indexer |

### 5.3 Proposed Separation Strategy

#### Layer 1: Shared Primitives Crate (`mpc-primitives` or extend existing)

Move pure identity/data types that both contract and node need:

```
mpc-primitives/
  src/
    domain.rs       → DistributedKeyId, Curve, Protocol, KeyPurpose
    key_state.rs    → EpochId, AttemptId, KeyEventId
    thresholds.rs   → ReconstructionThreshold, GovernanceThreshold
    signature.rs    → Payload, Tweak, SignRequest, SignRequestArgs
    ckd.rs          → CkdAppId, CKDRequest, CKDRequestArgs
    participants.rs → ParticipantId
```

Requirements for this crate:
- `no_std` compatible (needed for WASM contract target).
- Derives: `BorshSerialize`, `BorshDeserialize`, `Serialize`, `Deserialize`.
- No business logic — only data definitions, display, and conversions.
- No dependency on `near-sdk` (use `borsh` directly).

#### Layer 2: Contract-Interface DTOs (existing `near-mpc-contract-interface`)

Remains the public API surface for contract view calls:

```
near-mpc-contract-interface/
  types/
    state.rs        → DistributedKeyConfig, GovernanceBody, ProtocolContractState (DTOs)
    participants.rs → Participants, ParticipantInfo (DTOs)
    config.rs       → Config, InitConfig
```

This crate depends on `mpc-primitives` and re-exports its ID types.

#### Layer 3: Contract Internals (`mpc-contract`)

Internal state, business logic, validation:

```
mpc-contract/
  primitives/
    domain.rs       → DistributedKeyRegistry, AddDomainsVotes, validation logic
    key_state.rs    → KeyForDomain, Keyset (with NEAR-specific storage)
    thresholds.rs   → Validation logic (validate_threshold, etc.)
  state/            → ProtocolContractState, RunningContractState, etc.
```

This crate depends on `mpc-primitives` and `near-sdk`.

#### Layer 4: Node (`mpc-node`)

The node should depend on:
- `mpc-primitives` (for shared identity types)
- `near-mpc-contract-interface` (for DTOs from contract view calls)
- `threshold-signatures` (for crypto protocol types)

The node should **not** depend on `mpc-contract` internals. Currently, the main reasons it does are:

1. **Shared newtypes** (`DistributedKeyId`, `EpochId`, etc.) — solved by moving to `mpc-primitives`.
2. **`ProtocolContractState` enum** — the node needs to pattern-match on contract state. This should be exposed via contract-interface DTOs (it already is).
3. **`Keyset`, `KeyForDomain`** — used in keyshare storage. These should move to `mpc-primitives` or contract-interface.
4. **`SignRequest`, `Payload`** — request types. Should move to `mpc-primitives`.
5. **Migration types** (`BackupServiceInfo`) — these are node-specific migration logic currently in the contract crate; they should move to a shared location or the node itself.
6. **TEE types** — used for attestation; should live in a dedicated crate or `mpc-primitives`.
7. **`protocol_state_to_string`** — utility; trivially reimplemented or moved.

### 5.4 Dependency Graph

```
                    mpc-primitives (no_std, pure data)
                   /        |         \
                  /         |          \
   mpc-contract            |     near-mpc-contract-interface
   (near-sdk,              |     (serde DTOs, re-exports primitives)
    borsh storage,         |           |
    validation)            |           |
                           |          /
                      mpc-node
                     (depends on primitives + interface,
                      NOT on mpc-contract)
```

### 5.5 Migration Path for Decoupling

This can be done incrementally:

1. **Phase 1**: Move identity newtypes (`DistributedKeyId`, `EpochId`, `AttemptId`, `KeyEventId`, `ParticipantId`) to `mpc-primitives`. Update imports in contract and node. Leaf-level change, low risk.

2. **Phase 2**: Move data enums (`Curve`/`SignatureScheme`, `KeyPurpose`, `Protocol`) and request types (`Payload`, `Tweak`, `SignRequest`) to `mpc-primitives`.

3. **Phase 3**: Move composite data types (`KeyForDomain`, `Keyset`, `DistributedKeyConfig`) to `mpc-primitives` or contract-interface. These require more care since they have associated methods in the contract.

4. **Phase 4**: Move migration and TEE types to appropriate crates. Update node to depend only on `mpc-primitives` + `near-mpc-contract-interface`. Remove node's direct `mpc-contract` dependency.

---

## 6. Impact on State Machine

### 6.1 State Transitions (unchanged structure)

The state machine transitions remain the same:
```
NotInitialized → Running ↔ Initializing/Resharing
```

What changes is the data carried through transitions:
- `RunningContractState` replaces `parameters` with `governance: GovernanceBody`.
- `KeyEvent` carries both `GovernanceBody` (who participates) and `DistributedKeyConfig` (protocol + threshold + purpose).
- Resharing must validate ALL distributed keys' `reconstruction_threshold` against the proposed new participant set.

### 6.2 Vote Functions

| Function | Current threshold source | Proposed threshold source |
|---|---|---|
| `vote_add_domains` | `ThresholdParameters.threshold` | `GovernanceBody.governance_threshold` |
| `vote_new_parameters` | `ThresholdParameters.threshold` | `GovernanceBody.governance_threshold` |
| `vote_pk` | All participants | All participants (unchanged) |
| `vote_reshared` | All new participants | All new participants (unchanged) |
| `vote_cancel_resharing` | Old `ThresholdParameters.threshold` | Old `GovernanceBody.governance_threshold` |
| `vote_cancel_keygen` | `ThresholdParameters.threshold` | `GovernanceBody.governance_threshold` |

### 6.3 Adding Domains with Different Thresholds

With per-key `protocol` and `reconstruction_threshold`, `vote_add_domains` must now include these fields for each new distributed key:

```rust
// Old: vote_add_domains(Vec<DistributedKeyConfig>) where DistributedKeyConfig has scheme
// New: vote_add_domains(Vec<DistributedKeyConfig>) where DistributedKeyConfig has protocol + reconstruction_threshold
```

### 6.4 Resharing with Per-Domain Thresholds

During resharing, each domain's key must be reshared with its own `ReconstructionThreshold`. The `KeyEvent` for each domain already carries its config. The coordinator passes the per-domain threshold to the crypto protocol. Per-domain thresholds can only be changed via resharing — there is no independent vote function for threshold changes.

`ReconstructionThreshold` has uniform semantics across all protocols: it always means "number of shares needed to reconstruct the secret" (`t`). Each protocol may impose different constraints on `t` (e.g., DamgardEtAl requires `t < n/2`), but the stored value has the same meaning everywhere. The node handles the protocol-specific translation:


```rust
// Current (hack):
let threshold: usize = mpc_config.participants.threshold.try_into()?;
let threshold = ReconstructionLowerBound::from(threshold);

// Proposed (clean):
let dk = distributed_key_registry.get(distributed_key_id);
let active_signers = min_active_participants(&dk.protocol, &dk.reconstruction_threshold);
let threshold = match dk.protocol {
    Protocol::DamgardEtAl(_) => {
        let max_malicious = MaxMalicious::from(dk.reconstruction_threshold.inner() - 1);
        // Use MaxMalicious directly, no translation needed
    }
    _ => ReconstructionLowerBound::from(dk.reconstruction_threshold.inner()),
};
```

---

## 7. Open Questions

### 7.1 Governance Threshold Validation

Should the governance `GovernanceThreshold` be constrained relative to the cryptographic `ReconstructionThreshold`? For example, should we require `governance_threshold >= max(reconstruction_threshold for all configs)`?

If not, it is possible for a governance majority to approve a resharing that a cryptographic protocol cannot support.

### 7.2 Backward-Compatible View Methods

How long should the old `state()` view method be maintained alongside the new `state_v2()`? Should the old format be deprecated immediately or kept for N epochs? Are there external consumers (e.g., block explorers, SDK clients) that depend on the `state()` format?

### 7.3 Migration Consolidation

PRs 4 and 6 each require a Borsh `migrate()` function. Should these be separate contract deployments (one migration per deploy), or can they be combined into a single deploy with a combined migration? Separate deploys are safer but slower to roll out. Since partner-node compat shims are not needed (§4.1 principle 3), the incremental-deploy benefit is weaker — combining PRs 4+5+6 with one migration is a viable option.

---

## Appendix A: Full Type Dependency Map (Node → Contract)

For reference, every `use mpc_contract::` import in the node crate, grouped by module:

**`primitives::domain`** (30+ imports):
`DistributedKeyId`, `DistributedKeyConfig`, `SignatureScheme`, `KeyPurpose`, `AddDomainsVotes`

**`primitives::key_state`** (25+ imports):
`EpochId`, `AttemptId`, `KeyEventId`, `KeyForDomain`, `Keyset`

**`primitives::signature`** (10+ imports):
`Payload`, `SignRequest`, `SignRequestArgs`, `Bytes`, `Tweak`

**`primitives::thresholds`** (5 imports):
`Threshold`, `ThresholdParameters`

**`primitives::ckd`** (2 imports):
`CKDRequest`, `CKDRequestArgs`

**`state`** (8 imports):
`ProtocolContractState`, `key_event::KeyEvent`

**`node_migrations`** (4 imports):
`BackupServiceInfo`, `DestinationNodeInfo`, `NodeMigrations`

**`crypto_shared`** (2 imports):
`derive_tweak`, `CKDResponse`

**`tee`** (4 imports):
`proposal::LauncherDockerComposeHash`, `proposal::MpcDockerImageHash`, `tee_state::NodeId`

**`utils`** (1 import):
`protocol_state_to_string`

**`primitives::test_utils`** (3 imports, test-only):
`gen_participants`, `infer_purpose_from_scheme`, `bogus_ed25519_near_public_key`
