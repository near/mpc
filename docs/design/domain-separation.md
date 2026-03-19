# Domain Separation: Protocol & Governance Configuration Design

The addition of Robust ECDSA (aka DamgardEtAl) invalidates three assumptions in the current design:

✗ There is one protocol per curve (now: both CaitSith and DamgardEtAl operate over Secp256k1).$\newline$
✗ All domains share a single cryptographic threshold. The node already has a `translate_threshold()` hack to bridge this gap.$\newline$
✗ Governance voting threshold and cryptographic reconstruction threshold are the same value. The threshold of how many participants must vote to change parameters is currently the same `Threshold` value as the cryptographic reconstruction threshold.

Orthogonally, first trials of adding Robust ECDSA revealed an unecessary (a tech-dept) entanglement between the smart contract and the node which makes it difficult to update the Smart Contract "independently" of the node.

Goals:

- Determine cryptographic and governance thresholds of the MPC network by reading the contract state.
- Allow flexibility and ease in adding new protocol schemes with different configurations without requiring major contract refactors.
- Disentangle the SC from the node.


## Table of Contents

1. [Current State Analysis](#1-current-state-analysis)
2. [Proposed Design](#2-proposed-design)
3. [Validation Logic](#3-validation-logic)
4. [Migration Strategy](#4-migration-strategy)
5. [Shared Types Between Contract and Node](#5-shared-types-between-contract-and-node)
6. [Impact on State Machine](#6-impact-on-state-machine)
7. [Open Questions](#7-open-questions)


## 1. Current State Analysis

### 1.1 Contract Types (internal)

**`crates/contract/src/primitives/domain.rs`**:
```rust
pub struct DomainId(pub u64);

pub enum SignatureScheme {
    Secp256k1,
    Ed25519,
    Bls12381,
    V2Secp256k1,  // robust ECDSA, not yet deployed to mainnet
}

pub struct DomainConfig {
    pub id: DomainId,
    pub scheme: SignatureScheme,
    pub purpose: DomainPurpose,
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
pub enum SignatureScheme { Secp256k1, Ed25519, Bls12381, V2Secp256k1 }
pub struct DomainConfig { pub id: DomainId, pub scheme: SignatureScheme, pub purpose: Option<DomainPurpose> }
pub struct ThresholdParameters { pub participants: Participants, pub threshold: Threshold }
```

### 1.3 Node Usage

The node (`crates/node/`) imports types from **both** the internal contract crate and the contract-interface DTO crate:

| Import source | Count | Used for |
|---|---|---|
| `mpc_contract::primitives::domain::{DomainId, SignatureScheme, DomainConfig}` | ~30 files | Routing to providers, keyshare storage, key events |
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
| Secp256k1 | DamgardEtAl (V2Secp256k1) | Sign | Ongoing |


## 2. Proposed Design

### 2.1 New Contract Types

```rust
/// Identifies the elliptic curve. Used by the contract to verify
/// signature responses and derive public keys.
pub enum Curve {
    Secp256k1,
    Edwards25519,  // renamed from Ed25519 for clarity
    Bls12381,
}

/// Identifies the threshold signature protocol.
/// The contract does not execute protocols, but stores this
/// for nodes to know what to run and for external observability.
pub enum Protocol {
    CaitSith,
    Frost,
    ConfidentialKeyDerivation,
    DamgardEtAl,
}

/// Number of shares required to reconstruct the secret key.
pub struct ReconstructionThreshold(u64);

impl struct ReconstructionThreshold{
    pub fn new(u64) -> Self;
    pub fn inner(&self) -> u64; 
}

/// Unique identifier for a key configuration.
pub struct KeyConfigId(pub u64);

/// Specifies the cryptographic configuration for a domain's key.
pub struct KeyConfig {
    pub protocol: Protocol,
    pub curve: Curve,
    pub reconstruction_threshold: ReconstructionThreshold,
}

impl struct KeyConfig {
    pub fn activeParticipantsThreshold(&self) -> ActiveParticipantThreshold
}


/// Number of shares required to provide a valid signature.
/// e.g. Cait-Sith: ActiveParticipantsThreshold = ReconstructionThreshold
///     DamgardEtAl: ActiveParticipantsThreshold = 2*ReconstructionThreshold-1
/// No constructor for this struct except for the one in reconstruction threshold
pub struct ActiveParticipantsThreshold(u64);


/// Manages all key configurations.
pub struct KeyConfigs {
    configs: IterableMap<KeyConfigId, KeyConfig>,
    next_config_id: u64,
}

/// Updated domain configuration.
pub struct DomainConfig {
    pub id: DomainId,
    pub key_config_id: KeyConfigId,
    pub purpose: DomainPurpose,
}

/// Governs the participant set and voting rules,
/// decoupled from cryptographic thresholds.
pub struct GovernanceBody {
    pub participants: Participants,
    pub voting_threshold: VotingThreshold,
}

pub struct VotingThreshold(pub u64);
```

### 2.2 Design Rationale

#### Why `KeyConfigId` indirection?

Multiple domains can share the same `KeyConfig` (e.g., two Secp256k1/CaitSith domains for Sign and ForeignTx). The indirection avoids duplication and allows changing config for all domains that reference it atomically during resharing.

However, if the additional complexity is not justified, an alternative is to inline `KeyConfig` directly into `DomainConfig` and accept the duplication. The advantage is simplicity: no need for a separate `KeyConfigs` registry or ID management.

**Trade-off summary**:

| Approach | Pros | Cons |
|---|---|---|
| `KeyConfigId` indirection | No duplication, atomic config change | Extra registry, lookup overhead, more validation |
| Inline `KeyConfig` in `DomainConfig` | Simpler, self-contained | Duplication, must update each domain separately |

#### Why separate `GovernanceBody`?

- Governance votes (resharing, adding domains) should not be constrained by cryptographic threshold requirements.
- Example: governance may require 80% vote to change participants, while a CaitSith domain only needs 60% for reconstruction.
- The existing `ThresholdParameters` conflates these; splitting them makes both explicit.

#### Why `ReconstructionThreshold` is per-domain (via `KeyConfig`), not global?

- DamgardEtAl may need a different threshold than CaitSith over the same participant set.
- Future protocols may have different threshold requirements.
- Allows gradual rollout: add a new domain with a different threshold without affecting existing ones.

### 2.3 Relationship to Existing Types

| Current | Proposed | Change |
|---|---|---|
| `SignatureScheme` | `Curve` + `Protocol` | Split enum into two orthogonal enums |
| `DomainConfig.scheme` | `DomainConfig.key_config_id` | Reference to `KeyConfig` instead of scheme |
| `ThresholdParameters` | `GovernanceBody` (governance) + `KeyConfig.reconstruction_threshold` (crypto) | Split into two concerns |
| `Threshold` | `VotingThreshold` + `ReconstructionThreshold` | Distinct newtypes for distinct purposes |
| `V2Secp256k1` | `Protocol::DamgardEtAl` + `Curve::Secp256k1` | No more version-in-curve-name hack |

### 2.4 State Structure

```rust
pub struct RunningContractState {
    pub domains: DomainRegistry,
    pub key_configs: KeyConfigs,        // NEW: protocol/curve/threshold per config
    pub keyset: Keyset,
    pub governance: GovernanceBody,     // RENAMED from parameters, threshold is voting-only
    pub governance_votes: GovernanceVotes,  // RENAMED from parameters_votes
    pub add_domains_votes: AddDomainsVotes,
    pub previously_cancelled_resharing_epoch_id: Option<EpochId>,
}
```

### 2.5 KeyEvent Changes

`KeyEvent` currently carries `ThresholdParameters` to know the participant set and threshold for key generation. With the split:

```rust
pub struct KeyEvent {
    pub epoch_id: EpochId,
    pub domain: DomainConfig,
    pub governance: GovernanceBody,          // participant set
    pub key_config: KeyConfig,              // protocol + curve + reconstruction threshold
    pub instance: Option<KeyEventInstance>,
    pub next_attempt_id: AttemptId,
}
```

The `KeyEvent` needs both: `GovernanceBody` for who participates, and `KeyConfig` for the cryptographic threshold to enforce during generation/resharing.

---

## 3. Validation Logic

### 3.1 Curve-Protocol Compatibility

Only certain (curve, protocol) pairs are valid:

```rust
impl KeyConfig {
    pub fn validate_curve_protocol(&self) -> Result<(), Error> {
        match (&self.protocol, &self.curve) {
            (Protocol::CaitSith, Curve::Secp256k1) => Ok(()),
            (Protocol::Frost, Curve::Edwards25519) => Ok(()),
            (Protocol::ConfidentialKeyDerivation, Curve::Bls12381) => Ok(()),
            (Protocol::DamgardEtAl, Curve::Secp256k1) => Ok(()),
            _ => Err(Error::InvalidCurveProtocolCombination),
        }
    }
}
```

### 3.2 Threshold Validation per Protocol

Each protocol has different constraints on `ReconstructionThreshold` relative to the participant count:

```rust
impl KeyConfig {
    /// Validates that the reconstruction threshold is achievable
    /// given the number of participants.
    pub fn validate_threshold(&self, num_participants: u64) -> Result<(), Error> {
        let t = self.reconstruction_threshold.0;

        // Universal constraints
        if t < 2 {
            return Err(Error::ThresholdTooLow);
        }
        if t > num_participants {
            return Err(Error::ThresholdExceedsParticipants);
        }

        // Protocol-specific constraints
        match self.protocol {
            Protocol::CaitSith | Protocol::Frost | Protocol::ConfidentialKeyDerivation => {
                // t-of-n: t <= n (already checked above)
                // Minimum relative threshold: t >= ceil(3n/5)
                let min_relative = (3 * num_participants).div_ceil(5);
                if t < min_relative {
                    return Err(Error::ThresholdBelowMinimumRelative);
                }
                Ok(())
            }
            Protocol::DamgardEtAl => {
                // Requires exactly 2t-1 signers, so 2t-1 <= n
                let required = 2 * t - 1;
                if required > num_participants {
                    return Err(Error::InsufficientParticipantsForProtocol {
                        required,
                        available: num_participants,
                    });
                }
                Ok(())
            }
        }
    }
}
```

### 3.3 Resharing Validation

When resharing (changing participants/threshold), we need to validate that:
1. The new governance threshold is valid for the new participant count.
2. **Every** existing `KeyConfig`'s `reconstruction_threshold` remains achievable with the new participant set.
3. Enough old participants are retained to meet both governance and cryptographic thresholds.

```rust
impl KeyConfigs {
    /// Validates that all key configs remain valid under a new participant count.
    pub fn validate_for_participant_count(&self, num_participants: u64) -> Result<(), Error> {
        for (id, config) in self.configs.iter() {
            config.validate_threshold(num_participants).map_err(|e| {
                Error::KeyConfigIncompatibleWithNewParticipants { key_config_id: id, inner: e }
            })?;
        }
        Ok(())
    }

    /// Returns the minimum number of participants required across all key configs.
    pub fn min_participants_required(&self) -> u64 {
        self.configs.values().map(|c| {
            match c.protocol {
                Protocol::DamgardEtAl => 2 * c.reconstruction_threshold.0 - 1,
                _ => c.reconstruction_threshold.0,
            }
        }).max().unwrap_or(0)
    }

    /// Returns the valid range of reconstruction thresholds for a new key config
    /// given the protocol and current participant count.
    pub fn threshold_range(
        protocol: &Protocol,
        num_participants: u64,
    ) -> Option<(u64, u64)> {
        let min = 2u64;
        let max = match protocol {
            Protocol::DamgardEtAl => (num_participants + 1) / 2,
            _ => num_participants,
        };
        if min > max { None } else { Some((min, max)) }
    }
}
```

### 3.4 Governance Threshold Validation

```rust
impl GovernanceBody {
    pub fn validate(&self) -> Result<(), Error> {
        let n = self.participants.len() as u64;
        let t = self.voting_threshold.0;
        if t < 2 { return Err(Error::VotingThresholdTooLow); }
        if t > n { return Err(Error::VotingThresholdExceedsParticipants); }
        // Governance minimum: >= 60% (same policy as current)
        let min_relative = (3 * n).div_ceil(5);
        if t < min_relative {
            return Err(Error::VotingThresholdBelowMinimumRelative);
        }
        Ok(())
    }
}
```

---

## 4. Backwards-Compatible Migration Strategy

### 4.1 Guiding Principles

Every PR in the sequence must satisfy:

1. **No on-chain breakage**: The deployed contract's Borsh-serialized state must remain deserializable after each upgrade. If a struct layout changes, a `migrate()` function converts old to new.
2. **No node breakage**: Nodes running the previous release must be able to read the contract state emitted by the new release (and vice-versa during rollout). This is achieved by keeping the existing `state()` view method unchanged and adding `state_v2()` when the DTO shape changes.
3. **No JSON wire breakage**: Internal types serialized to JSON in contract calls (`vote_add_domains`, test fixtures) must remain parseable. Use `#[serde(rename = "old_name")]` for serialization compat and `#[serde(alias = "old_name")]` or `DomainConfigCompat` with `#[serde(from = "...")]` for deserialization of both old and new formats.
4. **Each PR is independently deployable**: The system must be functional after each PR lands, even if subsequent PRs are delayed.

### 4.2 Step-by-Step PR Plan

Below is the proposed PR sequence. PRs marked **[DONE]** have already landed. PRs that can be parallelized are noted.

---

#### PR 1 — Rename `SignatureScheme` to `Curve` (internal contract types) **[DONE]**

**Scope**: `crates/contract/src/primitives/domain.rs`, `dto_mapping.rs`, affected call sites.

**Changes**:
- Rename enum `SignatureScheme` to `Curve` and field `.scheme` to `.curve` in internal `DomainConfig`.
- Add `#[serde(rename = "scheme")]` on `DomainConfig.curve` to keep JSON wire format identical.
- `DomainConfigCompat` uses `#[serde(alias = "scheme")]` so both old and new JSON deserialize.
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

#### PR 3 — Clean up: delete `V2Secp256k1` variant from `Curve`

**Scope**: `crates/contract/src/primitives/domain.rs`, `crates/near-mpc-contract-interface/src/types/state.rs`, node provider routing.

**Precondition**: `V2Secp256k1` is not deployed to mainnet. No on-chain state references this variant.

**Changes**:
- Remove `V2Secp256k1` from internal `Curve` enum.
- Remove `V2Secp256k1` from DTO `SignatureScheme` enum.
- Remove `is_valid_scheme_for_purpose` entry for `V2Secp256k1`.
- Remove the `KeyshareData::V2Secp256k1` variant in the node (or gate behind a feature flag if reshare data exists in dev/testnet).
- Update `coordinator.rs` routing: the `V2Secp256k1` match arm is removed; robust ECDSA will be routed via `Protocol::DamgardEtAl` once that enum exists (PR 5).

**Borsh compat**: Since `V2Secp256k1` was the last variant (index 3), removing it does not shift other variant indices. No stored state references it. No migration needed.

**JSON compat**: No deployed contract emits this value. Safe to remove.

**Risk**: If any testnet/devnet deployment has `V2Secp256k1` domains, those nodes will fail to deserialize. Acceptable if coordinated with testnet reset.

---

#### PR 4 — Add `Protocol` enum (contract internals only)

**Scope**: `crates/contract/src/primitives/domain.rs` (new file or extend existing).

**Changes**:
- Add new enum:
  ```rust
  #[near(serializers=[borsh, json])]
  pub enum Protocol {
      CaitSith,                    // OT-based ECDSA (current Secp256k1)
      Frost,                       // Threshold Schnorr (current Edwards25519)
      ConfidentialKeyDerivation,   // BLS-based CKD
      DamgardEtAl,                 // Robust ECDSA (new)
  }
  ```
- Add `infer_protocol_from_curve()` helper:
  ```rust
  pub fn infer_protocol_from_curve(curve: &Curve) -> Protocol {
      match curve {
          Curve::Secp256k1 => Protocol::CaitSith,
          Curve::Edwards25519 => Protocol::Frost,
          Curve::Bls12381 => Protocol::ConfidentialKeyDerivation,
      }
  }
  ```
- **No changes to `DomainConfig` yet** — `Protocol` exists but is not wired into state.
- No changes to contract-interface DTO.

**Borsh compat**: New type, not stored yet. No migration.

**JSON compat**: Not exposed yet. No impact.

**Purpose**: Introduce the type early so subsequent PRs can reference it. Also enables early review of the enum design and naming.

---

#### PR 5 — Create `KeyConfig` struct, update `DomainConfig`

**Scope**: `crates/contract/src/primitives/domain.rs`, `crates/contract/src/dto_mapping.rs`, `crates/near-mpc-contract-interface/src/types/state.rs`.

This is the most complex PR. It wires `Protocol` and `Curve` together and changes `DomainConfig`'s shape.

**Changes (contract internals)**:
- Add `ReconstructionThreshold(u64)` newtype.
- Add `KeyConfig` struct:
  ```rust
  pub struct KeyConfig {
      pub protocol: Protocol,
      pub curve: Curve,
      pub reconstruction_threshold: ReconstructionThreshold,
  }
  ```
- Update `DomainConfig`:
  ```rust
  // Before:
  pub struct DomainConfig { pub id: DomainId, pub curve: Curve, pub purpose: DomainPurpose }
  // After:
  pub struct DomainConfig { pub id: DomainId, pub key_config: KeyConfig, pub purpose: DomainPurpose }
  ```
- Update `DomainConfigCompat` to handle deserialization of old format:
  ```rust
  // Old JSON: { "id": 0, "scheme": "Secp256k1", "purpose": "Sign" }
  // New JSON: { "id": 0, "key_config": { "protocol": "CaitSith", "curve": "Secp256k1",
  //             "reconstruction_threshold": 6 }, "purpose": "Sign" }
  //
  // DomainConfigCompat deserializes both formats.
  // When old format is detected, infer protocol from curve and use a sentinel/default threshold.
  ```

**Changes (contract-interface DTO)**:
- Add new DTO types: `dtos::Protocol`, `dtos::KeyConfig`, `dtos::ReconstructionThreshold`.
- Add new `dtos::DomainConfigV2` that includes `key_config`.
- **Keep existing `dtos::DomainConfig` unchanged** (with `scheme: SignatureScheme`).
- Add new view method `state_v2()` that returns the new DTO structure.
- Existing `state()` continues to return old DTO format via `dto_mapping.rs`.

**Changes (dto_mapping.rs)**:
- Map internal `KeyConfig` to `dtos::KeyConfig`.
- Map internal `DomainConfig` to old `dtos::DomainConfig` (for `state()`) by extracting `curve` from `key_config`.
- Map internal `DomainConfig` to new `dtos::DomainConfigV2` (for `state_v2()`).

**Borsh compat**: `DomainConfig`'s Borsh layout changes (from `(DomainId, Curve, DomainPurpose)` to `(DomainId, KeyConfig, DomainPurpose)`). Requires `migrate()`:
```rust
fn migrate(old: OldDomainConfig) -> DomainConfig {
    DomainConfig {
        id: old.id,
        key_config: KeyConfig {
            protocol: infer_protocol_from_curve(&old.curve),
            curve: old.curve,
            // Use global threshold as default for all existing domains
            reconstruction_threshold: ReconstructionThreshold(old_global_threshold),
        },
        purpose: old.purpose,
    }
}
```

**JSON compat**:
- Old nodes calling `state()` see unchanged JSON.
- New nodes call `state_v2()` for rich data, fall back to `state()` if `state_v2()` is not available (rolling upgrade).
- `vote_add_domains` accepts both old and new `DomainConfig` JSON via `DomainConfigCompat`.

**Node changes**: Minimal in this PR — node can continue using `state()`. Full node migration happens in PR 8.

---

#### PR 6 — Add per-domain threshold validation

**Scope**: `crates/contract/src/primitives/thresholds.rs`, `crates/contract/src/state/running.rs`, `crates/contract/src/state/key_event.rs`.

**Precondition**: PR 5 landed. `KeyConfig.reconstruction_threshold` exists but is populated from the global threshold during migration.

**Changes**:
- Add `KeyConfig::validate_threshold(num_participants)` with protocol-specific rules:
  - CaitSith/Frost/CKD: `t >= ceil(3n/5)` and `t <= n` (same as current).
  - DamgardEtAl: `2t - 1 <= n`.
- Update `vote_add_domains` to validate each new domain's `KeyConfig.reconstruction_threshold` against the current participant count.
- Update `KeyEvent` to pass per-domain threshold (from `DomainConfig.key_config`) instead of the global threshold.
- Update resharing validation: `validate_incoming_proposal` must check that ALL existing `KeyConfig` thresholds remain achievable under the proposed new participant count.
- Existing domains continue to have `reconstruction_threshold == global_threshold` (set during PR 5 migration). New domains can choose a different value.

**Borsh compat**: No struct layout changes (threshold is already in `KeyConfig` from PR 5). No migration.

**JSON compat**: `vote_add_domains` with old-format JSON infers threshold from global value via `DomainConfigCompat`.

**Key behavioral change**: This is where `DomainConfig` gains real per-domain threshold semantics. Before this PR, the threshold in `KeyConfig` was always the global value.

---

#### PR 7 — Separate governance threshold from signing thresholds

**Scope**: `crates/contract/src/primitives/thresholds.rs`, `crates/contract/src/state/`.

**Changes**:
- Add `VotingThreshold(u64)` newtype.
- Add `GovernanceBody` struct:
  ```rust
  pub struct GovernanceBody {
      pub participants: Participants,
      pub voting_threshold: VotingThreshold,
  }
  ```
- In `RunningContractState`, replace `parameters: ThresholdParameters` with `governance: GovernanceBody`.
- Update all vote-counting logic to use `governance.voting_threshold` instead of `parameters.threshold()`.
- `KeyEvent` retains its per-domain `KeyConfig.reconstruction_threshold` for crypto operations.
- Keep `ThresholdParameters` as a private type or remove it if no longer needed.

**Borsh compat**: `RunningContractState` layout changes. Requires `migrate()`:
```rust
fn migrate(old: OldRunningContractState) -> RunningContractState {
    RunningContractState {
        governance: GovernanceBody {
            participants: old.parameters.participants().clone(),
            voting_threshold: VotingThreshold(old.parameters.threshold().value()),
        },
        // ... other fields unchanged
    }
}
```

**JSON compat**:
- `state()` view method continues to emit old format (maps `GovernanceBody` back to `ThresholdParameters` DTO).
- `state_v2()` emits the new `GovernanceBody` structure.
- `vote_new_parameters` continues to accept `ThresholdParameters` JSON and internally converts to `GovernanceBody`.

**Behavioral change**: After this PR, governance votes and crypto thresholds are fully decoupled. Changing participants (`vote_new_parameters`) updates the `GovernanceBody` but does not automatically change any domain's `reconstruction_threshold`.

---

#### PR 8 — Update node to consume new contract types

**Scope**: `crates/node/src/coordinator.rs`, `crates/node/src/key_events.rs`, `crates/node/src/providers/`.

**Changes**:
- Node switches from `state()` to `state_v2()` for contract queries (with fallback to `state()` for backward compat during rolling upgrades).
- Coordinator reads per-domain `KeyConfig` from contract state instead of using global threshold.
- Remove `translate_threshold()` hack in `robust_ecdsa.rs` — the contract now provides the correct per-domain threshold, and the node translates `ReconstructionThreshold` to `MaxMalicious` cleanly based on `Protocol::DamgardEtAl`.
- Provider routing uses `Protocol` enum instead of pattern-matching on `SignatureScheme`/`Curve`:
  ```rust
  match key_config.protocol {
      Protocol::CaitSith => EcdsaSignatureProvider,
      Protocol::Frost => EddsaSignatureProvider,
      Protocol::ConfidentialKeyDerivation => CKDProvider,
      Protocol::DamgardEtAl => RobustEcdsaSignatureProvider,
  }
  ```

**No contract changes in this PR** — purely a node-side consumer update.

---

#### PR 9 — Move shared primitives to `mpc-primitives` crate

**Scope**: `crates/primitives/src/`, `crates/contract/`, `crates/node/`, `crates/near-mpc-contract-interface/`.

**Changes**:
- Move pure data types to `mpc-primitives`:
  - Identity newtypes: `DomainId`, `EpochId`, `AttemptId`, `KeyEventId`, `ParticipantId`.
  - Enums: `Curve`, `Protocol`, `DomainPurpose`.
  - Request types: `Payload`, `Tweak`, `SignRequest`, `SignRequestArgs`.
  - Threshold newtypes: `ReconstructionThreshold`, `VotingThreshold`.
- `mpc-primitives` is `no_std` compatible, depends only on `borsh` + `serde`.
- Both `mpc-contract` and `near-mpc-contract-interface` depend on `mpc-primitives` and re-export its types.
- Update all imports across contract and node.

**This is a large but mechanical refactor** — only import paths change, no logic changes.

---

#### PR 10 — Remove node's direct dependency on `mpc-contract`

**Scope**: `crates/node/Cargo.toml`, all `use mpc_contract::` imports in node.

**Precondition**: PR 9 landed. All types the node needs are available from `mpc-primitives` or `near-mpc-contract-interface`.

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
PR 1 [DONE] --> PR 2 [DONE] --> PR 3 (delete V2Secp256k1)
                                  |
                                  v
                               PR 4 (add Protocol enum)
                                  |
                                  v
                               PR 5 (KeyConfig + DomainConfig update + state_v2())
                                  |
                                  +---> PR 6 (per-domain threshold validation)
                                  |       |
                                  |       v
                                  |    PR 7 (GovernanceBody separation)
                                  |       |
                                  |       v
                                  +---> PR 8 (node consumes new types)
                                          |
                                          v
                                       PR 9 (move types to mpc-primitives)
                                          |
                                          v
                                       PR 10 (remove node -> mpc-contract dep)
```

PRs 6 and 8 can be developed in parallel after PR 5, though PR 8 should land after PR 7 to consume the final type shapes.

### 4.4 Backwards Compatibility Techniques Reference

Each technique used in the PR plan, summarized:

| Technique | What it achieves | Example |
|---|---|---|
| `#[serde(rename = "old")]` on field/variant | Serializes using old name, deserializes old name | `Curve::Edwards25519` serializes as `"Ed25519"` |
| `#[serde(alias = "old")]` on field | Deserializes both old and new name, serializes new name | `DomainConfigCompat.curve` accepts `"scheme"` |
| `#[serde(from = "CompatType")]` on struct | Custom deserialization from a flexible intermediate type | `DomainConfig` from `DomainConfigCompat` |
| `migrate()` in contract | Converts Borsh-stored old state to new layout on upgrade | `OldRunningContractState` to `RunningContractState` |
| `state()` + `state_v2()` view methods | Old consumers see old DTO, new consumers see new DTO | Node falls back to `state()` during rolling upgrade |
| `dto_mapping.rs` | Decouples internal type evolution from public API | Internal `GovernanceBody` maps to DTO `ThresholdParameters` |
| Borsh variant index preservation | Adding/removing enum variants at the end is safe | Remove `V2Secp256k1` (last variant) without shifting others |

### 4.5 Rolling Upgrade Scenario

During a deployment, old and new nodes coexist. The upgrade proceeds in two phases:

**Phase A — Contract upgrade (PRs 5-7)**:
1. Deploy new contract with `migrate()`.
2. On-chain state is converted to new Borsh layout.
3. `state()` continues to emit old JSON format.
4. Old nodes continue operating normally via `state()`.
5. `state_v2()` is available for new nodes.

**Phase B — Node upgrade (PR 8)**:
1. Deploy new node binary.
2. New nodes call `state_v2()`. If it fails (contract not yet upgraded), fall back to `state()` and infer `Protocol`/`KeyConfig` from `SignatureScheme`.
3. Once all nodes are upgraded, `state()` can be deprecated (but not removed immediately).

This two-phase approach means contract and node upgrades are **not** required to happen atomically.

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
| `DomainId(u64)` | `primitives::domain` | ~20 files: routing, storage, providers |
| `EpochId(u64)` | `primitives::key_state` | ~15 files: keyshare storage, coordination |
| `AttemptId(u64)` | `primitives::key_state` | ~8 files: key events |
| `KeyEventId { epoch_id, domain_id, attempt_id }` | `primitives::key_state` | ~15 files: key generation, resharing |

**Enum types (no methods, pure data)**:
| Type | Contract location | Node usage |
|---|---|---|
| `SignatureScheme` | `primitives::domain` | ~12 files: provider routing, domain matching |
| `DomainPurpose` | `primitives::domain` | ~6 files: test setup, domain creation |

**Composite types (data + some logic)**:
| Type | Contract location | Node usage |
|---|---|---|
| `DomainConfig` | `primitives::domain` | ~8 files: key events, test setup |
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
    domain.rs       → DomainId, Curve, Protocol, DomainPurpose, KeyConfigId
    key_state.rs    → EpochId, AttemptId, KeyEventId
    thresholds.rs   → ReconstructionThreshold, VotingThreshold
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
    state.rs        → DomainConfig, KeyConfig, GovernanceBody, ProtocolContractState (DTOs)
    participants.rs → Participants, ParticipantInfo (DTOs)
    config.rs       → Config, InitConfig
```

This crate depends on `mpc-primitives` and re-exports its ID types.

#### Layer 3: Contract Internals (`mpc-contract`)

Internal state, business logic, validation:

```
mpc-contract/
  primitives/
    domain.rs       → DomainRegistry, AddDomainsVotes, validation logic
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

1. **Shared newtypes** (`DomainId`, `EpochId`, etc.) — solved by moving to `mpc-primitives`.
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

1. **Phase 1**: Move identity newtypes (`DomainId`, `EpochId`, `AttemptId`, `KeyEventId`, `ParticipantId`) to `mpc-primitives`. Update imports in contract and node. Leaf-level change, low risk.

2. **Phase 2**: Move data enums (`Curve`/`SignatureScheme`, `DomainPurpose`, `Protocol`) and request types (`Payload`, `Tweak`, `SignRequest`) to `mpc-primitives`.

3. **Phase 3**: Move composite data types (`KeyForDomain`, `Keyset`, `DomainConfig`) to `mpc-primitives` or contract-interface. These require more care since they have associated methods in the contract.

4. **Phase 4**: Move migration and TEE types to appropriate crates. Update node to depend only on `mpc-primitives` + `near-mpc-contract-interface`. Remove node's direct `mpc-contract` dependency.

---

## 8. Impact on State Machine

### 8.1 State Transitions (unchanged structure)

The state machine transitions remain the same:
```
NotInitialized → Running ↔ Initializing/Resharing
```

What changes is the data carried through transitions:
- `RunningContractState` gains `key_configs: KeyConfigs` and replaces `parameters` with `governance: GovernanceBody`.
- `KeyEvent` carries both `GovernanceBody` (who participates) and `KeyConfig` (crypto params).
- Resharing must validate ALL `KeyConfig` thresholds against the proposed new participant set.

### 8.2 Vote Functions

| Function | Current threshold source | Proposed threshold source |
|---|---|---|
| `vote_add_domains` | `ThresholdParameters.threshold` | `GovernanceBody.voting_threshold` |
| `vote_new_parameters` | `ThresholdParameters.threshold` | `GovernanceBody.voting_threshold` |
| `vote_pk` | All participants | All participants (unchanged) |
| `vote_reshared` | All new participants | All new participants (unchanged) |
| `vote_cancel_resharing` | Old `ThresholdParameters.threshold` | Old `GovernanceBody.voting_threshold` |
| `vote_cancel_keygen` | `ThresholdParameters.threshold` | `GovernanceBody.voting_threshold` |

### 8.3 Adding Domains with Different Thresholds

With `KeyConfig` per domain, `vote_add_domains` must now also specify or reference a `KeyConfigId`:

```rust
// Old: vote_add_domains(Vec<DomainConfig>) where DomainConfig has scheme
// New: vote_add_domains(Vec<DomainConfig>) where DomainConfig has key_config_id
//   OR vote_add_domains(Vec<DomainConfig>, Vec<KeyConfig>) to create new configs atomically
```

### 8.4 Resharing with Per-Domain Thresholds

During resharing, each domain's key must be reshared with its own `ReconstructionThreshold`. The `KeyEvent` for each domain already carries its config. The coordinator passes the per-domain threshold to the crypto protocol.

On the node side, this eliminates the `translate_threshold()` hack:

```rust
// Current (hack):
let threshold: usize = mpc_config.participants.threshold.try_into()?;
let threshold = ReconstructionLowerBound::from(threshold);

// Proposed (clean):
let key_config = domain_registry.key_config_for(domain_id);
let threshold = match key_config.protocol {
    Protocol::DamgardEtAl => {
        let max_malicious = MaxMalicious::from(key_config.reconstruction_threshold.0 - 1);
        // Use MaxMalicious directly, no translation needed
    }
    _ => ReconstructionLowerBound::from(key_config.reconstruction_threshold.0),
};
```

---

## 9. Open Questions

### 9.1 KeyConfig Identity

**Option A**: `KeyConfigId` indirection (as proposed). Domains reference configs by ID.
- Pro: Shared configs, atomic updates.
- Con: Extra registry, indirection complexity.

**Option B**: Inline `KeyConfig` in `DomainConfig`.
- Pro: Simpler, self-contained.
- Con: Duplication, must update each domain individually.

**Recommendation**: Start with Option B (inline) for simplicity. Introduce indirection only if the need arises.

### 9.2 Governance Threshold Validation

Should the governance `VotingThreshold` be constrained relative to the cryptographic `ReconstructionThreshold`? For example, should we require `voting_threshold >= max(reconstruction_threshold for all configs)`?

If not, it is possible for a governance majority to approve a resharing that a cryptographic protocol cannot support.

### 9.3 Per-Domain Threshold Changes

Can individual domain thresholds be changed independently (via a new vote function), or only during resharing when all keys are re-distributed?

Allowing independent threshold changes would require a new resharing variant that only reshares affected domains. This adds complexity but offers flexibility.

### 9.4 `ReconstructionThreshold` Semantics

Should `ReconstructionThreshold` mean the same thing across all protocols (i.e., "number of shares to reconstruct"), or should each protocol interpret it according to its own conventions?

- **Uniform semantics**: The contract stores `t` meaning "t shares needed". DamgardEtAl requires `2t-1` participants, which is a protocol detail.
- **Protocol-native semantics**: DamgardEtAl stores `MaxMalicious` directly, and the contract understands each protocol's threshold meaning.

**Recommendation**: Uniform semantics (t = shares to reconstruct). The protocol-specific translation (`t → MaxMalicious = t-1`) happens in the node, keeping the contract simple and protocol-agnostic.

### 9.5 Backward-Compatible View Methods

How long should the old `state()` view method be maintained alongside the new `state_v2()`? Should the old format be deprecated immediately or kept for N epochs? Are there external consumers (e.g., block explorers, SDK clients) that depend on the `state()` format?

### 9.6 Migration Consolidation

PRs 5 and 7 each require a Borsh `migrate()` function. Should these be separate contract deployments (one migration per deploy), or can they be combined into a single deploy with a combined migration? Separate deploys are safer but slower to roll out.

---

## Appendix A: Full Type Dependency Map (Node → Contract)

For reference, every `use mpc_contract::` import in the node crate, grouped by module:

**`primitives::domain`** (30+ imports):
`DomainId`, `DomainConfig`, `SignatureScheme`, `DomainPurpose`, `AddDomainsVotes`

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
