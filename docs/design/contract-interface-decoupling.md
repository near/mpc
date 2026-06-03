# Contract Interface Decoupling: Design Document

## 1. What

Decouple the MPC node from the smart contract's internal types. The node should depend only on:
- `near-mpc-contract-interface` — DTOs (Data Transfer Objects) for the contract's public API (view calls, state deserialization)
- `mpc-primitives` — shared identity types (IDs, hashes)
- `threshold-signatures` — cryptographic protocol types

The node should **not** import from `mpc-contract` internals (`mpc_contract::primitives::*`, `mpc_contract::state::*`, etc.).

## 2. Why

Today the node compiles the full smart contract code to use shared types. This causes:

1. **Silent breaking changes** — An internal contract refactor (renaming a field, changing a method signature) can break the node at compile time or, worse, at runtime if serialization formats drift.
2. **Unclear API boundary** — No way to tell which contract types are public API vs. implementation details. Developers import whatever is convenient.
3. **Unnecessary dependencies** — The node pulls in `near-sdk` and WASM (WebAssembly)-related deps through the contract crate, bloating the build.
4. **Circular design** — The node should consume the contract's *public* interface, not its internals. The current coupling inverts this relationship.

This was first raised in [#381](https://github.com/near/mpc/issues/381) and discussed in [PR #376 review](https://github.com/Near-One/mpc/pull/376#pullrequestreview-2802234130).

## 3. How

### 3.1 Architecture Layers

```
                  ┌──────────────────────────────────────┐
                  │ mpc-primitives                        │
                  │ (pure data types, no near-sdk)        │
                  └──────────────────────────────────────┘
                     ▲             ▲              ▲
                     │             │              │
                     │   ┌─────────────────────────────────────┐
                     │   │ near-mpc-contract-interface          │
                     │   │ (serde DTOs, re-exports primitives)  │
                     │   └─────────────────────────────────────┘
                     │        ▲                    ▲
                     │        │                    │
        ┌────────────────────────────┐  ┌─────────────────────────────┐
        │ mpc-contract               │  │ mpc-node                    │
        │ (near-sdk, borsh storage,  │  │ (indexer, coordinator;      │
        │  validation; converts      │  │  depends on primitives +    │
        │  internal ⇄ DTO via        │  │  interface, NOT on          │
        │  dto_mapping.rs)           │  │  mpc-contract)              │
        └────────────────────────────┘  └─────────────────────────────┘

Each arrow points away from the depender, toward the crate it depends on
(`mpc-contract ──▲ near-mpc-contract-interface` reads "mpc-contract depends on
near-mpc-contract-interface").
```

Note that `mpc-contract` depends on `near-mpc-contract-interface`: its view
functions return DTOs and its call functions accept DTOs, converting to/from
internal types in `dto_mapping.rs`. The interface crate is the contract's
public boundary, consumed by both the contract itself and the node.

### 3.2 What Goes Where

| Crate | Contains | Depends on |
|-------|----------|------------|
| `mpc-primitives` | Pure identity newtypes (`DomainId`, `EpochId`, `AttemptId`, `KeyEventId`, `ParticipantId`), enums (`Curve`, `Protocol`), hash types | `borsh`, `serde` (no `near-sdk`) |
| `near-mpc-contract-interface` | DTOs for contract state (`ProtocolContractState`, `RunningContractState`, `Keyset`, etc.), public API types (`SignatureRequest`, `CKDRequest`), conversion traits | `mpc-primitives`, `near-mpc-crypto-types`, `serde`, `borsh` |
| `mpc-contract` | Internal state, validation logic, NEAR storage, business rules | `mpc-primitives`, `near-mpc-contract-interface`, `near-sdk` |
| `mpc-node` | Node binary — indexer, coordinator, providers, networking | Regular deps: `mpc-primitives`, `near-mpc-contract-interface`, `near-mpc-crypto-types`, `mpc-attestation`, `threshold-signatures` (no regular dep on `mpc-contract`). `mpc-contract` remains a `[dev-dependencies]` entry until Phase 8 (§3.3) — don't be misled by its presence in `Cargo.toml`. |

### 3.3 Incremental Migration Path

The decoupling is done incrementally, module by module. Each step removes some `mpc_contract::*` imports from the node.

| Phase | Scope | Status |
|-------|-------|--------|
| 1 | Participants boundary (`indexer/participants.rs`) | Done — no `mpc_contract::` imports |
| 2 | Key state / keyshares (`keyshare.rs`, `keyshare/*.rs`) | Done — no `mpc_contract::` imports |
| 3 | Coordinator / key events (`coordinator.rs`, `key_events.rs`) | Done — no `mpc_contract::` imports |
| 4 | Signature / request types (`types.rs`, `indexer/handler.rs`, `mpc_client.rs`, providers) | Done — these use `near_mpc_contract_interface::types as dtos`, not `mpc_contract` |
| 5 | Migration types (`migration_service/*`) | Done in production code (a `mpc_contract::` import remains only in a `#[cfg(test)]` block, `migration_service/types.rs`) |
| 6 | TEE (Trusted Execution Environment) types (`tee/*`, `indexer/tee.rs`) | Done — no `mpc_contract::` imports |
| 7 | Remove `mpc-contract` from node's regular dependencies | Done — `mpc-contract` is now only a `[dev-dependencies]` entry (`crates/node/Cargo.toml`), not a regular dependency |
| 8 | Remove `mpc-contract` from node's dev-dependencies (rewrite test code) | Not started — the only genuinely open phase. Remaining `mpc_contract::` references live in `#[cfg(test)]` blocks (`config.rs`, `migration_service/types.rs`) and test-only modules (`indexer/fake.rs` gated behind `#[cfg(test)] pub mod fake`, `tests/*` — e.g. `tests/changing_participant_details.rs:96`, `tests/onboarding.rs:18,199` — and `assets/test_utils.rs`) |

Statuses above were re-derived from `grep -rn "mpc_contract::" crates/node/src/` on this branch; production code is fully migrated. See the tracking issue [#381](https://github.com/near/mpc/issues/381) for the canonical remaining-work list. (Per-phase PR links are intentionally omitted here — PR status drifts faster than the design intent this table records, and a stale "Not started" badly overstates how much work is left.)

### 3.4 Conversion Pattern at Boundaries

When the node receives contract state (from indexer view calls), the data arrives as interface DTOs. The node works with these directly — no conversion back to contract-internal types.

For **test code** that still needs contract internals (e.g., `FakeMpcContractState`), conversions use the contract's existing `IntoContractType`/`IntoInterfaceType` traits in `dto_mapping.rs`. These go through the contract's DTO mapping layer, not ad-hoc JSON round-trips.

**Anti-pattern to avoid:** `serde_json::from_value(serde_json::to_value(&x))` for type conversion. This works when types are structurally identical over JSON but provides no compile-time guarantee that they stay in sync.

### 3.5 Method Access vs Field Access

Contract-internal types use private fields with accessor methods (e.g., `key_event.epoch_id()`). Interface DTOs use public fields (e.g., `key_event.epoch_id`). When migrating node code from contract types to interface types, method calls become field accesses. This is intentional — DTOs are pure data.

## 4. The DTO Pattern

The `near-mpc-contract-interface` crate uses a Data Transfer Object (DTO) pattern to decouple the contract's public JSON API from its internal representation. This was introduced in [PR #1990](https://github.com/near/mpc/pull/1990) (February 2026).

### 4.1 Why DTOs

The contract's internal types have:
- **Private fields** with accessor methods (enforcing invariants like duplicate-ID checks)
- **`near-sdk` dependencies** (NEAR storage traits, WASM-specific derives)
- **Internal representation** that may change (e.g., `Participants` migrated from `Vec` to `BTreeMap` in PR #1861)

DTOs mirror the same data with:
- **Public fields** (simple data carriers, no invariants)
- **No `near-sdk` dependency** (just `serde`, `borsh`)
- **Stable JSON wire format** (the public API surface doesn't change when internals are refactored)

### 4.2 Conversion Traits

The contract defines custom conversion traits in `crates/contract/src/dto_mapping.rs` to work around Rust's orphan rule (can't implement `From<ForeignType>` for another foreign type):

```rust
pub(crate) trait IntoContractType<ContractType> {
    fn into_contract_type(self) -> ContractType;
}

pub(crate) trait IntoInterfaceType<InterfaceType> {
    fn into_dto_type(self) -> InterfaceType;
}

pub(crate) trait TryIntoContractType<ContractType> {
    type Error;
    fn try_into_contract_type(self) -> Result<ContractType, Self::Error>;
}
```

The `TryIntoContractType` variant is used where a conversion can fail (e.g.
validating a DTO's fields when converting into the internal type).

The node has its own parallel trait in `crates/node/src/trait_extensions/convert_to_contract_dto.rs`:

```rust
pub(crate) trait IntoContractInterfaceType<InterfaceType> {
    fn into_contract_interface_type(self) -> InterfaceType;
}
```

### 4.3 How the Contract Exposes DTOs

View functions convert internal state to DTOs before returning:

```rust
// crates/contract/src/lib.rs
pub fn state(&self) -> near_mpc_contract_interface::types::ProtocolContractState {
    (&self.protocol_state).into_dto_type()
}
```

Call functions accept DTOs and convert to internal types:

```rust
pub fn submit_participant_info(
    &mut self,
    proposed_participant_attestation: dtos::Attestation,
    tls_public_key: dtos::Ed25519PublicKey,
) -> Result<(), Error> {
    let proposed_participant_attestation = proposed_participant_attestation.try_into_contract_type()?;
    // ... work with internal types
}
```

### 4.4 How the Node Consumes DTOs

The node's indexer calls contract view functions and deserializes the JSON response directly into DTO types:

```rust
// crates/node/src/indexer.rs
pub(crate) async fn get_mpc_contract_state_dto(
    &self,
    mpc_contract_id: AccountId,
) -> anyhow::Result<(u64, dtos::ProtocolContractState)> {
    // Calls the contract's state() view function at a block height
    // Response is deserialized as dtos::ProtocolContractState
    self.get_mpc_state(mpc_contract_id, STATE).await
}
```

The state is then broadcast to subsystems via `tokio::sync::watch` channels (see the `watch::channel` site in `crates/node/src/indexer/participants.rs`, where a `watch::Sender<dtos::ProtocolContractState>` pushes each freshly-fetched state). The node works with DTOs directly — it should not convert them back to contract-internal types.

### 4.5 Key Differences: Internal Types vs DTOs

| Aspect | Contract Internal | Interface DTO |
|--------|-------------------|---------------|
| Field visibility | Private (accessor methods) | Public (direct access) |
| Invariant enforcement | Validated at construction | None — pure data |
| `near-sdk` dependency | Yes | No |
| Backwards compat | Can change freely | Must maintain JSON wire format |
| `ParticipantInfo.tls_public_key` | `Ed25519PublicKey` | `Ed25519PublicKey` (was `String`, resolved [#2871](https://github.com/near/mpc/issues/2871)) |

Note: not every type has an internal/DTO split. `DomainConfig` is a shared type imported directly from the interface crate (`crates/contract/src/state.rs:18`), so the contract and node use the *same* definition — there is no separate internal representation to convert. `DomainConfig`'s fields are `id`, `protocol` (a `Protocol`), `reconstruction_threshold`, and `purpose` (a `DomainPurpose`).

`DomainRegistry`, by contrast, *does* have a split: the contract's internal type (`crates/contract/src/primitives/domain.rs:77`) has private `domains` / `next_domain_id` fields with accessor methods, while the DTO (`crates/near-mpc-contract-interface/src/types/state.rs:117`) exposes them as public fields. The contract converts between them via `impl IntoInterfaceType<dtos::DomainRegistry> for &DomainRegistry` (`crates/contract/src/dto_mapping.rs:663`), and `crates/contract/src/state.rs:11` imports the internal `DomainRegistry` from `crate::primitives::domain`, not from the interface crate.

### 4.6 Serialization Compatibility

The contract has tests ensuring JSON round-trip compatibility between internal types and DTOs:

```rust
// crates/contract/src/dto_mapping.rs (tests)
fn threshold_parameters_serde_is_compatible_with_dto() {
    let internal = ThresholdParameters::new(...);
    let json = serde_json::to_value(&internal).unwrap();
    let dto: dtos::ThresholdParameters = serde_json::from_value(json.clone()).unwrap();
    let dto_json = serde_json::to_value(&dto).unwrap();
    assert_eq!(json, dto_json);  // Must be identical
}
```

This is the correct pattern for ensuring DTO compatibility, and it is applied to several types — e.g. `participants_serde_is_compatible_with_dto` and `threshold_parameters_serde_is_compatible_with_dto`, both in `crates/contract/src/dto_mapping.rs`. The anti-pattern is ad-hoc `serde_json::from_value(serde_json::to_value(&x))` in test code without these guarantees.

### 4.7 Public API Surface

The interface crate exports ~80 types organized into:
- **State types:** `ProtocolContractState`, `RunningContractState`, `ResharingContractState`, `InitializingContractState`, `Keyset`, `KeyEvent`, `KeyEventInstance`, `ThresholdParameters`, etc.
- **Domain types:** `DomainConfig`, `DomainRegistry`, `Protocol`, `Curve`, `DomainPurpose`
- **Identity types:** `EpochId`, `AttemptId`, `DomainId`, `KeyEventId`, `ParticipantId`
- **Request types:** `SignatureRequest`, `SignRequestArgs`, `CKDRequest`, `Payload`, `Tweak`, `YieldIndex`
- **Attestation types:** `Attestation`, `VerifiedAttestation`, `MockAttestation`, `DstackAttestation`
- **Foreign chain types:** Full foreign chain policy and request types
- **Crypto types:** Re-exported from `near-mpc-crypto-types` (`PublicKey`, `PublicKeyExtended`, `SignatureResponse`, etc.)
- **Method name constants:** All contract method names (`SIGN`, `RESPOND`, `STATE`, etc.)

## 5. Design Rules

### 5.1 `near-sdk` should NOT be a dependency of the interface crate

The interface crate exists so consumers (node, SDKs, external tools) don't need the full contract stack. Adding `near-sdk` would defeat this purpose. If a specific type needs `near-sdk` features, it should be behind a feature flag (the crate already has a `near` feature gate for this).

**Consequence:** Types like `ParticipantInfo.tls_public_key` use a `near-mpc-crypto-types` wrapper (`Ed25519PublicKey`) instead of `near_sdk::PublicKey`. See §5.2.

### 5.2 Use typed wrappers, not bare Strings

Where possible, use existing typed wrappers from `near-mpc-crypto-types` (e.g., `Ed25519PublicKey`) instead of bare `String` fields. The interface crate already depends on `near-mpc-crypto-types`.

**Applied:** [#2871](https://github.com/near/mpc/issues/2871) — `ParticipantInfo.tls_public_key` is now `Ed25519PublicKey` (previously `String`).

### 5.3 KDF (Key Derivation Function) placement: `derive_tweak`, `derive_app_id`

These are security-sensitive hash functions with hardcoded prefix strings. They're not pure DTOs but are needed by both the contract and the node. **Current location:** `near-mpc-crypto-types::kdf` (`crates/near-mpc-crypto-types/src/kdf.rs`). The interface crate re-exports them via `pub use near_mpc_crypto_types::kdf` inside its `types` module (`crates/near-mpc-contract-interface/src/lib.rs:18`), so consumers can reach them as `near_mpc_contract_interface::types::kdf` without depending on the crypto-types crate directly. (The node currently imports them straight from `near_mpc_crypto_types::kdf` — see `crates/node/src/types.rs:6` — rather than through the interface re-export.)

This resolves the earlier open question of whether they belonged in `mpc-primitives` vs. the interface crate: they now live alongside the crypto types they operate on, not in either DTO crate, since hash functions aren't DTOs.

### 5.4 Conversions between contract and interface types should fail at deserialization, not at use

When the interface DTO uses a weaker type (e.g., `String` for a public key), validation should happen at the boundary where the string is first received — not deep in business logic. This keeps errors close to their source.

## 6. Open Questions

1. ~~**Where should `derive_tweak` / `derive_app_id` live?**~~ **Resolved** — they live in `near-mpc-crypto-types::kdf`, re-exported from the interface crate as `near_mpc_contract_interface::types::kdf`. See §5.3. (Originally raised in [PR #2831 discussion](https://github.com/near/mpc/pull/2831#issuecomment-4237068116).)

2. **Should we publish `mpc-primitives` to crates.io?** External consumers (wallets, SDKs) need shared types. ([#2703](https://github.com/near/mpc/issues/2703))

3. **How to handle the JSON round-trip bridge in tests?** Current test code uses `serde_json` round-trips to convert between contract and interface types. Should we add snapshot tests to enforce serialization compatibility, or migrate tests to use `IntoContractType`/`IntoInterfaceType` traits? ([#2060](https://github.com/near/mpc/issues/2060))

4. **Should `MockAttestation` be feature-gated?** It's not behind `#[cfg(test)]` and can be submitted to production contracts. No `WithConstraints` exists on-chain today, but the code path is open. (Observed during [PR #2855 review](https://github.com/near/mpc/pull/2855))

## 7. Related Issues and PRs

### Tracking Issues
- [#381](https://github.com/near/mpc/issues/381) — MPC node should not depend on the contract crate directly (root issue)
- [#2876](https://github.com/near/mpc/issues/2876) — Document contract interface design (this document)
- [#2167](https://github.com/near/mpc/issues/2167) — participants.rs should depend on contract-interface, not contract

### Active PRs
- [#2870](https://github.com/near/mpc/pull/2870) — refactor: participants should depend on contract interface not contract (gilcu3, Phase 1)
- [#2831](https://github.com/near/mpc/pull/2831) — refactor: decouple node production code from mpc-contract crate (SimonRastikian, attempted full migration — descoped)

### Follow-up Issues
- [#2871](https://github.com/near/mpc/issues/2871) — `ParticipantInfo.tls_public_key` should be `Ed25519PublicKey` instead of `String` (**resolved**: field is now `Ed25519PublicKey`)
- [#2480](https://github.com/near/mpc/issues/2480) — Move voting types from contract crate to contract-interface
- [#2060](https://github.com/near/mpc/issues/2060) — Refactor sandbox tests to eliminate DTO-to-contract type conversion methods
- [#2703](https://github.com/near/mpc/issues/2703) — Publish `mpc-primitives` crate to crates.io
- [#2234](https://github.com/near/mpc/issues/2234) — Don't leak internal interface types in the MPC SDK

### Related Design
- [Domain Separation Design Doc](domain-separation.md) — Section 5 covers shared types between contract and node in detail, including the proposed 4-layer architecture
