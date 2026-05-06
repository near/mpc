# Breaking out TEE attestation verification into a shared global contract

## Context

The MPC contract at [crates/contract/src/lib.rs](crates/contract/src/lib.rs) has grown to ~5,900 lines, of which ~2,100 lines (35%) are TEE-related: `tee/tee_state.rs` (1,406), `tee/proposal.rs` (540), `tee/measurements.rs` (198), plus ~15 public TEE-related entry-point methods in `lib.rs`. On top of that, the contract pulls in the `mpc-attestation` and `attestation` crates which transitively bring `dcap-qvl`, `ring`/`webpki`, X.509 parsing, SHA-2/SHA-3 — collectively the heaviest WASM dependency surface of the contract. This is the primary motivator for [near/mpc-private#303](https://github.com/near/mpc-private/issues/303).

A separate concern surfaced in conversations with Defuse and Proximity: both teams have already implemented (Proximity) or plan to implement (Defuse) on-chain TEE attestation verification, with logic that overlaps significantly with ours but diverges in details (Proximity whitelists PPIDs, doesn't whitelist launcher images, embeds measurements differently; Defuse wants a separate collateral-caching contract). All three teams running their own copy of `dcap_qvl::verify()` plus its dependency tree on-chain is wasteful and means every fix to `dcap-qvl` (e.g., TCB cert rotation, advisory-ID handling) has to be applied N times.

The goal is therefore twofold:

1. **Shrink the MPC contract** by removing dcap-qvl plumbing.
2. **Provide a shared verifier** that Defuse, Proximity, and any future TEE-using project on NEAR can adopt, so the dcap-qvl logic and its WASM cost are paid once across the network.

The intended outcome: a thin global contract wrapping `dcap_qvl::verify()` that takes (`quote`, `collateral`, `now`) and returns the parsed verified report. Per-team allowlists, report-data binding, and extra checks live outside the verifier. The MPC contract keeps its current TEE state shape for v1 to avoid Borsh migrations; longer term, that state moves into a separate per-team policy contract so application contracts become TEE-agnostic.

## Table of Contents

1. [Current state](#1-current-state)
2. [Design principles](#2-design-principles)
3. [Short-term design (v1)](#3-short-term-design-v1)
4. [Long-term design vision](#4-long-term-design-vision)
5. [Cross-team considerations](#5-cross-team-considerations)
6. [Migration](#6-migration)
7. [Open questions](#7-open-questions)

## 1. Current state

### 1.1 Where attestation verification lives today

Three Rust crates and one contract:

| Crate / file | Role | LOC |
|---|---|---|
| [dcap-qvl](https://github.com/Phala-Network/dcap-qvl) (external) | Cryptographic DCAP verification: cert chains, ECDSA P-256 signatures, TCB matching, QE identity matching. Returns a `VerifiedReport`. | external |
| [crates/attestation/src/](crates/attestation/src/) | Wraps `dcap_qvl::verify()`. Adds: TCB-status `UpToDate` check, advisory-IDs empty check, RTMR3 event-log replay, app-compose JSON parsing + validation, app-compose-hash event check, report_data binding via `ReportData`, RTMRs match against caller-supplied `ExpectedMeasurements`. **No knowledge of MPC-specific concepts.** | ~870 |
| [crates/mpc-attestation/src/](crates/mpc-attestation/src/) | MPC-specific extras on top of `attestation`: extracts MPC image hash from a launcher-emitted RTMR3 event, computes launcher compose hash from `app_compose.docker_compose_file`, checks both against caller-supplied allowlists. Defines `ValidatedDstackAttestation` and the `re_verify` method that re-checks a stored attestation against updated allowlists. Also defines `MockAttestation` for tests. | ~890 |
| [crates/contract/src/tee/](crates/contract/src/tee/) | On-chain state and governance: stores allowed measurements / image hashes / launcher images, tracks votes for adding/removing each, stores `VerifiedAttestation` blobs keyed by TLS pubkey, provides `add_participant` and `reverify_and_cleanup_participants`. Wired into 15+ entry points in [`lib.rs`](crates/contract/src/lib.rs) (`submit_participant_info`, `verify_tee`, `vote_code_hash`, `vote_add_launcher_hash`, `vote_remove_launcher_hash`, `vote_add_os_measurement`, `vote_remove_os_measurement`, `clean_invalid_attestations`, `clean_tee_status`, `get_attestation`, etc.). | ~2,140 |

The verification call chain on `submit_participant_info` ([`lib.rs:773`](crates/contract/src/lib.rs#L773)):

```
submit_participant_info(attestation, tls_pk)
  → tee_state.add_participant(node_id, attestation, grace_period)         // tee_state.rs:142
    → attestation.verify(expected_report_data, now, allowlists)            // mpc-attestation/attestation.rs:135
      → DstackAttestation::verify(report_data, now, accepted_measurements) // attestation/attestation.rs:126
        → dcap_qvl::verify::verify(quote, collateral, now)                 // dcap-qvl/verify.rs
```

Re-verification on whitelist change (`verify_tee`, [`lib.rs:1506`](crates/contract/src/lib.rs#L1506)):

```
verify_tee()
  → tee_state.reverify_and_cleanup_participants(participants, grace)       // tee_state.rs:212
    → for each participant: VerifiedAttestation::re_verify(now, allowlists) // mpc-attestation/attestation.rs:80
       (hash-list comparisons only — no dcap-qvl call)
```

The crucial property: **re-verification does not invoke dcap-qvl.** It just walks the stored `ValidatedDstackAttestation` (mpc image hash, launcher compose hash, measurements, expiry) against the current allowlists. This is what makes splitting the expensive verify out feasible — it only runs at first submission, not on every signature, and not even on every sweep.

### 1.2 What the other teams do

**Proximity** — [shade-attestation crate](https://github.com/NearDeFi/shade-agent-framework/tree/main/shade-attestation) and [shade-contract-template](https://github.com/NearDeFi/shade-agent-framework/tree/main/shade-contract-template):
- Crate signature: `DstackAttestation::verify(expected_report_data, now, accepted_measurements, accepted_ppids)`. Adds a **PPID whitelist check** that we don't have.
- Stores `approved_measurements`, `approved_ppids`, `agents` (verified agents map). Owner-gated governance (`require_owner()`).
- No launcher concept. No multi-image-hash grace period. Report-data binding is the caller's account ID, not a TLS+account pubkey hash.
- Uses `dcap-qvl 0.4.0`.

**Defuse** — no on-chain attestation contract yet. Their proposed design (the diagram in the user's TODO.md):
- Off-chain TEE component calls `verifier.verify_attestation(quote, ..., application_account_id, msg)`.
- Verifier callbacks into the application via `application.on_tee_attested(sender, msg)`.
- Application contract is fully TEE-agnostic; gates by `predecessor == verifier.near` plus its own ACL.
- Optional separate "Permissionless Collateral Caching Contract".
- Two separate contracts intended: "collateral governance" and "approved measurements governance", each gated by a single `admin_id` field.

**MPC** — current state described in §1.1.

The three implementations all wrap `dcap_qvl::verify` but disagree on:
1. **Report-data binding**: MPC binds `sha3_384(tls_pk || account_pk)`, Proximity binds the caller's account ID, tee-solver binds the signer's pubkey.
2. **Extra post-DCAP checks**: MPC checks launcher + MPC image hash via RTMR3 event-log replay; Proximity checks PPIDs + app-compose hash; tee-solver only checks compose hash.
3. **Allowlist storage**: all three keep allowlists on-chain but with different shapes and different governance (MPC: threshold-of-participants vote, Proximity: owner, Defuse: planned `admin_id`).

### 1.3 NEAR Global Contracts

[NEAR docs](https://docs.near.org/smart-contracts/global-contracts) describe two flavours:
- **By account ID**: deployed at an account; that account's owner can upgrade. Callers do normal cross-contract calls to that account. Async, like any cross-contract call. Upgradable.
- **By code hash**: code identified by hash; immutable. Other accounts can deploy that exact code at their own address (sharing the binary on-network but not state). Calls into the code happen in the local account's context.

Deployment cost is ~10x normal (10 NEAR per 100 KB), but per-call overhead is negligible.

## 2. Design principles

These guide both the v1 scope and the long-term direction:

- **The verifier is the thinnest possible wrapper around `dcap_qvl::verify()`.** Anything team-specific (allowlists, report_data binding, governance) lives outside it. This maximizes reuse: every team agrees on what `verify()` does because it does only what dcap-qvl does.
- **State stays where it's governed.** Per-team allowlists and stored attestations live in per-team contracts because per-team governance is what mutates them. The verifier doesn't store them and doesn't need to know about them.
- **Don't break the hot path.** Re-verification (called from `verify_tee`, post-reshare cleanup, `clean_invalid_attestations`) iterates over many participants and must stay synchronous and in-process. It already does — `re_verify` is hash comparisons only — so this is a "don't regress" property, not a new requirement.
- **Async cross-contract is fine for the cold path.** `submit_participant_info` is called once per node onboarding, then never again for that node. A one-Promise-plus-callback round-trip is acceptable there.
- **Borsh state is sacred.** Existing on-chain `TeeState` Borsh layout is not changed in v1. Migration of stored attestations is reserved for the long-term split.
- **Don't bake heterogeneity into the verifier.** Report-data binding differs across teams; the verifier doesn't check report_data at all. Extra checks differ across teams; the verifier doesn't run them.

## 3. Short-term design (v1)

### 3.1 What ships

A single new global contract, **`tee-verifier`**, deployed by-account-id (e.g. as `tee-verifier.near`). It exposes one method:

```rust
pub fn verify_quote(
    &self,
    quote: Vec<u8>,
    collateral: Collateral,
    now_seconds: u64,
) -> Result<VerifiedReport, VerificationError>;
```

Where:
- `Collateral` is a thin wrapper over `dcap_qvl::QuoteCollateralV3` (already exists in [crates/attestation/src/collateral.rs](crates/attestation/src/collateral.rs)).
- `VerifiedReport` is a Borsh-stable wire type that mirrors `dcap_qvl::verify::VerifiedReport`: `status: String`, `advisory_ids: Vec<String>`, `report: TDReport10` (RTMRs, MRTD, report_data, ...), `ppid: [u8; 16]`, plus the QE/platform TCB statuses. The wire type is owned by the verifier contract and re-exported via a small `tee-verifier-interface` crate.
- Errors: same enum as `dcap_qvl::verify` errors plus a `Custom(String)` variant.

The verifier does **only** what `dcap_qvl::verify::verify(&quote, &collateral, now_seconds)` does. No advisory-IDs check. No report_data binding. No RTMR3 replay. No measurement match. The caller does all of those — see §3.3.

The verifier method is `&self` (read-only logic) but must be a regular call (not a view call) because cross-contract calls to view methods aren't supported from a mutating context. It writes nothing.

### 3.2 Verifier state and governance (v1)

The verifier's state in v1 is **empty** (the contract has no fields apart from a near-sdk owner). PCCS root certs are compiled into the dcap-qvl crate as constants — the same as today. Upgrades to the verifier (e.g., to pick up a new `dcap-qvl` version with rotated Intel root certs or a new advisory list) are pushed by an `admin_id` (initially the MPC DAO; pluggable to a multi-team committee later — see §7).

Why no state? Because every per-team policy decision (which measurements, which advisory IDs, which TCB statuses to accept, what to bind in report_data) belongs in that team's policy contract, not in the shared verifier. Even "is `UpToDate` the only acceptable TCB status?" is something Proximity and MPC happen to agree on today but might diverge on tomorrow. Keeping it out of the verifier costs nothing and avoids forcing all teams into one policy.

### 3.3 MPC contract changes in v1

The MPC contract keeps its `TeeState` exactly as today (§1.1). The only behavioural change is that `tee_state.add_participant` in [tee_state.rs:142](crates/contract/src/tee/tee_state.rs#L142) no longer calls `attestation.verify()` synchronously. Instead:

```
submit_participant_info(attestation, tls_pk)        [entry point — lib.rs:773]
  ├─ assert caller is signer; extract account_pk
  ├─ build NodeId
  ├─ compute expected_report_data = ReportDataV1::new(tls_pk, account_pk).into_bytes()
  ├─ snapshot current allowlists (mpc_image_hashes, launcher_compose_hashes, measurements)
  ├─ stash (NodeId, expected_report_data, snapshot, attached_deposit) for the caller
  ├─ schedule Promise: tee_verifier.verify_quote(quote, collateral, now)
  └─ chain callback: on_attestation_verified(caller)

on_attestation_verified(caller)                     [callback — new]
  ├─ retrieve VerifiedReport from PromiseResult
  ├─ load (NodeId, expected_report_data, snapshot, deposit) for the caller
  ├─ run all the post-DCAP checks the attestation crate does today:
  │     - report.status == "UpToDate"
  │     - report.advisory_ids.is_empty()
  │     - report.report.as_td10().is_some()
  │     - SHA-3 binding match: report.report.report_data == expected_report_data
  │     - RTMR3 replay against tcb_info.event_log
  │     - app_compose JSON validation
  │     - app_compose hash event match
  │     - RTMR0/1/2/MRTD match against snapshot.measurements
  │     - key_provider digest match
  │     - extract & check MPC image hash against snapshot.mpc_image_hashes
  │     - compute & check launcher compose hash against snapshot.launcher_compose_hashes
  ├─ build ValidatedDstackAttestation { mpc_image_hash, launcher_compose_hash, expiry, measurements }
  ├─ insert into stored_attestations[node_id.tls_public_key]
  └─ refund excess attached_deposit; clear stashed pending state for the caller
```

The post-DCAP checks above are **exactly** what `attestation::DstackAttestation::verify` plus `mpc-attestation::Attestation::verify` do today (see [attestation.rs:126](crates/attestation/src/attestation.rs#L126) and [mpc-attestation/attestation.rs:135](crates/mpc-attestation/src/attestation.rs#L135)). They simply move from running synchronously inside `tee_state.add_participant` to running inside `on_attestation_verified` after the verifier returns the parsed report. The `DstackAttestation` struct itself becomes the input to the callback (the caller still submits `quote`, `collateral`, `tcb_info`); we only offload the cryptographic dcap-qvl part to the verifier, then re-attach the parsed report to the local `tcb_info` for the event-log/app-compose checks.

`re_verify` and `verify_tee` are unchanged — they don't call dcap-qvl, so they don't need the verifier.

#### Why split this way (and not call the verifier for everything)

The alternative is to have the verifier do RTMR3 replay, app_compose validation, and the report-data check too — i.e. host the whole `attestation` crate, not just `dcap_qvl`. That makes every consumer's caller-side code one line shorter, but:

1. RTMR3 replay needs `tcb_info.event_log`, which is a separate input from the quote. Either the verifier takes another argument, or every consumer agrees on Dstack's TCB-info shape.
2. App-compose validation is opinionated — MPC requires `kms_enabled == false`, `gateway_enabled == Some(false)`, etc. ([attestation.rs:366](crates/attestation/src/attestation.rs#L366)). Proximity may want different rules.
3. Report-data binding differs across teams (§1.2). The verifier returning the raw report and letting the caller compare is the cleanest way to support all three bindings.

So v1 keeps the verifier at "what dcap-qvl does" and lets the `attestation` crate (still no-std) be linked by each consumer's policy/application contract. Other teams can pull in whichever subset of `attestation` makes sense for them, or write their own.

### 3.4 PCCS / collateral handling (v1)

Unchanged from today: the off-chain MPC node fetches collateral (via `tee-authority` → Dstack → PCCS) and submits it inline as part of the attestation payload. The verifier accepts inline collateral on every call. No on-chain PCCS cache in v1.

This deliberately leaves the [Automata-style PCCS-on-chain](https://github.com/automata-network/automata-on-chain-pccs) idea for a follow-up workstream (§4.4).

### 3.5 What v1 saves on the MPC contract

- Removes `mpc-attestation`'s `dcap-qvl` transitive deps from the WASM build (the largest dep tree it has).
- Removes ~60 lines from `tee_state.rs` (the dcap-qvl call inside `add_participant`).
- Adds ~150 lines for the callback path and the `pending_attestations` map.
- Net WASM size win: roughly half of what a naive "move everything TEE-related" effort would yield, but with zero state-migration risk.

The "second half" of the savings is realized in the long-term split (§4).

## 4. Long-term design vision

### 4.1 Three-contract architecture

The end state has three contract roles per team:

```
                         ┌─────────────────────────────────┐
                         │  tee-verifier (global, shared)  │
                         │  verify_quote(quote, coll, now) │
                         │  → VerifiedReport               │
                         │  state: empty (or PCCS roots)   │
                         └──────────────┬──────────────────┘
                                        │
                       ┌────────────────┼────────────────────┐
                       │                │                    │
            ┌──────────▼─────┐  ┌───────▼────────┐  ┌────────▼──────────┐
            │ mpc-tee-policy │  │ defuse-policy  │  │ proximity-policy  │
            │ admin_id, all- │  │ admin_id, …    │  │ admin_id, ppids,  │
            │ owed measure-  │  │                │  │ measurements, …   │
            │ ments, image   │  │                │  │                   │
            │ hashes, launch │  │                │  │                   │
            │ er hashes,     │  │                │  │                   │
            │ stored_attest- │  │                │  │                   │
            │ ations         │  │                │  │                   │
            └──────────┬─────┘  └───────┬────────┘  └────────┬──────────┘
                       │                │                    │
            ┌──────────▼─────┐  ┌───────▼────────┐  ┌────────▼──────────┐
            │ mpc-contract   │  │ defuse-app     │  │ proximity-app     │
            │ TEE-agnostic:  │  │ TEE-agnostic   │  │ TEE-agnostic      │
            │ asks policy    │  │                │  │                   │
            │ "is X attested │  │                │  │                   │
            │  & authorized?"│  │                │  │                   │
            └────────────────┘  └────────────────┘  └───────────────────┘
```

- **`tee-verifier`** is the same global contract as in v1, unchanged. One per network.
- **Per-team policy contract** (e.g., `mpc-tee-policy.near`) holds: allowed measurements, allowed image / launcher hashes (or PPIDs, or whatever the team uses), stored verified attestations, and the team's extra-check logic (RTMR3 replay rules, report_data binding rules, app_compose validation rules). Single `admin_id` field for governance, per Defuse's design. The admin_id can be a DAO, a proxy, or a single account.
- **Application contract** (e.g., `mpc.near`) becomes TEE-agnostic. It calls into the policy contract to ask "is the caller currently a valid attested operator?" and the policy contract enforces whatever team-specific rules apply.

Why this end state:

- **TEE-agnostic application contracts.** The MPC contract today has 15+ entry points threading TEE concepts. Pushing them out makes the contract conceptually about MPC (signing, key events, governance) and not about TEEs. Bug fixes in attestation logic stop touching the signing-path code.
- **Per-team policy isolation.** Proximity wants PPID checks; we don't. Defuse may want timelock / DAO-veto integration. Each team's policy contract can encode whatever it needs without negotiating with the others.
- **Composable governance.** A single `admin_id` is the simplest possible governance interface and lets each team plug in any authorization scheme behind it (Sputnik DAO, RBAC proxy, multisig, single key) without the policy contract having to know.
- **Re-verification stays synchronous.** Re-verification (`verify_tee`) becomes a cross-contract call from the application to the policy contract — but only when triggered, not on the hot path. Inside the policy contract, the per-attestation `re_verify` work stays in-process, just like today.

### 4.2 The application/policy interface

Conceptually:

```rust
trait TeePolicyContract {
    // Cold path: a candidate node submits attestation evidence.
    // Async: schedules verifier call, runs extra checks in callback, stores result.
    fn submit_attestation(
        attestation: Attestation,
        node_id: NodeId,
        // optional opaque bytes the application contract wants bound into
        // report_data; the policy contract checks the binding using its own scheme
        report_data_payload: Vec<u8>,
    ) -> Promise;

    // Hot path: the application contract asks "is this account currently attested?"
    fn is_attested(&self, node_id: NodeId) -> bool;

    // Re-verification: triggered when whitelists change.
    fn reverify_all(&mut self) -> ReverifyResult;
}
```

The application contract holds the *participant set* (who's authorized to do MPC stuff at all), the policy contract holds the *attestation set* (who has a valid TEE quote on file). Hot-path checks become `policy.is_attested(node_id)` cross-contract calls, which the application contract caches optimistically (the post-attestation set is small and changes rarely).

This still carries the cost of a cross-contract call on a path that's currently synchronous (`is_caller_an_attested_participant`). The right way to dodge that is for the policy contract to publish "attested" events the application contract subscribes to, or for the application contract to keep a thin replica of the attested set and trust the policy contract's writes. The exact mechanism is a v2 design problem.

### 4.3 Migration to long-term

The v1 design is a stepping stone, not a dead end:

1. v1 ships the global verifier and re-points the MPC contract's `submit_participant_info` at it. State stays in MPC.
2. v2 introduces `mpc-tee-policy` and migrates `TeeState` out of the MPC contract into it. This requires Borsh state migration of the existing `stored_attestations` and the allowlist storage. The migration is mechanical (read from MPC, write to policy, mark as migrated).
3. v3 replaces `is_caller_an_attested_participant` and the rest of the TEE entry points in `mpc-contract` with calls into `mpc-tee-policy`.

### 4.4 PCCS on-chain caching (separate workstream)

Both Defuse and Proximity want collateral managed centrally, not re-uploaded on every call. The natural model is to mirror [Automata's on-chain PCCS](https://github.com/automata-network/automata-on-chain-pccs):

- A separate global contract `pccs.near` stores the freshest collateral per FMSPC, signed by an admin_id-controlled identity (or permissionless if root-CA chain validation is replayed on insert).
- The verifier optionally accepts a `(pccs_account_id, fmspc)` tuple instead of inline collateral; in that case it reads collateral via a cross-contract call.
- The MPC node fetches collateral once, submits it to `pccs.near`, then subsequent quotes from any team can reference it.

This is a separate design and a separate ship. v1 ignores it; the verifier API will need to grow a `verify_quote_via_pccs(quote, pccs_account_id, fmspc, now)` companion when the time comes. Not blocking.

## 5. Cross-team considerations

### 5.1 Report-data binding heterogeneity

The verifier doesn't check report_data — it just returns it inside `VerifiedReport.report.report_data`. Each team's policy contract checks report_data against whatever it wants:

- MPC: `sha3_384(tls_pk || account_pk)` ([report_data.rs:64](crates/mpc-attestation/src/report_data.rs#L64))
- Proximity: account ID padded to 64 bytes
- tee-solver: signer pubkey
- Future teams: anything else

This is achieved at zero verifier-side cost: the verifier returns the parsed report and stays out of the binding decision. The cost is that *every* policy contract has to explicitly check report_data — it's not enforced by the verifier. We accept that cost; it keeps the verifier shared.

### 5.2 Allowed-status policy heterogeneity

Today MPC requires `status == "UpToDate"` and `advisory_ids.is_empty()` ([attestation.rs:23](crates/attestation/src/attestation.rs#L23)). Proximity requires the same. If a future team wants to allow `OutOfDate` or specific advisory IDs (e.g., during a vulnerability patch window), they implement that in their policy contract. The verifier returns the raw status and advisory IDs; the policy decides.

### 5.3 Extra checks (RTMR3 replay, launcher, PPID, app_compose)

All of these are post-DCAP. The verifier doesn't run them. Each team's policy contract runs whichever subset it needs:

- MPC runs RTMR3 replay + launcher compose hash + MPC image hash + app_compose validation.
- Proximity runs RTMR3 replay (for app-compose-hash event) + PPID check + app_compose hash check.
- Defuse: TBD.

The `attestation` crate (not `mpc-attestation`) provides reusable building blocks for these — RTMR3 replay, app_compose JSON validation, etc. — that any team's policy contract can pull in. The crate is no_std and Borsh-serializable, so dropping it into a WASM contract is cheap.

### 5.4 Adoption path for Defuse and Proximity

In v1:
- Both teams continue running their own current verification stacks (Proximity's `shade-attestation` contract, Defuse's not-yet-deployed contract).
- They can adopt the global `tee-verifier` opportunistically by pointing their `verify` call at it instead of re-implementing dcap-qvl locally.

In v2:
- The `mpc-tee-policy` contract design becomes a reference implementation. Proximity could fork it and customize for PPID checks; Defuse could do the same.

### 5.5 dcap-qvl version alignment

MPC and Proximity currently pin different dcap-qvl versions in their respective `Cargo.toml`. The global verifier should pin to a specific dcap-qvl version, and that pin becomes the de facto network-wide standard. Bumping the pin is a verifier upgrade — pushed by the verifier's `admin_id`. This is the headline benefit of the global contract: dcap-qvl bugfixes get rolled out once, not three times.

## 6. Migration

The v1 migration is **state-preserving**: existing `stored_attestations` are untouched, the `TeeState` Borsh layout is unchanged, all governance entry points keep working. The only behavioural change is that `submit_participant_info` becomes a two-step transaction (Promise to the verifier + callback that finalizes insertion).

The verifier is deployed first; once stable, the MPC contract is upgraded to point at it. Node operators are coordinated since `submit_participant_info` becomes async on the off-chain side.

A detailed PR sequence will accompany the implementation; that lives outside this design doc.

## 7. Open questions

### 7.1 Verifier governance

Who owns `tee-verifier.near` and decides when to upgrade it? Options:

- MPC DAO controls it. Simplest, but feels presumptuous given that other teams will use it.
- A multi-team committee account (multisig or Sputnik DAO with reps from MPC, Defuse, Proximity).
- An on-chain process: e.g., "any pinned dcap-qvl version with at least N team approvals can be deployed".

Recommendation: **start with a multisig of 2-of-{MPC, Proximity, Defuse} reps**. Migrate to a heavier governance scheme if/when the verifier sees more adopters. The relevant near-sdk pattern is the same `admin_id` that Arseny proposed for policy contracts.

### 7.2 Promise gas budget for `submit_participant_info`

The verifier's `verify_quote` does a non-trivial amount of work (cert chain validation, multiple ECDSA P-256 sigs). Estimate is 5-15 TGas. Plus the callback's RTMR3 replay + hash checks (~3-5 TGas). Plus storage writes. Total budget request needs to be set on the cross-contract call. We need to measure on testnet before committing a number.

### 7.3 Failure modes of the async path

If the verifier promise fails (e.g., the verifier contract is unreachable, runs out of gas, or returns `VerificationError`), the callback must clean up the caller's stashed pending state and refund the attached deposit. If the callback itself fails, the deposit is potentially stuck. We should expose a sweep entry point (mirroring the existing `clean_invalid_attestations` pattern) so anyone can clear stale pending entries after a timeout.

### 7.4 Should the verifier optionally do the report_data binding?

Counter-argument to §3.3: every consumer is going to do *some* report_data binding, and 99% of them are going to bind some hash of public-key-ish data. A `verify_quote_with_binding(quote, collateral, expected_report_data: [u8; 64], now)` convenience method that adds a memcmp wouldn't hurt and would save consumers a few lines.

Recommendation: don't add it. The whole point is to keep the verifier minimal; one consumer's "convenience method" is another's "wrong abstraction." Consumers can write a 5-line wrapper.

### 7.5 What happens to `MockAttestation`?

`MockAttestation` (in [mpc-attestation/src/attestation.rs:47](crates/mpc-attestation/src/attestation.rs#L47)) is used heavily in tests. After the split, mock-attestation tests can short-circuit the verifier promise (no verifier call needed; the post-DCAP code path handles `MockAttestation` entirely). This works because the `Attestation` enum is still the input shape on `submit_participant_info` — only the `Dstack` variant requires the verifier round-trip. Make this explicit in the migration.

### 7.6 Versioning of the verifier wire types

The `VerifiedReport` Borsh shape will likely evolve with dcap-qvl (e.g., TDX 1.5 reports add fields). We need an explicit versioning story before mainnet so that an older caller doesn't crash on a newer verifier output. Options:

- Tag the response with a version byte; callers ignore unknown trailing fields.
- Require all callers and the verifier to be deployed in lockstep (they aren't — callers are independent).
- Verifier exposes both `verify_quote_v1` and `verify_quote_v2` in parallel during transitions.

Recommendation: third option. Always introduce a new method when the wire type changes.

### 7.7 Should v1 also expose `verify_post_dcap` from the verifier?

A shared "do the RTMR3 replay + measurement match given a list of allowed measurements" utility could itself be a verifier method. It's pure compute (no I/O), shared across teams, and would let the MPC contract drop more code. But the inputs heterogenize across teams (Proximity doesn't replay RTMR3 the same way), so it's not a clean abstraction.

Recommendation: not in v1. Re-evaluate in v2 once the policy contracts exist and we see what's actually duplicated.
