# Shared TEE Attestation Verifier Contract

[NEAR's MPC][mpc-repo], [Defuse][defuse-site], and [Proximity][proximity-shade-attestation] all run on-chain Intel TDX attestation verification, each carrying its own copy of `dcap_qvl::verify()` and its dependency closure (`ring`/`webpki`, X.509 parsing, SHA-2/SHA-3). Every fix to `dcap-qvl` (TCB cert rotation, advisory-ID handling) gets applied N times. Worse, the MPC contract WASM is approaching the 1.5 MB transaction-size limit imposed by [NEP-509][nep-509]; the attestation crates are the heaviest dependency surface in that contract.

Goals:

- Provide a shared, generic verifier serving any Intel TDX-based NEAR contract — `dcap-qvl` bugfixes ship once.
- Shrink the MPC contract WASM below the NEP-509 limit by breaking attestation verification out into a separate contract.
- Roll out incrementally: v1 keeps state migration to zero. Architectural improvements follow in v2 (per-team policy contracts) and v3 (ACL-shaped interfaces, on-chain PCCS caching).

Design choices that follow from these goals, applied throughout the design below:

- The verifier is the thinnest possible wrapper around `dcap_qvl::verify()`. Anything team-specific lives outside it.
- State stays where it's governed: per-team allowlists and stored attestations live in per-team contracts, not in the shared verifier.
- The hot path doesn't change. Re-verification is hash comparisons today; v1 does not regress that.

## Current State

### MPC contract today

The MPC contract has two attestation flows:

- **Initial verification** (`submit_participant_info`): runs `dcap_qvl::verify` plus all post-DCAP checks once per node onboarding. Cold path.
- **Re-verification** (`verify_tee`, post-reshare cleanup, `clean_invalid_attestations`): re-checks each stored `ValidatedDstackAttestation` against current allowlists using only hash comparisons. Hot enough to be called per-sweep across all participants. Crucially, this path does **not** invoke `dcap_qvl::verify`.

This asymmetry is what makes the breakout viable: only the cold path needs the heavyweight verifier; the hot path stays local and cheap.

MPC binds report-data as `sha3_384(tls_pk || account_pk)` (see [`crates/mpc-attestation/src/report_data.rs`][mpc-report-data]). It runs RTMR3 event-log replay, MPC image-hash whitelisting, launcher-compose-hash whitelisting, and app_compose JSON validation as post-DCAP checks. Allowlists are governed by a threshold-of-participants vote.

### Other teams

[**Proximity**][proximity-shade-attestation]:

- PPID whitelist check (MPC has no equivalent).
- No launcher concept: app images are stateless by design, so the [launcher pattern][mpc-launcher] isn't needed; app-image gating is via the app-compose hash whitelist.
- Report-data binding is the caller's account ID (vs. MPC's `sha3_384(tls_pk || account_pk)`).
- Single `owner_id` field gates all governance.

[**Defuse**][defuse-site]: no on-chain attestation contract yet. Their proposed design:

- Verifier is global; callbacks the application via `application.on_tee_attested(sender, msg)`.
- Application is fully TEE-agnostic — gates by `predecessor == verifier.near` plus its own ACL.
- Two contracts: collateral governance + measurements governance, each with a single `admin_id`.

## Short-Term Design (v1)

The MPC team needs the contract shrunk fast, so v1 is deliberately small: extract `dcap_qvl::verify()` into a shared verifier, point the MPC contract at it, change nothing else. Per-team policy contracts, on-chain PCCS caching, and ACL generalization wait for v2 and v3.

```
┌──────────────────────────────┐
│  tee-verifier-v1.near        │
│  Global Contract by CodeHash │
│  verify_quote(...)           │
│  → VerifiedReport            │
└──────▲────────────────┬──────┘
       │                │
       │ Promise        │ VerifiedReport
       │ (verify_quote) │ (callback)
       │                ▼
┌──────┴────────────────────────┐
│  mpc-contract                 │
│  TeeState unchanged           │
│  stored_attestations cache    │
│  re_verify hot path local     │
└───────────────────────────────┘
```

### Verifier contract

The verifier WASM is published as a [NEP-591][nep-591] **Global Contract by CodeHash**. CodeHash makes the published code immutable on the network and auditable by hash — the security story we want for an attestation-verification dependency. Upgrades happen by publishing a new hash and migrating consumers to a new versioned account; we never edit deployed code in place.

A versioned account (e.g., `tee-verifier-v1.near`) issues `UseGlobalContractAction(Global(<code_hash>))` to make itself a callable instance of the verifier. Consumers Promise into that account. When v2 of the verifier ships, a fresh account (e.g., `tee-verifier-v2.near`) issues `UseGlobalContractAction` against the new hash and consumers update their Promise targets explicitly. There is no admin on either the published code or the version account.

The verifier exposes one method:

```rust
pub fn verify_quote(
    &self,
    quote: Vec<u8>,
    collateral: Collateral,
    now_seconds: u64,
) -> Result<VerifiedReport, VerificationError>;
```

`Collateral` and `VerifiedReport` are Borsh-stable wire types matching `dcap_qvl::verify::QuoteCollateralV3` and `dcap_qvl::verify::VerifiedReport` respectively, exposed via a new `tee-verifier-interface` crate so callers can decode the response without depending on `dcap-qvl` directly. The returned `VerifiedReport` carries the parsed quote (RTMRs, MRTD, report_data, advisory IDs, TCB statuses); each consumer's downstream policy then decides what counts as acceptable for its application.

The verifier does only what `dcap_qvl::verify::verify` does. No advisory-ID check, no report-data binding, no RTMR3 replay, no measurement match — those checks differ across teams (RTMR3 inputs, app-compose policy, report-data binding all diverge), so they live in each consumer's policy/application code.

### MPC contract changes

`TeeState` (the MPC contract's stored attestations and allowlists) is unchanged in v1. Cross-contract calls into a Global Contract are normal NEAR async Promises; the MPC contract becomes a Promise + callback flow on the cold path:

```
submit_participant_info(attestation, tls_pk):
    1. The MPC contract validates the caller, builds a NodeId, computes the
       expected report_data, and snapshots its current allowlists (image hashes,
       launcher hashes, measurements).
    2. It stashes those values plus the caller's attached deposit, keyed by the
       caller's account ID, so the callback can find them again.
    3. It schedules a Promise to tee-verifier-v1.near.verify_quote(quote,
       collateral, now), chained to its own on_attestation_verified callback.

on_attestation_verified(caller):
    1. Loads the VerifiedReport from the Promise result and the stashed state.
    2. Runs the post-DCAP checks against the snapshot taken at submit time:
       status, advisory IDs, report_data binding, RTMR3 replay, app_compose
       validation, RTMR/MRTD match against allowed measurements, MPC image hash,
       launcher compose hash.
    3. On success: builds a ValidatedDstackAttestation and inserts it into
       stored_attestations.
    4. On failure: leaves stored_attestations untouched and refunds the deposit.
       Either way, clears the stashed state.
```

The post-DCAP checks happen on the MPC contract because:

- RTMR3 replay needs `tcb_info.event_log`, a separate input with a Dstack-specific shape we don't want to standardize at the verifier layer.
- App-compose validation is opinionated (MPC's `kms_enabled == false`, etc.); other teams may want different rules.
- Report-data binding differs across teams.

Each verified attestation is **cached** in the MPC contract's `stored_attestations` (keyed by TLS pubkey, just like today). Subsequent operations — signing, re-verification on allowlist changes, post-reshare cleanup — read from this cache and never call the verifier. The verifier is only invoked once per node onboarding.

### Re-verification doesn't call the verifier

`re_verify`, `verify_tee`, post-reshare cleanup, and `clean_invalid_attestations` are unchanged in v1. They operate on cached `ValidatedDstackAttestation` blobs and do hash comparisons against the current allowlists. None of them call the verifier; they don't even need a Promise. Same property as today.

In v2/v3, this logic moves into the per-team policy contract (see "Long-Term Direction" below). At every version, re-checking already-stored attestations against current allowlists never calls the verifier — it's a local read of the cache (`mpc-contract`'s in v1, `mpc-tee-policy`'s in v2/v3). The verifier only runs at first submission, never on re-checks.

### What v1 saves

- The `mpc-contract` WASM no longer transitively depends on `dcap-qvl`, `ring`, `webpki`, or X.509 parsing. This is the load-bearing reduction for the NEP-509 size constraint.
- No on-chain state migration: existing `stored_attestations` and allowlists keep their Borsh layout, all governance entry points keep working. The only behavioural change is that `submit_participant_info` becomes a two-step transaction.
- PCCS / collateral handling is unchanged: the off-chain MPC node fetches collateral via `tee-authority` → Dstack → PCCS and submits it inline as part of the attestation payload, and the verifier accepts inline collateral on every call. On-chain PCCS caching is pinned to v3.

## Long-Term Direction

### v2: Per-team policy contracts

```
                    ┌──────────────────────────────┐
                    │  tee-verifier-v1.near        │
                    │  (or v2, v3 by code hash)    │
                    └──────────────▲───────────────┘
                                   │ Promise(verify_quote)
              ┌────────────────────┼─────────────────────┐
              │                    │                     │
   ┌──────────┴─────┐  ┌───────────┴──────┐  ┌───────────┴──────┐
   │ mpc-tee-policy │  │  defuse-policy   │  │ proximity-policy │
   │ (per-team)     │  │  (per-team)      │  │ (per-team)       │
   │ allowlists,    │  │                  │  │                  │
   │ stored_attest- │  │                  │  │                  │
   │ ations,        │  │                  │  │                  │
   │ admin_id for   │  │                  │  │                  │
   │ governance     │  │                  │  │                  │
   └──────────▲─────┘  └───────────▲──────┘  └───────────▲──────┘
              │ is_attested?       │                     │
              │ (hot path)         │                     │
   ┌──────────┴─────┐  ┌───────────┴──────┐  ┌───────────┴──────┐
   │ mpc-contract   │  │ defuse-app       │  │ proximity-app    │
   │ TEE-agnostic   │  │ TEE-agnostic     │  │ TEE-agnostic     │
   └────────────────┘  └──────────────────┘  └──────────────────┘
```

Per-team policy contract (e.g., `mpc-tee-policy.near`) holds: allowlists, the team's extra-check logic, and `stored_attestations`. Each team's policy contract has its own `admin_id` for governance — the `admin_id` is per-team, not shared. That admin can be a DAO, a proxy, a multisig, or a single account. Different teams can pick different governance schemes behind the same interface.

Application contract becomes TEE-agnostic and asks the policy "is this node attested?". Re-verification on allowlist change moves with `TeeState` into `mpc-tee-policy`; the verifier remains uninvolved.

### v2 application/policy interface

Each team owns its policy contract — there's no shared codebase. We may publish a reference trait like the one below as documentation, but teams aren't required to conform exactly:

```rust
trait TeePolicyContract {
    // Cold path: candidate node submits attestation evidence.
    // Async: schedules verifier call, runs extra checks in callback, stores result.
    fn submit_attestation(
        attestation: Attestation,
        node_id: NodeId,
        report_data_payload: Vec<u8>,
    ) -> Promise;

    // Hot path: is this node currently attested?
    // Answered from the policy contract's local state — `stored_attestations`
    // is right here, so no further Promises are issued. The application
    // contract pays one cross-contract call per check; that's the same
    // round-trip we already accept for `vote_*` flows. If profiling later
    // shows it's still too expensive on the signing path, application-side
    // caching becomes a v3 optimization.
    fn is_attested(&self, node_id: NodeId) -> bool;

    // Triggered by an admin action that changes allowlists.
    fn reverify_all(&mut self) -> ReverifyResult;
}
```

`NodeId` is opaque to the trait — each team can use whatever shape it needs (MPC's `(account_id, tls_pubkey, account_pubkey)`, Proximity's account ID, etc.). The interface is currently TEE-flavoured (`is_attested`, `node_id`); v3 generalizes it (see below).

### v3: ACL-shaped interface and on-chain PCCS

**ACL generalization.** Most TEE-using applications don't actually want to know about TEEs — they want to know "is the caller authorized for this action?". TEE attestation just populates the answer.

Replacing `is_attested(node_id) -> bool` with `is_authorized(account_id, action) -> bool` lets the application contract drop every TEE type. Internally the policy maps `is_authorized` to "is `account_id` in `stored_attestations` AND does it re-verify AND does the action satisfy any role-based restriction?". TEE machinery becomes an implementation detail of the policy.

This generalizes naturally: non-TEE policies (admin-set ACL), multi-mechanism policies (TEE OR hardware key OR DAO membership), or delegated policies that forward to another ACL contract — all conform to the same interface.

This matches the preference Defuse and Proximity have expressed for hiding TEEs behind an authorization layer rather than baking TEE concepts into application contracts.

**On-chain PCCS caching.** Mirroring [Automata's design][automata-pccs]: a separate `pccs.near` contract stores fresh collateral per FMSPC, governed by an `admin_id` (or permissionless if root-CA validation is replayed on insert). The verifier grows a `verify_quote_via_pccs(quote, pccs_account_id, fmspc, now)` companion that reads collateral by cross-contract call instead of accepting it inline. This removes the obligation for off-chain components to fetch and bundle collateral on every call.

## Adoption Path

**v1**: Defuse and Proximity continue running their own verification stacks. They can opportunistically swap their local `dcap_qvl::verify` call for a Promise to `tee-verifier-v1.near`, getting the dcap-qvl-bugfix-once benefit without rewriting their state model.

**v2**: `mpc-tee-policy` becomes a reference policy implementation. Other teams fork and customize.

**v3**: ACL-shaped interface and PCCS-on-chain available; teams adopt as they like.

## Open Questions

### Verifier governance

By-CodeHash means there is no admin on the verifier code itself — bugs are fixed by publishing a new hash, deploying it at a new versioned account (e.g., `tee-verifier-v2.near`), and getting consumers to migrate their Promise targets. Open questions:

- Who has the authority to publish new code hashes? The publication action burns ~25–30 NEAR per ~250–300 KB of WASM.
- Who deploys versioned accounts? Same answer presumably.

### Promise gas budget

`verify_quote` does cert-chain validation and multiple ECDSA P-256 verifies — non-trivial gas. Measurements needed on testnet before pinning a number.

The MPC contract attaches gas to its outbound Promise. The deposit attached to `submit_participant_info` covers storage staking for the new attestation entry; gas is paid out of the MPC contract's balance, not the caller's. If the caller wants to retry after a verifier-side gas exhaustion, they re-submit (paying storage staking again from their deposit, refunded if the prior pending entry was already cleaned up).

### Failure modes of the async path

If the verifier Promise fails (verifier unreachable, gas exhaustion, `VerificationError`), the callback must clear the caller's stashed pending state and refund the attached deposit. If the callback itself fails, the deposit is potentially stuck. Provide a sweep entry point (mirror of the existing `clean_invalid_attestations` pattern) so anyone can clear stale pending entries after a timeout.

### `MockAttestation` in tests

`MockAttestation` was an in-process Rust enum used by the MPC contract's tests — it doesn't make sense on a Global Contract verifier (the verifier accepts raw quote bytes; there's no mock variant on the wire). For unit/integration tests of consumer contracts, deploy a stub verifier contract that returns a hand-crafted `VerifiedReport` without invoking `dcap-qvl`. Document this in the v1 migration so test authors know the test scaffolding pattern is changing.

### Versioning of the verifier wire types

`VerifiedReport`'s Borsh shape will evolve with `dcap-qvl` (e.g., TDX 1.5 reports add fields). With the by-CodeHash architecture this is automatic: each `dcap-qvl` version corresponds to a different code hash, deployed at a different versioned account. Consumers explicitly migrate when ready. No in-place wire-format compatibility tricks needed.

[mpc-repo]: https://github.com/near/mpc
[defuse-site]: https://near-intents.org
[proximity-shade-attestation]: https://github.com/NearDeFi/shade-agent-framework/tree/main/shade-attestation
[mpc-launcher]: ../securing-mpc-with-tee-design-doc.md#launcher
[mpc-report-data]: https://github.com/near/mpc/blob/main/crates/mpc-attestation/src/report_data.rs
[nep-509]: https://github.com/near/NEPs/blob/master/neps/nep-0509.md
[nep-591]: https://github.com/near/NEPs/blob/master/neps/nep-0591.md
[automata-pccs]: https://github.com/automata-network/automata-on-chain-pccs
