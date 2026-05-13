# Shared TEE Attestation Verifier Contract

[NEAR's MPC][mpc-repo], [Defuse][defuse-site], and [Proximity][proximity-shade-attestation] all run on-chain Intel TDX attestation verification, each carrying its own copy of `dcap_qvl::verify()` and its dependency closure (`ring`/`webpki`, X.509 parsing, SHA-2/SHA-3). Every fix to `dcap-qvl` (TCB cert rotation, advisory-ID handling) gets applied N times. Compounding this, the MPC contract WASM is approaching the 1.5 MB transaction-size limit imposed by [NEP-509][nep-509]; the attestation crates are the heaviest dependency surface in that contract.

Goals:

- Provide shared on-chain TEE attestation verification functionality.
- Shrink the MPC contract WASM below the NEP-509 limit.

## Design choices

These constraints apply throughout the design below; each is a deliberate trade-off, not a consequence of the goals above.

- **The verifier is the thinnest possible wrapper around `dcap_qvl::verify()`.** Anything team-specific (RTMR3 replay, app-compose validation, allowlist matches) lives outside it. Keeps the shared component minimal and Dstack-agnostic.
- **State stays where it's governed.** Per-team allowlists and stored attestations live in per-team contracts; the verifier holds no per-team state. Keeps the verifier reusable and avoids tying it to one team's governance.
- **The hot path doesn't change.** Re-verification of cached attestations is hash comparisons today and stays that way in v1. The async cross-contract call only affects the cold path (initial attestation).

## Current State

### MPC contract today

MPC uses an *enrollment* model: a node attests once at onboarding, the result is cached, and later operations read from the cache. Two attestation flows result:

- **Initial verification** (`submit_participant_info`): runs `dcap_qvl::verify` plus all post-DCAP checks once per node onboarding. Cold path.
- **Re-verification** (`verify_tee`, post-reshare cleanup, `clean_invalid_attestations`): re-checks each stored `ValidatedDstackAttestation` against current allowlists using only hash comparisons. This path does **not** invoke `dcap_qvl::verify`.

Both paths live in the attestation flow, not on the signing critical path. Only the initial-verification path needs the heavyweight verifier (full `dcap_qvl::verify` + post-DCAP checks); subsequent re-verifications are partial — hash comparisons against the cached `ValidatedDstackAttestation`.

Other teams use different patterns — Proximity, for example, verifies measurements on every request (see "Other teams" below). The shared verifier serves both patterns; the enrollment/per-call split is a policy decision in the consumer contract.

MPC binds report-data as `sha3_384(tls_pk || account_pk)` (see [`crates/mpc-attestation/src/report_data.rs`][mpc-report-data]). It runs RTMR3 event-log replay, MPC image-hash whitelisting, launcher-compose-hash whitelisting, and app_compose JSON validation as post-DCAP checks. Allowlists are governed by a threshold-of-participants vote.

### Other teams

[**Proximity**][proximity-shade-attestation]:

- *Per-call* attestation model: measurements are verified on every request, not cached at enrollment. The shared verifier is invoked on the hot path rather than only at onboarding.
- Device-identity whitelist check using PPID (or `device_id` — Dstack-defined, `sha256(ppid)` in Dstack ≥0.5.6, forward-compatible with non-TDX hardware). MPC plans to add the same check as a defense against forged quotes from compromised hardware.
- No launcher concept: app images are stateless by design, so the [launcher pattern][mpc-launcher] isn't needed; app-image gating is via the app-compose hash whitelist.
- No constraints on app-compose contents: the contract only checks that the attested `app_compose` hash matches an approved hash, so users can configure fields like `public_logs` freely. MPC, by contrast, enforces specific fields (e.g. `kms_enabled == false`) as part of post-DCAP validation.
- Report-data binding is the caller's account ID (vs. MPC's `sha3_384(tls_pk || account_pk)`).
- Single `owner_id` field gates all governance.

[**Defuse**][defuse-site]: no on-chain attestation contract yet. Their proposed design:

- Verifier is global; callbacks the application via `application.on_tee_attested(sender, msg)`.
- Application is fully TEE-agnostic — gates by `predecessor == verifier.near` plus its own ACL.
- Two contracts: collateral governance + measurements governance, each with a single `admin_id`.

## Short-Term Design (v1)

v1 is deliberately small: extract `dcap_qvl::verify()` into a shared verifier, point the MPC contract at it, change nothing else. Per-team policy contracts, on-chain PCCS caching, and ACL generalization wait for v2 and v3.

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

Consequently, the verifier has no on-chain configuration to govern. Policy (acceptable measurements, image hashes, launcher hashes, advisory-ID handling) lives in the consumer contract via existing governance flows — for MPC, that's `vote_code_hash` / `vote_add_launcher_hash` / `vote_add_os_measurement` on `mpc-contract`. Verifier-internal parameters (`dcap-qvl` version, Intel root certs, `VerifiedReport` schema) are bound to the published code hash and change only by publishing a new hash and creating a new versioned account.

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

`TeeState` (the MPC contract's stored attestations and allowlists) is unchanged in v1. Cross-contract calls into a Global Contract are normal NEAR async Promises; the MPC contract becomes a Promise + callback flow on the cold path.

Beyond the sync → async shift, three things change from today:

- **Reject-if-pending guard.** Today's `submit_participant_info` is one transaction: it either succeeds or reverts entirely. In v1 the call returns before the verifier has answered, so the contract holds a *pending entry* (caller's `account_id` → submitted state) until the callback resolves. To prevent a second submission silently overwriting the first's pending entry and stranding its attached deposit, v1 rejects re-submissions while a prior one is in flight.
- **Allowlists re-read at callback time.** The MPC contract's allowlists (image hashes, launcher hashes, measurements) can change by governance vote at any time. Today they're read once during the synchronous verification. In v1 they're re-read in the callback, so a vote that lands between submit and callback takes effect immediately — a freshly-revoked measurement causes the submission to be rejected even if the verifier already approved the quote.
- **Explicit refund-on-failure.** NEAR contracts pay *storage staking* (NEAR locked while state exists) for every entry they write. The caller attaches a deposit to cover the storage staking for the new `stored_attestations` entry; if there's no entry inserted, the deposit is refunded. Today, a failed attestation reverts the whole transaction and the deposit is rolled back automatically. In v1 the submit transaction commits *before* the verifier responds, so the deposit sits with the contract until the callback resolves; on failure, the callback has to refund it explicitly.

Everything else is unchanged: `NodeId` shape, `Sha3_384(tls_pk || account_pk)` binding, post-DCAP checks, `stored_attestations` layout, storage staking, 7-day expiry.

```
submit_participant_info(attestation, tls_pk):
    1. The MPC contract validates the caller and builds a NodeId
       { account_id, tls_public_key, account_public_key }.
    2. If a pending entry already exists for the caller, reject the call.
       The off-chain MPC node retries after the prior submission's callback
       has resolved (success or failure). This avoids the second submission
       silently overwriting the first and leaking its attached deposit.
    3. Otherwise, stash for the callback under the caller's account ID:
       NodeId (used to compute expected_report_data and key the insert),
       the attestation payload (for RTMR3 replay and app_compose validation),
       and the attached deposit (for storage staking or refund).
    4. Schedule a Promise to tee-verifier-v1.near.verify_quote(quote,
       collateral, now), chained to its own on_attestation_verified callback.

on_attestation_verified(caller):
    1. Load the VerifiedReport from the Promise result and the stashed state.
    2. Read current allowlists (image hashes, launcher hashes, measurements)
       directly from TeeState — not a snapshot taken at submit time. If
       governance revoked a measurement while the verifier round-trip was in
       flight, the submission is correctly rejected here.
    3. Run the post-DCAP checks: status, advisory IDs, report_data binding,
       RTMR3 replay, app_compose validation, RTMR/MRTD match against the
       current allowlist, MPC image hash, launcher compose hash.
    4. On success: build a ValidatedDstackAttestation and insert into
       stored_attestations.
    5. On failure: leave stored_attestations untouched and refund the deposit.
       Either way, clear the stashed pending entry.
```

The post-DCAP checks happen on the MPC contract because:

- RTMR3 replay needs `tcb_info.event_log`, a separate input with a Dstack-specific shape we don't want to standardize at the verifier layer.
- App-compose validation is opinionated (MPC's `kms_enabled == false`, etc.); other teams may want different rules.
- Report-data binding differs across teams.

### Re-verification doesn't call the verifier

`re_verify`, `verify_tee`, post-reshare cleanup, and `clean_invalid_attestations` are unchanged in v1. They operate on cached `ValidatedDstackAttestation` blobs and do hash comparisons against the current allowlists. None of them call the verifier; they don't even need a Promise. Same property as today.

In v2/v3, this logic moves into the per-team policy contract (see "Long-Term Direction" below). At every version, re-checking already-stored attestations against current allowlists never calls the verifier — it's a local read of the cache (`mpc-contract`'s in v1, `mpc-tee-policy`'s in v2/v3). The verifier only runs at first submission, never on re-checks.

### What v1 saves

- The `mpc-contract` WASM no longer transitively depends on `dcap-qvl`, `ring`, `webpki`, or X.509 parsing. This is the load-bearing reduction for the NEP-509 size constraint.
- No on-chain state migration: existing `stored_attestations` and allowlists keep their Borsh layout, all governance entry points keep working. The only behavioural change is that `submit_participant_info` becomes a two-step transaction.
- PCCS / collateral handling is unchanged: the off-chain MPC node fetches collateral via `tee-authority` → Dstack → PCCS and submits it inline as part of the attestation payload, and the verifier accepts inline collateral on every call. On-chain PCCS caching is pinned to v3.

Achieving the WASM reduction requires splitting the `attestation` crate: the Borsh types and post-DCAP helpers (`re_verify`, RTMR3 replay) stay in a base crate that `mpc-contract` depends on; the `dcap_qvl::verify`-using `DstackAttestation::verify` moves into a separate crate that only the verifier depends on. Without the split, `dcap-qvl` gets linked into the `mpc-contract` WASM regardless of whether `verify` is called at runtime.

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

    // Hot path: answered from local state — no further Promises.
    fn is_attested(&self, node_id: NodeId) -> bool;

    // Triggered by an admin action that changes allowlists.
    fn reverify_all(&mut self) -> ReverifyResult;
}
```

`NodeId` is opaque to the trait — each team can use whatever shape it needs (MPC's `(account_id, tls_pubkey, account_pubkey)`, Proximity's account ID, etc.). The interface is currently TEE-flavoured (`is_attested`, `node_id`); v3 generalizes it (see below).

### v3: ACL-shaped interface and on-chain PCCS

**ACL generalization.** Most TEE-using applications don't actually want to know about TEEs — they want to know "is the caller authorized for this action?". TEE attestation just populates the answer.

Replacing `is_attested(node_id) -> bool` with `is_authorized(account_id, action) -> bool` lets the application contract drop every TEE type. Internally the policy maps `is_authorized` to "is `account_id` in `stored_attestations` AND does it re-verify AND does the action satisfy any role-based restriction?". TEE machinery becomes an implementation detail of the policy.

This generalizes naturally: non-TEE policies (admin-set ACL), multi-mechanism policies (TEE or DAO membership), or delegated policies that forward to another ACL contract — all conform to the same interface.

This matches the preference Defuse has expressed for hiding TEEs behind an authorization layer rather than baking TEE concepts into application contracts.

**On-chain PCCS caching.** Mirroring [Automata's design][automata-pccs]: a separate `pccs.near` contract stores fresh collateral per FMSPC, governed by an `admin_id` (or permissionless if root-CA validation is replayed on insert). The verifier grows a `verify_quote_via_pccs(quote, pccs_account_id, fmspc, now)` companion that reads collateral by cross-contract call instead of accepting it inline. This removes the obligation for off-chain components to fetch and bundle collateral on every call.

[mpc-repo]: https://github.com/near/mpc
[defuse-site]: https://near.com
[proximity-shade-attestation]: https://github.com/NearDeFi/shade-agent-framework/tree/main/shade-attestation
[mpc-launcher]: ../securing-mpc-with-tee-design-doc.md#launcher
[mpc-report-data]: https://github.com/near/mpc/blob/main/crates/mpc-attestation/src/report_data.rs
[nep-509]: https://github.com/near/NEPs/blob/master/neps/nep-0509.md
[nep-591]: https://github.com/near/NEPs/blob/master/neps/nep-0591.md
[automata-pccs]: https://github.com/automata-network/automata-on-chain-pccs
