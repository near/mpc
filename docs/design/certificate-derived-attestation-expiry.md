# Certificate-Derived Attestation Expiry

Design for [#1639](https://github.com/near/mpc/issues/1639). An attestation should stop being
trusted when Intel's collateral stops vouching for it, so the contract stores the collateral's own
expiry and nothing else:

```text
expiry = earliest_collateral_expiration
```

`DEFAULT_EXPIRATION_DURATION_SECONDS` is deleted. The contract keeps no expiry constant of its own.

## Why

Today the contract stamps `now + 7 days`. Those 7 days are added to *submission time*, and the node
picks that time — so it can present collateral with an hour of validity left and still receive a
full week of trust. Nothing rejects it, because DCAP only asks whether the collateral is valid right
now.

That matters because the contract cannot learn about a newer CRL, which is the premise #1639 opens
with. A stored attestation is never re-checked against fresher collateral; trust ends only at
expiry. So a platform Intel revokes in the *next* PCK CRL keeps a valid on-chain attestation for up
to 7 days after the CRL that vouched for it stopped being authoritative — and an operator who wants
that extension only has to time its submissions. Until on-chain CRL updates exist
([#1050](https://github.com/near/mpc/issues/1050)), this expiry is the only bound on revocation
latency.

It is also *more* generous in the common case: Intel's windows are 30 days, so a node with fresh
collateral gets about 30 days rather than 7.

## What the expiry is

`dcap-qvl` (0.6.3, our pin) computes it as `QuoteClaims::earliest_expiration_date` — the earliest of
eight dates, matching Intel's own `qve_get_collateral_dates()`:

| Source | Field | Typical window |
|---|---|---|
| TCB Info JSON | `nextUpdate` | 30 days |
| QE Identity JSON | `nextUpdate` | 30 days |
| PCK CRL | `nextUpdate` | 30 days |
| Root CA CRL | `nextUpdate` | 1 year |
| PCK certificate chain | `notAfter` | 7–30 years |
| PCK CRL issuer chain | `notAfter` | 7–30 years |
| TCB Info issuer chain | `notAfter` | 7–30 years |
| QE Identity issuer chain | `notAfter` | 7–30 years |

In practice one of the three 30-day rows always wins, so the stored expiry is about 30 days minus
the age of the collateral the node presented.

## How the value reaches the contract

`tee-verifier` gains a method `verify_quote_with_claims`, returning today's report plus
`earliest_expiration_seconds`. `verify_quote` is untouched.

This keeps the verifier 1:1 with `dcap-qvl` rather than diverging from it: `QuoteClaims` *is*
`dcap-qvl`'s own API, returned by `verify_with_policy`, so the new method exposes more of the
upstream surface instead of a shape of our own.

It is a second method rather than a new field on `verify_quote` only for the upgrade path. The
verifier account is key-locked, so a changed return type means a new account and a
`vote_tee_verifier_change`; during that rotation an old verifier may answer a new contract or the
reverse, and a new name fails closed instead of mis-decoding.

`mpc-contract` threads the value from `resolve_verification` into `verify_and_store_dstack`.
`verify_locally` (node, CLI, `tee-authority`) reads the same number, so off-chain verification agrees
with the chain.

A re-submission always **overwrites** the stored expiry, even when the new one is earlier. The
stored value should describe the collateral actually presented; keeping the longer of the two would
let a node retain trust from collateral it no longer holds. Shortening is never a security problem,
only a self-inflicted one, and the node-side rule below makes it rare.

## What else has to change

Six things depend on the expiry always being `now + constant`, and break without it.

**1. Confirming a submission landed.** The node infers this from the stored expiry *increasing*
([`tx_sender.rs`](../../crates/node/src/indexer/tx_sender.rs)), which stops working once that value
is a calendar date repeating for weeks. Fix: store `attested_at_seconds` on
[`NodeAttestation`](../../crates/contract/src/tee/tee_state.rs) — it wraps both the Dstack and Mock
variants, so one field covers both with no enum change. That restores today's semantics exactly and
doubles as a better operator health signal. Costs +8 bytes (entry 599 → 607, so
`WORST_CASE_ENTRY_BYTES` moves off 604 and the fee floor needs re-checking) and a state migration.
Supersedes [#4301](https://github.com/near/mpc/issues/4301).

**2. Launcher-image eviction.** A launcher hash is evicted once unused for
`launcher_hash_unused_ttl_seconds` (14 days), where "used" means an accepted attestation by a
current participant refreshed it. `re_verify` re-checks a stored attestation's launcher hash against
the *current* allowed set, so evicting a hash kicks a node whose attestation is still valid. Today
`Config::validate` rules that out by requiring the TTL to exceed the 7-day expiry constant — which
disappears.

Without that invariant, a node that attests once with 30 days of certificate validity and then stops
loses its hash at day 14 and is kicked with 16 days left: effective validity becomes
`min(certificate expiry, 14 days since the last attestation)`, turning launcher cleanup into a
second, implicit attestation deadline.

Fix: keep the TTL, but never evict a hash still referenced by a current participant's non-expired
attestation. The TTL then does only the job it is still needed for — retiring hashes nobody adopted
— and retention is driven by use. This mirrors the existing refresh gate
(`refresh_launcher_usage` requires `AuthenticatedParticipantId`) and is cheap, since
`cleanup_expired()` runs inside `reverify_and_cleanup_participants`, which already iterates the
stored attestations. `cleanup_expired()` keeps its rule of never emptying the list.

**3. Shortening after a verifier rotation.** [#3734](https://github.com/near/mpc/issues/3734) wants a
short window after a rotation so entries a rotated-away verifier may have wrongly accepted age out
quickly. It was written as "lower the constant", which no longer exists. With the timestamp from
item 1 the replacement is O(1): record `verifier_rotated_at` when `vote_tee_verifier_change` passes,
and in `re_verify` treat any entry with `attested_at < verifier_rotated_at` as expiring at
`min(expiry, verifier_rotated_at + 1 day)`. Entries submitted after the rotation are untouched, and
every node gets a full day to re-attest. No sweep, no per-entry write.

**4. Near-expiry collateral.** A node presenting nearly stale collateral now gets a nearly worthless
attestation, and because `nextUpdate` is shared across the fleet, every node's expiry converges on
the same instant. Both are node-side fixes: refuse to submit, and refresh early, once collateral has
less than a few days left. Today `MAX_COLLATERAL_AGE` allows 31 days, permitting collateral right up
to expiry. No contract change.

**5. Sandbox fixture.** The checked-in quote is dated 2026-08-13 and is already past Intel's 30-day
window, so a certificate-derived expiry lands in the past relative to sandbox block time and recedes
further every day. Submission still succeeds, but anything re-verifying afterwards sees an expired
entry. Cheapest fix is to extend the pinned-clock trick to the contract side, mirroring
`tee_verifier_contract_with_pinned_clock`. Regenerating the fixture is not a fix — it would have a
30-day shelf life.

**6. Gas budget.** See below; the config change is a governance vote of its own.

## Gas

Measured on mainnet (`v1.signer` → `tee-verifier-2026-08-04.near`). Gas limit is the ceiling a
receipt may spend; the unburnt remainder is refunded.

| Receipt | Burnt | Gas limit | Set by |
|---|---|---|---|
| `submit_participant_info` | 16.28 | 300 | node's prepaid gas — protocol max, covers the whole chain |
| `verify_quote` | **175.81** | 200 | `verifier_tera_gas` |
| `resolve_verification` | 4.60 | 60 | `resolve_verification_tera_gas` |
| Total burnt, incl. tx and refunds | 199.73 | | |

The 300 is the chain's budget, not the verifier's: the submit receipt spends 16.3 itself and commits
200 + 60 to its two promises, leaving only ~20 TGas unallocated. So `verifier_tera_gas` can reach
~220 as things stand, or ~270 if `resolve_verification`'s 60 is trimmed toward its 4.6 — keeping
worst-case room there. Not 300.

`claims()` re-parses the two JSON documents and parses the certificate chains, so measure it before
choosing the split. Fallback if it does not fit: read `nextUpdate` from the two CRLs and the two JSON
documents only. That drops the four certificate chains from the minimum, which is safe given their
7–30 year lifetimes, but it should be a deliberate choice rather than an accident.

## Rollout

1. **Land item 1** (stored submission timestamp), so confirmation keeps working.
2. **Vote the gas config** (`propose_update` / `vote_update`). Separate governance from the contract
   upgrade, and it must come first — otherwise step 4 runs the heavier method under the old budget
   and every submission runs out of gas.
3. **Deploy the new verifier and vote it in.** It still serves `verify_quote`, so nothing changes on
   chain yet; reversible by voting back.
4. **Upgrade `mpc-contract`** to call `verify_quote_with_claims`. Certificate-derived expiry takes
   effect here, and from this point voting back to the old verifier no longer works.
5. **Release the node** with the near-expiry refresh rule.

Both verifiers are already live (`tee-verifier-2026-08-04.near`,
`tee-verifier-2026-07-22.testnet`), so step 3 is a rotation, not a first deployment.

Operators will see a healthy node's `expiry_timestamp_seconds` stop advancing hourly — it moves only
when the node picks up refreshed collateral, roughly monthly — while sitting further out than today.
[`tdx-tcb-status.md`](../tdx-tcb-status.md) sells the old behaviour as the cheapest health signal and
needs rewriting, as does the `mpc_attestation_expiry_timestamp_seconds` description from
[#4236](https://github.com/near/mpc/pull/4236). The new `attested_at_seconds` is the replacement
signal.

## Open questions

- **How much gas does `claims()` add?** Measure, then choose between re-balancing against
  `resolve_verification` and the lean fallback.
- **How early should a node refuse to submit collateral** (item 4)? Needs a number.
- **Whose attestation protects a launcher hash** (item 2)? Current participants only, matching the
  existing refresh gate, leaves a joining node's hash unprotected during resharing.

## Alternatives considered

- **A contract-side cap on top of the certificate value.** Dropped: it adds a second expiry to keep
  in sync, does not help the fleet-convergence risk in item 4, and #3734 turned out not to need it.
- **Deriving the expiry inside `mpc-contract`** from the collateral it already forwards. No verifier
  change, but it means re-adding DER/X.509 parsing to the contract wasm, undoing
  [#3264](https://github.com/near/mpc/issues/3264).
- **Reading receipt outcomes to confirm submissions** ([#4301](https://github.com/near/mpc/issues/4301)).
  Works and needs no extra tracked shard, but item 1 achieves the same with far less machinery.
