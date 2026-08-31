# Certificate-Derived Attestation Expiry

Design for [#1639](https://github.com/near/mpc/issues/1639): an attestation stops being trusted when
Intel's collateral stops guaranteeing freshness, instead of a fixed 7 days later.

```text
expiry = min(now + MAX_ATTESTATION_VALIDITY_SECONDS, earliest_collateral_expiration)
```

The certificate value can only **shorten** the window. `MAX_ATTESTATION_VALIDITY_SECONDS` is today's
`DEFAULT_EXPIRATION_DURATION_SECONDS` (7 days), renamed and documented as a ceiling.

## Background

DCAP rejects collateral past its `nextUpdate`, but the 7 days are added to *submission time* — and
the submitter chooses when to submit. So a node can present collateral with an hour of validity left
and receive a full 7 days of trust. Nothing rejects it: DCAP only asks whether the collateral is
valid *right now*.

That matters because the contract cannot learn about a newer CRL — the premise #1639 opens with. A
stored attestation is never re-checked against updated collateral; trust ends only at expiry. So a
platform Intel revokes in the *next* PCK CRL keeps a valid on-chain attestation for up to 7 days
after the CRL that vouched for it stopped being authoritative, and an operator wanting that
extension only has to time its submissions. Until on-chain CRL updates exist
([#1050](https://github.com/near/mpc/issues/1050)), this expiry is the only bound on revocation
latency.

Intel refreshes the PCK CRL, TCB Info and QE Identity every 30 days, the root CA CRL yearly, and
certificates last 7–30 years ([analysis](https://github.com/near/mpc/issues/1629#issuecomment-3635983666)),
so the binding constraint is always one of the three 30-day items. `dcap-qvl` 0.6.1 — already our
pin, with `default-x509` enabled — computes it as `QuoteClaims::earliest_expiration_date`, the
minimum of `nextUpdate`/`notAfter` over all eight collateral sources.

### Relation to the collateral freshness policy

The check removed in [#3736](https://github.com/near/mpc/pull/3736) — the node's 120-second
`MAX_ATTESTATION_AGE` — was a *self-confirmation* check, never a gate on what the contract accepted,
and it went because it was broken ([#3686](https://github.com/near/mpc/issues/3686)). So this design
does not restore it.

The surviving policy is the node's `MAX_COLLATERAL_AGE`, 31 days
([`tee_authority.rs:245`](../../crates/tee-authority/src/tee_authority.rs)). Being *looser* than
Intel's 30-day window it constrains nothing in the tail — exactly where the overhang lives — and it
binds only a node's own submission. [#3946](https://github.com/near/mpc/issues/3946) asks whether
freshness should be judged against the collateral's own window rather than a hand-tuned max-age; this
design answers yes for the contract side, leaving #3946 as a narrower node-side question.

## Design

### Where the expiry comes from

`tee-verifier` gains a new method, `verify_quote_with_claims`, returning the report plus
`earliest_expiration_seconds`. `verify_quote` stays as it is. Both halves of that follow from the
verifier account being key-locked and trusted by vote, so a new return type means a new account and
a `vote_tee_verifier_change`:

- **A second method, not an extra Borsh field.** During a rotation an old verifier may answer a new
  contract or the reverse. Appending a field breaks one direction whichever order we roll out; a
  distinct method name breaks neither.
- **Named after the returned shape, not the new field.** The name can never be changed on that
  account, and `..._with_claims` still reads true if a later version returns another `QuoteClaims`
  field.

The body swaps `dcap_qvl::verify::verify` for
`QuoteVerifier::new_prod().verify_with_policy(quote, collateral, now, &QuotePolicy::claims_only(now))`
and rebuilds today's `VerifiedReport` from the returned `QuoteClaims`, which carries every field it
needs.

`mpc-contract` threads that value from `resolve_verification` into `verify_and_store_dstack` and on
into `AcceptedAttestation::dstack`, which applies the `min`. `ValidatedDstackAttestation`'s layout is
unchanged, so **no state migration**. `verify_locally` (node, CLI, `tee-authority`) reads the same
number from `claims()`, so off-chain verification agrees with the chain. The mock path keeps stamping
`now + MAX`; [#4005](https://github.com/near/mpc/issues/4005) stays open.

### Why the cap stays

- `Config::validate` requires `launcher_hash_unused_ttl_seconds >= DEFAULT_EXPIRATION_DURATION_SECONDS`
  (14 days ≥ 7): a launcher hash backing a still-valid attestation must not be evicted first.
- [#3734](https://github.com/near/mpc/issues/3734) specifies 7 days by default and 1 day on verifier
  rotation, for containment of entries a rotated-away verifier may have wrongly accepted. `MAX` is
  therefore a value the protocol varies deliberately, so it has to stay the ceiling.

Keeping the ceiling means the certificate value binds only in the tail — when collateral is within
`MAX` of its `nextUpdate`. That tail is the gap this design closes. What `MAX` should be is #3734,
not this document.

### Node submit-confirmation

The node confirms a submission landed by checking that the stored expiry *changed*
([`tx_sender.rs:201`](../../crates/node/src/indexer/tx_sender.rs)), which works only because the
expiry is always `now + 7 days`. Once the certificate value binds and the collateral has not changed,
re-submitting stamps the same expiry, so accepted and rejected become indistinguishable in contract
state — no state-based rule can separate them.

Fixed by reading the receipt execution outcome instead:
[#4301](https://github.com/near/mpc/issues/4301), which needs no additional tracked shard. Best
landed **before** this change, so there is never a window where a rejected submission reports as
success.

## Gas

Measured on mainnet (`v1.signer` → `tee-verifier-2026-08-04.near`).

Gas limit is the ceiling a receipt may spend before running out of gas; the unburnt remainder is
refunded.

| Receipt | Burnt | Gas limit | Set by |
|---|---|---|---|
| `submit_participant_info` | 16.28 | 300 | node's prepaid gas — protocol max, covers the whole chain |
| `verify_quote` | **175.81** | 200 | `verifier_tera_gas`, static gas on the cross-contract call |
| `resolve_verification` | 4.60 | 60 | `resolve_verification_tera_gas`, static gas on the callback |
| Total burnt, incl. tx and refunds | 199.73 | | |

The 300 is the chain's budget, not the verifier's: the submit receipt spends 16.3 itself and commits
200 + 60 to its two promises, leaving only ~20 TGas unallocated. So `verifier_tera_gas` can reach
~220 as things stand, or ~270 if `resolve_verification`'s 60 is trimmed toward its 4.6 — keeping
worst-case room there for larger allowlists. Not 300.

`claims()` re-parses `tcb_info` and `qe_identity` and parses six certificates, so measure it before
choosing the split. Fallback if it still does not fit: a lean computation reading `nextUpdate` from
the two CRLs plus a minimal `{ nextUpdate }` struct for the JSON documents, which avoids
materializing all `tcbLevels`.

## Operations plan

The verifier is live on both networks (`tee-verifier-2026-08-04.near`,
`tee-verifier-2026-07-22.testnet`), so this is a rotation, not a first deployment.

1. **Land [#4301](https://github.com/near/mpc/issues/4301)** (node confirmation).
2. **Deploy the new verifier and vote it in**, per [`deploy-tee-verifier.md`](../deploy-tee-verifier.md).
   It still serves `verify_quote`, so nothing changes on chain yet; reversible by voting back.
3. **Upgrade `mpc-contract`** to call `verify_quote_with_claims`. Certificate-derived expiry takes
   effect here.

Operator-visible change: a healthy node's `expiry_timestamp_seconds` is no longer always ~7 days out
and no longer advances on every hourly submission — it stops advancing once the collateral's window
is the shorter of the two. So a node whose PCCS has gone stale shows a *shrinking* expiry before a
stuck one. [`tdx-tcb-status.md`](../tdx-tcb-status.md) sells the old behaviour as the cheapest health
signal and needs rewriting, as does the `mpc_attestation_expiry_timestamp_seconds` metric
description from [#4236](https://github.com/near/mpc/pull/4236).

## Open questions

- **How much gas does `claims()` add, and where does it come from?** Measure first; re-balancing
  against `resolve_verification` is the expected answer, the lean computation the fallback.
- **Order.** #4301 is listed first because it removes a window where rejections report as success.
  Confirm that is worth blocking on.

## For discussion: cap, or pure certificate-derived?

The one choice here that changes the security argument rather than the mechanism.

**For pure certificate-derived:** it is the only expiry Intel vouches for; every shorter window is
our own invention, and a self-chosen number is what caused the fleet-wide outage on 2026-07-23, when
the node's then 7-day `MAX_COLLATERAL_AGE` rejected a valid 30-day PCK CRL and no node could attest
([#3946](https://github.com/near/mpc/issues/3946)). One freshness authority instead of two that can
disagree.

**For the cap:** Intel holds one CRL for most of its 30-day window, so pure certificate-derived is
~30 days in the common case — four times today's window, too long for #3734's containment, and it
breaks the `launcher_hash_unused_ttl_seconds` invariant unless that TTL is raised past 30 days.

**Middle ground:** keep the cap but resolve #3946 and #3734 together, so the node's collateral-age
bound and the contract's `MAX` come from one reading of Intel's cadence rather than being tuned
separately.

Recommendation: ship the cap, a strict improvement either way, and revisit if the team prefers a
single freshness authority.

## Alternatives considered

- **Derive the expiry in `mpc-contract`** from the collateral it already round-trips through
  `VerificationContext`. Needs no verifier change or rotation — but covering the PCK CRL means
  re-adding DER/X.509 parsing to the contract wasm, undoing
  [#3264](https://github.com/near/mpc/issues/3264).
- **Floor the window to a minimum.** Reintroduces the gap this design closes.
- **An `attested_at_seconds` field** on the stored entry, for exact submit confirmation. +8 bytes
  (599 → 607, so `WORST_CASE_ENTRY_BYTES` and the fee floor need re-checking) *and* a state
  migration. #4301 achieves the same with neither.

## Follow-up issues

- [#4301](https://github.com/near/mpc/issues/4301) — node submit-confirmation from the receipt
  outcome (opened).
- To be split out: verifier method + deployment, contract plumbing, doc updates.
