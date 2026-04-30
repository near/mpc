# Attestation verification contract

A pre-call brief on extracting on-chain DCAP attestation verification out of the MPC contract into a separate, reusable contract.

Status: Draft — discussion material for the May 4 sync with Defuse. The opinions here are starting positions, not decisions; the point of the call is to converge on the high-level shape before any implementation work begins.

## Why this is on the table

Today on-chain DCAP attestation verification lives inside the MPC contract. Two pressures push us to break it out.

First, the MPC contract is at NEAR's WASM size ceiling, and we have already had to land multiple rounds of size-reduction work to stay under it. The attestation-verification path (the DCAP library, its certificate-validation machinery, the bundled TCB measurements) is one of the larger contributors and is not specific to MPC.

Second, other ecosystem teams need the same on-chain attestation verification:

- Defuse's Outlayer (a rewrite of their off-chain code execution effort);
- The Proximity team;
- NEAR AI-infra projects.

If we do nothing, every team that needs on-chain attestation verification will have to ship their own copy of the DCAP path and bump up against the same size ceiling we are already hitting, and we will accumulate divergent verification logic across the ecosystem. Extracting it gives partners a shared, audited verifier they don't have to re-implement.

## Where the conversation stands

The MPC team and Arseny from Defuse have synced in the run-up to the May 4 call. Defuse needs the same on-chain attestation verification for Defuse's Outlayer, and the conversation has surfaced a different shape than what we originally drafted.

Defuse's stated requirements:

- Very small, composable contracts.
- All contracts deployable under [NEP-616](https://github.com/near/NEPs/blob/master/neps/nep-0616.md) (deterministic account ids derived from `StateInit` — contract code plus initial storage).
- A single `admin_id` field on each governance contract carrying full approval rights, with custom governance logic (Sputnik DAO, role-proxy, etc.) delegated to whatever contract `admin_id` points to.

Defuse also proposed splitting verification across **three contracts**: a pure verifier plus separate governance contracts for collateral and approved measurements. Whether we go that far, or only extract the verification logic, is open.

## What we likely agree on

Not explicitly confirmed yet, but based on the conversations so far the call probably won't need to spend much time on these:

- The verifier itself is **stateless and pure**: takes a quote plus collateral plus the caller's expected report data and allowlists, returns a verified attestation or an error.
- The verifier has **no opinion** on what the report data means or which measurements are acceptable. Each consumer binds whatever identity makes sense for them and ships its own allowlists.
- The MPC team owns the **verification library crate** (the existing Rust library that wraps the DCAP work). Whichever contracts get built, they use it as a library.
- **Mock attestations are rejected** by the production verifier. There is no "is this dev mode?" gate to misconfigure in production.

## What we need to decide on the call

The call will be open-ended, but at a minimum we should touch on these topics:

### 1. How many contracts?

The single biggest question. The shape of the breakout is open-ended; some starting points to anchor the discussion, not an exhaustive list:

- **A single stateless verifier.** One new contract: a pure stateless verifier. Each consumer keeps its own state, and allowlists.
- **Verifier plus collateral governance** (two contracts). Pull the PCCS collateral (CRLs, TCB info, QE identity, root CA) into a separately governed contract so collateral updates are global, but leave each consumer to manage its own measurements. See [automata-on-chain-pccs](https://github.com/automata-network/automata-on-chain-pccs) for a Solidity reference.
- **Verifier plus collateral plus measurements governance** (three contracts — Defuse's proposal). Adds a per-project measurements-governance contract on top, so each consumer can rotate approved measurements through its own DAO independently of collateral.

### 2. Who can call the contracts?

For each contract we end up designing, we need to decide which methods are callable by whom.

- **The verifier.** Our starting position is that `verify` is open to any caller — no whitelist of permitted contract ids, no vote gate. The verifier is stateless, so there is no state to corrupt and no DoS surface beyond the caller's own gas budget.
- **A collateral-governance contract** (if we have one). Read methods should be open so the verifier and any indexer can pull collateral.
- **A measurements-governance contract** (if we have one or more). Same: read methods open.

Shared principle: read methods are open across the board; write methods are governed (see next section).

### 3. Who can administer the contracts?

Distinct from "who calls them" — this is about who can change their state: rotating collateral, adding/removing approved measurements, pausing, upgrading. The Defuse idiom is to abstract all of this behind a single `admin_id` field on each contract: the contract itself only checks "is the caller equal to `admin_id`?", and whatever governance shape sits behind that account (a Sputnik DAO, a role-proxy, a multisig, a project's own contract) is the consumer's choice. We don't bake the governance into the verification contracts.

- **Are we comfortable adopting the `admin_id` pattern for the governance contracts?** It keeps each contract small and lets every consumer layer their own governance on top.
- **Who holds `admin_id` on the collateral-governance contract?** The MPC team doesn't have a DAO today; on the MPC side governance happens through operator voting (the existing `vote_*` methods on the MPC contract require a threshold of operator votes). One option is to wire `admin_id` to a contract that gates collateral updates behind operator votes the same way. Worth confirming up front that every consumer is happy with the same approved collateral set.
- **`admin_id` on each measurements-governance contract.** Each consumer wires this to whatever governance they want (it's their own contract, per-project).
- **Pause authority.** Do we want a pause authority on the verifier, or is clearing the per-consumer measurement allowlist a sufficient kill switch?
- **Upgrade path.** Versioned redeploy (new account, new pinned id, consumers cut over on their timeline) vs. an in-place upgrade authority.

### 4. NEP-616 — what it is and whether we need it

Defuse stated that all contracts must be deployable under [NEP-616](https://github.com/near/NEPs/blob/master/neps/nep-0616.md) — deterministic account ids derived from the contract's `StateInit` (its wasm code plus initial storage).

- **What does NEP-616 actually buy a consumer?** What property does deterministic addressing give them that a named account doesn't? Is the value in trust-minimization (the address is a function of the code, so anyone can verify what's deployed there), in sharded deployment (anyone can deploy their own instance with their own init params and get a predictable address), or in something specific to Defuse's architecture we don't yet see?
- **Should the MPC contract itself migrate to NEP-616?** If we're adopting it for the new contracts, it's worth asking whether the MPC contract should follow. Out of scope for the immediate breakout, but worth flagging.

### 5. Ownership and timeline

Arseny offered to drive the implementation of the governance contract(s) using our verification library crate. We should clarify how to split the work more broadly — who owns which contract, who works on what, etc.

### 6. Are there other teams we should be designing for?

We have three consumers in mind so far (MPC; Defuse's Outlayer; Proximity), with prospective NEAR AI-infra projects on the horizon. Worth checking on the call whether there are other teams in the ecosystem who will need the same on-chain attestation verification — both because they should have a voice in the design, and because their requirements might surface needs we haven't accounted for. If there are teams we don't yet know about, we should at least loop them in before we commit to a shape.
