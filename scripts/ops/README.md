# `scripts/ops/` — operator tooling

Scripts an operator runs **by hand** to cut releases and roll them out to the MPC
clusters. They automate the mechanical, error-prone parts of the runbooks in
[`how-to/`](../../how-to/) — they do not replace them; read the relevant runbook
alongside.

> **Scope.** This directory is for repo-level operator tasks (release cutting,
> cluster upgrades, announcements). Deploy assets stay in [`deployment/`](../../deployment/)
> and CI/lint helpers stay in [`scripts/`](../). Nothing here reads secrets from a
> store — every credential (near key/account, tokens) is supplied at invocation.

## Menu

```bash
./scripts/ops/menu.sh
```

Interactive entry point. Presents the actions below, prompts for the inputs each
needs, and runs the matching script. Every script is also runnable on its own —
the menu is a convenience, not a gate.

## Scripts

| Script | What it does | Runbook |
|---|---|---|
| `prepare-release.sh <VERSION>` | Cut a release locally: changelog, version bump, ABI snapshot, licenses, commit. | [`RELEASES.md`](../../RELEASES.md) |
| `upgrade-prepare.sh <VERSION>` | Download the contract WASM, build `serialized.bin`, print its sha256, and print the node manifest digest (both forms). | [`contract-upgrade.md`](../../how-to/contract-upgrade.md), [`node-hash-vote.md`](../../how-to/node-hash-vote.md) |
| `upgrade-commands.sh <VERSION> <net> [--update-id ID] [--account ACCT]` | Print the ready-to-run `propose_update` / `vote_update` / `vote_code_hash` commands with account + network filled in. Prints only; submits nothing. | [`contract-upgrade.md`](../../how-to/contract-upgrade.md) |
| `upgrade-status.sh <net> [node-ip...]` | Read-only view of where an upgrade stands: contract `version`, `proposed_updates`, `state` (+ `code_hash_votes` / `allowed_docker_image_hashes` on TEE nets), and each node's build-info metric. | [`cluster-upgrade.md`](../../how-to/cluster-upgrade.md) |
| `lib.sh` | Shared helpers — sourced by the others, not executed. | — |

`<net>` is one of `mainnet` · `testnet` · `dev-testnet` · `dev-mainnet`.

## Conventions

- **Manual credentials.** The signing account in `upgrade-commands.sh` is a
  placeholder you fill in (or pass `--account`); `upgrade-status.sh` issues only
  read-only calls. No script reads a secret store.
- **Traceable.** `lib.sh` provides `run()`, which echoes every external command
  (`+ cmd …`, shell-quoted) before executing it, plus an `ERR` trap that reports
  the failing command, script, and line. So a run shows exactly what it did and
  where it stopped.
- **Read-only vs. mutating.** Nothing in Phase 0 (the scripts above) submits a
  transaction or touches a running node. Transaction-submitting scripts arrive in
  later phases and will be clearly marked.

## Roadmap

These scripts are Phase 0 of a phased automation of the `how-to/` runbooks.
Planned next, each landing here as its own script + menu entry:

1. `slack-announce.sh` — fill and optionally post the upgrade announcements.
2. `dev-node-upgrade.sh` — dev-cluster Nomad image swap.
3. `propose-update.sh` / `vote-update.sh` / `vote-code-hash.sh` — submit the txns.
4. `prod-node-upgrade.sh` — assisted, human-gated production node rollout.
