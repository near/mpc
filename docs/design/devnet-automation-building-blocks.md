# Building blocks for automating dev-cluster operations

Upgrading a NEAR One dev cluster is a manual runbook: retag each `mpc-node-*`
Nomad job through the UI, check the nodes came back, then propose and vote the
contract update. This lists the capabilities needed to automate it and what we know
about each.

## What decides the language

- **Contract-typed** — correctness depends on a type, constant or method name in
  this workspace (serialization, deposits, method names, request DTOs). These
  belong in Rust: we do not guarantee backwards compatibility on operator and
  governance endpoints, so a refactor can invalidate an encoding written in
  shell with no compile error anywhere.
- **Infrastructure-typed** — correctness depends on Nomad, HTTP or the
  filesystem. A schema change surfaces as a run-time error rather than silent
  corruption, so shell is adequate.

The test per block: *if someone refactors the contract, does this break
silently?*

## Blocks

| # | Block | Type |
|---|-------|------|
| 1 | Nomad client | infra |
| 2 | Node secret key fetcher | infra |
| 3 | Keychain storage | infra |
| 4 | Node upgrader | infra |
| 5 | Node address discovery | infra |
| 6 | Release verifier | infra |
| 7 | Contract argument serializer | contract |
| 8 | Deposit calculator | contract |
| 9 | Signer | contract |
| 10 | Update proposer / voter | contract |
| 11 | Test signature | contract |
| 12 | Operator front end | operator |
| 13 | Announcer (Slack) | infra |

### Non-obvious constraints

**1. Nomad client.** The HTTP API ignores `NOMAD_NAMESPACE` (a CLI-only
feature); it must ride the query string. Credentials and job definitions must
never reach `argv` — job definitions carry node secrets.

**2. Key fetcher.** Identify the MPC task by the presence of `MPC_ACCOUNT_SK`,
never by image name: the dev clusters run `nearone/mpc-node`, not
`nearone/mpc-node-gcp` as the runbooks imply. Matching on the name finds
nothing, and "no match" is indistinguishable from "nothing to do" — so it must
report task names and env variable *names* (never values) when it finds no key.

**3. Keychain storage.** near-cli's `import-account` cannot be scripted: after
the key it prompts for the account id and keychain, neither of which has a
flag. Write its legacy files directly — `<account>.json` and
`<account>/<curve>_<public key>.json`, each `{public_key, private_key}`, mode
0600. No cryptography needed: an ed25519 secret key is seed ‖ public key.
Consumers must use `sign-with-legacy-keychain`; the default reads the OS keyring
and will not see these files.

**4. Node upgrader.** Derive the target from the job's own image repository,
replacing only the tag (watch registry ports: `registry:5000/foo:tag`). Rewrite
only the MPC task. A job already on the target is a no-op, so partial rollouts
re-run safely. `FailedTGAllocs` from `plan` means Nomad cannot place the new
allocation — registering anyway stops a node with nothing to replace it. Wait
for each node before touching the next, or the cluster can drop below threshold.

**5. Address discovery.** Nomad reports the *client* address, which on GCP is a
private VPC IP unreachable from an operator's machine. Prefer the platform's
external IP attribute, fall back to the private one. The port is static (8080).

**6. Release verifier.** Retry — a node is still warming up right after its
allocation starts. Keep *unreachable* separate from *wrong version*; collapsing
them reports a failed upgrade when the operator simply cannot see the node.

**7–8. Serializer and deposit.** `ProposeUpdateArgs` and
`propose_update_required_deposit_yoctonear` already exist in
`near-mpc-contract-interface`. The formula is `(32_768 + payload_bytes) × 10¹⁹`
— ~12.35 NEAR at the current 1,235,000-byte WASM ceiling. A hardcoded deposit
has no link to that ceiling and silently under-pays when either changes.

**9. Signer.** The gap blocking reuse of devnet's contract commands: every `mpc`
subcommand starts from `devnet_setup.yaml` (networks devnet created, keys it
generated), and `ProposeUpdateContract` also funds the proposer. Neither applies
to a long-lived cluster whose keys live in the operator's keystore (block 3).

**11. Test signature.** The deposit should come from `SIGN_DEPOSIT_YOCTONEAR`
(1 yoctoNEAR, excess refunded), not a hand-picked number. That constant was
called `MINIMUM_SIGN_REQUEST_DEPOSIT` and lived in `contract/src/lib.rs` until
recently — the kind of rename a shell script cannot notice.

**12. Front end.** Stays in shell deliberately: it is what a reviewer compares
against the runbook, and printing each command before running it keeps the
automation auditable. One place owns operator interaction, so the compiled
blocks stay non-interactive and testable.

## Dependencies

```
12 front end
 ├── 1 Nomad client ── 2 key fetcher ── 3 keychain storage
 │        └── 4 node upgrader ── 5 address discovery ── 6 release verifier
 ├── 9 signer ── 7 serializer ── 8 deposit ── 10 propose/vote
 │                                     └── 11 test signature
 └── 13 announcer
```

Blocks 7–11 all depend on the signer (9), which makes it the highest-leverage
one to build first: it is what lets contract-typed operations reuse this
workspace's types instead of restating them.

## Open questions

- **Where does cluster mode belong?** These blocks operate on a cluster this
  tooling did not create, so they cannot use `devnet_setup.yaml`. Should they be
  a `cluster` subcommand of `mpc-devnet`, or a separate `mpc-ops` crate?
- **Reachability.** Node metrics are currently served on public addresses.
  Restricting them to the VPC would mean verifying from inside the network.
- **Mainnet gating.** Nothing yet distinguishes a dev cluster from production;
  destructive steps need a gate beyond a yes/no prompt before that changes.
