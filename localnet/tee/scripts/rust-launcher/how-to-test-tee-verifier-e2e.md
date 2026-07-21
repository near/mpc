# Testing the TEE verifier contract on a localnet TDX cluster

`deploy-tee-cluster.sh` deploys the standalone [`tee-verifier`](../../../../crates/tee-verifier)
contract and votes it in as the MPC contract's trusted verifier, so the verifier
path can be exercised on a real-TDX localnet cluster (not just in-WASM/sandbox).

This tracks [near/mpc#3642](https://github.com/near/mpc/issues/3642): the verifier
account voting (`vote_tee_verifier_change`) is on `main`; the async
`submit_participant_info` → `verify_quote` wiring lands with
[#3714](https://github.com/near/mpc/pull/3714).

## What the script does

Two steps run automatically as part of the normal deploy (no extra flags):

1. **`deploy_verifier`** (in the `near_contract` phase) — builds
   `crates/tee-verifier` (or reuses `TEE_VERIFIER_PATH`), creates
   `tee-verifier.<root>`, and deploys the wasm (stateless, no init call).
2. **`vote_tee_verifier_threshold`** (right after `init`, while the contract is
   `Initializing`) — every node account calls `vote_tee_verifier_change`
   committing to the wasm's sha256 as `expected_code_hash`, crossing threshold so
   the verifier account is trusted before keygen finishes.

`authenticate_update_vote` allows voting in both `Initializing` and `Running`, so
voting during `Initializing` is intentional — it lets the nodes' Dstack
attestations route through the verifier as soon as keygen starts.

## Running it

```bash
source localnet/tee/scripts/rust-launcher/set-localnet-env.sh
export RESUME=0
# Optional prebuilt verifier wasm (else the script builds crates/tee-verifier):
export TEE_VERIFIER_PATH="$(pwd)/target/near/tee_verifier/tee_verifier.wasm"
bash localnet/tee/scripts/rust-launcher/deploy-tee-cluster.sh
```

## Verifying

```bash
export NEAR_ENV=mpc-localnet
C=mpc.mpc-local.test.near

# verifier adopted (pending votes consumed => threshold reached)
near contract call-function as-read-only $C tee_verifier_votes json-args {} network-config mpc-localnet now   # {}

# nodes attested; then confirm each is a real Dstack attestation (not Mock)
near contract call-function as-read-only $C get_tee_accounts json-args {} network-config mpc-localnet now
near contract call-function as-read-only $C get_attestation \
  json-args '{"tls_public_key":"ed25519:<node tls key from get_tee_accounts>"}' \
  network-config mpc-localnet now       # => { "Dstack": { ... } }

# contract Running + a signature works end-to-end
near contract call-function as-read-only $C state json-args {} network-config mpc-localnet now   # Running
near contract call-function as-transaction $C sign \
  file-args docs/localnet/args/sign_ecdsa.json prepaid-gas '300.0 Tgas' \
  attached-deposit '1 yoctoNEAR' sign-as node0.mpc-local.test.near \
  network-config mpc-localnet sign-with-keychain send
```

## verify_quote gas budget (with #3714)

Once the async path (#3714) is in play, the MPC contract forwards
`config.verifier_tera_gas` to the cross-contract `verify_quote`. Real
`dcap_qvl::verify` on a valid quote burns **~173 Tgas**, above the contract's
`DEFAULT_VERIFIER_TERA_GAS = 100`, so the default OOGs the cross-call and
attestation never completes. Override it at init:

```bash
export VERIFIER_TERA_GAS_OVERRIDE=200   # verify(≈173) + resolve(60) + callback(10) fits under the 300 Tgas tx cap
```

Leave `VERIFIER_TERA_GAS_OVERRIDE` unset on `main` — `InitConfig` has no
`verifier_tera_gas` field there yet, so the script omits `init_config` entirely.
