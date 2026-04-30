# Contract build size optimization

## Why this exists

The `mpc-contract` WASM artifact is deployed to NEAR mainnet by passing the
bytes through a `DeployContract` action. NEAR's protocol-level
`max_transaction_size` is **1,572,864 bytes** (1.5 MiB), so the deploy
transaction — which carries the wasm — must fit under that ceiling. The repo
guards this in `scripts/check-contract-wasm-size.sh` with a tighter
self-imposed limit of 1,490,000 bytes to keep some headroom.

The contract has been growing close to that limit. Before this change the
artifact built by `cargo near build reproducible-wasm` was **1,499,976 bytes**
— already over the safety margin. This change reduces it to
**~1,435,586 bytes** (–64 KB / –4.3%) while keeping the reproducibility
guarantee intact.

## What changed

The reproducible build runs inside a digest-pinned docker image. The pinned
upstream image (`sourcescan/cargo-near:0.17.0-rust-1.86.0`) only exposes
`cargo-near`'s bundled wasm-opt at `-O`, with no flag to choose a different
optimization level. To run wasm-opt at `-Os` we need a standalone `wasm-opt`
binary on PATH inside the container — and the pinned image doesn't have one.

This PR adds a thin custom image (`nearone/cargo-near-mpc`) that extends the
pinned base with `apt-get install binaryen`. The contract's
`[package.metadata.near.reproducible_build]` then points at it, skips
cargo-near's bundled wasm-opt (`--no-wasmopt`), and chains `wasm-opt -Os
--strip-*` as the optimization step.

Reproducibility is preserved: everything still happens inside a digest-pinned
image, with the same source and the same flags. Anyone running
`cargo near build reproducible-wasm` produces byte-identical output. The
sha256 published in GitHub release notes — and used by participants in
`vote_update` — remains derivable from source.

## Why `-Os` and not `-O` or `-Oz`

We measured all three on the same raw (un-optimized) wasm using wasm-opt 120
inside the new image, with `--strip-debug --strip-producers
--strip-target-features --vacuum` applied to all variants:

| Pipeline | Size (bytes) | Δ vs current production | Runtime tradeoff |
|---|---|---|---|
| Current production (cargo-near's bundled `-O`, no extra strip flags) | 1,499,976 | — | baseline |
| Our pipeline `-O` + strip-flags | 1,435,586 | **−64,390 (−4.29%)** | none |
| Our pipeline `-Os` + strip-flags | 1,435,586 | **−64,390 (−4.29%)** | none |
| Our pipeline `-Oz` + strip-flags | 1,413,072 | −86,904 (−5.79%) | possibly slower runtime |

Two takeaways:

1. **Most of the win comes from the strip-flags**, not the optimization level.
   Cargo-near's bundled wasm-opt doesn't strip the `producers` /
   `target_features` sections by default, and those weigh ~64 KB on this
   contract.
2. **`-O` and `-Os` produce byte-identical output here.** wasm-opt 120's `-O`
   pipeline already runs all the size-reducing passes that `-Os` enables;
   there's nothing extra for `-Os` to do on this binary. `-Oz` runs additional
   shrink-only passes (e.g. avoiding inlining that costs bytes) and saves a
   further ~22 KB at the cost of potentially slower generated code.

We chose **`-Os`** for this PR because:

- It captures the entire 64 KB win from the strip-flags with **zero runtime
  risk** versus today's production binary (it is byte-identical to `-O` on
  this contract — the instruction selection is unchanged).
- The remaining 22 KB difference vs `-Oz` would require validating gas
  parity on representative calls (e.g. `sign()`), which is an additional
  step we would prefer not to bundle into a build-pipeline PR.
- 64 KB of headroom is enough to bring the artifact comfortably under the
  self-imposed 1,490,000-byte safety margin (54 KB headroom under the script
  limit, 137 KB under the protocol ceiling).

If size pressure returns later, switching to `-Oz` is a one-line change to
`container_build_command`, gated on a quick gas-parity measurement.

## Reproducibility argument

The full chain remains end-to-end deterministic:

1. **Source** is fixed (the contract crate at a given commit).
2. **Image** is fixed by digest (`image_digest` in `Cargo.toml` is the sha256
   manifest digest of the published image; cargo-near refuses to run if the
   pulled image doesn't match).
3. **Compiler toolchain** is the rust toolchain bundled in the pinned image.
4. **Optimizer** is `binaryen=120-4` from Debian trixie, installed at image
   build time. The pinned image digest captures the exact `wasm-opt`
   binary bytes; no rebuild can drift it without changing the digest.
5. **Build command** is fixed in `container_build_command`.

We verified empirically that two clean runs through this pipeline produce
byte-identical output (sha256 stable across runs).

## Operational notes

- The image is published to `nearone/cargo-near-mpc` via
  `.github/workflows/cargo-near-image.yml`. The workflow tags every build
  with the source commit sha and `latest`, and prints the published manifest
  digest in the workflow log.
- After the first publish, update `image_digest` in
  `crates/contract/Cargo.toml` to the published digest. Without this, the
  reproducible build will fail.
- When bumping the rust toolchain or cargo-near version, update the `FROM`
  line in `docker/cargo-near-mpc/Dockerfile`, push a new image, and update
  `image_digest` in lockstep.
- The contract sha256 changes once on first release after this lands (the
  release-notes hash will reflect the new value automatically; consumers
  with hardcoded expectations of the prior hash need a heads-up).
