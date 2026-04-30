# Contract build size optimization — investigation log

> **Status: superseded by measurement-driven conclusion. PR closed without
> merging.** This document is the record of what we investigated and what
> the corrected measurements showed. Kept here so future readers don't
> repeat the same analysis from scratch. The current build pipeline is
> unchanged; revisit if real size pressure appears.

## Why this was opened

The contract WASM was thought to be ~1,499,976 bytes — over the repo's
self-imposed safety margin in `scripts/check-contract-wasm-size.sh`
(`HARD_LIMIT=1490000`) and approaching NEAR's 1,572,864-byte
`max_transaction_size` ceiling.

The proposed remedy was to extend the pinned cargo-near reproducible-build
image with `binaryen` so we could swap cargo-near's bundled `wasm-opt -O`
for `-Os` (or `-Oz`) and apply `--strip-*` flags. The expected savings were
~64 KB from the strip flags and an additional ~22 KB from `-Oz`.

## What measurement actually showed

### The 1,499,976 baseline was wrong

The "production" baseline came from a stale local-host build using
`cargo-near 0.20.0`, not from a `cargo near build reproducible-wasm` run.
The real reproducible-build output, produced inside the digest-pinned
`sourcescan/cargo-near:0.17.0-rust-1.86.0` image, is **~1,436,167 bytes**
— already 54 KB *under* the safety margin and 137 KB under the protocol
ceiling. The headline urgency was based on a number that doesn't represent
what actually ships.

### The strip flags save 0 bytes

Measured inside the same docker image, on the identical raw (un-optimized)
wasm, applying each strip flag in isolation:

| Pipeline | Size |
|---|---|
| Raw (no opt) | 1,755,836 |
| `-O` (no flags) | 1,435,586 |
| `-O --vacuum` | 1,435,586 |
| `-O --strip-debug` | 1,435,586 |
| `-O --strip-producers` | 1,435,586 |
| `-O --strip-target-features` | 1,435,586 |
| `-O` + all four strip-flags | 1,435,586 |

Every variant produces byte-identical output. The release profile already
has `strip = true` in `[profile.release-contract]` so debug info is gone
before wasm-opt sees the file, and the producer/target-features sections
are either already absent or are dropped by `-O`'s default passes. The
"~64 KB from strip flags" figure earlier in the investigation was actually
the build-environment difference between cargo-near 0.20 (host) and
cargo-near 0.17 (docker) — a baseline error, not a flag-attributable win.

### `-O` and `-Os` are byte-identical on this contract

| Pipeline | Size |
|---|---|
| `-O + strip-flags` | 1,435,586 |
| `-Os + strip-flags` | 1,435,586 |

Same sha256 across the two outputs. wasm-opt 120's `-O` already runs the
size-favoring passes that `-Os` enables; there's nothing extra to do on
this binary.

### Only `-Oz` saves real bytes

| Pipeline | Size | vs reproducible production |
|---|---|---|
| Reproducible production today | ~1,436,167 | — |
| Any `-O` / `-Os` pipeline (with or without strip-flags) | ~1,435,586 | ~580 B (noise) |
| `-Oz + strip-flags` | 1,413,072 | **−23,095 B (−1.6%)** |

`-Oz` is the only variant that materially differs. It runs additional
shrink-only passes (e.g. avoiding inlining decisions that would grow the
binary) at the cost of potentially slower generated code.

## Conclusion

The PR's premise was *"we're over the limit, this is urgent."* Real
measurement shows we're not over any limit, and the proposed `-Os` change
saves nothing on this contract. The `-Oz` path would save ~23 KB but
introduces a new optimization level whose runtime cost would need to be
validated with gas measurements on a representative call (e.g. `sign()`)
before merging.

Since there is no immediate size pressure, the PR was closed without
merging. The build pipeline remains:

- `cargo near build reproducible-wasm` against the
  `sourcescan/cargo-near:0.17.0-rust-1.86.0` image,
- which runs cargo-near's bundled `wasm-opt -O` post-step,
- producing ~1,436,167 bytes today, with ~54 KB headroom under the
  self-imposed safety margin.

## When to revisit

Pivot to a `-Oz` pipeline if **either** of these becomes true:

1. The contract grows past ~1.45 MB and headroom under the safety margin
   shrinks below ~40 KB.
2. A specific feature lands that pushes us past the script's
   `HARD_LIMIT=1490000`.

If revisited, the work is roughly:

- Build a custom image extending the pinned `sourcescan/cargo-near` base
  with `binaryen` (the Dockerfile from the closed PR is preserved at
  `docker/cargo-near-mpc/Dockerfile` on branch
  `experiment/wasm-opt-oz-reproducible-build` if useful).
- Update `[package.metadata.near.reproducible_build]` in
  `crates/contract/Cargo.toml` to point at the new image and chain
  `bash -c "cargo near build … --no-wasmopt && wasm-opt -Oz --strip-* --vacuum …"`.
- Gas-validate a representative `sign()` call on sandbox before merging.

For larger headroom (multi-hundred-KB), structural options remain (in
preference order):

1. Move DCAP/TDX quote verification off the contract (sub-contract or
   off-chain attestation oracle). Single call site at
   `crates/attestation/src/attestation.rs`. Frees ~300–500 KB.
2. Delete `crates/contract/src/v3_9_1_state.rs` once 3.9.1 has fully
   rolled out (~20–50 KB).
3. Collapse `crates/contract/src/dto_mapping.rs` (975 lines bridging two
   parallel type universes).

## Process lesson for next time

The measurement design should isolate each variable from the start. The
right setup is: same docker image, same source, vary one flag, measure.
Comparing a host build to a docker build and calling the gap a "saving"
mixed two effects (environment and flag) and produced misleading
headline numbers. The corrected numbers above came from doing the
isolation properly.
