#!/usr/bin/env bash
set -euo pipefail

# Reproducible mpc-node build, driven by cargo inside the repo's Nix dev shell.
#
# Produces a bit-identical mpc-node binary on any machine that uses this repo's
# `nix develop` shell, regardless of where the checkout or the cargo home live.
#
# Usage (must run inside the dev shell):
#   nix develop --command bash scripts/build-mpc-node-reproducible.sh
#
# How reproducibility holds: the dev shell pins the toolchain and every linked
# library in the content-addressed Nix store (identical on every machine). The
# env below mirrors the release build's repro-env block in
# deployment/build-images.sh, with two additions needed because this build runs
# in the dev shell rather than repro-env's fixed-path container:
#   1. `-include cstdint` in CXXFLAGS  — the Nix toolchain needs it for neard's
#      rocksdb C++ build (repro-env's container does not).
#   2. path remapping                  — repro-env mounts the workspace at a
#      fixed path; here we scrub the two machine-varying roots ($PWD and
#      $CARGO_HOME) out of rustc- and cc-emitted strings.
#   3. RUNPATH normalization           — `nix develop` injects a per-checkout
#      `-rpath $out/lib` that lands in the binary's RUNPATH; normalize it.

CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"

# x86-64-v3 plus PCLMUL and AES — keeps rocksdb's PCLMUL CRC32C path compiled
# in. Matches deployment/build-images.sh and flake.nix's prodCFlags.
march="-march=x86-64-v3 -mpclmul -maes"

# Scrub absolute paths from the cc-rs-compiled C/C++ deps so their objects don't
# vary by checkout / cargo-home location. (Rust paths are handled by cargo's
# trim-paths below, not these — `trim-paths` only governs rustc, not cc-rs.)
file_prefix_map="-ffile-prefix-map=$PWD=/build/source -ffile-prefix-map=$CARGO_HOME=/cargo"


# `nix develop` sets $out to $PWD/outputs/out and injects `-rpath $out/lib` via
# NIX_LDFLAGS; the ld wrapper bakes that per-checkout path into the binary's
# RUNPATH. In a real derivation $out is a fixed store path, but here it varies
# per machine and breaks reproducibility. Normalize it to a fixed placeholder —
# the entry is unused at runtime, since the real libraries resolve via the
# /nix/store rpaths the cc wrapper adds from the linked inputs.
if [ -n "${out:-}" ] && [ -n "${NIX_LDFLAGS:-}" ]; then
  export NIX_LDFLAGS="${NIX_LDFLAGS//"$out"//build/nix-shell-out}"
fi

# Link against the dev shell's nixpkgs openssl instead of openssl-sys' vendored
# copy. A workspace dep (reqwest's `native-tls-vendored`) force-enables
# openssl-sys' `vendored` feature, which otherwise builds openssl from source
# and bakes host-specific absolute paths (ENGINESDIR, the build CFLAGS string,
# rpaths) into the binary — differing per machine. The nixpkgs openssl is a
# content-addressed /nix/store path, identical across machines via flake.lock.
export OPENSSL_NO_VENDOR=1

# Prevents rocksdb's build.rs from probing /proc/cpuinfo and baking host-specific
# ISA choices into its object files — without it, the C deps compile differently
# per build-host CPU and the binary is not reproducible across machines.
export PORTABLE=1

# Pin jemalloc's ./configure auto-detected values so tikv-jemalloc-sys produces
# identical bytes across builders (values match the standard x86_64 Linux ABI).
export SOURCE_DATE_EPOCH=0
export JEMALLOC_SYS_WITH_LG_VADDR=48
export JEMALLOC_SYS_WITH_LG_PAGE=12
export JEMALLOC_SYS_WITH_LG_HUGEPAGE=21

# Stop jemalloc's ./configure from walking up to the repo's .git and baking the
# mpc commit SHA into jemalloc's VERSION file (and the linked binary).
export GIT_CEILING_DIRECTORIES="$PWD/target"

# Pin the `built` crate's GIT_VERSION so local tags aren't embedded.
git_commit="$(git rev-parse --short=7 HEAD)"
export BUILT_OVERRIDE_mpc_node_GIT_VERSION="$git_commit"

# An env RUSTFLAGS *replaces* (does not merge with) .cargo/config.toml's
# [target.cfg(x86_64)] rustflags, so re-include target-cpu here. Path
# remapping is handled by trim-paths (above), not here — see that note.
export RUSTFLAGS="-C target-cpu=x86-64-v3"

# Pin the C/C++ ISA on BOTH the unscoped and target-scoped vars. cc-rs (rocksdb,
# blst) reads CFLAGS_<target>, but jemalloc's ./configure and aws-lc's cmake read
# the *unscoped* CFLAGS/CXXFLAGS — without those, they fall back to host-CPU
# detection and the binary differs per build machine. Setting both keeps every
# C/C++ build system on the same fixed ISA and path remap.
#
# `-g0`: the release-style build carries no Rust debug info (profile sets
# debug=false), but the C deps (jemalloc, ring) pass `-g` themselves, and their
# DWARF differs per build host. Suppress it at the source rather than stripping
# it from the final binary.
cflags="$march -g0 $file_prefix_map"
export CFLAGS="$cflags"
export CXXFLAGS="$march -g0 -include cstdint $file_prefix_map"
export CFLAGS_x86_64_unknown_linux_gnu="$cflags"
export CXXFLAGS_x86_64_unknown_linux_gnu="$march -g0 -include cstdint $file_prefix_map"

cargo build -p mpc-node --profile reproducible --locked

sha256sum target/reproducible/mpc-node
