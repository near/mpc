# Reproducible Builds

This project supports reproducible builds for the node and launcher Docker
images, and for the on-chain MPC contract WASM. Reproducible builds ensure that
the same source code always produces identical binaries, which is important for
security and verification purposes.

## Prerequisites

**Common requirements** (for both node and launcher Docker images):

- `docker` with buildx support
- `jq`
- `git`

**Additional requirements for building the node image**:

- `repro-env` - Tool for reproducible build environments ([install here](https://github.com/kpcyrd/repro-env))
- `podman`

**Requirements for building the MPC contract** (either path works):

- [Nix](https://nixos.org/download/) with flakes enabled (Nix path), or
- `docker` and [`cargo-near`](https://github.com/near/cargo-near) (NEP-330 path)

## Building Images

The build script is located at `deployment/build-images.sh` and must be run from the project root directory.

**Build both node and launcher images** (default behavior):

```bash
./deployment/build-images.sh
```

**Build only the node image**:

```bash
./deployment/build-images.sh --node
```

**Build only the launcher image**:

```bash
./deployment/build-images.sh --rust-launcher
```

The script will output the image hashes and other build information, which can be used to verify the reproducibility of the build.

## mpc-contract

The MPC contract WASM is built reproducibly via two coexisting paths. They do
**not** produce byte-identical output: the cargo-near build embeds an extra
NEP-330 `build_info` metadata section that the Nix build omits, so their hashes
differ by exactly that section. The released artifact is the cargo-near build.

### cargo-near (released artifact / third-party verifiers)

The contract carries [NEP-330](https://github.com/near/NEPs/blob/master/neps/nep-0330.md)
build metadata in `crates/contract/Cargo.toml`
(`[package.metadata.near.reproducible_build]`), which pins a
`sourcescan/cargo-near` Docker image whose tag and digest match
`rust-toolchain.toml` (`1.93.0`). This metadata is embedded in the WASM, which
lets automated third-party verifiers such as sourcescan.io and nearblocks replay
the build and confirm the on-chain contract matches the published source. This
is the build CI publishes as the release artifact. It requires `docker`:

```bash
cargo near build reproducible-wasm --manifest-path crates/contract/Cargo.toml
sha256sum target/near/mpc_contract/mpc_contract.wasm
```

To verify a release artifact, compare the SHA-256 above against the
`sha256:<digest>` value listed under "MPC contract" in the GitHub release notes.

### Nix

The Nix derivation at [`nix/mpc-contract.nix`](../nix/mpc-contract.nix) provides
a hermetic toolchain (Rust pinned by `rust-toolchain.toml`, clang/LLVM, vendored
cargo registry), so the build does not depend on a third-party Docker image. CI
exercises it on every change as an independent reproducible path, and it is the
quickest way to rebuild locally when you only need to compare contract logic
(not the NEP-330 metadata):

```bash
nix build .#mpc-contract
sha256sum result/mpc_contract.wasm
```
