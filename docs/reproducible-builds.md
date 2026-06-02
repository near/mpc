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

**Requirements for building the MPC contract**:

- [Nix](https://nixos.org/download/) with flakes enabled

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

The MPC contract WASM is built reproducibly via the Nix derivation at
[`nix/mpc-contract.nix`](../nix/mpc-contract.nix). The Nix sandbox provides the
hermetic toolchain (Rust pinned by `rust-toolchain.toml`, clang/LLVM, vendored
cargo registry), so the build does not depend on a third-party Docker image.

From the project root:

```bash
nix build .#mpc-contract
sha256sum result/mpc_contract.wasm
```

To verify a release artifact, compare the SHA-256 above against the
`sha256:<digest>` value listed under "MPC contract" in the GitHub release notes.
The exact same command runs in CI for every release, so the hashes must match
byte-for-byte.

> **Note on third-party verification.** The contract WASM no longer carries
> NEP-330 build metadata that points at a `sourcescan/cargo-near` Docker image,
> so automated verifiers such as sourcescan.io and nearblocks cannot replay the
> build. Verification is now "anyone with a checkout and Nix can rebuild and
> compare hashes" using the command above.
