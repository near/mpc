# Reproducible Builds

This project supports reproducible builds for the node and launcher Docker
images, and for the on-chain MPC contract WASM. Reproducible builds ensure that
the same source code always produces identical binaries, which is important for
security and verification purposes.

The image builds are driven entirely by Nix. The flake's package set produces both the bare binaries (verifiably bit-for-bit reproducible across builders) and the OCI image tarballs that wrap them.

## Prerequisites

- [Nix](https://nixos.org/download/) with flakes enabled
- `git`

No other tooling is needed: skopeo (used for pushing) is pinned in the flake
and invoked via `nix run .#skopeo`.

**Requirements for building the MPC contract** (either path works):

- Nix (as above), or
- `docker` and [`cargo-near`](https://github.com/near/cargo-near) (NEP-330 path)

## Building binaries

```bash
nix build .#mpc-node       # → result/bin/mpc-node
nix build .#tee-launcher   # → result/bin/tee-launcher
```

The output binaries are bit-for-bit identical across builders. Hash with `sha256sum result/bin/<name>` if you want a quick receipt.

## Building images

Image derivations package the binaries above into OCI tarballs and are only available on Linux builders.

```bash
nix build .#node-image              # general node image
nix build .#node-gcp-image          # node image with google-cloud-sdk
nix build .#rust-launcher-image     # tee-launcher image
```

The `result` symlink points to a docker-archive tarball.

Alternatively, `deployment/build-images.sh` wraps the derivations above. Run from the project root:

```bash
./deployment/build-images.sh [--node] [--node-gcp] [--rust-launcher] [--push]
```

With no image flags it builds all three. It prints the binary hashes and manifest digests for every image it builds, and with `--push` uploads them to Docker Hub (digest-preserving). This is the same entry point the release workflows use.

## Verifying a manifest digest

The manifest digest is the value participants vote for. Each image has a companion derivation that computes it deterministically inside the Nix sandbox:

```bash
nix build .#node-image-manifest-digest && cat result
# → sha256:<hex>
```

Same for `node-gcp-image-manifest-digest` and `rust-launcher-image-manifest-digest`. Two builders running the same Nix expression at the same revision must produce the same digest.

## Pushing to Docker Hub

`./deployment/build-images.sh --push` pushes every image it built. To push a single image by hand, copy its `dir:` layout — the exact bytes the manifest digest was computed from — with the flake-pinned skopeo:

```bash
nix run .#skopeo -- copy --preserve-digests \
  dir:$(nix build --no-link --print-out-paths .#node-image-dir) \
  docker://docker.io/nearone/mpc-node:<tag>
```

Substitute `node-gcp-image-dir` / `rust-launcher-image-dir` and the matching destination repo as needed. Skopeo must be authenticated to the registry beforehand (`nix run .#skopeo -- login docker.io`).

## mpc-contract

The MPC contract WASM is built reproducibly via two coexisting paths. Each is
independently reproducible, but the two do **not** produce byte-identical output
because they use different build environments: cargo-near builds inside a
`sourcescan/cargo-near` Docker image and embeds NEP-330 `build_info` metadata,
while Nix builds in its own sandbox. The cargo-near build is the released
artifact; the Nix build is a fallback that is not used for releases.

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
quickest way to rebuild the contract locally. It is a fallback and is not the
released artifact; its output is not byte-identical to the cargo-near build:

```bash
nix build .#mpc-contract
sha256sum result/mpc_contract.wasm
```
