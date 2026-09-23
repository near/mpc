# Reproducible Builds

This project supports reproducible builds for the node and launcher Docker
images, and for the on-chain MPC contract WASM. Reproducible builds ensure that
the same source code always produces identical binaries, which is important for
security and verification purposes.

## Docker images

The `mpc-node`, `mpc-node-gcp` and `mpc-launcher` images are built hermetically
with [Nix](https://nixos.org/download/) (flakes enabled). Every build step runs
in the Nix sandbox without network access, from inputs pinned by `flake.lock`,
`Cargo.lock` and `rust-toolchain.toml`: only the download of those pinned
inputs uses the network, and each download is checked against its hash, so
code that runs during the build (build scripts, proc-macros) cannot fetch
anything. Nix enables the sandbox by default on Linux, but where the kernel
refuses the namespaces it needs (e.g. inside a container) it silently builds
without it; set `sandbox-fallback = false` in `nix.conf`, as CI does, so such a
build fails instead.

Each image builds to the exact layout pushed to Docker Hub, so the SHA-256 of
its `manifest.json` is the manifest digest that operators vote on:

```bash
nix build github:near/mpc/<commit-hash>#packages.x86_64-linux.mpc-node-image
sha256sum result/manifest.json
```

Use `mpc-node-gcp-image` or `mpc-launcher-image` for the other images. Building
`.#packages.x86_64-linux.mpc-node-image` from a checkout gives the same result
only if the working tree is clean, because the commit hash is embedded in the
node binary. The digest also covers `flake.lock`, so bumping nixpkgs changes it
even when the code does not. Commits without these flake outputs, such as
patch releases from release branches created before the switch to Nix, are
reproduced by following this guide in that checkout.

To run an image locally, load it into Docker:

```bash
docker load --input "$(nix build --no-link --print-out-paths .#packages.x86_64-linux.mpc-node-image.archive)"
```

### Building on macOS

The images are `x86_64-linux` builds, so Nix needs a Linux builder to run them.
On Apple silicon with macOS 26 or newer, nixpkgs' `darwin.linux-builder-vz`
runs a NixOS builder VM that executes `x86_64-linux` builds through Rosetta. It
is only in nixpkgs-unstable (not 26.05), so with
[nix-darwin](https://github.com/nix-darwin/nix-darwin) on nixpkgs-unstable,
add:

```nix
nix.linux-builder = {
  enable = true;
  package = pkgs.darwin.linux-builder-vz;
  systems = [ "aarch64-linux" "x86_64-linux" ];
  config.virtualisation = {
    cores = 8;
    darwin-builder.memorySize = 16 * 1024;
    darwin-builder.diskSize = 100 * 1024;
  };
};
```

Install Rosetta (`softwareupdate --install-rosetta --agree-to-license`) and run
`sudo darwin-rebuild switch`; the commands above then work unchanged. The
[nixpkgs documentation](https://github.com/NixOS/nixpkgs/blob/56c02bc00adcf003215cc4bd996d6efaf4cff188/doc/packages/darwin-builder.section.md)
describes the setup without nix-darwin.

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
`rust-toolchain.toml` (`1.97.1`). This metadata is embedded in the WASM, which
lets automated third-party verifiers such as sourcescan.io and nearblocks replay
the build and confirm the on-chain contract matches the published source. This
is the build CI publishes as the release artifact. It requires `docker` and
[`cargo-near`](https://github.com/near/cargo-near):

```bash
cargo near build reproducible-wasm --manifest-path crates/contract/Cargo.toml
sha256sum target/near/mpc_contract/mpc_contract.wasm
```

To verify a release artifact, compare the SHA-256 above against the
`sha256:<digest>` value listed under "MPC contract" in the GitHub release notes.

### Nix

The Nix derivation at [`nix/mpc-contract.nix`](../../nix/mpc-contract.nix) provides
a hermetic toolchain (Rust pinned by `rust-toolchain.toml`, clang/LLVM, vendored
cargo registry), so the build does not depend on a third-party Docker image. CI
exercises it on every change as an independent reproducible path, and it is the
quickest way to rebuild the contract locally. It is a fallback and is not the
released artifact; its output is not byte-identical to the cargo-near build:

```bash
nix build .#mpc-contract
sha256sum result/mpc_contract.wasm
```
