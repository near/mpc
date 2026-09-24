# Reproducible Builds

The `mpc-node`, `mpc-node-gcp` and `mpc-launcher` Docker images and the MPC
contract WASM are built reproducibly: the same commit yields the same bytes,
so anyone can check what is deployed against the source.

## Docker images

The images are built with [Nix](https://nixos.org/download/) (flakes enabled).
Every build step runs in the Nix sandbox without network access, from inputs
pinned by `flake.lock`, `Cargo.lock` and `rust-toolchain.toml`; only fetching
those inputs touches the network, and each fetch is checked against its hash.
Where the kernel refuses the sandbox (for example inside a container) Nix
silently builds without it, so set `sandbox-fallback = false` in `nix.conf`,
as CI does, to make such a build fail instead.

Each image is built in the exact layout pushed to Docker Hub, so the SHA-256 of
its `manifest.json` is the manifest digest operators vote on. The same commands
work on x86_64 Linux and, with the builder below, on macOS:

```bash
nix build github:near/mpc/<commit-hash>#packages.x86_64-linux.mpc-node-image
sha256sum result/manifest.json
```

Use `mpc-node-gcp-image` or `mpc-launcher-image` for the other images. From a
checkout, `.#packages.x86_64-linux.mpc-node-image` gives the same digest only
with a clean working tree, because the node binary embeds the commit hash. The
digests also cover `flake.lock`, so a nixpkgs bump changes them without any
code change. Commits without these flake outputs, such as patch releases from
release branches created before the switch to Nix, are reproduced by following
this guide in that checkout.

To run an image locally, load it into Docker with `skopeo`:

```bash
skopeo copy dir:result docker-daemon:mpc-node:latest
```

### Building on macOS

The images are `x86_64-linux` derivations, so Nix needs a Linux builder. On
Apple silicon, nixpkgs' `darwin.linux-builder-vz` runs a NixOS VM that executes
the same derivations a Linux host does, translated by Rosetta rather than cross
compiled, so the digests match. It needs macOS 26 or newer (older Rosetta lacks
the x86-64-v3 instructions the build runs) with Rosetta installed
(`softwareupdate --install-rosetta --agree-to-license`), and it exists only in
nixpkgs-unstable (not 26.05), which the
[nix-darwin](https://github.com/nix-darwin/nix-darwin) template tracks:

```bash
sudo mkdir -p /etc/nix-darwin
sudo chown "$(id -nu):$(id -ng)" /etc/nix-darwin
cd /etc/nix-darwin
nix flake init -t nix-darwin/master
sed -i '' "s/simple/$(scutil --get LocalHostName)/" flake.nix
```

Add to `configuration` in `flake.nix`:

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
# Managing PAM files needs Full Disk Access on recent macOS
security.pam.services.sudo_local.enable = false;
```

Install nix-darwin, which also starts the builder. If it reports files in
`/etc` it did not create (such as the `/etc/bashrc` written by the Nix
installer), rename them with a `.before-nix-darwin` suffix and rerun:

```bash
sudo nix --extra-experimental-features 'nix-command flakes' run nix-darwin/master#darwin-rebuild -- switch
```

The Linux commands above now work unchanged.

Without a Linux builder, Docker Desktop with Rosetta enabled and at least 16 GB
of memory runs the same build in a container:

```bash
docker run --rm --privileged --platform linux/arm64 \
  -e NIX_CONFIG=$'experimental-features = nix-command flakes\nsandbox = true\nsandbox-fallback = false\nextra-platforms = x86_64-linux' \
  nixos/nix:2.33.6 \
  sh -c 'nix build github:near/mpc/<commit-hash>#packages.x86_64-linux.mpc-node-image && sha256sum result/manifest.json'
```

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
