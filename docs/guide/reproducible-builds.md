# Reproducible Builds

This project supports reproducible builds for the node and launcher Docker
images, and for the on-chain MPC contract WASM. Reproducible builds ensure that
the same source code always produces identical binaries, which is important for
security and verification purposes.

## Prerequisites

**Common requirements** (for building the node and launcher images with the script below):

- `docker` with buildx support
- `jq`
- `git`
- `podman` - runs the pinned `skopeo` image that compresses the layers; its
  gzip output determines the manifest digest, so the pin (not a host `skopeo`)
  is what makes that digest reproducible

**Additional requirements for building the node image**:

- `repro-env` - Tool for reproducible build environments ([install here](https://github.com/kpcyrd/repro-env))

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

## Nix-built images

<!-- TODO(#4562): make this the main build once releases use these images, and remove the script above -->

CI also builds every image with [Nix](https://nixos.org/download/) (flakes
enabled), as an alternative to the script above, and publishes it as
`nearone/<image>:<branch>-<short-sha>-nix`.

Every build step runs in the Nix sandbox, from inputs pinned by `flake.lock`,
`Cargo.lock` and `rust-toolchain.toml`; only fetching those pinned inputs, or
their signed pre-built outputs from the Nix binary cache, touches the network.
Where the kernel refuses the sandbox (for example inside a container) Nix
silently builds without it, so set `sandbox-fallback = false` in `nix.conf`, as
CI does, to make such a build fail instead.

Pre-built outputs are accepted only from `https://cache.nixos.org/` and only if
signed with its key `cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=`,
which are Nix's defaults and what CI checks. Some installers add their own
caches and keys, which could then supply any binary, including the images' own,
so make sure `nix config show substituters` and
`nix config show trusted-public-keys` print exactly these values and
`nix config show require-sigs` prints `true`.

Each image is built in the exact layout pushed to Docker Hub, so the SHA-256 of
its `manifest.json` equals the digest of the published `-nix` tag. The same
commands work on x86_64 Linux and, with a Linux builder (see
[Appendix: Building the Nix images on macOS](#appendix-building-the-nix-images-on-macos)),
on macOS:

```bash
nix build github:near/mpc/<commit-hash>#packages.x86_64-linux.mpc-node-image
sha256sum result/manifest.json
```

Take the full `<commit-hash>` from `main` or the release branch, since GitHub
also serves commits from any fork under `near/mpc`. For a release that includes
these images, the version tag works too (e.g. `github:near/mpc/3.17.0#…`):
our releases are immutable, so their tags cannot be moved. Use
`mpc-node-gcp-image` or `mpc-launcher-image` for the other images. From a
checkout, `.#packages.x86_64-linux.mpc-node-image` gives the same digest only
with a clean working tree, because the node binary embeds the commit hash.

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
is the build CI publishes as the release artifact. It is reproducible but not
hermetic, as its container has network access. It requires `docker`:

```bash
cargo near build reproducible-wasm --manifest-path crates/contract/Cargo.toml
sha256sum target/near/mpc_contract/mpc_contract.wasm
```

To verify a release artifact, compare the SHA-256 above against the
`sha256:<digest>` value listed under "MPC contract" in the GitHub release notes.

### Nix

The Nix derivation at [`nix/mpc-contract.nix`](../../nix/mpc-contract.nix) builds the
contract hermetically (Rust pinned by `rust-toolchain.toml`, clang/LLVM, vendored
cargo registry), so the build does not depend on a third-party Docker image. CI
exercises it on every change as an independent reproducible path, and it is the
quickest way to rebuild the contract locally. It is a fallback and is not the
released artifact; its output is not byte-identical to the cargo-near build:

```bash
nix build .#mpc-contract
sha256sum result/mpc_contract.wasm
```

## Appendix: Building the Nix images on macOS

The images are `x86_64-linux` derivations, so Nix needs a Linux builder. On
Apple silicon, nixpkgs' `darwin.linux-builder-vz` runs a NixOS VM that executes
the same derivations a Linux host does, translated by Rosetta rather than cross
compiled, so the digests match. It needs macOS 26 or newer (older Rosetta lacks
the x86-64-v3 instructions the build runs) with Rosetta installed
(`softwareupdate --install-rosetta --agree-to-license`), and it exists only in
nixpkgs-unstable, which the [nix-darwin](https://github.com/nix-darwin/nix-darwin)
template tracks:

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

Without a Linux builder, Docker Desktop on macOS 26 or newer, with Rosetta
enabled and at least 16 GB of memory, runs the same build in a container:

```bash
docker run --rm --privileged --platform linux/arm64 \
  -e NIX_CONFIG=$'experimental-features = nix-command flakes\nsandbox = true\nsandbox-fallback = false\nextra-platforms = x86_64-linux' \
  nixos/nix:2.33.6@sha256:a29d7e469a042a4f7e82fea231a1096cd57f17e3ac499b0c5472fadc5ef95188 \
  sh -c 'nix build github:near/mpc/<commit-hash>#packages.x86_64-linux.mpc-node-image && sha256sum result/manifest.json'
```
