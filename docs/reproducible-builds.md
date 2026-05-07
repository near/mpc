# Reproducible Builds

This project supports reproducible builds for both the node and launcher Docker images. Reproducible builds ensure that the same source code always produces identical binaries — important for security and verification.

The build is driven entirely by Nix. The flake's package set produces both the bare binaries (verifiably bit-for-bit reproducible across builders) and the OCI image tarballs that wrap them.

## Prerequisites

- `nix` (with flakes enabled)
- `git`

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

## Verifying a manifest digest

The manifest digest is the value participants vote for. Each image has a companion derivation that computes it deterministically inside the Nix sandbox:

```bash
nix build .#node-image-manifest-digest && cat result
# → sha256:<hex>
```

Same for `node-gcp-image-manifest-digest` and `rust-launcher-image-manifest-digest`. Two builders running the same Nix expression at the same revision must produce the same digest.

## Pushing to Docker Hub

Push the locally-built tarball with `skopeo`, preserving the manifest digest you just verified:

```bash
nix run nixpkgs#skopeo -- copy --preserve-digests \
  docker-archive:$(nix build --print-out-paths .#node-image) \
  docker://docker.io/nearone/mpc-node:<tag>
```

Substitute `node-gcp-image` / `rust-launcher-image` and the matching destination repo as needed. Skopeo must be authenticated to the registry beforehand (`nix run nixpkgs#skopeo -- login docker.io`).
