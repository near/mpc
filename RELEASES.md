# Release Guide

This document outlines our release process for the NEAR MPC project.

## Overview

The NEAR MPC project consists of two main components that are released together as a single bundle:
- **MPC Node Binary**: The core MPC signing node implementation.
- **Chain Signatures Contract**: The smart contract that manages signing requests and node coordination.

## Release Principles

### 1. Release from the `main` branch
Releases are created by pushing a release tag on the `main` branch. The [Release workflow](.github/workflows/release.yml) then automatically creates a draft GitHub release with all artifacts.

Before creating the tag, make sure to update the version number in the workspace `Cargo.toml` file.

### 2. Use dedicated branches for patch releases
The exception to the rule above is when we backport critical fixes.
For these patch releases, we create dedicated release branches
of the format `release/vX.Y.Z`, based on the previous release tag `X.Y.Z-1`.

### 3. Respect SemVer compatibility guarantees

We follow [Semantic Versioning (SemVer)](https://semver.org/) with the following compatibility guarantees:

#### Major Version Bumps (X.Y.Z → X+1.0.0)
- **Contract Compatibility**: The new contract must maintain compatibility with nodes from the previous major version.
- **Breaking Changes**: Node-to-node communication protocols may change, requiring coordinated upgrades.

#### Minor Version Bumps (X.Y.Z → X.Y+1.0)
- **Backward Compatibility**: Both contract and node must be compatible with previous versions of the node binary.

#### Patch Version Bumps (X.Y.Z → X.Y.Z+1)
- **Full Backward Compatibility**: No breaking changes allowed.
- **Bug Fixes Only**: Only bug fixes and security patches.

## Automated Release Script

We also have a script that automates the local steps (changelog, version bump, snapshot update, license regeneration) described below. You can find it at [`scripts/prepare-release.sh`](https://github.com/near/mpc/blob/main/scripts/prepare-release.sh). Run it with the desired version:

```sh
./scripts/prepare-release.sh 3.1.0
```

The remaining steps (opening the PR, creating the tag, and publishing the release) still need to be done manually.

## How to make a release

In practice when making a release, you need to do the following things:

1. Update the changelog.
2. Bump the crate versions.
3. Update license versions.
4. Open and merge a PR with the changes.
5. Create the release tag.
6. Edit and publish the draft GitHub release.

The following sections will walk you through the steps of doing this for the `3.1.0` release.
Replace this with whatever release version you're making.

### 1. Update the changelog
We use `git-cliff` to maintain the changelog.
Installation instructions can be found [here](https://git-cliff.org/docs/installation/).

> ⚠️ Ensure your current branch is pushed to GitHub (e.g. `origin`). Otherwise `git-cliff` will not be able to resolve PR links in the generated notes.

For typical releases, the following command should be sufficient.
```sh
git-cliff --prepend CHANGELOG.md --unreleased -t 3.1.0
```

This prepends the new release block to `CHANGELOG.md` rather than regenerating the entire file, so any hand-authored sections (e.g. for releases whose tag does not live on `main`, like a backport tagged on a `release/vX.Y.Z` branch) are preserved. If a previous patch release was tagged off-`main` and its fixes were also cherry-picked to `main`, append the main-side cherry-pick commits to `.cliffignore` so they don't reappear in the next auto-generated block.

Note: The tag doesn't have to have been created yet.

### 2. Bump the crate versions
To bump the crate versions, just update the `version` field in `Cargo.toml`.
After this, the `Cargo.lock` file and contract ABI snapshot tests must be updated.
This can be done by running the snapshot test and reviewing the new snapshot with cargo insta.

```sh
cargo nextest run -p mpc-contract abi_has_not_changed
cargo insta review
```

### 3. Update license versions
Follow the [how-to-regenerate](https://github.com/near/mpc/tree/main/third-party-licenses#how-to-regenerate) guide, to update the license versions.

### 4. Open and merge a PR with the changelog and version bumps
At this point it's appropriate to open a PR with the changelog and crate and license version changes.
See [the 3.0.6 PR](https://github.com/near/mpc/pull/1549) for reference.
Once approved, merge it to `main` before creating the release tag.

### 5. Create the release tag
Once the changelog and crate versions have been bumped on latest `main`
we're ready to create the release tag.

Before pushing the tag, verify that the Docker images for the tagged commit have already been published by the CI pipeline (e.g. `main-<short-sha>` tags on Docker Hub). The Release workflow retags these existing images, so it will fail if they don't exist yet.

You can create the tag directly in GitHub, but I prefer to do it locally:

```sh
git tag 3.1.0
git push origin 3.1.0 # Assuming `origin` points at github.com:near/mpc.git
```

### 6. Edit and publish the draft GitHub release

Pushing the tag in the previous step triggers the [Release workflow](.github/workflows/release.yml), which automatically:

1. Retags the Docker images (`mpc-launcher`, `mpc-node`, `mpc-node-gcp`) from `main-<short-sha>` to the release version.
2. Builds the contract reproducibly and computes its SHA-256 digest.
3. Creates a **draft** GitHub release with the changelog, Docker image digests, and the contract artifact attached.

Once the workflow completes, go to the [releases page](https://github.com/near/mpc/releases), review and edit the draft as needed, then publish it.

<details>
<summary>Manual alternative (if the workflow is unavailable)</summary>

To create the launcher and MPC node docker images, use the following workflows:

- **Launcher**: [Release Launcher Docker Image](https://github.com/near/mpc/actions/workflows/docker_launcher_release.yml)
- **Node**: [Release Node Docker Image](https://github.com/near/mpc/actions/workflows/docker_node_release.yml)

Note: the **Node** workflow should be run twice, for `nearone/mpc-node-gcp` and `nearone/mpc-node` images.

Both of these work the same way. They take an existing image and retag it with the provided tag.

Run these workflows with the source image tag `main-<short-commit-hash>` using the short commit hash
as the release tag.
To get the release tag run:
````sh
git rev-parse --short=7 3.1.0
````
Or, you can find this exact tag at docker hub.
For example for the node image, visit the [nearone/mpc-node-gcp](https://hub.docker.com/r/nearone/mpc-node-gcp/tags)
page and find the image associated with the commit at the release tag.

Build the contract locally:

```sh
cargo near build reproducible-wasm --manifest-path crates/contract/Cargo.toml
```

Rename and compress the contract into a `.tar.gz` archive:

```sh
cd target/near/mpc_contract/
mv mpc_contract.wasm mpc-contract-v3.1.0.wasm
mv mpc_contract_abi.json mpc-contract-v3.1.0-abi.json
tar -czf mpc-contract-v3.1.0.tar.gz mpc-contract-v3.1.0.wasm mpc-contract-v3.1.0-abi.json
```

To get the digest of the MPC contract:

```sh
sha256sum mpc-contract-v3.1.0.wasm
```

Then create the release from the [release page](https://github.com/near/mpc/releases) — click "Draft a new release",
paste the relevant changelog entries, add Docker image links, and attach the contract artifact.

</details>

Note: When you want to roll this release out to testnet and mainnet,
you can use the same re-tagging action to re-tag the released images as `nearone/mpc-node-gcp:testnet-release`
and `nearone/mpc-node-gcp:mainnet-release`.