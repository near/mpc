# Release Guide

This document outlines our release process for the NEAR MPC project.

## Overview

The NEAR MPC project consists of two main components that are released together as a single bundle:
- **MPC Node Binary**: The core MPC signing node implementation.
- **Chain Signatures Contract**: The smart contract that manages signing requests and node coordination.

## Release Principles

### 1. Release from the `main` branch
Releases are created by making a release tag on the `main` branch, followed by the manual steps outlined in the
[GitHub release documentation](https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository#creating-a-release).

Before creating the tag, make sure to update the version number in all relevant `Cargo.toml` files.

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

### 4. Rebase `mainnet-release` and `testnet-release` branches
In addition to the version-tags, we have branches to mark the current releases running on `mainnet` and `testnet`: `mainnet-release` and `testnet-release`. Whenever we upgrade `mainnet` or `testnet`, we must set the `mainnet-release` and `testnet-release` branches to point to the release tag we intend to run in these environments.

Note: When patching `mainnet` and `testnet` we should not merge new commits into the `mainnet-release` or `testnet-release` branches. Instead, we should create a SemVer patch-release with the appropriate tag first, and then rebase the `mainnet-release` or `testnet-release` tags on top of this version.

## How to make a release

In practice when making a release, you need to do the following things:

1. Update the changelog.
2. Bump the crate versions.
3. Create the release tag.
4. Create release artifacts.
5. Create the release on GitHub.

The following sections will walk you through the steps of doing this for the `3.1.0` release.
Replace this with whatever release version you're making.

### 1. Update the changelog
We use `git-cliff` to maintain the changelog.
Installation instructions can be found [here](https://git-cliff.org/docs/installation/).

For typical releases, the following command should be sufficient.
```sh
git-cliff -t 3.1.0 > CHANGELOG.md
```

Note: The tag doesn't have to have been created yet.

### 2. Bump the crate versions
To bump the crate versions, just update the `version` field in `Cargo.toml`.
After this, the `Cargo.lock` file and contract ABI snapshot tests must be updated.
This can be done by running the snapshot test and reviewing the new snapshot with cargo insta.

```sh
cargo nextest run -p mpc-contract abi_has_not_changed
cargo insta review
```

At this point it's appropriate to open a PR with the changelog and crate version changes.
See [the 3.0.6 PR](https://github.com/near/mpc/pull/1549) for reference.

### 3. Create the release tag
Once the changelog and crate versions have been bumped on latest `main`
we're ready to create the release tag.
You can do this directly in GitHub, but I prefer to do it locally:

```sh
git tag 3.1.0
git push origin 3.1.0 # Assuming `origin` points at github.com:near/mpc.git
```

### 4. Create the release artifacts
Once the tag has been pushed the following release artifacts should be created:

1. The launcher and MPC node docker images.
2. The contract.

For small patches we can omit publishing the contract if there are no changes to it.

To create the launcher and MPC node docker images, use the following workflows:

- **Launcher**: [Release Launcher Docker Image](https://github.com/near/mpc/actions/workflows/docker_launcher_release.yml)
- **Node**: [Release Node Docker Image](https://github.com/near/mpc/actions/workflows/docker_node_release.yml)

Both of these work the same way. They take an existing image and re-tags it with the provided tag.

Run these workflows with the source image tag `main-<short-commit-hash>` using the short commit hash
at the release tag.
It's easiest to find this exact tag at docker hub.
For example for the node image, visit the [nearone/mpc-node-gcp](https://hub.docker.com/r/nearone/mpc-node-gcp/tags)
page and find the image associated with the commit at the release tag.

We don't have a workflow to build and publish the contract yet, so this is easiest to build
locally using the normal command:

```sh
cargo near build reproducible-wasm --manifest-path crates/contract/Cargo.toml
```

Naturally using reproducible builds.

After this we should rename the contract and compress this into a `.tar.gz` archive.

```sh
cd target/near/mpc_contract/
mv mpc_contract.wasm mpc-contract-v3.1.0.wasm
mv mpc_contract_abi.json mpc-contract-v3.1.0-abi.json
tar -czf mpc-contract-v3.1.0.tar.gz mpc-contract-v3.1.0.wasm mpc-contract-v3.1.0-abi.json
```

### 5. Create the release on GitHub
Now we should be all set to create the actual release on Github.

From the [release page](https://github.com/near/mpc/releases) click "Draft a new release",
write some sentences about the release and paste the relevant changelog entries to it.

Then, add the appropriate links to the docker images and attach the contract in the UI.

Look at previous releases for reference.

Once it looks good, click "publish release" and enjoy.

Note: When you want to roll this release out to testnet and mainnet,
you can use the same re-tagging action to re-tag the released images as `nearone/mpc-node-gcp:testnet-release`
and `nearone/mpc-node-gcp:mainnet-release`.