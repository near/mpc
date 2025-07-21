# Release Guide

This document outlines our release process for the NEAR MPC project.

## Overview

The NEAR MPC project consists of two main components that are released together as a single bundle:
- **MPC Node Binary**: The core MPC signing node implementation.
- **Chain Signatures Contract**: The smart contract that manages signing requests and node coordination.

## Release Principles

### 1. Release from the `main` branch
Releases are created by making a release tag on the `main` branch, followed by the manual steps outlined in the
[GitHub release documentation](https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repoaitory#creating-a-release).

Before creating the tag, make sure to update the version number in all relevant `Cargo.toml` files.

### 2. Use dedicated branches for patch releases
The exception to the rule above is when we backport critical fixes.
For these patch releases, we create dedicated release branches
of the format `release/vX.Y.Z`, based on the previous release tag `vX.Y.Z-1`.

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
