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

## How to make a release

The release script automates the full process end-to-end. Run it with:

```sh
./scripts/prepare-release.sh all 3.1.0
```

This runs all steps in sequence. If interrupted or if any step fails, re-running the same command
will skip completed steps and resume from where it left off.

You can also run individual steps:

```sh
./scripts/prepare-release.sh prepare 3.1.0      # Branch, changelog, version bump, ABI, licenses, commit
./scripts/prepare-release.sh draft-pr 3.1.0      # Push branch and open PR
./scripts/prepare-release.sh wait-merge 3.1.0    # Wait for PR to be merged (interactive prompt)
./scripts/prepare-release.sh wait-images 3.1.0   # Poll DockerHub until images exist for the merge commit
./scripts/prepare-release.sh create-tag 3.1.0    # Verify images, create and push the release tag
./scripts/prepare-release.sh wait-release 3.1.0  # Poll until the draft GitHub release is created
./scripts/prepare-release.sh status 3.1.0        # Show which steps are done/pending
```

### Step details

#### 1. `prepare` — Local release preparation
Creates a `release/v3.1.0` branch, generates the changelog with `git-cliff`, bumps the workspace
version in `Cargo.toml`, updates the contract ABI snapshot, regenerates third-party licenses, and
commits all changes. Requires: `git-cliff`, `cargo-about`, `cargo-insta`, `cargo-nextest`.

#### 2. `draft-pr` — Open a pull request
Pushes the release branch and opens a PR against `main` via `gh`. Requires: `gh`.

#### 3. `wait-merge` — Wait for the PR to be merged
Prints the PR URL and prompts you to press Enter after you've reviewed and merged it.
Verifies the merge before continuing. Requires: `gh`.

#### 4. `wait-images` — Wait for Docker images
Polls DockerHub (via `skopeo`) until all three images (`mpc-node`, `mpc-node-gcp`, `mpc-launcher`)
are published with the `main-<short-sha>` tag corresponding to the merge commit.
These images are built by CI when commits land on `main`. Requires: `skopeo`.

#### 5. `create-tag` — Create the release tag
Verifies Docker images exist, then creates and pushes the release tag pointing at the merge commit
on `main`. This triggers the [Release workflow](.github/workflows/release.yml). Requires: `gh`, `skopeo`.

#### 6. `wait-release` — Wait for the draft release
Polls until the Release workflow creates the draft GitHub release. Requires: `gh`.

#### 7. Publish the release (manual)
Once the draft release is created, go to the [releases page](https://github.com/near/mpc/releases),
review and edit it as needed, then publish.

### Options

```
--poll-interval SECONDS   Polling interval for wait commands (default: 30)
--timeout SECONDS         Max polling time before giving up (default: 3600)
```

<details>
<summary>Manual alternative (if the script or workflow is unavailable)</summary>

#### Update the changelog
```sh
git-cliff -t 3.1.0 > CHANGELOG.md
```
> ⚠️ Ensure your current branch is pushed to GitHub (e.g. `origin`). Otherwise `git-cliff` will not be able to resolve PR links in the generated notes.

#### Bump the crate versions
Update the `version` field in `Cargo.toml`, then update the ABI snapshot:
```sh
cargo nextest run -p mpc-contract abi_has_not_changed
cargo insta review
```

#### Update license versions
Follow the [how-to-regenerate](https://github.com/near/mpc/tree/main/third-party-licenses#how-to-regenerate) guide.

#### Create the release tag
Before pushing the tag, verify that the Docker images for the tagged commit have already been published by the CI pipeline (e.g. `main-<short-sha>` tags on Docker Hub). The Release workflow retags these existing images, so it will fail if they don't exist yet.

```sh
git tag 3.1.0
git push origin 3.1.0
```

#### Docker image retagging (if the Release workflow is unavailable)

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