# Release Guide

This document describes the release process for the NEAR MPC project.

## Overview

The NEAR MPC project ships two artifacts together as one release bundle:

- **MPC Node binary** — distributed as Docker images
  (`nearone/mpc-node`, `nearone/mpc-node-gcp`, `nearone/mpc-launcher`).
- **Chain Signatures contract** — distributed as a reproducibly-built WASM
  attached to the GitHub release.

A release is a [Release workflow](.github/workflows/release.yml) run that
promotes already-built artifacts to a versioned release. The workflow:

1. Reads the version from `Cargo.toml` on the dispatched branch.
2. Retags the Docker images that were built for the branch HEAD
   (`nearone/mpc-{node,node-gcp,launcher}:<branch>-<short-sha>`) to the
   release version (`:X.Y.Z`).
3. Downloads the reproducibly-built contract WASM from the matching
   [Build Contract](.github/workflows/build_contract.yml) run.
4. Creates a draft GitHub release with the changelog, image digests, and
   contract archive.
5. Creates and pushes the `X.Y.Z` git tag at the released commit.

The git tag is the **receipt** of a successful release, not its trigger.
If the tag exists, the release succeeded.

## Branch model

Releases ship from protected branches:

- **`main`** — ships the next minor or major.
- **`release/vX.Y`** — ships patches for the X.Y line (`X.Y.0`, `X.Y.1`, ...).
  Created from `main` by a repository admin when a release line needs its
  own branch.

Patches accumulate on `release/vX.Y` over time:

- `release/v3.11` ships `3.11.0`, then `3.11.1`, then `3.11.2`, ...
- `release/v3.12` ships `3.12.0` and onward.

Branch protection on `main` and `release/v*` requires every commit to land
via a reviewed PR. Branch *creation* on `release/v*` is restricted to repo
admins — admins are trusted to fork release branches from `main` HEAD.

## How to make a release

The walkthrough below uses `3.11.0` as the example version. Replace it
with whatever version you're releasing.

### 1. Prepare the release PR

Run [`scripts/prepare-release.sh`](./scripts/prepare-release.sh) on the
branch you intend to release from:

```sh
# For a minor/major release:
git checkout main && git pull
./scripts/prepare-release.sh 3.11.0

# For a patch release:
git checkout release/v3.11 && git pull
./scripts/prepare-release.sh 3.11.1
```

The script generates the changelog section, bumps the workspace version in
`Cargo.toml`, updates the contract ABI snapshot, regenerates third-party
licenses, and commits the result. Push the branch and open a PR against
`main` (for minor releases) or `release/vX.Y` (for patches).

Once the PR is reviewed and merged, the merge commit is what will be
released.

### 2. Wait for the build workflows

When the release PR merges, four workflows fire on the protected branch:

- [Build Docker Node Image](.github/workflows/docker_build_node.yml)
- [Build Docker Node GCP Image](.github/workflows/docker_build_node_gcp.yml)
- [Build Docker Rust Launcher Image](.github/workflows/docker_build_rust_launcher.yml)
- [Build Contract](.github/workflows/build_contract.yml)

The image workflows push `nearone/mpc-{node,node-gcp,launcher}:<branch>-<short-sha>`.
The contract workflow uploads the reproducible WASM as a GitHub Actions
artifact named `contract`.

Wait for all four to finish successfully. The Release workflow refuses to
run if any artifact is missing.

> **Tip:** The pre-release images are deployable. If you want to
> smoke-test on testnet before promoting, deploy
> `nearone/mpc-node-gcp:release-v3.11-<short-sha>` directly.

### 3. Run the Release workflow

Trigger the [Release workflow](.github/workflows/release.yml) against the
branch:

```sh
gh workflow run release.yml --ref release/v3.11
```

Or use the Actions UI: "Release" → "Run workflow" → pick the branch.

The workflow runs in the `production` environment and uses
`DOCKERHUB_PAT` to retag images. If the version's git tag already exists
on origin, or if any source artifact for the branch HEAD is missing, the
workflow refuses.

### 4. Edit and publish the draft release

When the workflow finishes, a draft release named `MPC 3.11.0` appears on
the [releases page](https://github.com/near/mpc/releases). The draft
includes the changelog section, Docker image manifest digests, and the
contract `.tar.gz`.

Review the draft and click "Publish release."

### 5. Promote to operator floating tags (optional)

Some operators consume floating tags like `nearone/mpc-node-gcp:testnet-release`
and `:mainnet-release`. Promote with the retag workflows:

- [Release Node Docker Image](.github/workflows/docker_node_release.yml) — run twice (once per repository)
- [Release Launcher Docker Image](.github/workflows/docker_launcher_release.yml)

Use `source-tag = 3.11.0` and `release-tag = testnet-release` or
`mainnet-release`.

## Re-running after a failure

The Release workflow is idempotent up until the git tag is created (the
last step). If something fails partway:

- Re-run the workflow. Image retags overwrite cleanly; the draft release
  will be recreated.
- If the workflow ran to completion but produced a bad release, delete
  the draft release **and** the `X.Y.Z` git tag, then re-run.

The tag-existence check is a guard against silently re-pointing `:X.Y.Z`
at a different commit. Image overwrites at the same `:X.Y.Z` tag are
allowed by design — useful for recovering from a bad build by re-running
from a fixed commit.

## Creating a new release branch

When a minor line needs its own branch (typically just before or just
after shipping `X.Y.0`), a repo admin forks from `main`:

```sh
git checkout main && git pull
git push origin main:refs/heads/release/v3.11
```

The branch ruleset on `release/v*` restricts creation to admins. After
the initial push, the branch's protection rules require PRs for any
further commits.

## SemVer compatibility guarantees

We follow [Semantic Versioning](https://semver.org/) with these compatibility rules:

### Major version bumps (X.Y.Z → X+1.0.0)
- **Contract compatibility**: the new contract must remain compatible
  with nodes from the previous major version.
- **Breaking changes**: node-to-node protocol may change, requiring
  coordinated upgrades.

### Minor version bumps (X.Y.Z → X.Y+1.0)
- **Backward compatibility**: both contract and node must remain
  compatible with previous node binaries.

### Patch version bumps (X.Y.Z → X.Y.Z+1)
- **Full backward compatibility**: no breaking changes.
- **Bug fixes only**: bug fixes and security patches.

## Changelog conventions

We use [`git-cliff`](https://git-cliff.org/) to maintain `CHANGELOG.md`.
The `prepare-release.sh` script invokes it with the right range for the
release being prepared.

For patch releases tagged off a `release/vX.Y` branch, the script
generates the section from the previous patch tag (`git-cliff --from-tag
X.Y.(Z-1)`). For minor/major releases on `main`, it uses `--unreleased`.

If a previous patch was tagged off a release branch and its fixes were
also cherry-picked to `main`, append the main-side cherry-pick commits
to `.cliffignore` so they don't reappear in the next auto-generated
block on `main`.
