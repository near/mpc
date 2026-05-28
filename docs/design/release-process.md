# Release process redesign

> **Status:** design — implementation pending. This document supersedes the
> current process described in [`RELEASES.md`](../../RELEASES.md). Once the
> implementation lands, `RELEASES.md` will be rewritten in its terms and this
> document either deleted or marked superseded.

## Background

The current release process triggers on `git push` of a `*.*.*` tag. CI then
retags a previously-built `nearone/mpc-node:main-<short-sha>` image to the
release version, builds the contract, and creates a draft GitHub release.

Two recent constraints break this:

1. **Secrets are gated by the `production` GitHub Environment** ([#3287][3287]).
   The environment's deployment-ref policy currently grants access only to
   `main`. A tag-push workflow runs under `refs/tags/<version>`, which is
   neither `main` nor any branch — so the release workflow cannot reach
   `DOCKERHUB_PAT` and fails before pushing any image.

2. **Patch releases need to ship from `release/v*` branches, not `main`.**
   The build workflows that produce `main-<sha>` images only fire on push to
   `main`, so a cherry-picked fix landing on a release branch never produces
   an image to retag. The existing flow has no concept of "release-branch
   image."

A natural reaction is to widen the environment's ref policy to include tags
and release branches, plus add a tag-creation ruleset. But GitHub has no
review/approval flow for tag pushes — tag protection only gates *who* can
push, not *what*. The current model leans on tag pushes as the privileged
release trigger; that triggering surface cannot be reviewed in the same way
PRs can.

[3287]: https://github.com/near/mpc/pull/3287

## Goals

- A release flow whose trigger surface is naturally reviewable by GitHub's
  branch-protection mechanisms.
- A single workflow that works identically for any release — minors from
  `main` and patches from a release line.
- Artifacts built reproducibly from the exact commit being released. No
  reliance on previously-built images keyed by branch name.
- A low ceremony bar for invoking a release initially, with room to add
  defense-in-depth (reviewers, time gates) later if needed.

## Design

### Core idea

A release is a workflow run, invoked from a protected branch, that publishes
artifacts and records the release as a git tag.

The tag is the **receipt** of a successful release, not the **trigger**.
Authorization for the release is whatever authorization already governs
landing the version-bump-and-changelog commit on the protected branch. No
separate tag-protection story is needed.

### Trigger

`workflow_dispatch` on a protected branch (`main` or `release/vX.Y`). Invoked
via the Actions UI or `gh workflow run release.yml --ref <branch>`.

The branch identifies *what* is being released; the workflow run is the act
of releasing it.

### Version source

The workspace `version` field in `Cargo.toml` on the branch is the source of
truth. The workflow reads it directly. No version is passed as a workflow
input.

This makes the version-bump PR the proposal-of-release: merging it onto a
protected branch is the meaningful authorization. The workflow run is the
acceptance.

### Workflow shape

```
1. Checkout the branch HEAD.
2. Read version V from Cargo.toml.
3. Refuse if git tag V already exists. (Idempotency guard.)
4. Verify CHANGELOG.md has a section for V.
5. Build images reproducibly (deployment/build-images.sh).
6. Build contract reproducibly.
7. Push images as nearone/mpc-{node,node-gcp,launcher}:V.
   (Overwrites any pre-existing tag at this version.)
8. Create draft GitHub release with notes, image digests, contract artifact.
9. Create and push git tag V at the released commit. (Last step.)
```

Two properties fall out:

- `git tag V exists ⟺ release V succeeded.` A re-run after a partial failure
  is safe — the tag is the final step, and every preceding step is
  idempotent (re-pushing a Docker tag overwrites; the draft release can be
  recreated).
- Image tag overwrites are allowed by design. If the wrong image was pushed
  to `:V`, a re-run from a fixed commit overwrites it. The git tag check
  remains the guard against silently re-pointing `:V` at a different
  *commit*.

### Branch convention

Release branches are **per minor line**, accumulating patches over time:

- `release/v3.11` ships `3.11.0`, then `3.11.1`, then `3.11.2`, ...
- `release/v3.12` ships `3.12.0` and onward.
- `main` ships the next minor or major.

A patch flow is:

1. Cherry-pick fix(es) onto `release/vX.Y`.
2. Open a PR bumping `Cargo.toml`'s patch version and prepending the
   changelog section. Merge.
3. Run the release workflow against `release/vX.Y`.

A minor/major flow is either:

- Bump on `main`, run the workflow against `main`, then fork
  `release/vX.Y` from the released commit (or shortly after); or
- Fork `release/vX.Y` from `main` first, bump on the new branch, run the
  workflow against `release/vX.Y`.

Either is fine; the workflow does not care.

After the release, `Cargo.toml` on the branch sits at the just-released
version. The next patch PR bumps it again.

Existing per-patch release branches (`release/v3.10.1`, `release/v3.9.1`,
etc.) become legacy artifacts. They are not migrated; the new convention
applies going forward.

### Authorization model

- **Branch protection** on `main` and `release/vX.Y`:
  - PR required, ≥1 review, dismiss stale approvals on push, no force-push,
    no direct push.
- **Branch creation ruleset** on `release/v*`: creation restricted to
  repository admins. Closes the gap where branch protection only governs
  what lands on an existing branch via PR, not where the branch is
  initially rooted. Admins are trusted to fork from `main` HEAD.
- **`production` environment ref policy:** `main` and `release/v*` allowed.
  No required reviewer initially. Tags are not in the ref policy and are
  never the deployment ref.
- **No tag ruleset initially.** The release workflow creates the
  `*.*.*` tag using `GITHUB_TOKEN` with `contents: write`. In practice only
  the workflow creates these tags; we rely on convention rather than a
  ruleset for now.

The two-human invariant is provided by branch protection: every commit on a
release-eligible branch has been touched by ≥2 humans (author + reviewer).
Anyone with workflow-dispatch permission can then trigger a release run,
but can only release code that has already been reviewed.

Defense-in-depth options not adopted since they are overkill for our releases:

- Required environment reviewer (adds time gating and accidental-trigger
  catch).
- Restricting `workflow_dispatch` to a release-manager team.
- Replacing admin-restricted `release/v*` creation with a bot-only
  `create-release-branch.yml` workflow that mechanically forks from `main`.
- Tag ruleset on `*.*.*` restricting creation to the workflow bot.

## What changes

High-level inventory; concrete edits to follow in implementation PRs.

### Workflows

- **`release.yml`**: rewritten. Trigger becomes `workflow_dispatch`. The
  workflow body absorbs the responsibilities currently spread across
  `release.yml`, `docker_node_release.yml`, and `docker_launcher_release.yml`
  — build images directly, push at `:V`, build contract, create GH release,
  create tag.
- **`docker_node_release.yml`, `docker_launcher_release.yml`**: deleted.
  Their retag responsibility is gone in the new model.
- **`docker_build_node.yml`, `docker_build_node_gcp.yml`,
  `docker_build_rust_launcher.yml`**: status TBD. These currently produce
  `main-<sha>` images on every push to `main`. The release workflow no
  longer consumes them. If they have other consumers (smoke tests, manual
  testnet deploys), they stay; if not, they can be deleted or moved to a
  separate "preview" environment with its own credential.
- **`docker_release_legacy.yml`**: deleted. Manual fallback for the old
  retag flow.

### Scripts

- **`scripts/prepare-release.sh`**: simplified. Still produces the release
  PR's contents (branch checkout, changelog generation, version bump, ABI
  snapshot, licenses, commit) but stops pushing the branch and creating
  it from `HEAD` unconditionally. For patches, it operates on a checkout
  of `release/vX.Y`. For minors, on `main`. The script's job ends at "you
  have a commit, open a PR."

### Documentation

- **`RELEASES.md`**: rewritten in terms of the new flow.
- This design doc: deleted or marked superseded once the implementation
  lands.
- Any other references to tag-push triggering or the retag flow: audited
  and updated.

### Repository settings (out-of-band)

Not in any PR; needs to be configured by someone with repo-admin access:

- Branch protection ruleset for `release/v*` (PR required, ≥1 review,
  dismiss stale approvals on push, no force-push, no direct push).
- Branch creation ruleset for `release/v*` restricting creation to repo
  admins.
- `production` environment deployment-ref policy: `main`, `release/v*`.

## Open questions

- **Pre-release / RC versions.** The model supports them naturally (set
  `Cargo.toml` to `3.11.0-rc1`, run workflow), but the tag regex
  `*.*.*` may need adjustment.
- **What happens to the `mainnet-release` / `testnet-release` tags?** Today
  the same retag action is reused for promoting releases to these floating
  tags. In the new model, this promotion is a separate concern from the
  release itself and likely deserves its own (small) workflow.
