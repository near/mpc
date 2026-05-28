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

Artifacts are built continuously on push to protected branches, and the
release workflow promotes pre-built artifacts rather than building fresh.

**Build (continuous, on push to `main` and `release/v*`):**

- Existing `docker_build_node.yml`, `docker_build_node_gcp.yml`,
  `docker_build_rust_launcher.yml`, extended to trigger on `release/v*`.
  Push images as `nearone/mpc-{node,node-gcp,launcher}:<branch>-<short-sha>`.
- New `build_contract.yml`. Builds the contract reproducibly, uploads the
  WASM as a GitHub Actions artifact named `contract`.

**Release (`workflow_dispatch` on protected branch):**

```
1. Validate ref is main or release/v*.
2. Checkout the branch HEAD.
3. Read version V from Cargo.toml; compute branch-tag <branch>-<short-sha>.
4. Refuse if git tag V exists on origin.
5. Refuse if a GitHub release (draft or published) for V already exists.
6. Verify CHANGELOG.md has a section for V.
7. Verify nearone/mpc-{node,node-gcp,launcher}:<branch-tag> all exist.
8. Locate the build_contract.yml run for this SHA; download the artifact.
9. Retag images :<branch-tag> → :V via skopeo copy --preserve-digests --all.
10. Collect manifest digests of the retagged images.
11. Create draft GitHub release (--target SHA --draft) with notes, digests,
    contract archive. The git tag is NOT created here; GitHub creates it
    at the stored target_commitish when the operator publishes the draft.
```

Three properties fall out:

- `git tag V exists ⟺ release V was published.` Per GitHub's behavior,
  draft releases do not materialize tags — the tag is created at publish
  time. So tag presence is a strong receipt: someone explicitly clicked
  Publish on the draft. The workflow's tag-existence and release-existence
  checks together ensure a workflow re-run cannot quietly re-release the
  same version.
- Image tag overwrites are allowed by design. If the wrong image was
  promoted to `:V`, a re-run from a fixed commit (after deleting the stale
  draft) overwrites it. The tag- and release-existence checks guard against
  silently re-pointing `:V` at a different *commit* once it has shipped.
- Digest preservation via `skopeo copy --preserve-digests` keeps the
  manifest digest identical between the `<branch>-<sha>` tag and the `V`
  tag. The release artifact is byte-identical to what was built and (if
  applicable) deployed for pre-release validation.

Re-runnability after partial failure:

| State after partial failure   | Recovery action                         |
|-------------------------------|------------------------------------------|
| No draft, no tag              | Re-run; retags overwrite cleanly.        |
| Draft exists, no tag          | Delete the draft on releases page, re-run. |
| Tag and published release     | Already shipped. Re-running requires deleting both. |

The release runs in seconds — there is no reproducible build on the
critical path. The slow build cost is amortized across branch pushes.

A pre-release validation window exists by construction: between when the
build workflows finish and when an operator runs the release workflow,
the `:<branch>-<sha>` images are deployable for smoke-testing. We do not
currently wire any automated validation into this window, but the seam
is there for later.

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

- **`release.yml`**: rewritten. Trigger becomes `workflow_dispatch`. Reads
  version from `Cargo.toml`, retags the pre-built `<branch>-<sha>` images
  to `:V`, downloads the contract artifact from the matching
  `build_contract.yml` run, creates the draft GH release with the tag.
- **`build_contract.yml`**: new. Builds the contract reproducibly on push
  to `main` and `release/v*`, uploads WASM as a GH Actions artifact.
- **`docker_build_node.yml`, `docker_build_node_gcp.yml`,
  `docker_build_rust_launcher.yml`**: extended to trigger on `release/v*`
  pushes in addition to `main`. Otherwise unchanged.
- **`docker_node_release.yml`, `docker_launcher_release.yml`**: kept as-is.
  No longer used by the release flow; retained for promoting `:V` images
  to floating operator tags (`:mainnet-release`, `:testnet-release`).
- **`docker_release_legacy.yml`**: deleted.

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
  `Cargo.toml` to `3.11.0-rc1`, run workflow), but `Cargo.toml`'s version
  regex and the workflow's semver check may need adjustment.
- **Artifact retention.** GitHub Actions artifacts default to 90-day
  retention. A patch released more than 90 days after its merge commit
  will fail at the contract-download step. Acceptable for now (we don't
  promote artifacts older than 90 days in practice), but if the limit
  starts biting, bump `retention-days` on the upload-artifact step or
  re-run `build_contract.yml` manually before triggering the release.
