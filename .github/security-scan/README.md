# Scanning changed files for disguised content

`.github/workflows/security-scan.yml` inspects the *content* of every file a push or pull
request touches, and reports any file whose bytes are code or an executable while its
extension claims an inert binary asset: JavaScript named `.woff2`, an ELF named `.png`, and
so on.

Findings are uploaded as [SARIF][sarif] and become code scanning alerts. Blocking a merge is
configured in a ruleset, not in the script.

## Why content and not extension

Selecting files by extension is the blind spot this exists to close. Scanners that filter
candidates by name never open a payload called `fa-solid-400.woff2`, so the disguise works
precisely because tooling declines to look. [magika][magika] classifies by content, so the
name cannot hide anything from it.

The check fires only on a three-way conjunction, in `find-type-mismatches.py`: magika reports
the content as code or executable, *and* the extension is one that promises inert data, *and*
magika does not list that extension as expected for the type it detected. The third condition
is what spares assets that are executable by nature, such as a genuine `.wasm`.

## Running it locally

The dev shell provides magika at the version CI uses:

```sh
nix develop --command bash -c '
  BASE_SHA=$(git merge-base origin/main HEAD) HEAD_SHA=$(git rev-parse HEAD) \
    .github/scripts/scan-changed-files.sh'
```

That writes `results.sarif`. Tests:
`nix develop --command .github/scripts/tests/test-scan-changed-files.sh`.

## What blocks a merge

Nothing in the script does. It always exits 0 when it merely *found* something, and exits 2
only when it could not scan properly. Gating is a **code scanning** rule on the branch
ruleset, with the alerts threshold set to `Errors`, matching the `level` the SARIF emits.

That rule also blocks when the tool's analysis is still running or is not configured at all,
so a job that never reports cannot be mistaken for a clean result. Using it instead of a
required status check avoids a trap: this workflow skips itself for same-repo pull requests to
avoid scanning twice, the skipped run publishes a check with the same name as the real one,
and GitHub counts a skipped check as satisfying a requirement.

To accept a finding, dismiss the alert in the repository's Security tab. That is per finding
and it persists, so there is no allowlist file to maintain.

## Fork pull requests

Forks cap `security-events` at read, so SARIF cannot be uploaded for them. The workflow fails
the job directly in that case, which annotates the offending lines instead. Same detection,
different reporting surface.

## Version pinning

magika is pinned twice and both must move together:

| | local | CI |
|---|---|---|
| magika | `nix/magika.nix` | `.github/scripts/fetch-scanners.sh` |

Both take the same upstream release binary, checksummed. Deliberately not from nixpkgs: on
Darwin that build installs a binary with no `LC_RPATH` that cannot resolve
`libonnxruntime.dylib` and aborts on every call.

CI downloads rather than using nix because nix is the slower path *for this job*: installing
Nix plus restoring its cache is measured at 7s + 22s here, against roughly 1s for one
checksummed download. Release assets are maintainer-mutable, so the pinned digest is the
protection, not the tag. Never use a floating tag such as magika's `cli-latest`.

[sarif]: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/uploading-a-sarif-file-to-github
[magika]: https://github.com/google/magika
