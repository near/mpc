# Scanning changed files for disguised content

`security-scan.yml` classifies the *content* of every file a push or PR touches and reports
any file whose bytes are code or an executable while its extension claims an inert asset:
JavaScript named `.woff2`, an ELF named `.png`.

## Why content and not extension

Selecting files by extension is the blind spot this closes. A scanner that filters candidates
by name never opens `fa-solid-400.woff2`, so the disguise works because tooling declines to
look. [magika][magika] classifies by content, so the name hides nothing.

The check needs all three of: magika reports code or an executable, the extension promises
inert data, and magika does not list that extension as expected for the detected type. The
last condition spares assets that are code by nature, such as a real `.wasm`.

## Running it

```sh
nix develop --command uv run .github/scripts/scan-changed-files.py   # writes results.sarif
nix develop --command python3 .github/scripts/tests/test-scan-changed-files.py
```

`uv` reads the pinned magika version from the inline script metadata, so CI and local runs
resolve the same dependency and there is nothing to keep in step.

## What blocks a merge

Not the script. It exits 0 on a finding and 2 only when it could not scan. Gating is a
**code scanning** rule on the branch ruleset with the alerts threshold at `Errors`, matching
the SARIF `level`.

That rule also blocks while analysis is running or if the tool is not configured, so a job
that never reports cannot look clean. It is used instead of a required status check because
this workflow skips itself for same-repo PRs, the skipped run publishes a check with the same
name as the real one, and GitHub counts a skipped check as satisfying a requirement.

To accept a finding, dismiss the alert in the Security tab. That is per finding and persists,
so there is no allowlist to maintain.

Fork PRs cap `security-events` at read and cannot upload SARIF, so the job fails directly and
annotates the lines instead.

[magika]: https://github.com/google/magika
