# YARA scanning of changed files

`.github/workflows/security-scan.yml` runs a generic malicious-code rule pack over the files a
push or pull request touches. The rules come from
[DataDog/guarddog](https://github.com/DataDog/guarddog) (Apache-2.0) and describe behaviour —
obfuscation, download-and-execute, silent process spawn, reverse shells, exfiltration, autostart
persistence — rather than signatures for any single campaign.

## The rules are not committed here

`.github/scripts/fetch-yara-rules.sh` downloads them from a pinned GuardDog release and verifies
the wheel's SHA-256 before extracting. That keeps 54 files of third-party content out of the
repository and out of review, while still being reproducible: the version and checksum are pinned
in that script, so a change to what CI enforces is a one-line diff rather than a 54-file one. This
matches how `ci.yml` already pins `repro-env`.

The rules ship inside the published wheel, so nothing GuardDog depends on gets installed and
Python is not needed to evaluate them.

Run it locally the same way CI does:

```sh
.github/scripts/fetch-yara-rules.sh /tmp/yara-rules
RULES_DIR=/tmp/yara-rules \
BASE_SHA=$(git merge-base origin/main HEAD) HEAD_SHA=$(git rev-parse HEAD) \
  .github/scripts/scan-changed-files.sh
```

## Why not GuardDog's own scanner

Every rule declares `path_include = "*.js,*.ts,..."` in its `meta:` block. That key is not a YARA
construct: GuardDog's Python driver parses it and filters candidates with `fnmatch`, so it never
opens a file whose extension is absent from the list. Selecting files by extension is the blind
spot this scan exists to close — a payload named `.woff2` would simply be skipped. The `yara`
binary treats unknown `meta:` keys as inert, so pointing it at a file list scans everything
regardless of name.

## Before making this a required check

The workflow runs on `push` for same-repo branches and on `pull_request` only for forks, so a PR is
not scanned twice. The skipped run still publishes a check run under the same name as the real one,
and GitHub treats a skipped check as satisfying a requirement. Ordering favours safety today, since
the skip resolves in seconds while the scan takes minutes, but it is not guaranteed.

So before wiring `Scan changed files` in as required, settle the naming: distinct job names per
event make the gate unambiguous, at the cost of fork PRs never producing the push-event check. Pick
one deliberately rather than inheriting this default.

## blocking-rules.txt

Only the rules listed there fail the build. Everything else in the pack still runs and still
annotates the PR, but advisory only.

The split is measured, not guessed: a rule qualifies as blocking only with zero false positives
across both the whole tracked tree and every file version touched by the last 400 commits on
`main`. Of 54 rules, 36 qualified; the 18 excluded are mostly `capability_*` rules, which flag the
presence of a capability rather than misuse of it and so fire on ordinary code. Defaulting new
rules to advisory means bumping the pinned version cannot silently introduce a gate nobody
measured.

## Bumping the version

1. Edit `VERSION`, `WHEEL_URL` and `WHEEL_SHA256` in
   `.github/scripts/fetch-yara-rules.sh`. All three come from
   `https://pypi.org/pypi/guarddog/<version>/json`, from the `py3-none-any.whl` entry
   under `.urls[]`.
2. Re-measure both halves of the criterion, from a clean tree. First the tracked tree:

   ```sh
   .github/scripts/fetch-yara-rules.sh /tmp/yara-rules
   yarac -w /tmp/yara-rules/*.yar /tmp/rules.yarc
   git ls-files -z | xargs -0 -n1 yara -w -C /tmp/rules.yarc
   ```

   Then the historical sweep, which the criterion also covers — every file version touched by the
   last 400 commits on `main`:

   ```sh
   corpus=$(mktemp -d)
   for sha in $(git log origin/main -400 --format=%H); do
     for f in $(git diff-tree --no-commit-id --name-only --diff-filter=ACMR -r "$sha"); do
       mkdir -p "$corpus/$sha/$(dirname "$f")"
       git cat-file blob "$sha:$f" > "$corpus/$sha/$f" 2>/dev/null || true
     done
   done
   find "$corpus" -type f -print0 | xargs -0 -n1 yara -w -C /tmp/rules.yarc
   ```

   `yara` accepts many rule files but only one target path, and given several it silently treats
   the extras as rule sources and still exits 0 — hence `-n1` in both.
3. Any rule that fires in either sweep has a false positive: drop it from `blocking-rules.txt` with
   a note, or fix the offending file. The scan refuses to start if `blocking-rules.txt` names a rule
   the pack no longer has, so a rule renamed upstream surfaces immediately rather than quietly
   dropping to advisory.
4. Run the scanner's own tests: `.github/scripts/tests/test-scan-changed-files.sh`.
