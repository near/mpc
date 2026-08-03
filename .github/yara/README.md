# YARA scanning of changed files

`.github/workflows/security-scan.yml` runs a generic malicious-code rule pack over the files a
push or pull request touches. The rules come from
[DataDog/guarddog](https://github.com/DataDog/guarddog) (Apache-2.0) and describe behaviour —
obfuscation, download-and-execute, silent process spawn, reverse shells, exfiltration, autostart
persistence — rather than signatures for any single campaign.

The engine is [YARA-X](https://github.com/VirusTotal/yara-x) (`yr`), VirusTotal's Rust successor to
YARA. All new upstream work goes there; YARA 4.x now gets bug fixes only.

## Running it locally

The dev shell provides both scanners at the versions CI uses:

```sh
nix develop --command bash -c '
  .github/scripts/fetch-yara-rules.sh /tmp/yara-rules
  RULES_DIR=/tmp/yara-rules \
  BASE_SHA=$(git merge-base origin/main HEAD) HEAD_SHA=$(git rev-parse HEAD) \
    .github/scripts/scan-changed-files.sh'
```

Tests: `nix develop --command .github/scripts/tests/test-scan-changed-files.sh`.

## Versions are pinned in two places, keep them in step

| | local | CI |
|---|---|---|
| `yr` | `nix/yara-x.nix` | `.github/scripts/fetch-scanners.sh` |
| `magika` | `nix/magika.nix` | `.github/scripts/fetch-scanners.sh` |

Both pin the same versions from upstream release binaries, checksummed. Deliberately not taken from
nixpkgs: `yara-x` there is older, and a nixpkgs bump would change the engine underneath the measured
blocking allowlist without anyone noticing. `magika-cli` in nixpkgs is worse than stale — on Darwin
it installs a binary with no `LC_RPATH` that cannot resolve `libonnxruntime.dylib` and aborts on
every call.

CI downloads instead of using nix because nix is the slower path *for this job*: measured in this
repo, `Install Nix` plus `Restore /nix from cache` is 7s + 22s, against roughly 1.5s for two
checksummed downloads. Release assets are maintainer-mutable, so the pinned digest is the protection,
not the tag — never use a floating tag like magika's `cli-latest`.

## The rules are not committed here

`.github/scripts/fetch-yara-rules.sh` downloads them from a pinned GuardDog release and verifies
the wheel's SHA-256 before extracting. That keeps 54 files of third-party content out of the
repository and out of review, while still being reproducible: the version and checksum are pinned
in that script, so a change to what CI enforces is a one-line diff rather than a 54-file one. This
matches how `ci.yml` already pins `repro-env`.

The rules ship inside the published wheel, so nothing GuardDog depends on gets installed and
Python is not needed to evaluate them.

## Why not GuardDog's own scanner

Every rule declares `path_include = "*.js,*.ts,..."` in its `meta:` block. That key is not a YARA
construct: GuardDog's Python driver parses it and filters candidates with `fnmatch`, so it never
opens a file whose extension is absent from the list. Selecting files by extension is the blind
spot this scan exists to close — a payload named `.woff2` would simply be skipped. `yr` treats
unknown `meta:` keys as inert, so pointing it at a file list scans everything regardless of name.

## Three `yr` behaviours worth knowing before editing the script

- **It exits 0 when it cannot read a listed file**, reporting only on stderr, and has no
  `--fail-on-error`. The script therefore treats non-empty stderr as fatal. Removing that check
  reintroduces a silent pass.
- **`include` resolves against the working directory**, not the including file, unlike YARA 4.x.
  Three rules `include` the `.meta` files by bare name, so compiling needs `--include-dir`; without
  it the pack fails with seven `include file not found` errors.
- **`--scan-list` must precede the positional arguments**, or the target is rejected as an
  unexpected argument.

## Performance, and why the script sets `--threads 1` for small runs

Measured on a 3-file scan against the 54-rule pack, best of seven, with rules precompiled:

| | 3 files | 930 files |
|---|---|---|
| `yr` default | 33ms | 116ms |
| `yr --threads 1` | 27ms | 330ms |
| `yara` 4.5.8 | 8ms | 288ms |

`yr` pays about 22–31ms deserialising the compiled pack, and that cost scales with pack size (23 KB
→ 14ms, 1.46 MB → 36ms) against a 5ms bare process floor. Its thread pool is pure overhead on a
short list, so the script goes single-threaded below 50 files — comfortably above this repo's p90
diff of 17 files — and lets it use every core above that. `--fast-scan` changes nothing measurable
and is not used. Precompiling with `yr compile` matters: scanning from source costs 133ms against
35ms for 3 files.

Note the honest comparison: `yara` 4.5.8 is faster at typical diff sizes, and `yr` only wins past
roughly 150 files. The engine choice here is about following upstream, not speed. If the scan step
ever becomes a bottleneck, the lever is the install step, not the scanner.

### Where the load cost goes, and why we are not chasing it further

`Rules::deserialize` does three things: a bincode decode, a wasmtime Cranelift JIT of the rules'
WASM module, and an Aho-Corasick rebuild. Neither the native code nor the automaton is serialised
into a `.yarc` by default — both are regenerated on every load, which is the deliberate price of
[PR #202](https://github.com/VirusTotal/yara-x/pull/202) making the format platform-independent. That
is also why the cost tracks generated-code size rather than file size: 318 KB → 422 KB adds 1ms while
422 KB → 1.46 MB adds 11ms.

There is a documented escape hatch, the `native-code-serialization` cargo feature, which embeds the
JIT output and would plausibly take a 3-file scan from ~27ms to ~12ms. **Deliberately not used**: it
requires building `yr` from source, so this security-critical job would swap an upstream release
binary for one we build ourselves, and take on a Rust build plus its maintenance — a poor trade for
~15ms in a 14s job. Upstream `main` already serialises the Aho-Corasick automaton
(commit `3c61ef8d1`), so some of this improves for free on a future release.

If you ever do want to measure the split rather than guess, the timings are already instrumented
behind a cargo feature: build with `--features logging,yara-x/logging` and run with `RUST_LOG=info`
to get `Deserialization time`, `WASM build time` and the automaton build time separately.

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

## Bumping a version

Whichever you bump — the rule pack or a scanner — re-measure, because both can move the match set.

1. For the rules, edit `VERSION`, `WHEEL_URL` and `WHEEL_SHA256` in
   `.github/scripts/fetch-yara-rules.sh`; all three come from
   `https://pypi.org/pypi/guarddog/<version>/json`, from the `py3-none-any.whl` entry under
   `.urls[]`. For a scanner, edit both its `nix/*.nix` and `fetch-scanners.sh` entries together.
2. Re-measure both halves of the criterion, from a clean tree. First the tracked tree:

   ```sh
   .github/scripts/fetch-yara-rules.sh /tmp/yara-rules
   ( cd /tmp/yara-rules && yr compile -w *.yar -o /tmp/rules.yarc )
   git ls-files > /tmp/list.txt
   yr scan -w --compiled-rules --scan-list /tmp/rules.yarc /tmp/list.txt
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
   find "$corpus" -type f > /tmp/hist.txt
   yr scan -w --compiled-rules --scan-list /tmp/rules.yarc /tmp/hist.txt
   ```

   Both sweeps currently report 171 matches across 18 rule types, none of them in
   `blocking-rules.txt`.
3. Any rule that fires in either sweep has a false positive: drop it from `blocking-rules.txt` with
   a note, or fix the offending file. The scan refuses to start if `blocking-rules.txt` names a rule
   the pack no longer has, so a rule renamed upstream surfaces immediately rather than quietly
   dropping to advisory.
4. Run the scanner's own tests: `nix develop --command .github/scripts/tests/test-scan-changed-files.sh`.
