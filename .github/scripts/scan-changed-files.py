#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["magika==1.0.3"]
# ///
"""Report changed files whose content is executable but whose extension claims an asset.

    uv run scan-changed-files.py

Range comes from the GitHub event, or from BASE_SHA and HEAD_SHA when both are set.
Writes SARIF to SARIF_OUT (default `results.sarif`).

Exit 0 even on a finding, since merge protection does the blocking; 1 instead when
FAIL_ON_FINDINGS is set, for fork PRs that cannot upload SARIF; 2 when it could
not scan, which must never look clean.

See .github/security-scan/README.md.
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

from magika import Magika

RULE_ID = "content-extension-mismatch"

ASSET_EXTENSIONS = frozenset(
    """
    woff woff2 ttf otf eot
    png jpg jpeg gif bmp ico webp avif tiff heic psd
    pdf docx xlsx pptx
    zip gz bz2 xz 7z rar tar zst br lz4 cab deb rpm dmg msi
    wasm so dylib dll exe o a lib bin dat db sqlite
    mp3 mp4 wav mov mkv webm ogg flac avi
    pack idx class pyc pyo jar img iso
    """.split()
)

EXECUTABLE_GROUPS = frozenset({"code", "executable"})

# Runs on repo open or build without being invoked. Warned, never blocked.
AUTO_EXEC = re.compile(
    r"^\.(vscode|devcontainer|githooks|cursor|claude|idea|github)/"
    r"|\.code-workspace$"
    r"|(^|/)build\.rs$"
    r"|^\.cargo/config\.toml$"
    r"|^(Makefile\.toml|justfile|flake\.nix|shell\.nix)$"
    r"|\.(bat|cmd|ps1)$"
)

RULE = {
    "id": RULE_ID,
    "name": "ContentExtensionMismatch",
    "shortDescription": {"text": "Executable content under a binary-asset extension"},
    "fullDescription": {
        "text": (
            "Content is code or an executable while the extension declares an "
            "inert asset. Extension-based scanners never open such a file, which "
            "is what makes it a hiding place."
        )
    },
    "defaultConfiguration": {"level": "error"},
}


def die(message: str) -> None:
    print(message, file=sys.stderr)
    sys.exit(2)


def note(message: str) -> None:
    print(message, file=sys.stderr)


def env_flag(name: str) -> bool:
    # Workflow expressions render "false", which a plain get() reads as set.
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes"}


def git_out(*args: str) -> str:
    result = subprocess.run(["git", *args], capture_output=True, text=True)
    if result.returncode:
        die(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def has_commit(sha: str) -> bool:
    return not subprocess.run(
        ["git", "cat-file", "-e", f"{sha}^{{commit}}"], capture_output=True
    ).returncode


def branch_delta(default_branch: str) -> str:
    """Base for a range whose start is unknown or unreachable.

    `before` is zeroes on branch creation and orphaned after a force-push. Both
    carry several commits, so HEAD~1 would leave most of the range unexamined.
    """
    base = git_out("merge-base", f"origin/{default_branch}", "HEAD")
    # Pushing to the default branch itself: merge-base is HEAD.
    return git_out("rev-parse", "HEAD~1") if base == git_out("rev-parse", "HEAD") else base


def resolve_range() -> tuple[str, str]:
    base, head = os.environ.get("BASE_SHA"), os.environ.get("HEAD_SHA")
    if base and head:
        return base, head

    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not event_path:
        die("Set BASE_SHA and HEAD_SHA, or run inside a GitHub event.")
    event = json.loads(Path(event_path).read_text())

    if pull_request := event.get("pull_request"):
        return pull_request["base"]["sha"], pull_request["head"]["sha"]

    default_branch = event.get("repository", {}).get("default_branch", "main")
    before = event.get("before")
    head = os.environ.get("GITHUB_SHA") or git_out("rev-parse", "HEAD")
    return (before if before and has_commit(before) else branch_delta(default_branch)), head


def require_commit(sha: str, name: str) -> None:
    # A commit absent from the clone empties the diff, which would look clean.
    if not has_commit(sha):
        die(f"{name} {sha} is not in this clone; needs actions/checkout with fetch-depth: 0.")


def changed_files(base: str, head: str) -> list[str]:
    # -z: core.quotePath would quote any byte above 0x80, and the quoted literal
    # then matches no file on disk, dropping a homoglyph-named payload.
    result = subprocess.run(
        ["git", "diff", "--name-only", "--diff-filter=ACMR", "-z", base, head],
        capture_output=True,
    )
    if result.returncode:
        die(f"git diff {base}..{head} failed: {result.stderr.decode(errors='replace').strip()}")
    return [p for p in result.stdout.decode("utf-8", "surrogateescape").split("\0") if p]


def extension_of(path: str) -> str:
    name = path.rsplit("/", 1)[-1]
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


def is_mismatch(path: str, output) -> bool:
    # Last condition spares assets that are code by nature: magika lists "wasm"
    # as expected for a real .wasm.
    extension = extension_of(path)
    return (
        output.group in EXECUTABLE_GROUPS
        and extension in ASSET_EXTENSIONS
        and extension not in {e.lower() for e in output.extensions}
    )


def make_result(path: str, output) -> dict:
    return {
        "ruleId": RULE_ID,
        "ruleIndex": 0,
        "level": "error",
        "message": {
            "text": (
                f"Content is {output.label}, but the .{extension_of(path)} "
                f"extension declares a binary asset."
            )
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": path},
                    "region": {"startLine": 1},
                }
            }
        ],
    }


def build_sarif(results: list) -> dict:
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "disguised-content",
                        "informationUri": "https://github.com/google/magika",
                        "rules": [RULE],
                    }
                },
                "results": results,
            }
        ],
    }


def main() -> int:
    if bool(os.environ.get("BASE_SHA")) != bool(os.environ.get("HEAD_SHA")):
        die("BASE_SHA and HEAD_SHA must be set together, or neither.")

    base, head = resolve_range()
    sarif_out = Path(os.environ.get("SARIF_OUT", "results.sarif"))

    require_commit(base, "base")
    require_commit(head, "head")

    paths = []
    for path in changed_files(base, head):
        if Path(path).is_file():
            paths.append(path)
        else:
            # ACMR excludes deletions, so anything else here is unexpected.
            note(f"Skipping {path}: not a regular file.")

    results = []
    if paths:
        note(f"Scanning {len(paths)} changed file(s).")
        identified = Magika().identify_paths([Path(p) for p in paths])
        for path, outcome in zip(paths, identified):
            # Unread file means unexamined, which must not report as clean.
            if not outcome.ok:
                die(f"magika could not read {path}: {outcome.status}")
            if is_mismatch(path, outcome.output):
                results.append(make_result(path, outcome.output))
    else:
        note("No files to scan.")

    # Written even when empty: uploading that is what clears an earlier commit's
    # alerts. A failed write must exit 2, not surface as a traceback's 1.
    try:
        sarif_out.write_text(json.dumps(build_sarif(results), indent=2) + "\n")
    except OSError as error:
        die(f"Could not write {sarif_out}: {error}")

    for result in results:
        uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        print(f"::error file={uri}::{result['message']['text']}")

    for path in paths:
        if AUTO_EXEC.search(path):
            print(
                f"::warning::{path}: runs automatically when the repo is opened "
                "or built - review as code"
            )

    note(f"Wrote {sarif_out} with {len(results)} finding(s).")
    # Fork PRs cap security-events at read, so the exit code is the only signal.
    return 1 if results and env_flag("FAIL_ON_FINDINGS") else 0


if __name__ == "__main__":
    sys.exit(main())
