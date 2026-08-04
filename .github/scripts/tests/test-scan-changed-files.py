#!/usr/bin/env python3
"""Tests for scan-changed-files.py, run against throwaway git repos.

    python3 .github/scripts/tests/test-scan-changed-files.py

Needs git and uv on PATH; uv supplies the scanner's own dependency, so this runs
the scanner exactly the way CI does. Exits 0 when every case passes.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SCANNER = Path(__file__).resolve().parent.parent / "scan-changed-files.py"

passed = 0
failed = 0


def check(name: str, expected, actual) -> None:
    global passed, failed
    if expected == actual:
        print(f"ok   {name}")
        passed += 1
    else:
        print(f"FAIL {name} (expected {expected!r}, got {actual!r})")
        failed += 1


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=True
    ).stdout.strip()


def new_repo() -> Path:
    repo = Path(tempfile.mkdtemp())
    git(repo, "init", "-q", "-b", "main")
    git(repo, "config", "user.email", "t@example.com")
    git(repo, "config", "user.name", "Test")
    (repo / "README.md").write_text("seed\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "seed")
    return repo


def commit_all(repo: Path, message: str) -> None:
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", message)


def write_payload(path: Path) -> None:
    """JavaScript behind a long run of spaces, saved under an asset name.

    Content that is code, a name claiming an inert asset, and a payload pushed
    off-screen in a diff. magika still types this as javascript.
    """
    path.write_text(
        " " * 1700
        + "globalThis['r']=require;\n"
        + "function go(x){return x*2};\nmodule.exports={go};\n"
    )


def scan(repo: Path, base: str, head: str, drop_head: bool = False) -> tuple[int, Path]:
    sarif = Path(tempfile.mkstemp()[1])
    env = {**os.environ, "BASE_SHA": base, "SARIF_OUT": str(sarif)}
    if drop_head:
        env.pop("HEAD_SHA", None)
    else:
        env["HEAD_SHA"] = head
    completed = subprocess.run(
        ["uv", "run", str(SCANNER)],
        cwd=repo,
        env=env,
        capture_output=True,
    )
    return completed.returncode, sarif


def findings(sarif: Path) -> int:
    return len(json.loads(sarif.read_text())["runs"][0]["results"])


# --- the payload is reported, under an ASCII name and a homoglyph one ----------
# The Cyrillic 'a' matters: git quotes such paths unless the diff is read -z, and
# a quoted path would not match the file on disk.
for label, name in [("ascii", "fa-solid-400.woff2"), ("homoglyph", "fа-solid-400.woff2")]:
    repo = new_repo()
    (repo / "public" / "fonts").mkdir(parents=True)
    write_payload(repo / "public" / "fonts" / name)
    commit_all(repo, "payload")
    rc, sarif = scan(repo, git(repo, "rev-parse", "HEAD~1"), git(repo, "rev-parse", "HEAD"))
    check(f"scan succeeds ({label})", 0, rc)
    check(f"payload reported ({label})", 1, findings(sarif))
    shutil.rmtree(repo)

# --- a genuine font is left alone --------------------------------------------
repo = new_repo()
(repo / "public" / "fonts").mkdir(parents=True)
(repo / "public" / "fonts" / "real.woff2").write_bytes(b"wOF2\x00\x01\x00\x00" + os.urandom(4000))
commit_all(repo, "font")
rc, sarif = scan(repo, git(repo, "rev-parse", "HEAD~1"), git(repo, "rev-parse", "HEAD"))
check("genuine woff2 exits 0", 0, rc)
check("genuine woff2 reports nothing", 0, findings(sarif))
shutil.rmtree(repo)

# --- a payload in an earlier commit of a multi-commit range is still found ----
# Regression for the base-commit fallback: scanning only the tip missed this.
repo = new_repo()
(repo / "public" / "fonts").mkdir(parents=True)
write_payload(repo / "public" / "fonts" / "fa-solid-400.woff2")
commit_all(repo, "payload")
(repo / "later.txt").write_text("later\n")
commit_all(repo, "later")
_, sarif = scan(repo, git(repo, "rev-parse", "HEAD~2"), git(repo, "rev-parse", "HEAD"))
check("payload in a non-tip commit reported", 1, findings(sarif))
_, sarif = scan(repo, git(repo, "rev-parse", "HEAD~1"), git(repo, "rev-parse", "HEAD"))
check("tip-only range misses it (why the fallback matters)", 0, findings(sarif))
shutil.rmtree(repo)

# --- refusing to scan nothing ------------------------------------------------
repo = new_repo()
head = git(repo, "rev-parse", "HEAD")
missing = "deadbeef" * 5

rc, _ = scan(repo, head, missing)
check("absent head sha exits 2", 2, rc)

rc, _ = scan(repo, missing, head)
check("absent base sha exits 2", 2, rc)

rc, _ = scan(repo, head, head, drop_head=True)
check("missing HEAD_SHA exits 2", 2, rc)

# An empty diff must still write a run: uploading it is what clears alerts an
# earlier commit raised.
rc, sarif = scan(repo, head, head)
check("empty diff exits 0", 0, rc)
check("empty diff still writes an empty run", 0, findings(sarif))
shutil.rmtree(repo)

# --- a file the scanner cannot read must not pass -----------------------------
repo = new_repo()
unreadable = repo / "unreadable.txt"
unreadable.write_text("secret\n")
commit_all(repo, "unreadable")
unreadable.chmod(0o000)
rc, _ = scan(repo, git(repo, "rev-parse", "HEAD~1"), git(repo, "rev-parse", "HEAD"))
unreadable.chmod(0o644)
check("unreadable file exits 2", 2, rc)
shutil.rmtree(repo)

# --- a path containing a newline is scanned, not dropped -----------------------
# The shell version had to refuse these because both scanners took newline
# delimited file lists. Passing paths as arguments removes that limitation.
repo = new_repo()
try:
    weird = repo / "we\nird.woff2"
    write_payload(weird)
    commit_all(repo, "newline")
except OSError:
    print("skip newline case (filesystem rejected the name)")
else:
    _, sarif = scan(repo, git(repo, "rev-parse", "HEAD~1"), git(repo, "rev-parse", "HEAD"))
    check("newline in path is still scanned", 1, findings(sarif))
shutil.rmtree(repo)

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
