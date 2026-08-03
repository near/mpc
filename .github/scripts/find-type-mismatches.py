#!/usr/bin/env python3
"""Report files whose content is executable but whose extension claims an asset.

Reads magika JSONL on stdin, writes `path<TAB>label<TAB>extension` per mismatch.
Used by scan-changed-files.sh; see .github/yara/README.md.
"""

import json
import sys

ASSET_EXTENSIONS = frozenset(
    """
    woff woff2 ttf otf eot png jpg jpeg gif bmp ico webp avif tiff pdf
    zip gz bz2 xz 7z rar tar wasm so dylib dll exe o a lib bin dat db
    sqlite mp3 mp4 wav mov mkv pack idx class pyc pyo jar img iso
    """.split()
)

EXECUTABLE_GROUPS = frozenset({"code", "executable"})


def is_mismatch(path: str, detected: dict) -> bool:
    name = path.rsplit("/", 1)[-1]
    extension = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    expected = {e.lower() for e in detected.get("extensions", ())}
    # The last condition spares assets that are executable by nature: a real
    # .wasm is code, and magika lists "wasm" as an expected extension for it.
    return (
        detected.get("group") in EXECUTABLE_GROUPS
        and extension in ASSET_EXTENSIONS
        and extension not in expected
    )


def main() -> int:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            # Format drift, not a clean file.
            print(f"unparseable magika output: {line[:120]}", file=sys.stderr)
            return 2

        result = entry.get("result", {})
        if result.get("status") != "ok":
            # Unclassifiable, so this file leaves the check unexamined. Say so
            # rather than letting it drop out silently.
            print(
                f"magika could not classify {entry.get('path', '?')}: "
                f"{result.get('status', 'unknown')}",
                file=sys.stderr,
            )
            continue

        path = entry.get("path", "")
        detected = result.get("value", {}).get("output", {})
        if is_mismatch(path, detected):
            label = detected.get("label", "unknown")
            print(f"{path}\t{label}\t{path.rsplit('.', 1)[-1]}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
