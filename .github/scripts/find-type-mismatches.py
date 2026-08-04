#!/usr/bin/env python3
"""Report files whose content is executable but whose extension claims an asset.

Reads magika JSONL on stdin, writes a SARIF 2.1.0 run on stdout for upload to
GitHub code scanning. Always writes a run, empty when there is nothing to
report, so an upload clears alerts that a previous commit raised.

Used by scan-changed-files.sh; see .github/security-scan/README.md.
"""

import json
import sys

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

RULE = {
    "id": RULE_ID,
    "name": "ContentExtensionMismatch",
    "shortDescription": {"text": "Executable content under a binary-asset extension"},
    "fullDescription": {
        "text": (
            "The content is code or an executable while the extension declares "
            "an inert binary asset. Scanners that pick files by extension never "
            "open such a file, which is what makes it a convenient hiding place."
        )
    },
    "defaultConfiguration": {"level": "error"},
    "help": {
        "text": (
            "Confirm what the file really is. If it is a genuine asset, magika "
            "would report a matching type, so a mismatch means either the file "
            "is misnamed or its content is not what the name claims."
        )
    },
}


def extension_of(path: str) -> str:
    name = path.rsplit("/", 1)[-1]
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


def is_mismatch(path: str, detected: dict) -> bool:
    expected = {e.lower() for e in detected.get("extensions", ())}
    # The last condition spares assets that are executable by nature: a real
    # .wasm is code, and magika lists "wasm" as an expected extension for it.
    return (
        detected.get("group") in EXECUTABLE_GROUPS
        and extension_of(path) in ASSET_EXTENSIONS
        and extension_of(path) not in expected
    )


def make_result(path: str, detected: dict) -> dict:
    return {
        "ruleId": RULE_ID,
        "ruleIndex": 0,
        "level": "error",
        "message": {
            "text": (
                f"Content is {detected.get('label', 'unknown')}, but the "
                f".{extension_of(path)} extension declares a binary asset."
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
    results = []

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
            results.append(make_result(path, detected))

    json.dump(build_sarif(results), sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
