#!/usr/bin/env bash
#
# Fetches the GuardDog YARA rule pack from a pinned release, verifying its
# checksum before extracting anything.
#
#   .github/scripts/fetch-yara-rules.sh <destination-directory>
#
# The rules ship inside the wheel, so none of GuardDog's dependencies are
# installed and Python is not needed to evaluate them.

set -euo pipefail

# Bump all three together, then re-measure the allowlist per .github/yara/README.md.
# From https://pypi.org/pypi/guarddog/<version>/json - PyPI URLs embed a content
# hash, so they are stable per file.
readonly VERSION="3.1.0"
readonly WHEEL_URL="https://files.pythonhosted.org/packages/ca/34/989428df4a2221dc6873944b23efa1e91bf10d49f4a1fcca9b1ceb6ecf12/guarddog-3.1.0-py3-none-any.whl"
readonly WHEEL_SHA256="80572d0dfccb9028a78c0a61e66d54b95ea71b335b105b54c97955786fc00846"

# Well under 3.1.0's 54 means the wheel layout changed and the globs missed.
readonly MIN_RULES=40

dest="${1:?usage: fetch-yara-rules.sh <destination-directory>}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

curl --fail --silent --show-error --location --output "$tmp/wheel.zip" "$WHEEL_URL"
printf '%s  %s\n' "$WHEEL_SHA256" "$tmp/wheel.zip" | shasum -a 256 -c - >/dev/null

mkdir -p "$dest"
# -j flattens paths: three rules `include` the .meta files by bare name, so those
# must land beside the .yar files.
unzip -q -o -j "$tmp/wheel.zip" \
    'guarddog/analyzer/sourcecode/*.yar' \
    'guarddog/analyzer/sourcecode/*.meta' \
    -d "$dest"

rule_count="$(find "$dest" -name '*.yar' | wc -l | tr -d ' ')"
if (( rule_count < MIN_RULES )); then
    echo "Extracted only $rule_count rules, expected at least $MIN_RULES." >&2
    exit 1
fi

echo "Fetched $rule_count YARA rules from guarddog $VERSION into $dest" >&2
