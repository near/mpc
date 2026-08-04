#!/usr/bin/env bash
#
# Downloads the scanner the security scan needs, verifying its checksum before
# use.
#
#   .github/scripts/fetch-scanners.sh <destination-directory>
#
# CI only, and x86_64 Linux only. Locally the same version comes from the nix dev
# shell (nix/magika.nix) - keep the version here in step with that file.
#
# Downloading rather than installing from a package manager: apt + pipx cost ~16s
# of a 26s job, against roughly 1s for one checksummed download.

set -euo pipefail

# Release assets are maintainer-mutable - a tag can be deleted and re-uploaded -
# so the digest is what protects this job, not the tag. Never use a floating tag
# such as magika's `cli-latest`.
#
# magika versions its CLI separately from its Python package, and the CLI number
# is what `magika --version` reports.
readonly MAGIKA_VERSION="1.1.0"
readonly MAGIKA_SHA256="6b4c1010c84d1f4f06205ccef4597f1690bcd7744f46d841eee26426bc100485"

dest="${1:?usage: fetch-scanners.sh <destination-directory>}"

if [[ "$(uname -s)-$(uname -m)" != "Linux-x86_64" ]]; then
    echo "This script only handles Linux x86_64 (CI). Use 'nix develop' locally." >&2
    exit 2
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

mkdir -p "$dest"

curl --fail --silent --show-error --location --output "$tmp/magika.tar.xz" \
    "https://github.com/google/magika/releases/download/cli/v${MAGIKA_VERSION}/magika-cli-x86_64-unknown-linux-gnu.tar.xz"
printf '%s  %s\n' "$MAGIKA_SHA256" "$tmp/magika.tar.xz" | sha256sum -c - >/dev/null

# The archive nests the binary one directory deep.
tar xJf "$tmp/magika.tar.xz" -C "$dest" --strip-components=1

"$dest/magika" --version | grep -q "$MAGIKA_VERSION" \
    || { echo "magika is not version $MAGIKA_VERSION" >&2; exit 1; }

echo "Fetched magika $MAGIKA_VERSION into $dest" >&2
