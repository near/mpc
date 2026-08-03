#!/usr/bin/env bash
#
# Downloads the scanners the security scan needs, verifying each checksum before
# use, and prints the directory they landed in.
#
#   eval "$(.github/scripts/fetch-scanners.sh <destination-directory>)"
#
# CI only, and x86_64 Linux only. Locally the same versions come from the nix dev
# shell (nix/yara-x.nix, nix/magika.nix) - keep the versions here in step with
# those files.
#
# This replaces apt + pipx, which cost ~16s of a 26s job: apt-get update 5.4s,
# apt-get install yara 2.9s, pipx install magika 7.4s.

set -euo pipefail

# Release assets are maintainer-mutable - a tag can be deleted and re-uploaded -
# so the digest is what protects this job, not the tag. Never use a floating tag
# such as magika's `cli-latest`.
readonly YARA_X_VERSION="1.19.0"
readonly YARA_X_SHA256="a97d78189e3548797ac45b7b4a5fd8975783861875c594f772ec9b8bb5fa4d72"

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

fetch() {
    local url="$1" out="$2" sha="$3"
    curl --fail --silent --show-error --location --output "$out" "$url"
    printf '%s  %s\n' "$sha" "$out" | sha256sum -c - >/dev/null
}

mkdir -p "$dest"

fetch "https://github.com/VirusTotal/yara-x/releases/download/v${YARA_X_VERSION}/yara-x-v${YARA_X_VERSION}-x86_64-unknown-linux-gnu.tar.gz" \
    "$tmp/yara-x.tar.gz" "$YARA_X_SHA256"
# Holds a bare `yr`.
tar xzf "$tmp/yara-x.tar.gz" -C "$dest" yr

fetch "https://github.com/google/magika/releases/download/cli/v${MAGIKA_VERSION}/magika-cli-x86_64-unknown-linux-gnu.tar.xz" \
    "$tmp/magika.tar.xz" "$MAGIKA_SHA256"
# Nests the binary one directory deep, unlike the yara-x archive.
tar xJf "$tmp/magika.tar.xz" -C "$dest" --strip-components=1

"$dest/yr" --version | grep -q "$YARA_X_VERSION" \
    || { echo "yr is not version $YARA_X_VERSION" >&2; exit 1; }
"$dest/magika" --version | grep -q "$MAGIKA_VERSION" \
    || { echo "magika is not version $MAGIKA_VERSION" >&2; exit 1; }

echo "Fetched yara-x $YARA_X_VERSION and magika $MAGIKA_VERSION into $dest" >&2
