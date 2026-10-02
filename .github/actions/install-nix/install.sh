#!/usr/bin/env bash
set -euo pipefail

# Installs a hash-pinned Nix release and fails unless it applies exactly the settings in nix.conf

NIX_VERSION=2.35.2
# The SHA-256 published with the release, which the release's online installer also checks
NIX_TARBALL_SHA256=0c3960a9792331a22081c3c7a5d8465db9b17c50b3acdf18587fa4c6f2cb1158

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RELEASE="nix-$NIX_VERSION-x86_64-linux"
NIX=/nix/var/nix/profiles/default/bin/nix
NIX_DAEMON=/nix/var/nix/profiles/default/bin/nix-daemon
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

die() {
  printf '::error::%s\n' "$*"
  exit 1
}

# A store, config folder or Nix cache left by an earlier install, or restored from a cache, could
# hold packages, files or cached results that the checks below never see, so the script only
# installs onto a runner without any of them
for path in /nix /etc/nix "${XDG_CACHE_HOME:-$HOME/.cache}/nix"; do
  [[ ! -e "$path" ]] || die "$path already exists on this runner"
done

curl -fsSL --retry 3 -o "$TMP_DIR/$RELEASE.tar.xz" \
  "https://releases.nixos.org/nix/nix-$NIX_VERSION/$RELEASE.tar.xz"
sha256sum --check --quiet <<< "$NIX_TARBALL_SHA256  $TMP_DIR/$RELEASE.tar.xz" ||
  die "The Nix tarball doesn't match its pinned hash"
tar -xf "$TMP_DIR/$RELEASE.tar.xz" -C "$TMP_DIR"

# The installer writes this folder's nix.conf into Nix's system config, which every Nix process
# reads, and starts the daemon that builds for the runner. A channel would be an unpinned source of
# packages, so none is added
"$TMP_DIR/$RELEASE/install" --daemon --yes --no-channel-add \
  --nix-extra-conf-file "$SCRIPT_DIR/nix.conf"

# The installer's systemd service can get options or environment variables from the runner's
# systemd configuration, so the script replaces it with a service that runs the daemon with no
# options and an empty environment, and fails if a drop-in in that configuration applies to the
# new service too
sudo systemctl stop nix-daemon.socket nix-daemon.service
sudo systemd-run --unit nix-daemon-clean --quiet env -i "$NIX_DAEMON"
DROP_INS="$(systemctl show --property DropInPaths --value nix-daemon-clean.service)"
[[ -z "$DROP_INS" ]] ||
  die "Drop-ins in the runner's systemd configuration change the daemon's service: $DROP_INS"
SECONDS=0
until "$NIX" store info &> /dev/null; do
  (( SECONDS < 30 )) || die "The daemon didn't start"
  sleep 0.1
done

# Installing nix.conf doesn't guarantee that the builds use it: user config files and environment
# variables override it, and Nix ignores a setting it doesn't know with only a warning. So the
# checks below ask Nix to print the settings it uses, warnings included, and expect exactly what it
# prints when this folder's nix.conf is its only config. Any difference is a setting that came from
# somewhere else, or a line of nix.conf that Nix didn't understand. Two Nix processes take part in
# a build and are checked in turn: the runner's Nix, which evaluates what to build, and the daemon,
# which runs as root and builds it

# Without Nix's stderr, so that such a warning becomes a difference instead of appearing on both
# sides
EXPECTED_SETTINGS="$TMP_DIR/expected-settings"
env -i NIX_CONF_DIR="$SCRIPT_DIR" NIX_USER_CONF_FILES= "$NIX" config show > "$EXPECTED_SETTINGS"

# Some of Nix's environment variables aren't settings, such as those locating its store or daemon
# socket, so the runner must have none of Nix's variables, internal ones included
compgen -e | grep -E '^_?NIX_' &&
  die "The runner's environment sets the Nix variables above"
diff -u --label nix.conf --label "the runner's Nix" \
  "$EXPECTED_SETTINGS" <("$NIX" config show 2>&1) ||
  die "The runner's Nix settings differ from nix.conf"

# The runner's Nix must build through the daemon as an untrusted user: the daemon then ignores most
# of the settings it sends, so the options and environment of later Nix commands can't loosen the
# settings the daemon builds with
STORE_INFO="$("$NIX" store info --json)"
jq --exit-status '.url == "daemon" and .trusted == false' <<< "$STORE_INFO" > /dev/null ||
  die "The runner must use the daemon as an untrusted user, but its store is $STORE_INFO"

# The daemon can't be asked for its settings, but it runs as root with no options and an empty
# environment, so running Nix the same way prints them
diff -u --label nix.conf --label "the daemon" \
  "$EXPECTED_SETTINGS" <(sudo env -i "$NIX" config show 2>&1) ||
  die "The daemon's settings differ from nix.conf"
