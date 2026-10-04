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

# Nix runs in two processes: the client, which the job's steps call to work out what to build, and
# the daemon, which runs as root and runs the builds. Installing nix.conf doesn't make either use
# only it: other config files and environment variables override it, and Nix skips a setting it
# doesn't know with only a warning. So the script compares the settings each process ends up with
# against what nix.conf alone gives, and fails on any difference

# The settings both the client and the daemon are expected to have: what Nix prints with this
# folder's nix.conf as its system config file, no user config files and an otherwise empty
# environment. Its warnings are left out, so that a setting in nix.conf that Nix doesn't know
# shows up as a difference
EXPECTED_SETTINGS="$(env -i NIX_CONF_DIR="$SCRIPT_DIR" NIX_USER_CONF_FILES= "$NIX" config show)"

expect_nix_conf_settings() {
  local nix_process="$1" actual_settings="$2"
  diff -u --label nix.conf --label "$nix_process" \
    <(echo "$EXPECTED_SETTINGS") <(echo "$actual_settings") ||
    die "The settings of $nix_process differ from nix.conf"
}

# Checks of the Nix client, which runs as the runner's user in the job's environment

# Some of Nix's environment variables aren't settings, such as those that locate its store or the
# daemon's socket, so comparing settings would miss them. The job's environment must have none of
# Nix's variables, including the internal ones that start with an underscore
compgen -e | grep -E '^_?NIX_' && die "The Nix client's environment sets the Nix variables above"
expect_nix_conf_settings "the Nix client" "$("$NIX" config show 2>&1)"

# If the runner's user were trusted, any later Nix call could make the daemon use another cache
# and key, or build without the sandbox, just by passing its own settings for that call. So the
# client must build through the daemon as an untrusted user: the daemon then accepts only a few
# harmless settings from it, such as how many builds to run at once, and ignores the rest
STORE_INFO="$("$NIX" store info --json)"
jq --exit-status '.url == "daemon" and .trusted == false' <<< "$STORE_INFO" > /dev/null ||
  die "The Nix client must use the daemon as an untrusted user, but its store is $STORE_INFO"

# Checks of the Nix daemon, which runs as root with no options and an empty environment

# A running daemon can't be asked for its settings. The client, run as root with an empty
# environment like the daemon, reads the same config files, including root's own and any that
# only root can read, so it prints the settings the daemon uses
expect_nix_conf_settings "the Nix daemon" "$(sudo env -i "$NIX" config show 2>&1)"
