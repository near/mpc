#!/usr/bin/env bash
set -euo pipefail

# Installs Nix from its official release tarball, checked against a pinned hash, and fails unless
# Nix applies exactly the settings in nix.conf, which the image builds rely on

NIX_VERSION=2.35.2
NIX_TARBALL_SHA256=0c3960a9792331a22081c3c7a5d8465db9b17c50b3acdf18587fa4c6f2cb1158

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RELEASE="nix-$NIX_VERSION-x86_64-linux"
TMP_DIR="$(mktemp -d)"
NIX=/nix/var/nix/profiles/default/bin/nix

fail() {
  echo "::error::$*"
  exit 1
}

curl -fsSL --retry 3 -o "$TMP_DIR/$RELEASE.tar.xz" "https://releases.nixos.org/nix/nix-$NIX_VERSION/$RELEASE.tar.xz"
sha256sum -c <<< "$NIX_TARBALL_SHA256  $TMP_DIR/$RELEASE.tar.xz"
tar -xf "$TMP_DIR/$RELEASE.tar.xz" -C "$TMP_DIR"

# The installer copies this folder's nix.conf to Nix's config folder, which every Nix process reads,
# and starts the daemon that builds for the runner. It adds no channel, an unpinned source of packages
"$TMP_DIR/$RELEASE/install" --daemon --yes --no-channel-add --nix-extra-conf-file "$SCRIPT_DIR/nix.conf"

# Installing nix.conf doesn't guarantee that the builds use it: Nix also reads user config files,
# environment variables and command-line options, which override it, and it ignores a setting it
# doesn't know with only a warning. So the checks below ask Nix to print the settings it uses,
# warnings included, and expect exactly what it prints when this folder's nix.conf is its only
# config: nix.conf plus Nix's own defaults for everything else. Any difference is a setting that
# came from somewhere else, or a line of nix.conf that Nix didn't understand. Two Nix processes
# take part in a build and are checked in turn: the runner's, which evaluates what to build, and
# the daemon, which builds it as root

# The settings Nix prints with this folder's nix.conf as its only config: no user config files, no
# environment. Its stderr is left out on purpose: a warning about a line of nix.conf that Nix didn't
# understand must show up as a difference below, not on both sides
EXPECTED_SETTINGS="$TMP_DIR/expected-settings"
env -i NIX_CONF_DIR="$SCRIPT_DIR" NIX_USER_CONF_FILES= "$NIX" config show > "$EXPECTED_SETTINGS"

# Besides settings, Nix reads variables that locate its daemon, store and config files, which no
# comparison of settings can see, so the runner must have none of Nix's variables, internal ones included
env | grep -E '^(NIX_|_NIX_)' && fail "The runner's environment sets the Nix variables above"
diff -u --label nix.conf --label "the runner's Nix" "$EXPECTED_SETTINGS" <("$NIX" config show 2>&1) ||
  fail "The runner's Nix uses other settings than nix.conf"

# The runner's Nix must build through the daemon, to which it sends its settings. The daemon applies
# them only from a trusted user, so the runner must not be one
STORE_INFO="$("$NIX" store info --json)"
jq --exit-status '.url == "daemon" and .trusted == false' <<< "$STORE_INFO" > /dev/null ||
  fail "The runner must use the daemon as an untrusted user, but its store is $STORE_INFO"

# The daemon can't be asked for its settings, so Nix is run as root with an empty environment
# instead. That matches the daemon only if it was started just as plainly: no options on its
# command line, and no variables in its environment that Nix reads or that locate root's config files
DAEMON_PID="$(systemctl show --property MainPID --value nix-daemon.service)"
DAEMON_COMMAND_LINE="$(ps -o args= -p "$DAEMON_PID")"
[[ "$DAEMON_COMMAND_LINE" == 'nix-daemon --daemon' ]] ||
  fail "The daemon was started as '$DAEMON_COMMAND_LINE' instead of 'nix-daemon --daemon'"
DAEMON_ENVIRONMENT="$(sudo cat "/proc/$DAEMON_PID/environ" | tr '\0' '\n')"
grep -E '^(NIX_|_NIX_|XDG_|HOME=)' <<< "$DAEMON_ENVIRONMENT" &&
  fail "The daemon's environment sets the variables above"
diff -u --label nix.conf --label "the daemon" "$EXPECTED_SETTINGS" <(sudo env -i "$NIX" config show 2>&1) ||
  fail "The daemon uses other settings than nix.conf"
