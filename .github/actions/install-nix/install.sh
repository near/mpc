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

curl -fsSL -o "$TMP_DIR/$RELEASE.tar.xz" "https://releases.nixos.org/nix/nix-$NIX_VERSION/$RELEASE.tar.xz"
echo "$NIX_TARBALL_SHA256  $TMP_DIR/$RELEASE.tar.xz" | sha256sum -c
tar -xJf "$TMP_DIR/$RELEASE.tar.xz" -C "$TMP_DIR"
"$TMP_DIR/$RELEASE/install" --daemon --yes --no-channel-add --nix-extra-conf-file "$SCRIPT_DIR/nix.conf"

# Some of Nix's environment variables aren't settings, such as those pointing it at another daemon
# or store, so the runner must not set any
if env | grep -E '^(NIX_|_NIX_)'; then
  fail "The runner's environment sets the Nix variables above"
fi

# Nix reads settings from several config files and environment variables, and ignores a setting it
# doesn't know with only a warning. So compare all the settings it applies, and its warnings, with
# those it applies when this folder's nix.conf is its only config
WITH_ONLY_NIX_CONF=(env -i NIX_CONF_DIR="$SCRIPT_DIR" NIX_USER_CONF_FILES=)
diff -u --label "nix.conf alone" --label "the runner's settings" \
  <("${WITH_ONLY_NIX_CONF[@]}" "$NIX" config show) <("$NIX" config show 2>&1) ||
  fail "The runner's Nix settings differ from nix.conf"

# The runner's Nix passes its settings on to the daemon, which ignores all but a few harmless ones
# unless it trusts the runner
STORE_INFO="$("$NIX" store info --json)"
[[ "$STORE_INFO" == "{\"trusted\":false,\"url\":\"daemon\",\"version\":\"$NIX_VERSION\"}" ]] ||
  fail "Expected an untrusted connection to the Nix $NIX_VERSION daemon, got $STORE_INFO"

# The daemon runs the builds as root. Options on its command line, or variables in its environment,
# would change its settings or where it reads them from
DAEMON_PID="$(systemctl show --property MainPID --value nix-daemon.service)"
DAEMON_ARGS="$(ps -o args= -p "$DAEMON_PID")"
[[ "$DAEMON_ARGS" == "nix-daemon --daemon" ]] ||
  fail "The daemon's command line is '$DAEMON_ARGS', not 'nix-daemon --daemon'"
DAEMON_ENV="$(sudo cat "/proc/$DAEMON_PID/environ" | tr '\0' '\n')"
if grep -E '^(NIX_|_NIX_|XDG_|HOME=)' <<< "$DAEMON_ENV"; then
  fail "The daemon's environment sets the variables above"
fi

# Without those, the daemon applies the settings root gets with an empty environment. Some defaults
# differ for root, so nix.conf alone is read as root too
diff -u --label "nix.conf alone" --label "the daemon's settings" \
  <(sudo "${WITH_ONLY_NIX_CONF[@]}" "$NIX" config show) <(sudo env -i "$NIX" config show 2>&1) ||
  fail "The daemon's Nix settings differ from nix.conf"
