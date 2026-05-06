#!/usr/bin/env bash
# Stage the nearone-testnet CVM deploy config into a working directory on Bob
# and inject the two secrets.
#
# Run on Bob (not Alice) — Alice never sees the secrets.
#
# Usage:
#   # Provide the OLD node's backup_encryption_key via one of:
#   OLD_NODE_BACKUP_KEY=<64-hex> ./stage.sh
#   BACKUP_KEY_FILE=/tmp/old-backup-key ./stage.sh
#
# Environment overrides (optional):
#   DST_DIR   — target working dir (default: /mnt/data/mpc/deployments/nearone-testnet)
#
# The script:
#   1. Copies user-config.toml, launcher_docker_compose.yaml, default.env,
#      and deploy-launcher.sh into $DST_DIR (owned by the mpc user).
#   2. Verifies the launcher compose hash matches the contract allow-list.
#   3. Generates a fresh secret_store_key_hex (16 bytes) and injects it.
#   4. Injects the OLD node's backup_encryption_key_hex.
#   5. Confirms both placeholders are gone.
#   6. Prints the exact deploy-launcher.sh command to run next.

set -euo pipefail

SRC_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DST_DIR="${DST_DIR:-/mnt/data/mpc/deployments/nearone-testnet}"
EXPECTED_COMPOSE_HASH="efb095f3e9adfeb04d637813a838fa666778b9915d752cfd796ae2a254fe705f"

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# --- 1. Copy files
echo ">> Staging from $SRC_DIR -> $DST_DIR"
sudo -u mpc mkdir -p "$DST_DIR"
sudo -u mpc cp -f "$SRC_DIR/user-config.toml"              "$DST_DIR/"
sudo -u mpc cp -f "$SRC_DIR/launcher_docker_compose.yaml"  "$DST_DIR/"
sudo -u mpc cp -f "$SRC_DIR/default.env"                   "$DST_DIR/"
sudo -u mpc cp -f "$SRC_DIR/../../deploy-launcher.sh"      "$DST_DIR/"
sudo -u mpc chmod +x "$DST_DIR/deploy-launcher.sh"

# --- 2. Verify compose hash
echo ">> Verifying compose hash"
ACTUAL_HASH=$(sha256sum "$DST_DIR/launcher_docker_compose.yaml" | awk '{print $1}')
[ "$ACTUAL_HASH" = "$EXPECTED_COMPOSE_HASH" ] \
  || die "compose hash $ACTUAL_HASH != expected $EXPECTED_COMPOSE_HASH"
echo "   $ACTUAL_HASH (OK)"

# --- 3. Inject secret_store_key_hex
echo ">> Injecting secret_store_key_hex (fresh)"
SECRET_STORE_KEY=$(openssl rand -hex 16)
[ "$(printf %s "$SECRET_STORE_KEY" | wc -c)" -eq 32 ] \
  || die "secret_store_key_hex is not 32 hex chars"
sudo -u mpc sed -i "s/<<GENERATE_ON_BOB>>/$SECRET_STORE_KEY/" "$DST_DIR/user-config.toml"
unset SECRET_STORE_KEY

# --- 4. Inject backup_encryption_key_hex from the OLD node
echo ">> Injecting backup_encryption_key_hex (OLD node)"
if [ -z "${OLD_NODE_BACKUP_KEY:-}" ]; then
  if [ -n "${BACKUP_KEY_FILE:-}" ] && [ -r "$BACKUP_KEY_FILE" ]; then
    OLD_NODE_BACKUP_KEY=$(tr -d '\n\r' < "$BACKUP_KEY_FILE")
  else
    die "set OLD_NODE_BACKUP_KEY in env, or BACKUP_KEY_FILE pointing at a file containing the key"
  fi
fi
[ "$(printf %s "$OLD_NODE_BACKUP_KEY" | wc -c)" -eq 64 ] \
  || die "backup_encryption_key_hex must be 64 hex chars"
# Use a different sed delimiter? Both are hex strings so "/" is safe.
sudo -u mpc sed -i "s/<<OLD_NODE_BACKUP_KEY>>/$OLD_NODE_BACKUP_KEY/" "$DST_DIR/user-config.toml"
unset OLD_NODE_BACKUP_KEY

# --- 5. Sanity — no placeholders left
echo ">> Verifying no placeholders remain"
LEFT=$(grep -cE '<<GENERATE_ON_BOB>>|<<OLD_NODE_BACKUP_KEY>>' "$DST_DIR/user-config.toml" || true)
[ "$LEFT" = "0" ] || die "$LEFT placeholder(s) still present in user-config.toml"
echo "   OK"

# --- 6. Next step
cat <<EOF

Staged. Deploy with:

  cd $DST_DIR
  sudo -u mpc ./deploy-launcher.sh \\
    --env-file ./default.env \\
    --base-path /mnt/data/mpc/dstack \\
    --python-exec python3
EOF
