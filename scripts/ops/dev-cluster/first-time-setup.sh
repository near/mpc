#!/usr/bin/env bash
#
# first-time-setup.sh — copy member signing keys from the Nomad job definitions
# into the local near-cli keystore (source, don't run). The node already signs
# with these keys, so only the operator's local copy can be missing.
#

# "account sk" per task carrying an MPC_ACCOUNT_SK, from a job definition on
# stdin. Keyed on the secret itself, not the image, so it survives job-spec
# changes; tasks that inject it via a template stanza have no Env and drop out.
job_signing_creds() {
    jq -r '.TaskGroups[]?.Tasks[]?
         | (.Env // .Config.env // {}) as $env
         | select(($env.MPC_ACCOUNT_SK // "") != "")
         | "\($env.MPC_ACCOUNT_ID // "") \($env.MPC_ACCOUNT_SK)"'
}

# Task names and their env var *names* (never values), to show where the key
# lives when the selector above comes up empty.
job_env_summary() {
    jq -r '.TaskGroups[]?.Tasks[]?
         | "    \(.Name // "?") [\(.Driver // "?")]: \(
             (.Env // .Config.env // {}) | keys | join(",") // "no env")"'
}

# near-cli's import can't be scripted, so write its two keystore files directly.
# An ed25519 secret key embeds its public half (last 32B) — no crypto needed.
import_signing_key() {
    local account=$1 sk=$2
    step "==> storing key for ${account}"
    MPC_IMPORT_SK="$sk" MPC_IMPORT_ACCOUNT="$account" \
    MPC_IMPORT_DIR="${HOME}/.near-credentials/${NEAR_NET}" \
        python3 - <<'PY' || { warn "Could not store key for ${account}."; return; }
import json, os, sys

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def b58decode(s):
    n = 0
    for c in s:
        n = n * 58 + _B58.index(c)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return b"\x00" * (len(s) - len(s.lstrip("1"))) + body

def b58encode(b):
    n = int.from_bytes(b, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    return "1" * (len(b) - len(b.lstrip(b"\x00"))) + out

sk = os.environ["MPC_IMPORT_SK"]
account = os.environ["MPC_IMPORT_ACCOUNT"]
base = os.environ["MPC_IMPORT_DIR"]

prefix, _, body = sk.partition(":")
raw = b58decode(body)
if len(raw) != 64:
    sys.stderr.write("unexpected ed25519 key length: %d bytes\n" % len(raw))
    sys.exit(1)
pub_b58 = b58encode(raw[32:])
record = {"public_key": "%s:%s" % (prefix, pub_b58), "private_key": sk}

def write(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(record, f)

write(os.path.join(base, "%s.json" % account))
write(os.path.join(base, account, "%s_%s.json" % (prefix, pub_b58)))
PY
    ok "${account}: key stored in ~/.near-credentials/${NEAR_NET}."
}

# Imports any missing member-account keys found in a job's definition.
ensure_job_keys() {
    local job_id=$1 job creds account sk found=0
    job=$(nomad_curl GET "/job/${job_id}") || { warn "Could not fetch ${job_id}."; return; }
    # Capture rather than pipe into the loop: a jq failure there is invisible.
    creds=$(job_signing_creds <<<"$job") \
        || { warn "${job_id}: could not read task env (unexpected job JSON)."; return; }

    while read -r account sk; do
        [[ -n "$sk" ]] || continue
        found=1
        if [[ -z "$account" ]]; then
            warn "${job_id}: a task has MPC_ACCOUNT_SK but no MPC_ACCOUNT_ID — skipping."
        elif have_signing_key "$account"; then
            ok "${account}: key already in ~/.near-credentials."
        else
            import_signing_key "$account" "$sk"
        fi
    done <<<"$creds"

    if (( ! found )); then
        warn "${job_id}: no MPC_ACCOUNT_SK in the job definition. Tasks (env var names only):"
        job_env_summary <<<"$job" >&2 || true
    fi
}
