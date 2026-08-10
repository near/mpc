#!/usr/bin/env bash
#
# first-time-setup.sh — first-run helpers that copy the member accounts'
# signing keys from the Nomad job definitions into the local near-cli
# keystore (source, don't run). The node signs with MPC_ACCOUNT_SK already,
# so the key is on-chain — only the operator's local copy can be missing.
#

# "account sk" per MPC task, from a job definition on stdin. Secrets injected
# via a template stanza instead of Env come out empty and are skipped upstream.
job_signing_creds() {
    jq -r --arg prefix "$NODE_IMAGE_PREFIX" \
        '.TaskGroups[].Tasks[]
         | select(.Config.image // "" | startswith($prefix))
         | "\(.Env.MPC_ACCOUNT_ID // "") \(.Env.MPC_ACCOUNT_SK // "")"'
}

# near-cli offers no stdin path for the key, so it rides argv (visible in
# /proc for its lifetime) — but it is masked in the echoed command.
import_signing_key() {
    local account=$1 sk=$2
    show_cmd near account import-account using-private-key '<MPC_ACCOUNT_SK>' \
        network-config "$NEAR_NET"
    near account import-account using-private-key "$sk" network-config "$NEAR_NET" \
        || warn "Import did not complete — signing as ${account} may fail."
}

# Imports any missing member-account keys found in a job's definition.
ensure_job_keys() {
    local job_id=$1 job account sk
    job=$(nomad_curl GET "/job/${job_id}") || { warn "Could not fetch ${job_id}."; return; }
    while read -r account sk; do
        [[ -n "$account" && -n "$sk" ]] || continue
        if have_signing_key "$account"; then
            ok "${account}: key already in ~/.near-credentials."
        else
            import_signing_key "$account" "$sk"
        fi
    done < <(job_signing_creds <<<"$job")
}
