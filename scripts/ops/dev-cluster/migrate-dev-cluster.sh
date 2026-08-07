#!/usr/bin/env bash
#
# migrate-dev-cluster.sh — Step 1 of a dev-cluster upgrade: swap every
# mpc-node-* Nomad job to nearone/mpc-node-gcp:<VERSION> — plan, confirm, run.
# Verification is the caller's job (menu.sh runs it next).
#
# Usage: NOMAD_ADDR=http://<host> ./scripts/ops/dev-cluster/migrate-dev-cluster.sh <VERSION>
# Env:   NOMAD_ADDR (required); NOMAD_HTTP_AUTH="user:password" for the
#        endpoint's basic auth (prompted when unset, set it empty to skip);
#        NOMAD_TOKEN for an ACL token.
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../common.sh
source "${SCRIPT_DIR}/../common.sh"

# Echoes the request being made and, for mutations, the response the caller
# would otherwise swallow. Credentials are never part of what's printed.
nomad_curl() {
    local method=$1 path=$2 data=${3:-}
    local url="${NOMAD_ADDR%/}/v1${path}"
    local args=(-sf --max-time 30 -X "$method" "$url")
    [[ -z "${NOMAD_TOKEN:-}" ]] || args+=(-H "X-Nomad-Token: ${NOMAD_TOKEN}")
    [[ -z "$data" ]] || args+=(-H 'Content-Type: application/json' --data "$data")

    show_cmd curl -X "$method" "$url" ${data:+--data @-}

    local response
    if [[ -n "${NOMAD_HTTP_AUTH:-}" ]]; then
        # -K - keeps the credentials out of the process list.
        response=$(printf 'user = "%s"\n' "$NOMAD_HTTP_AUTH" | curl -K - "${args[@]}") || return 1
    else
        response=$(curl "${args[@]}") || return 1
    fi

    # GET bodies are job definitions the caller only parses; showing them buries
    # the interesting output, so only mutations are echoed.
    [[ "$method" == GET ]] || show_output "$response"
    printf '%s' "$response"
}

# Credentials are supplied per run rather than kept in the environment.
prompt_http_auth() {
    local user pass
    read -rp "Nomad user for ${NOMAD_ADDR} (blank for none): " user
    if [[ -z "$user" ]]; then
        NOMAD_HTTP_AUTH=""
        return
    fi
    read -rsp "Nomad password: " pass
    echo
    NOMAD_HTTP_AUTH="${user}:${pass}"
}

wait_for_alloc() {
    local job_id=$1 tries=36 job_version status
    job_version=$(nomad_curl GET "/job/${job_id}" | jq -r '.Version')
    printf '    waiting for allocation (job version %s) ' "$job_version"
    while (( tries-- > 0 )); do
        status=$(nomad_curl GET "/job/${job_id}/allocations" \
            | jq -r --argjson v "$job_version" \
              '[.[] | select(.JobVersion == $v)] | sort_by(.CreateIndex) | last | .ClientStatus // "pending"')
        if [[ "$status" == "running" ]]; then
            ok "running."
            return
        fi
        printf '.'
        sleep 5
    done
    echo
    warn "    WARNING: allocation not running after 3m (last status: ${status}) — check the Nomad UI."
}

upgrade_nomad_job() {
    local job_id=$1 image=$2
    local job current updated
    job=$(nomad_curl GET "/job/${job_id}") || die "Could not fetch job ${job_id}."
    current=$(jq -r '[.TaskGroups[].Tasks[].Config.image // empty
        | select(startswith("nearone/mpc-node-gcp:"))] | unique | join(", ")' <<<"$job")

    if [[ -z "$current" ]]; then
        step "==> ${job_id}: no nearone/mpc-node-gcp task found, skipping."
        return
    fi
    if [[ "$current" == "$image" ]]; then
        step "==> ${job_id}: already on ${image}, skipping."
        return
    fi
    step "==> ${job_id}: ${current} -> ${image}"

    updated=$(jq --arg img "$image" '(.TaskGroups[].Tasks[].Config
        | select(.image != null and (.image | startswith("nearone/mpc-node-gcp:")))).image = $img' <<<"$job")

    local plan failed warnings
    plan=$(nomad_curl POST "/job/${job_id}/plan" \
        "$(jq -n --argjson job "$updated" '{Job: $job, Diff: true}')") \
        || die "Plan failed for ${job_id}."
    failed=$(jq -r '.FailedTGAllocs // {} | keys | join(", ")' <<<"$plan")
    warnings=$(jq -r '.Warnings // empty' <<<"$plan")
    [[ -z "$failed" ]] || die "Plan reports failed allocations for: ${failed}"
    [[ -z "$warnings" ]] || warn "    plan warnings: ${warnings}"

    confirm "    Apply to ${job_id} on ${NOMAD_ADDR}?" || { echo "    skipped."; return; }
    nomad_curl POST "/job/${job_id}" "$(jq -n --argjson job "$updated" '{Job: $job}')" >/dev/null \
        || die "Job registration failed for ${job_id}."
    echo
    wait_for_alloc "$job_id"
}

[[ $# -eq 1 ]] || die "Usage: $0 <VERSION>  (e.g. 3.14.0)"
VERSION=$1
check_version "$VERSION"
require_cmds curl jq
[[ -n "${NOMAD_ADDR:-}" ]] || die "NOMAD_ADDR is not set (target dev cluster's Nomad endpoint)."
[[ -n "${NOMAD_HTTP_AUTH+set}" ]] || prompt_http_auth

IMAGE="nearone/mpc-node-gcp:${VERSION}"

# The tag must be a published release build, or the swapped jobs won't start.
if command -v skopeo >/dev/null 2>&1; then
    skopeo inspect --no-creds --format '{{.Digest}}' "docker://${IMAGE}" >/dev/null \
        || die "${IMAGE} not found on Docker Hub — is the release published?"
else
    warn "WARNING: skopeo not found, skipping existence check for ${IMAGE}."
fi

JOB_IDS=$(nomad_curl GET "/jobs?prefix=mpc-node" | jq -r '.[].ID') \
    || die "Could not list jobs from ${NOMAD_ADDR}."
[[ -n "$JOB_IDS" ]] || die "No mpc-node-* jobs found at ${NOMAD_ADDR}."

for job_id in $JOB_IDS; do
    upgrade_nomad_job "$job_id" "$IMAGE"
done
