#!/usr/bin/env bash
#
# migrate-dev-cluster.sh — Step 1 of a dev-cluster upgrade: swap every
# mpc-node-* Nomad job to nearone/mpc-node-gcp:<VERSION> — plan, confirm, run.
# Verification is the caller's job (menu.sh runs it next).
#
# Usage: ./scripts/ops/dev-cluster/migrate-dev-cluster.sh <VERSION>
# The Nomad IP address and its basic-auth credentials are prompted for. Exporting
# NOMAD_ADDR / NOMAD_HTTP_AUTH="user:password" skips the matching prompt;
# NOMAD_TOKEN adds an ACL token header.
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../common.sh
source "${SCRIPT_DIR}/../common.sh"
# shellcheck source=dev-common.sh
source "${SCRIPT_DIR}/dev-common.sh"

# Echoes the request being made and, for mutations, the response the caller
# would otherwise swallow. Credentials are never part of what's printed.
nomad_curl() {
    local method=$1 path=$2 data=${3:-}
    local url="${NOMAD_ADDR%/}/v1${path}"
    # --fail-with-body (curl >= 7.76) keeps Nomad's diagnostics on a non-2xx;
    # plain -f discards exactly the body the operator needs to see.
    local args=(-sS --fail-with-body --max-time 30 -X "$method" "$url")
    [[ -z "$data" ]] || args+=(-H 'Content-Type: application/json' --data "$data")

    show_cmd curl -X "$method" "$url" ${data:+--data @-}

    # Both the basic-auth pair and the ACL token go through the config stream:
    # anything in argv is readable from ps / /proc/<pid>/cmdline.
    local config=""
    [[ -z "${NOMAD_HTTP_AUTH:-}" ]] || config+="user = \"${NOMAD_HTTP_AUTH}\""$'\n'
    [[ -z "${NOMAD_TOKEN:-}" ]] || config+="header = \"X-Nomad-Token: ${NOMAD_TOKEN}\""$'\n'

    local response status=0
    if [[ -n "$config" ]]; then
        response=$(printf '%s' "$config" | curl -K - "${args[@]}") || status=$?
    else
        response=$(curl "${args[@]}") || status=$?
    fi
    if (( status != 0 )); then
        [[ -z "$response" ]] || show_output "$response"
        return "$status"
    fi

    # GET bodies are job definitions the caller only parses; showing them buries
    # the interesting output, so only mutations are echoed.
    [[ "$method" == GET ]] || show_output "$response"
    printf '%s' "$response"
}

wait_for_alloc() {
    local job_id=$1 tries=36 job_version status
    job_version=$(nomad_curl GET "/job/${job_id}" | jq -r '.Version') \
        || die "Could not read the new job version for ${job_id}."
    printf '    waiting for allocation (job version %s) ' "$job_version"
    while (( tries-- > 0 )); do
        # A blip here must not abandon the jobs still queued behind this one.
        status=$(nomad_curl GET "/job/${job_id}/allocations" \
            | jq -r --argjson v "$job_version" \
              '[.[] | select(.JobVersion == $v)] | sort_by(.CreateIndex) | last | .ClientStatus // "pending"') \
            || status="unreachable"
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

# One job's worth of the runbook's Definition -> Edit -> Plan -> Run, over the
# API instead of the UI. The registration at the end is the only write; Nomad
# reconciles the new definition by restarting the task on the new image.
upgrade_nomad_job() {
    local job_id=$1 image=$2
    local job current updated
    job=$(nomad_curl GET "/job/${job_id}") || die "Could not fetch job ${job_id}."
    current=$(jq -r '[.TaskGroups[].Tasks[].Config.image // empty
        | select(startswith("nearone/mpc-node-gcp:"))] | unique | join(", ")' <<<"$job")

    # The prefix query can match jobs that merely start with "mpc-node".
    if [[ -z "$current" ]]; then
        step "==> ${job_id}: no nearone/mpc-node-gcp task found, skipping."
        return
    fi
    # Keeps a re-run after a partially applied rollout a no-op.
    if [[ "$current" == "$image" ]]; then
        step "==> ${job_id}: already on ${image}, skipping."
        return
    fi
    step "==> ${job_id}: ${current} -> ${image}"

    # `select` confines the rewrite to the MPC task: sidecars in the same group
    # keep their own images, and every other field is copied through untouched.
    updated=$(jq --arg img "$image" '(.TaskGroups[].Tasks[].Config
        | select(.image != null and (.image | startswith("nearone/mpc-node-gcp:")))).image = $img' <<<"$job")

    # Dry run first, as the UI's Plan does. A non-empty FailedTGAllocs means
    # Nomad could not place the new allocation, so registering would take the
    # node down with nothing to replace it.
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
    # Confirm this node is back before the caller moves to the next one.
    wait_for_alloc "$job_id"
}

[[ $# -eq 1 ]] || die "Usage: $0 <VERSION>  (e.g. 3.14.0)"
VERSION=$1
check_version "$VERSION"
require_cmds curl jq
prompt_nomad_ip
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
