#!/usr/bin/env bash
#
# migrate-dev-nodes.sh — Step 1 of a dev-cluster upgrade: swap every
# mpc-node-* Nomad job to nearone/mpc-node-gcp:<VERSION> — plan, confirm, run.
# Verification is the caller's job (dev-menu.sh runs it next).
#
# Usage: ./scripts/ops/dev-cluster/migrate-dev-nodes.sh <VERSION>
# The Nomad IP address and its basic-auth credentials are prompted for. Exporting
# NOMAD_ADDR / NOMAD_HTTP_AUTH="user:password" skips the matching prompt;
# NOMAD_TOKEN adds an ACL token header; NOMAD_NAMESPACE targets that namespace.
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../common.sh
source "${SCRIPT_DIR}/../common.sh"
# shellcheck source=dev-common.sh
source "${SCRIPT_DIR}/dev-common.sh"

# curl -K parses values as quoted strings with backslash escapes.
curl_cfg_escape() {
    local s=${1//\\/\\\\}
    printf '%s' "${s//\"/\\\"}"
}

# Echoes the request, and the response for mutations. Never the credentials.
nomad_curl() {
    local method=$1 path=$2 data=${3:-}
    local url="${NOMAD_ADDR%/}/v1${path}"
    # The API ignores the NOMAD_NAMESPACE env var (a nomad-CLI feature).
    if [[ -n "${NOMAD_NAMESPACE:-}" ]]; then
        local sep="?"; [[ "$url" != *\?* ]] || sep="&"
        url+="${sep}namespace=${NOMAD_NAMESPACE}"
    fi
    # --fail-with-body (curl >= 7.76): plain -f discards Nomad's error body.
    local args=(-sS --fail-with-body --max-time 30 -X "$method" "$url")
    [[ -z "$data" ]] || args+=(-H 'Content-Type: application/json' --data-binary @-)

    show_cmd curl -X "$method" "$url" ${data:+--data-binary @-}

    # Secrets not on argv: credentials via config stream, body via stdin.
    local config=""
    [[ -z "${NOMAD_HTTP_AUTH:-}" ]] || config+="user = \"$(curl_cfg_escape "$NOMAD_HTTP_AUTH")\""$'\n'
    [[ -z "${NOMAD_TOKEN:-}" ]] || config+="header = \"X-Nomad-Token: $(curl_cfg_escape "$NOMAD_TOKEN")\""$'\n'

    local response status=0
    response=$(printf '%s' "$data" | curl -K <(printf '%s' "$config") "${args[@]}") || status=$?
    if (( status != 0 )); then
        [[ -z "$response" ]] || show_output "$response"
        return "$status"
    fi

    # GET bodies are whole job definitions — too noisy to echo.
    [[ "$method" == GET ]] || show_output "$response"
    printf '%s' "$response"
}

wait_for_alloc() {
    local job_id=$1 tries=36 job_version status
    job_version=$(nomad_curl GET "/job/${job_id}" | jq -r '.Version') \
        || die "Could not read the new job version for ${job_id}."
    printf '    waiting for allocation (job version %s) ' "$job_version"
    while (( tries-- > 0 )); do
        # A blip must not abandon the jobs queued behind this one.
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
    warn "    Allocation not running after 3m (last status: ${status}) — check the Nomad UI."
    # Continuing with this node down could drop the cluster below threshold.
    confirm "    Continue to the next job anyway?" \
        || die "Stopping the rollout — ${job_id} never reported running."
}

NODE_IMAGE_PREFIX="nearone/mpc-node-gcp:"

# The MPC image(s) a job runs; empty for an unrelated job.
image_in_job() {
    jq -r --arg prefix "$NODE_IMAGE_PREFIX" \
        '[.TaskGroups[].Tasks[].Config.image // empty
         | select(startswith($prefix))] | unique | join(", ")'
}

# Retargets only the MPC task; sidecars and every other field pass through.
job_with_image() {
    jq --arg img "$1" --arg prefix "$NODE_IMAGE_PREFIX" \
        '(.TaskGroups[].Tasks[].Config
         | select(.image != null and (.image | startswith($prefix)))).image = $img'
}

# The runbook's Definition -> Edit -> Plan -> Run for one job, over the API.
# Registering is the only write; Nomad then restarts the task on the new image.
upgrade_nomad_job() {
    local job_id=$1 image=$2
    local job current updated
    job=$(nomad_curl GET "/job/${job_id}") || die "Could not fetch job ${job_id}."
    current=$(image_in_job <<<"$job")

    # The prefix query also matches unrelated jobs.
    if [[ -z "$current" ]]; then
        step "==> ${job_id}: no ${NODE_IMAGE_PREFIX}* task found, skipping."
        return
    fi
    # Makes a re-run after a partial rollout a no-op.
    if [[ "$current" == "$image" ]]; then
        step "==> ${job_id}: already on ${image}, skipping."
        return
    fi
    step "==> ${job_id}: ${current} -> ${image}"

    updated=$(job_with_image "$image" <<<"$job")

    # FailedTGAllocs means Nomad can't place the new allocation.
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
    # The next job waits on this node coming back, unless the operator overrides.
    wait_for_alloc "$job_id"
}

[[ $# -eq 1 ]] || die "Usage: $0 <VERSION>  (e.g. 3.14.0)"
VERSION=$1
check_version "$VERSION"
require_cmds curl jq
prompt_nomad_ip
[[ -n "${NOMAD_HTTP_AUTH+set}" ]] || prompt_http_auth

IMAGE="nearone/mpc-node-gcp:${VERSION}"

# An unpublished tag would leave the swapped jobs unable to start.
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
