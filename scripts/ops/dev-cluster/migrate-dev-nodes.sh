#!/usr/bin/env bash
#
# migrate-dev-nodes.sh — Step 1 of a dev-cluster upgrade: swap every
# mpc-node-* Nomad job to nearone/mpc-node-gcp:<VERSION> — plan, confirm, run.
# Verification is the caller's job (dev-menu.sh runs it next).
#
# Usage: ./scripts/ops/dev-cluster/migrate-dev-nodes.sh <testnet|mainnet> <VERSION>
# The Nomad IP address and its basic-auth credentials are prompted for. Exporting
# NOMAD_ADDR / NOMAD_HTTP_AUTH="user:password" skips the matching prompt;
# NOMAD_TOKEN adds an ACL token header; NOMAD_NAMESPACE targets that namespace.
# Member-account keys found in the job definitions are imported into the local
# near-cli keystore if missing, so the later signing steps can run.
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../common.sh
source "${SCRIPT_DIR}/../common.sh"
# shellcheck source=dev-common.sh
source "${SCRIPT_DIR}/dev-common.sh"
# shellcheck source=first-time-setup.sh
source "${SCRIPT_DIR}/first-time-setup.sh"

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

# An unpublished tag would leave the swapped jobs unable to start.
check_image_exists() {
    local image=$1
    if ! command -v skopeo >/dev/null 2>&1; then
        warn "WARNING: skopeo not found, skipping existence check for ${image}."
        return 0
    fi
    skopeo inspect --no-creds --format '{{.Digest}}' "docker://${image}" >/dev/null \
        || die "${image} not found on Docker Hub — is the release published?"
}

[[ $# -eq 2 ]] || die "Usage: $0 <testnet|mainnet> <VERSION>  (e.g. testnet 3.14.0)"
NETWORK=$1
VERSION=$2
check_version "$VERSION"
require_cmds curl jq near
resolve_dev_cluster "$NETWORK"
prompt_nomad_ip
[[ -n "${NOMAD_HTTP_AUTH+set}" ]] || prompt_http_auth

IMAGE="nearone/mpc-node-gcp:${VERSION}"
check_image_exists "$IMAGE"
JOB_IDS=$(discover_job_ids)

step "==> Local signing keys"
for job_id in $JOB_IDS; do
    ensure_job_keys "$job_id"
done

for job_id in $JOB_IDS; do
    upgrade_nomad_job "$job_id" "$IMAGE"
done
