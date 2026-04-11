#!/usr/bin/env bash
#
# prepare-release.sh — Automates the full MPC release process.
#
# Usage:  ./prepare-release.sh <command> <VERSION> [options]
#
# Commands:
#   draft-pr       Create release branch, changelog, version bump, ABI, licenses, commit, open PR
#   wait-merge     Wait for PR to be merged (interactive prompt)
#   wait-images    Poll DockerHub until all 3 Docker images exist for the merge commit
#   create-tag     Verify images exist, then create and push the release tag
#   wait-release   Poll until the GitHub draft release is created by CI
#   all            Run all steps in sequence
#   status         Show which steps are done/pending for a given version
#
# Options:
#   --poll-interval SECONDS   Polling interval for wait commands (default: 30)
#   --timeout SECONDS         Max time to poll before giving up (default: 3600)
#
# Examples:
#   ./prepare-release.sh all 3.9.0
#   ./prepare-release.sh draft-pr 3.9.0
#   ./prepare-release.sh wait-images 3.9.0 --poll-interval 60
#   ./prepare-release.sh status 3.9.0
#
# NOTE: This script assumes GNU coreutils (sed -i, grep -P).
# Run from within 'nix develop' to ensure correct tool versions.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
REMOTE="${REMOTE:-origin}"
POLL_INTERVAL="${POLL_INTERVAL:-30}"
TIMEOUT="${TIMEOUT:-3600}"
IMAGES=("mpc-node" "mpc-node-gcp" "mpc-launcher")

# ─── Output helpers ──────────────────────────────────────────────────────────

info()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
step()  { printf '\033[1;36m  ->\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33mWARNING:\033[0m %s\n' "$*" >&2; }
die()   { printf '\033[1;31mError:\033[0m %s\n' "$*" >&2; exit 1; }

trap 'printf "\n"; warn "Interrupted. Re-run the same command to resume."; exit 130' INT TERM

# ─── Dependency helpers ──────────────────────────────────────────────────────

require_cmds() {
    local missing=0
    for cmd in "$@"; do
        command -v "$cmd" >/dev/null 2>&1 || {
            printf 'Missing dependency: %s\n' "$cmd" >&2
            missing=1
        }
    done
    [[ "${missing}" -eq 0 ]] || die "Please install the missing dependencies above (hint: run from within 'nix develop')."
}

ensure_github_token() {
    if [[ -z "${GITHUB_TOKEN:-}" ]]; then
        if command -v gh &>/dev/null && gh auth status &>/dev/null; then
            step "GITHUB_TOKEN not set, obtaining from 'gh auth token'."
            export GITHUB_TOKEN
            GITHUB_TOKEN=$(gh auth token)
        else
            warn "GITHUB_TOKEN is not set and 'gh' CLI is not authenticated."
            warn "PR links in the changelog may be missing. Fix: export GITHUB_TOKEN=<token> or 'gh auth login'."
        fi
    fi
}

# ─── Argument parsing ────────────────────────────────────────────────────────

usage() {
    sed -n '3,27s/^# \?//p' "$0"
    exit 1
}

if [[ $# -lt 2 ]]; then
    usage
fi

COMMAND="$1"
shift

VERSION=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --poll-interval) POLL_INTERVAL="$2"; shift 2 ;;
        --timeout)       TIMEOUT="$2";       shift 2 ;;
        -*)              die "Unknown option: $1" ;;
        *)
            if [[ -z "$VERSION" ]]; then
                VERSION="$1"; shift
            else
                die "Unexpected argument: $1"
            fi
            ;;
    esac
done

if [[ -z "$VERSION" ]]; then
    die "VERSION is required."
fi

if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    die "'$VERSION' is not valid semver (expected MAJOR.MINOR.PATCH)."
fi

# ─── Derived constants ───────────────────────────────────────────────────────

BRANCH="release/v${VERSION}"
TAG="${VERSION}"
CARGO_TOML="${REPO_ROOT}/Cargo.toml"

cd "$REPO_ROOT"

# ─── Shared state-query helpers ──────────────────────────────────────────────

# Returns the merge commit SHA on main. Tries tag first, then merged PR.
get_merge_commit_sha() {
    # If tag exists locally, dereference to commit (needed for annotated tags)
    local tag_sha
    tag_sha=$(git rev-parse "refs/tags/${TAG}^{commit}" 2>/dev/null || true)
    if [[ -n "${tag_sha}" ]]; then
        echo "${tag_sha}"
        return 0
    fi

    # If the PR is merged, get the merge commit from GitHub
    local merge_sha
    merge_sha=$(gh pr view "${BRANCH}" --json mergeCommit --jq '.mergeCommit.oid' 2>/dev/null || true)
    if [[ -n "${merge_sha}" && "${merge_sha}" != "null" ]]; then
        echo "${merge_sha}"
        return 0
    fi

    die "Cannot determine merge commit SHA. Is the PR merged?"
}

get_pr_number() {
    gh pr list --head "${BRANCH}" --state all --json number --jq '.[0].number' 2>/dev/null || true
}

get_pr_state() {
    gh pr view "${BRANCH}" --json state --jq '.state' 2>/dev/null || true
}

get_pr_url() {
    gh pr view "${BRANCH}" --json url --jq '.url' 2>/dev/null || true
}

# Check if a single Docker image exists on DockerHub.
image_exists() {
    local repo="$1" tag="$2"
    skopeo inspect "docker://nearone/${repo}:${tag}" >/dev/null 2>&1
}

# Check all 3 images. Returns 0 if ALL exist.
all_images_exist() {
    local tag="$1"
    for repo in "${IMAGES[@]}"; do
        image_exists "${repo}" "${tag}" || return 1
    done
    return 0
}

# Print per-image status. Sets IMAGES_READY to the count of ready images.
IMAGES_READY=0
print_image_status() {
    local tag="$1"
    IMAGES_READY=0
    for repo in "${IMAGES[@]}"; do
        if image_exists "${repo}" "${tag}"; then
            printf '  \033[1;32m[OK]\033[0m nearone/%s:%s\n' "${repo}" "${tag}"
            (( IMAGES_READY++ )) || true
        else
            printf '  \033[1;33m[..]\033[0m nearone/%s:%s\n' "${repo}" "${tag}"
        fi
    done
}

# Generic polling loop.
# Usage: poll_until "description" check_function [args...]
poll_until() {
    local description="$1"; shift
    local check_fn="$1"; shift
    local elapsed=0

    while ! "${check_fn}" "$@"; do
        if (( elapsed >= TIMEOUT )); then
            die "Timed out waiting for ${description} after ${TIMEOUT}s."
        fi
        local mins=$(( elapsed / 60 ))
        local secs=$(( elapsed % 60 ))
        info "Waiting for ${description}... (elapsed: ${mins}m ${secs}s, next check in ${POLL_INTERVAL}s)"
        sleep "${POLL_INTERVAL}"
        (( elapsed += POLL_INTERVAL ))
    done
}

# ─── Subcommand: draft-pr ────────────────────────────────────────────────────

cmd_draft_pr() {
    require_cmds git-cliff cargo-about cargo-insta cargo-nextest gh
    ensure_github_token

    # Check if already fully done: PR already exists for this branch
    local pr_number
    pr_number=$(get_pr_number)
    if [[ -n "${pr_number}" ]]; then
        local pr_url
        pr_url=$(get_pr_url)
        info "PR already exists: ${pr_url} — skipping."
        return 0
    fi

    # Check if branch already has the release commit (prepare done, PR not yet opened)
    local head_msg
    head_msg=$(git log -1 --format=%s "refs/heads/${BRANCH}" 2>/dev/null || true)
    local need_prepare=true
    if [[ "${head_msg}" == "release: v${VERSION}" ]]; then
        info "Branch '${BRANCH}' already has release commit. Skipping to PR creation."
        need_prepare=false
    fi

    if [[ "${need_prepare}" == true ]]; then
        info "Preparing release v${VERSION}"

        # Clean working tree check
        if ! git diff --quiet || ! git diff --cached --quiet; then
            die "Working tree has uncommitted changes. Please commit or stash them first."
        fi

        # Branch creation / checkout
        if git show-ref --verify --quiet "refs/heads/${BRANCH}"; then
            step "Branch '${BRANCH}' already exists locally. Switching to it."
            git checkout "${BRANCH}"
        else
            git fetch "${REMOTE}" --quiet
            if git show-ref --verify --quiet "refs/remotes/${REMOTE}/${BRANCH}"; then
                step "Branch '${BRANCH}' exists on remote. Checking out."
                git checkout -b "${BRANCH}" "${REMOTE}/${BRANCH}"
            else
                step "Creating branch '${BRANCH}' from $(git rev-parse --short HEAD)"
                git checkout -b "${BRANCH}"
            fi
        fi

        # Push to remote (needed for git-cliff PR link resolution)
        if ! git ls-remote --heads "${REMOTE}" "${BRANCH}" | grep -q .; then
            step "Pushing '${BRANCH}' to ${REMOTE}..."
            git push -u "${REMOTE}" "${BRANCH}"
        fi

        # Generate changelog (always — fast and deterministic)
        step "Generating changelog..."
        git-cliff -t "${VERSION}" > CHANGELOG.md

        # Bump workspace version (idempotent)
        local current_version
        current_version=$(grep -Po '(?<=^version = ")[0-9]+\.[0-9]+\.[0-9]+(?=")' "${CARGO_TOML}")
        if [[ "${current_version}" != "${VERSION}" ]]; then
            step "Bumping workspace version: ${current_version} -> ${VERSION}"
            sed -i "0,/^version = \"${current_version}\"/s//version = \"${VERSION}\"/" "${CARGO_TOML}"
        else
            step "Version already ${VERSION} in Cargo.toml."
        fi

        # ABI snapshot
        step "Verifying contract ABI changed after version bump..."
        if cargo nextest run --cargo-profile=test-release -p mpc-contract abi_has_not_changed 2>/dev/null; then
            die "abi_has_not_changed test passed unexpectedly — ABI was not affected by version bump."
        fi
        step "Accepting updated ABI snapshot..."
        cargo insta accept

        # Third-party licenses
        step "Regenerating third-party licenses..."
        (cd "${REPO_ROOT}/third-party-licenses" && cargo about generate --locked -m ../Cargo.toml about.hbs > licenses.html)

        # Commit (idempotent)
        if git diff --quiet && git diff --cached --quiet && [[ -z "$(git ls-files --others --exclude-standard)" ]]; then
            step "No changes to commit. Already prepared."
        else
            git add -A
            git commit -m "release: v${VERSION}"
        fi
    fi

    # Push latest commits and open PR
    step "Pushing '${BRANCH}' to ${REMOTE}..."
    git push -u "${REMOTE}" "${BRANCH}"

    step "Creating PR..."
    gh pr create \
        --base main \
        --head "${BRANCH}" \
        --title "chore: create mpc-node release v${VERSION}" \
        --body "Release v${VERSION}

See CHANGELOG.md for details."

    local pr_url
    pr_url=$(get_pr_url)
    info "PR created: ${pr_url}"
}

# ─── Subcommand: wait-merge ──────────────────────────────────────────────────

cmd_wait_merge() {
    require_cmds gh

    # Check if already merged
    local state
    state=$(get_pr_state)
    if [[ "${state}" == "MERGED" ]]; then
        local merge_sha
        merge_sha=$(get_merge_commit_sha)
        info "PR already merged. Merge commit: ${merge_sha:0:7}"
        return 0
    fi

    # Check PR exists
    local pr_number
    pr_number=$(get_pr_number)
    if [[ -z "${pr_number}" ]]; then
        die "No PR found for branch '${BRANCH}'. Run 'draft-pr' first."
    fi

    local pr_url
    pr_url=$(get_pr_url)
    info "PR is open: ${pr_url}"
    info "Please review and merge the PR, then press Enter to continue..."
    read -r

    # Verify it's actually merged
    git fetch "${REMOTE}" --quiet
    state=$(get_pr_state)
    if [[ "${state}" != "MERGED" ]]; then
        die "PR is not merged yet (state: ${state}). Merge it and re-run this command."
    fi

    local merge_sha
    merge_sha=$(get_merge_commit_sha)
    info "PR merged. Merge commit: ${merge_sha:0:7}"
}

# ─── Subcommand: wait-images ─────────────────────────────────────────────────

cmd_wait_images() {
    require_cmds skopeo

    local merge_sha
    merge_sha=$(get_merge_commit_sha)
    local short_sha="${merge_sha:0:7}"
    local image_tag="main-${short_sha}"

    info "Checking Docker images tagged '${image_tag}'..."
    print_image_status "${image_tag}"

    if (( IMAGES_READY == ${#IMAGES[@]} )); then
        info "All images ready."
        return 0
    fi

    local elapsed=0
    while true; do
        if (( elapsed >= TIMEOUT )); then
            die "Timed out waiting for Docker images after ${TIMEOUT}s."
        fi
        local mins=$(( elapsed / 60 ))
        local secs=$(( elapsed % 60 ))
        info "${IMAGES_READY}/${#IMAGES[@]} images ready. Retrying in ${POLL_INTERVAL}s... (elapsed: ${mins}m ${secs}s)"
        sleep "${POLL_INTERVAL}"
        (( elapsed += POLL_INTERVAL ))

        info "Checking Docker images tagged '${image_tag}'..."
        print_image_status "${image_tag}"

        if (( IMAGES_READY == ${#IMAGES[@]} )); then
            break
        fi
    done

    info "All images ready."
}

# ─── Subcommand: create-tag ──────────────────────────────────────────────────

cmd_create_tag() {
    require_cmds gh skopeo

    # Check if tag already exists on remote
    git fetch "${REMOTE}" --tags --quiet
    if git ls-remote --tags "${REMOTE}" "refs/tags/${TAG}" 2>/dev/null | grep -q .; then
        info "Tag '${TAG}' already exists on ${REMOTE}."
        return 0
    fi

    # Verify images exist before tagging
    local merge_sha
    merge_sha=$(get_merge_commit_sha)
    local short_sha="${merge_sha:0:7}"
    local image_tag="main-${short_sha}"

    if ! all_images_exist "${image_tag}"; then
        info "Docker image status for '${image_tag}':"
        print_image_status "${image_tag}"
        die "Not all Docker images are ready. Run 'wait-images' first."
    fi

    # Verify the merge commit is on main
    git fetch "${REMOTE}" main --quiet
    if ! git merge-base --is-ancestor "${merge_sha}" "${REMOTE}/main"; then
        die "Merge commit ${merge_sha:0:7} is not on ${REMOTE}/main."
    fi

    # Create tag (handle: exists locally but not on remote)
    if git tag -l "${TAG}" | grep -q .; then
        step "Tag '${TAG}' exists locally. Pushing to ${REMOTE}..."
    else
        step "Creating tag '${TAG}' at ${merge_sha:0:7}..."
        git tag -a -m "Release v${TAG}" "${TAG}" "${merge_sha}"
    fi

    git push "${REMOTE}" "${TAG}"
    info "Tag '${TAG}' pushed to ${REMOTE}."
}

# ─── Subcommand: wait-release ────────────────────────────────────────────────

_check_release_exists() {
    gh release view "${TAG}" --json tagName >/dev/null 2>&1
}

cmd_wait_release() {
    require_cmds gh

    # Check if release already exists
    if _check_release_exists; then
        local url
        url=$(gh release view "${TAG}" --json url --jq '.url' 2>/dev/null || true)
        info "Draft release exists: ${url}"
        return 0
    fi

    poll_until "draft release for ${TAG}" _check_release_exists

    local url
    url=$(gh release view "${TAG}" --json url --jq '.url' 2>/dev/null || true)
    info "Draft release created: ${url}"
}

# ─── Subcommand: status ──────────────────────────────────────────────────────

cmd_status() {
    info "Release v${VERSION} status:"
    echo ""

    # 1. draft-pr (prepare + PR creation)
    local pr_number pr_state pr_url
    pr_number=$(get_pr_number)
    if [[ -n "${pr_number}" ]]; then
        pr_state=$(get_pr_state)
        pr_url=$(get_pr_url)
        printf '  \033[1;32m[x]\033[0m draft-pr     — PR #%s (%s) %s\n' "${pr_number}" "${pr_state}" "${pr_url}"
    else
        local head_msg
        head_msg=$(git log -1 --format=%s "refs/heads/${BRANCH}" 2>/dev/null || \
                   git log -1 --format=%s "refs/remotes/${REMOTE}/${BRANCH}" 2>/dev/null || true)
        if [[ "${head_msg}" == "release: v${VERSION}" ]]; then
            printf '  \033[1;33m[~]\033[0m draft-pr     — Branch %s ready but PR not created\n' "${BRANCH}"
        else
            printf '  \033[1;90m[ ]\033[0m draft-pr     — Not started\n'
        fi
    fi

    # 2. wait-merge
    if [[ "$(get_pr_state)" == "MERGED" ]]; then
        local merge_sha
        merge_sha=$(get_merge_commit_sha 2>/dev/null || true)
        printf '  \033[1;32m[x]\033[0m wait-merge   — Merged at %s\n' "${merge_sha:0:7}"
    else
        printf '  \033[1;90m[ ]\033[0m wait-merge   — PR not yet merged\n'
    fi

    # 3. wait-images
    local merge_sha
    merge_sha=$(get_merge_commit_sha 2>/dev/null || true)
    if [[ -n "${merge_sha}" ]]; then
        local short_sha="${merge_sha:0:7}"
        local image_tag="main-${short_sha}"
        local ready=0
        for repo in "${IMAGES[@]}"; do
            image_exists "${repo}" "${image_tag}" && (( ready++ )) || true
        done
        if (( ready == ${#IMAGES[@]} )); then
            printf '  \033[1;32m[x]\033[0m wait-images  — All %d images ready (%s)\n' "${#IMAGES[@]}" "${image_tag}"
        else
            printf '  \033[1;90m[ ]\033[0m wait-images  — %d/%d images ready (%s)\n' "${ready}" "${#IMAGES[@]}" "${image_tag}"
        fi
    else
        printf '  \033[1;90m[ ]\033[0m wait-images  — Merge commit unknown\n'
    fi

    # 4. create-tag
    if git ls-remote --tags "${REMOTE}" "refs/tags/${TAG}" 2>/dev/null | grep -q .; then
        printf '  \033[1;32m[x]\033[0m create-tag   — Tag %s pushed\n' "${TAG}"
    elif git tag -l "${TAG}" | grep -q .; then
        printf '  \033[1;33m[~]\033[0m create-tag   — Tag %s exists locally but not on remote\n' "${TAG}"
    else
        printf '  \033[1;90m[ ]\033[0m create-tag   — Tag not created\n'
    fi

    # 5. wait-release
    if gh release view "${TAG}" --json tagName >/dev/null 2>&1; then
        local is_draft
        is_draft=$(gh release view "${TAG}" --json isDraft --jq '.isDraft' 2>/dev/null || true)
        if [[ "${is_draft}" == "false" ]]; then
            printf '  \033[1;32m[x]\033[0m wait-release — Release published\n'
        else
            printf '  \033[1;32m[x]\033[0m wait-release — Draft release created\n'
        fi
    else
        printf '  \033[1;90m[ ]\033[0m wait-release — No release found\n'
    fi

    echo ""
}

# ─── Subcommand: all ──────────────────────────────────────────────────────────

cmd_all() {
    cmd_draft_pr
    cmd_wait_merge
    cmd_wait_images
    cmd_create_tag
    cmd_wait_release
    info "Done! Draft release created. Review and publish at:"
    info "  https://github.com/near/mpc/releases"
}

# ─── Dispatch ─────────────────────────────────────────────────────────────────

case "${COMMAND}" in
    draft-pr)     cmd_draft_pr     ;;
    wait-merge)   cmd_wait_merge   ;;
    wait-images)  cmd_wait_images  ;;
    create-tag)   cmd_create_tag   ;;
    wait-release) cmd_wait_release ;;
    status)       cmd_status       ;;
    all)          cmd_all          ;;
    *)            die "Unknown command: ${COMMAND}. Run '$0' for usage." ;;
esac
