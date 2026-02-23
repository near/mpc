#! /usr/bin/env bash

# Checks that shell scripts (.sh), YAML configs (.yml/.yaml), and documentation
# (.md) use kebab-case filenames (lowercase + hyphens only).
#
# Excludes:
#   - Git submodules (libs/)
#   - Python packages (tee_launcher/, pytest/) where snake_case is required
#   - Standard uppercase files (README.md, CHANGELOG.md, etc.)
#   - TEE attestation artifacts (launcher_docker_compose*.yaml, launcher_image_compose.yaml)
#   - GitHub issue templates (.github/ISSUE_TEMPLATE/)
#   - GitHub workflow files (.github/workflows/) — checked separately
#   - Infrastructure configs (infra/) — checked separately
#   - Generated/vendored directories (target/, node_modules/, .git/)

has_error=0

# Directories to search (only directories we own and enforce conventions on)
SEARCH_DIRS=(
    ./crates
    ./docs
    ./scripts
    ./deployment
    ./localnet
)

OFFENDERS=""
for dir in "${SEARCH_DIRS[@]}"; do
    [ -d "$dir" ] || continue
    FOUND=$(find "$dir" \
        \( -name '*.sh' -o -name '*.yml' -o -name '*.yaml' -o -name '*.md' \) \
        -print0 | \
        xargs -0 -n 1 basename 2>/dev/null | \
        grep -v '^launcher_docker_compose' | \
        grep -v '^launcher_image_compose' | \
        grep -vE '^(README|CHANGELOG|CONTRIBUTING|LICENSE|RELEASES|AGENTS|CLAUDE|Makefile)' | \
        grep -E '[_A-Z]' || true)
    if [ -n "$FOUND" ]; then
        OFFENDERS="${OFFENDERS}${FOUND}"$'\n'
    fi
done

OFFENDERS=$(echo "$OFFENDERS" | sort -u | sed '/^$/d')

if [ -n "$OFFENDERS" ]; then
    echo "The following files use underscores or uppercase instead of kebab-case:"
    echo "$OFFENDERS"
    echo "Please rename them to use kebab-case (e.g., 'my-script.sh' instead of 'my_script.sh')."
    has_error=1
fi

if [ $has_error -eq 1 ]; then
    exit 1
else
    echo "All file names adhere to kebab-case naming."
    exit 0
fi
