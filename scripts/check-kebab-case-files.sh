#! /usr/bin/env bash

# Checks that .sh, .yml/.yaml, and .md files use kebab-case filenames
# (lowercase + hyphens only).
#
# Only searches directories listed in SEARCH_DIRS below.
# Everything else (libs/, pytest/, .github/, infra/, etc.) is ignored.

# Directories to search (only directories we own and enforce conventions on)
SEARCH_DIRS=(./crates ./docs ./scripts ./deployment ./localnet)

# File extensions to check
CHECK_EXTENSIONS=(sh yml yaml md)

# Build a regex that matches any of the checked file extensions
EXT_PATTERN="\.($( IFS='|'; echo "${CHECK_EXTENSIONS[*]}" ))$"

# Exact filenames exempt from kebab-case
EXEMPT_FILES=(
    README.md
    CHANGELOG.md
    CONTRIBUTING.md
    LICENSE.md
    RELEASES.md
    AGENTS.md
    CLAUDE.md
    Makefile.md
    launcher_docker_compose.yaml           # TEE attestation artifact
    launcher_docker_compose_nontee.yaml    # TEE attestation artifact (non-TEE variant)
    launcher_image_compose.yaml            # TEE test asset
)

# Build a regex that matches any of the allowed non-kebab-case filenames
EXEMPT_PATTERN="^($( IFS='|'; echo "${EXEMPT_FILES[*]}" ))$"

OFFENDERS=$(
    # List every file under the directories we enforce conventions on
    find "${SEARCH_DIRS[@]}" -type f -exec basename {} \; |
    # Keep only the extensions we care about (.sh, .yml, .yaml, .md)
    grep -E "$EXT_PATTERN" |
    # Exclude allowed non-kebab-case filenames (README.md, CHANGELOG.md, …)
    grep -vE "$EXEMPT_PATTERN" |
    # Flag anything containing underscores or uppercase letters
    grep -E '[_A-Z]' |
    # Deduplicate (same basename may appear in multiple directories)
    sort -u ||
    true
)

if [ -n "$OFFENDERS" ]; then
    echo "The following files use underscores or uppercase instead of kebab-case:"
    echo "$OFFENDERS"
    echo "Please rename them to use kebab-case (e.g., 'my-script.sh' instead of 'my_script.sh')."
    exit 1
fi

echo "All file names adhere to kebab-case naming."
