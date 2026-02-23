#! /usr/bin/env bash

# Checks that .sh, .yml/.yaml, and .md files use kebab-case filenames
# (lowercase + hyphens only).
#
# Only searches directories listed in SEARCH_DIRS below.
# Everything else (libs/, pytest/, .github/, infra/, etc.) is ignored.

# Directories to search recursively
SEARCH_DIRS=(./crates ./docs ./scripts ./deployment ./localnet)

# File extensions to check
CHECK_EXTENSIONS=(sh yml yaml md)

# Build a regex that matches any of the checked file extensions
EXT_PATTERN="\.($( IFS='|'; echo "${CHECK_EXTENSIONS[*]}" ))$"

# Exact filenames exempt from kebab-case
EXEMPT_FILES=(
    AGENTS.md
    CHANGELOG.md
    CLAUDE.md
    CONTRIBUTING.md
    LICENSE.md
    Makefile.md
    README.md
    RELEASES.md
    launcher_docker_compose.yaml
    launcher_docker_compose_nontee.yaml
    launcher_image_compose.yaml
)

# Build a regex that matches any of the allowed non-kebab-case filenames
EXEMPT_PATTERN="^($( IFS='|'; echo "${EXEMPT_FILES[*]}" ))$"

OFFENDERS=()
while IFS= read -r filepath; do
    filename=${filepath##*/}

    # Skip files whose extension we don't check
    [[ $filename =~ $EXT_PATTERN ]] || continue
    # Skip allowed non-kebab-case filenames
    [[ $filename =~ $EXEMPT_PATTERN ]] && continue
    # Flag filenames containing underscores or uppercase letters
    [[ $filename =~ [_A-Z] ]] && OFFENDERS+=("$filepath")
done < <(
    # Top-level repo files only (no recursion)
    find . -maxdepth 1 -type f
    # Subdirectories we enforce conventions on (recursive)
    find "${SEARCH_DIRS[@]}" -type f
)

if [ ${#OFFENDERS[@]} -gt 0 ]; then
    echo "The following files use underscores or uppercase instead of kebab-case:"
    printf '%s\n' "${OFFENDERS[@]}" | sort
    bad=${OFFENDERS[0]}
    good=${bad%/*}/$(echo "${bad##*/}" | tr '[:upper:]_' '[:lower:]-')
    echo "Please rename to kebab-case (e.g., '$bad' -> '$good')."
    exit 1
fi

echo "All file names adhere to kebab-case naming."
