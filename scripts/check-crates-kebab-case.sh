#! /usr/bin/env bash

has_error=0

OFFENDERS=$(cargo metadata --format-version 1 --no-deps |
    jq -r '.packages[] | select(.source == null) | .name' |
    grep "_")

if [ -n "$OFFENDERS" ]; then
    echo "❌ Error: The following crates use underscores instead of hyphens:"
    echo "$OFFENDERS"
    echo "👉 Please rename them to use kebab-case (e.g., 'my-crate' instead of 'my_crate')."
    has_error=1
fi

BAD_FOLDERS=$(find crates -mindepth 1 -maxdepth 1 -type d -name "*_*")

if [ -n "$BAD_FOLDERS" ]; then
    echo "❌ Error: The following crate folders use underscores:"
    echo "$BAD_FOLDERS"
    echo "👉 Please rename these folders to use hyphens."
    has_error=1
fi

if [ $has_error -eq 1 ]; then
    exit 1
else
    echo "✅ All crate names and folders adhere to kebab-case naming."
    exit 0
fi
