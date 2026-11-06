#!/usr/bin/env bash
# Render the design doc's figures from their mermaid sources.
# Usage: ./render.sh          (from this attachments folder)
set -euo pipefail
cd "$(dirname "$0")"

for f in *.mmd; do
  out="${f%.mmd}.png"
  echo "rendering $f -> $out"
  npx -y @mermaid-js/mermaid-cli \
    -i "$f" -o "$out" \
    -b white -s 2 -c mermaid-config.json
done

# The doc links these by relative path, so nothing else to update.
echo "done"
