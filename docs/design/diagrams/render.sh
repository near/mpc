#!/usr/bin/env bash
# Re-render the design doc's step figures from their mermaid sources.
# Usage: ./render.sh          (from 01-nep641/diagrams)
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
