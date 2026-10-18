#!/usr/bin/env bash
# ==============================================================================
# build_style_bundle.sh — Concatenates modular stylesheets into style.css
#
# Generates web/static/css/style.css by concatenating the 7 canonical CSS modules
# in deterministic order, preserving parity with TestStyleCSSConcatenationParity.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CSS_DIR="$REPO_ROOT/web/static/css"
OUTPUT_FILE="$CSS_DIR/style.css"

MODULES=(
    "tokens.css"
    "base.css"
    "layout.css"
    "components.css"
    "tables.css"
    "server.css"
    "vpn.css"
)

TEMP_FILE="$(mktemp "${OUTPUT_FILE}.tmp.XXXXXX")"
trap 'rm -f "$TEMP_FILE"' EXIT INT TERM

for mod in "${MODULES[@]}"; do
    mod_path="$CSS_DIR/$mod"
    if [[ ! -f "$mod_path" ]]; then
        echo "Error: required CSS module not found: $mod_path" >&2
        exit 1
    fi
    cat "$mod_path" >> "$TEMP_FILE"
done

mv "$TEMP_FILE" "$OUTPUT_FILE"
echo "Successfully generated $OUTPUT_FILE from ${#MODULES[@]} modules."
exit 0
