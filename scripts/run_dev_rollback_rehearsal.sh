#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# Legacy Rollback Rehearsal Wrapper
# Forwards all arguments to scripts/run_upstream_restart_durability.sh
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$SCRIPT_DIR/run_upstream_restart_durability.sh" "$@"
