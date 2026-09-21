#!/usr/bin/env bash
# ==============================================================================
# run_e2e_lifecycle.sh — Deterministic Clean-Slate E2E Lifecycle Verification
#
# Executes a 3-stage lifecycle verification suite against an uninitialized
# Amnezia Nexus panel instance:
#   Stage 1: Initial Setup Wizard (test_setup.py)
#   Stage 2: Server 1 Onboarding & AWG 3.1 Deployment (test_onboard.py)
#   Stage 3: Full Functional E2E Suite (auth, settings, users, connections,
#            my_connections, share, servers)
#
# Configurable via environment variables:
#   E2E_BASE_URL        Panel URL (default: http://127.0.0.1:8000)
#   E2E_ADMIN_USER      Admin username (default: admin)
#   E2E_ADMIN_PASS      Admin password (default: AdminPass123!)
#   E2E_SERVER_HOST     Target server host (default: 172.17.0.1)
#   E2E_SERVER_SSH_KEY  Path to SSH private key (optional)
#   E2E_SERVER_SSH_PORT SSH port (default: 22)
#   E2E_SERVER_SSH_USER SSH username (default: ubuntu)
#   E2E_SERVER_SSH_PASS SSH password (optional fallback)
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Configuration defaults
export E2E_BASE_URL="${E2E_BASE_URL:-http://127.0.0.1:8000}"
export E2E_ADMIN_USER="${E2E_ADMIN_USER:-admin}"
export E2E_ADMIN_PASS="${E2E_ADMIN_PASS:-AdminPass123!}"
export E2E_SERVER_HOST="${E2E_SERVER_HOST:-172.17.0.1}"
export E2E_SERVER_SSH_KEY="${E2E_SERVER_SSH_KEY:-}"
export E2E_SERVER_SSH_PORT="${E2E_SERVER_SSH_PORT:-22}"
export E2E_SERVER_SSH_USER="${E2E_SERVER_SSH_USER:-ubuntu}"
export E2E_SERVER_SSH_PASS="${E2E_SERVER_SSH_PASS:-}"
export E2E_TESTING="${E2E_TESTING:-true}"

# Stage status trackers
STAGE1_STATUS="SKIPPED"
STAGE2_STATUS="SKIPPED"
STAGE3_STATUS="SKIPPED"
OVERALL_STATUS=0

print_banner() {
    echo "=================================================================="
    echo "  Amnezia Nexus — Deterministic E2E Lifecycle Verification"
    echo "=================================================================="
    echo "Target Base URL   : ${E2E_BASE_URL}"
    echo "Admin User        : ${E2E_ADMIN_USER}"
    echo "Server Host       : ${E2E_SERVER_HOST}"
    echo "Server SSH Port   : ${E2E_SERVER_SSH_PORT}"
    echo "Server SSH User   : ${E2E_SERVER_SSH_USER}"
    echo "E2E Testing       : ${E2E_TESTING}"
    if [ -n "${E2E_SERVER_SSH_KEY}" ]; then
        echo "Server SSH Key    : ${E2E_SERVER_SSH_KEY}"
    else
        echo "Server SSH Key    : (default / ssh-agent)"
    fi
    echo "=================================================================="
}

print_summary() {
    echo ""
    echo "=================================================================="
    echo "  E2E Lifecycle Verification Summary Report"
    echo "=================================================================="
    echo "  Stage 1: Initial Setup Wizard       : ${STAGE1_STATUS}"
    echo "  Stage 2: Server Onboard & AWG 3.1   : ${STAGE2_STATUS}"
    echo "  Stage 3: Full Functional E2E Suite  : ${STAGE3_STATUS}"
    echo "------------------------------------------------------------------"
    if [ "$OVERALL_STATUS" -eq 0 ]; then
        echo "  OVERALL VERDICT: ALL STAGES PASSED [SUCCESS]"
    else
        echo "  OVERALL VERDICT: LIFECYCLE VERIFICATION FAILED [EXIT ${OVERALL_STATUS}]"
    fi
    echo "=================================================================="
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    print_banner
    echo "Usage: $0 [PYTEST_ARGS...]"
    echo ""
    echo "Runs the 3-stage clean-slate verification against E2E_BASE_URL."
    echo "Stages:"
    echo "  1. Initial Setup Wizard (test_setup.py)"
    echo "  2. Server 1 Onboard & AWG 3.1 Deploy (test_onboard.py)"
    echo "  3. Full Functional E2E Suite"
    echo ""
    echo "Environment Variables:"
    echo "  E2E_BASE_URL        Target panel URL (default: http://127.0.0.1:8000)"
    echo "  E2E_ADMIN_USER      Admin username (default: admin)"
    echo "  E2E_ADMIN_PASS      Admin password (default: AdminPass123!)"
    echo "  E2E_SERVER_HOST     Server host for onboarding (default: 172.17.0.1)"
    echo "  E2E_SERVER_SSH_PORT Server SSH port (default: 22)"
    echo "  E2E_SERVER_SSH_USER Server SSH user (default: ubuntu)"
    echo "  E2E_SERVER_SSH_KEY  Path to SSH private key"
    echo "  E2E_SERVER_SSH_PASS SSH password (optional fallback)"
    exit 0
fi

# ------------------------------------------------------------------------------
# Readiness Probe
# ------------------------------------------------------------------------------
print_banner
echo ""
echo "==> Probing server readiness at ${E2E_BASE_URL}/api/health..."
READY=0
for i in $(seq 1 30); do
    if curl -s -f "${E2E_BASE_URL}/api/health" >/dev/null 2>&1; then
        READY=1
        break
    fi
    sleep 1
done

if [ "$READY" -ne 1 ]; then
    echo "ERROR: Target server at ${E2E_BASE_URL} failed readiness probe within 30s." >&2
    echo "Please ensure the panel is running on a clean-slate database before running this script." >&2
    OVERALL_STATUS=1
    print_summary
    exit 1
fi
echo "==> Server is healthy at ${E2E_BASE_URL}."

# ------------------------------------------------------------------------------
# Stage 1: Initial Setup Wizard
# ------------------------------------------------------------------------------
echo ""
echo "=================================================================="
echo "  Stage 1: Initial Setup Wizard (Clean-Slate Provisioning)"
echo "=================================================================="
if pytest "$REPO_ROOT/tests/e2e/test_setup.py" -v -m e2e "$@"; then
    STAGE1_STATUS="PASSED"
    echo "==> Stage 1 PASSED: Initial admin setup provisioned and locked."
else
    STAGE1_STATUS="FAILED"
    OVERALL_STATUS=1
    echo "ERROR: Stage 1 FAILED. Aborting subsequent stages." >&2
    print_summary
    exit "$OVERALL_STATUS"
fi

# ------------------------------------------------------------------------------
# Stage 2: Server Onboarding & AWG 3.1 Deployment
# ------------------------------------------------------------------------------
echo ""
echo "=================================================================="
echo "  Stage 2: Server Onboarding & AWG 3.1 Protocol Deployment"
echo "=================================================================="
if pytest "$REPO_ROOT/tests/e2e/test_onboard.py" -v -m e2e "$@"; then
    STAGE2_STATUS="PASSED"
    echo "==> Stage 2 PASSED: Server 1 onboarded and AWG 3.1 verified healthy."
else
    STAGE2_STATUS="FAILED"
    OVERALL_STATUS=1
    echo "ERROR: Stage 2 FAILED. Aborting subsequent stages." >&2
    print_summary
    exit "$OVERALL_STATUS"
fi

# ------------------------------------------------------------------------------
# Stage 3: Full Functional E2E Suite
# ------------------------------------------------------------------------------
echo ""
echo "=================================================================="
echo "  Stage 3: Full Functional E2E Test Suite"
echo "=================================================================="
if pytest "$REPO_ROOT/tests/e2e/test_auth.py" \
          "$REPO_ROOT/tests/e2e/test_settings.py" \
          "$REPO_ROOT/tests/e2e/test_users.py" \
          "$REPO_ROOT/tests/e2e/test_connections.py" \
          "$REPO_ROOT/tests/e2e/test_my_connections.py" \
          "$REPO_ROOT/tests/e2e/test_share.py" \
          "$REPO_ROOT/tests/e2e/test_servers.py" -v -m e2e "$@"; then
    STAGE3_STATUS="PASSED"
    echo "==> Stage 3 PASSED: All functional E2E tests succeeded."
else
    STAGE3_STATUS="FAILED"
    OVERALL_STATUS=1
    echo "ERROR: Stage 3 FAILED." >&2
fi

print_summary
exit "$OVERALL_STATUS"
