#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
GO_DIR="${GO_DIR:-$REPO_ROOT}"

# Setup hermetic temporary directory
TMP_DIR=$(mktemp -d /tmp/amnezia-e2e-XXXXXX)
SERVER_PID=""

cleanup() {
    local exit_code=$?
    if [ -n "$SERVER_PID" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -rf "$TMP_DIR"
    exit "$exit_code"
}
trap cleanup EXIT INT TERM

export DATA_DIR="$TMP_DIR"
export DB_PATH="$TMP_DIR/panel.db"
export SECRET_KEY="e2e-secret-key-32-bytes-minimum-length-string-12345"
export PORT="${E2E_PORT:-8000}"
export HOST="127.0.0.1"
export LOG_LEVEL="WARN"
export E2E_TESTING="true"
export E2E_BASE_URL="http://${HOST}:${PORT}"
export E2E_ADMIN_USER="admin"
export E2E_ADMIN_PASS="AdminPass123!"

wait_for_server() {
    local ready=0
    for i in $(seq 1 30); do
        if ! kill -0 "$SERVER_PID" 2>/dev/null; then
            echo "ERROR: Server process $SERVER_PID died unexpectedly"
            return 1
        fi
        if curl -s -f "http://${HOST}:${PORT}/api/health" >/dev/null 2>&1; then
            ready=1
            break
        fi
        sleep 0.5
    done

    if [ "$ready" -ne 1 ]; then
        echo "ERROR: Server failed to start on http://${HOST}:${PORT} within 15 seconds"
        return 1
    fi

    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "ERROR: Server process $SERVER_PID died immediately after readiness probe"
        return 1
    fi
    return 0
}

# 1. Build binary
echo "==> Building Go panel binary..."
(cd "$GO_DIR" && go build -tags with_utls -trimpath -ldflags="-s -w" -o bin/panel ./cmd/panel)

# 2. Seed database
echo "==> Seeding E2E test database..."
python3 -c "
import sqlite3, bcrypt, os, time, uuid

conn = sqlite3.connect('$DB_PATH')
with open('$GO_DIR/internal/database/schema.sql') as f:
    conn.executescript(f.read())

now = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
pw_hash = bcrypt.hashpw(b'AdminPass123!', bcrypt.gensalt(12)).decode('utf-8')
admin_id = str(uuid.uuid4())

conn.execute('''
INSERT INTO users (id, username, password_hash, role, enabled, created_at, password_change_required)
VALUES (?, 'admin', ?, 'admin', 1, ?, 0)
''', (admin_id, pw_hash, now))

conn.execute('''
INSERT INTO servers (id, name, host, ssh_user, ssh_port, ssh_pass, protocols, created_at)
VALUES (1, 'E2E Test Server', '127.0.0.1', 'root', 22, '', '{\"awg\":{\"installed\":true,\"port\":51820},\"telemt\":{\"installed\":true,\"port\":443},\"dns\":{\"installed\":true}}', ?)
''', (now,))

conn.commit()
conn.close()
"

# 3. Start server
echo "==> Starting Amnezia Go panel server on port $PORT..."
"$GO_DIR/bin/panel" &
SERVER_PID=$!

# 4. Wait for server readiness
echo "==> Waiting for server to become healthy..."
if ! wait_for_server; then
    exit 1
fi
echo "==> Server is healthy!"

# 5. Run Playwright E2E suite
#
# E2E_PATHS selects what this invocation is responsible for, space separated and
# relative to the repository root. The default is the whole directory. It exists
# because a caller cannot narrow the selection with extra arguments: the
# directory argument is already present, so passing a file inside it collects
# that file twice instead of replacing it.
E2E_PATHS="${E2E_PATHS:-tests/e2e/}"
E2E_TARGETS=()
for path in $E2E_PATHS; do
    E2E_TARGETS+=("$REPO_ROOT/$path")
done

selection_includes_test_auth() {
    local target
    for target in "${E2E_TARGETS[@]}"; do
        case "$target" in
            */tests/e2e/|*/tests/e2e/test_auth.py) return 0 ;;
        esac
    done
    return 1
}

echo "==> Running Playwright E2E tests: ${E2E_PATHS}"
E2E_LOG="$TMP_DIR/e2e_pytest.log"
E2E_JUNIT="$TMP_DIR/e2e_junit.xml"
pytest "${E2E_TARGETS[@]}" -m e2e -v -rs --junitxml="$E2E_JUNIT" "$@" 2>&1 | tee "$E2E_LOG"

# A skip is a declared outcome, not a silent pass. E2E_ALLOWED_SKIPS names the
# tests that may skip; an undeclared skip fails, and so does collecting nothing.
# Counting skips alone would accept any one skip, including a real regression
# hiding behind a missing prerequisite.
echo "==> Verifying skips against the declared policy..."
python3 "$SCRIPT_DIR/check_e2e_skips.py" \
    --junit "$E2E_JUNIT" \
    --allowed "${E2E_ALLOWED_SKIPS:-}"

# 6. Also verify rate limiting against a server started without E2E_TESTING.
# Only when the selection includes test_auth.py: the default directory does, a
# narrower hosted selection may not.
if [ "$#" -eq 0 ] && selection_includes_test_auth; then
    echo "==> Verifying login rate-limiting test against rate-limited server..."
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true

    unset E2E_TESTING
    "$GO_DIR/bin/panel" &
    SERVER_PID=$!
    if ! wait_for_server; then
        echo "ERROR: Restarted rate-limited server failed readiness check"
        exit 1
    fi

    RERUN_JUNIT="$TMP_DIR/e2e_rate_limit_junit.xml"
    pytest "$REPO_ROOT/tests/e2e/test_auth.py::test_login_rate_limiting" \
        -m e2e -v -rs --junitxml="$RERUN_JUNIT"

    # The rerun exists to prove the test runs; a skip here means the flag was
    # still on and nothing was verified.
    python3 "$SCRIPT_DIR/check_e2e_skips.py" \
        --junit "$RERUN_JUNIT" \
        --require-passed test_login_rate_limiting
fi

echo "==> All E2E verification successfully completed!"

