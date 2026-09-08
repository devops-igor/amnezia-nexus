#!/usr/bin/env bash
# ==============================================================================
# deploy-dev.sh: Automated Deployment & Health Verification for Amnezia Nexus
# ==============================================================================
set -eo pipefail

# Color formatting helpers
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
log_ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }

# 1. Configuration & defaults
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-$SCRIPT_DIR/docker-compose.prod.yaml}"
CONTAINER_NAME="${CONTAINER_NAME:-amnezia-panel}"
IMAGE_REPO="${IMAGE_REPO:-ghcr.io/devops-igor/amnezia-nexus}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
TARGET_IMAGE="${IMAGE_REPO}:${IMAGE_TAG}"

HEALTH_URL="${HEALTH_URL:-http://localhost:8080/api/health}"
VPN_STATUS_URL="${VPN_STATUS_URL:-http://localhost:8080/api/vpn/status}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-60}"
POLL_INTERVAL="${POLL_INTERVAL:-3}"

log_info "Starting deployment of Amnezia Nexus..."
log_info "Target image:   ${TARGET_IMAGE}"
log_info "Compose file:   ${COMPOSE_FILE}"
log_info "Container name: ${CONTAINER_NAME}"
log_info "Health URL:     ${HEALTH_URL}"
log_info "VPN Status URL: ${VPN_STATUS_URL}"

# 2. Check docker and docker-compose availability
if ! command -v docker >/dev/null 2>&1; then
    log_error "docker command not found on host. Please install Docker."
    exit 1
fi

if docker compose version >/dev/null 2>&1; then
    DOCKER_COMPOSE="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
    DOCKER_COMPOSE="docker-compose"
else
    log_error "Neither 'docker compose' nor 'docker-compose' found on host."
    exit 1
fi

if [ ! -f "$COMPOSE_FILE" ]; then
    log_error "Compose file not found at: $COMPOSE_FILE"
    exit 1
fi

# 3. Optional registry authentication
if [ -n "${GHCR_TOKEN:-}" ]; then
    log_info "Authenticating with GitHub Container Registry (ghcr.io)..."
    REGISTRY_USER="${GHCR_USER:-${GITHUB_ACTOR:-deploy-bot}}"
    echo "${GHCR_TOKEN}" | docker login ghcr.io -u "${REGISTRY_USER}" --password-stdin
fi

# 4. Capture current state for rollback
PREV_IMAGE_TAG=$(docker inspect --format='{{.Config.Image}}' "$CONTAINER_NAME" 2>/dev/null || true)
PREV_IMAGE_ID=$(docker inspect --format='{{.Image}}' "$CONTAINER_NAME" 2>/dev/null || true)
CONTAINER_WAS_RUNNING=$(docker inspect --format='{{.State.Running}}' "$CONTAINER_NAME" 2>/dev/null || echo "false")

if [ -n "$PREV_IMAGE_TAG" ]; then
    log_info "Current active image: ${PREV_IMAGE_TAG} (ID: ${PREV_IMAGE_ID:0:12})"
else
    log_info "No currently active container named '${CONTAINER_NAME}'. First-time deployment."
fi

# 5. Pull target image
log_info "Pulling container image: ${TARGET_IMAGE}..."
if ! docker pull "${TARGET_IMAGE}"; then
    log_error "Failed to pull image: ${TARGET_IMAGE}"
    exit 1
fi

# 6. Deploy container
log_info "Deploying container with docker compose..."
export AMNEZIA_IMAGE="${TARGET_IMAGE}"
if ! $DOCKER_COMPOSE -f "$COMPOSE_FILE" up -d --force-recreate "$CONTAINER_NAME"; then
    log_error "Failed to start container with docker compose."
    exit 1
fi

# 7. Post-deployment health verification loop (up to TIMEOUT_SECONDS)
log_info "Verifying container health (timeout: ${TIMEOUT_SECONDS}s, interval: ${POLL_INTERVAL}s)..."

START_TIME=$(date +%s)
HEALTHY=false

while true; do
    CURRENT_TIME=$(date +%s)
    ELAPSED=$(( CURRENT_TIME - START_TIME ))

    if [ "$ELAPSED" -ge "$TIMEOUT_SECONDS" ]; then
        log_warn "Health verification timed out after ${ELAPSED}s."
        break
    fi

    # Check 1: API Health (expect HTTP 200)
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$HEALTH_URL" 2>/dev/null || echo "000")

    # Check 2: VPN Listener Status (expect listener_running: true or log confirmation)
    VPN_RESP=$(curl -s "$VPN_STATUS_URL" 2>/dev/null || true)
    VPN_RUNNING=false

    if echo "$VPN_RESP" | grep -Eq '"listener_running":[[:space:]]*true'; then
        VPN_RUNNING=true
    elif docker logs --tail 40 "$CONTAINER_NAME" 2>&1 | grep -q "VPN endpoint started"; then
        VPN_RUNNING=true
    fi

    log_info "Elapsed: ${ELAPSED}s | /api/health: ${HTTP_CODE} | VPN listener: ${VPN_RUNNING}"

    if [ "$HTTP_CODE" = "200" ] && [ "$VPN_RUNNING" = "true" ]; then
        HEALTHY=true
        break
    fi

    sleep "$POLL_INTERVAL"
done

# 8. Handle health outcome
if [ "$HEALTHY" = "true" ]; then
    log_ok "=================================================================="
    log_ok "Deployment SUCCESSFUL!"
    log_ok "Amnezia Nexus is up and healthy."
    log_ok "  - /api/health:       HTTP 200 OK"
    log_ok "  - VPN Listener:      Active & Running (port 51820/udp)"
    log_ok "  - Active Container:  ${CONTAINER_NAME}"
    log_ok "  - Deployed Image:    ${TARGET_IMAGE}"
    log_ok "=================================================================="
    exit 0
fi

# 9. Health verification failed: Initiate Rollback
log_error "Health verification FAILED after ${TIMEOUT_SECONDS} seconds!"
log_warn "Recent container logs:"
docker logs --tail 50 "$CONTAINER_NAME" 2>&1 || true

if [ "$CONTAINER_WAS_RUNNING" = "true" ] && [ -n "$PREV_IMAGE_TAG" ]; then
    log_warn "Initiating automated rollback to previous image: ${PREV_IMAGE_TAG}..."
    export AMNEZIA_IMAGE="${PREV_IMAGE_TAG}"
    if $DOCKER_COMPOSE -f "$COMPOSE_FILE" up -d --force-recreate "$CONTAINER_NAME"; then
        log_ok "Rollback executed successfully. Reverted to: ${PREV_IMAGE_TAG}"
    else
        log_error "CRITICAL: Rollback failed to execute! Manual intervention required."
    fi
else
    log_warn "No prior container image available to roll back to."
fi

exit 1
