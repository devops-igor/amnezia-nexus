#!/usr/bin/env bash
# Preflight: prove the Naive Caddy image can still be obtained, before the
# Playwright suite spends four 120-second install timeouts discovering it cannot.
#
# Why this exists (issue #680): NaiveManager.Install compiles Caddy from source on
# the target host, inside the synchronous install request. That build resolves
# github.com/caddyserver/forwardproxy@caddy2 through proxy.golang.org, and when
# that endpoint is unreachable from the build container the build fails and every
# multiprotocol-client test fails with a generic install_failed or a client
# timeout.
#
# The preflight checks the same inputs the build needs, one bounded step at a
# time, and prints a closed reason so the failure is attributable from the log:
#
#   PREFLIGHT OK: check=<name> duration_ms=<n>
#   PREFLIGHT FAILED: check=<name> reason=<closed> duration_ms=<n>
#
# Two layers are measured separately on purpose:
#   * host_egress  - the runner host, which is the path `docker pull` uses
#                    (the daemon's own network, not a container namespace).
#   * module_dns / module_probe - from inside the builder image, which is the
#                    path `docker build` uses. A resolver failure is
#                    `dns_failure`; a resolved-but-unreachable name is
#                    `module_network_timeout`. They are not the same problem.
#
# It deliberately does NOT run the xcaddy build. A build here would warm the
# Docker layer cache and could make the subsequent install succeed, hiding the
# very cold-build dependency this preflight exists to surface.
#
# Once the pinned prebuilt image lands (issue #680 Phase 1), set
# NAIVE_CADDY_IMAGE=<ref> and the preflight verifies that image and its module
# list instead of the source-build inputs.

set -uo pipefail

IMAGE="${NAIVE_CADDY_IMAGE:-}"
IMAGE="${IMAGE#docker://}"
MODULE="http.handlers.forward_proxy"
# The exact endpoint whose failure was reproduced against the source Dockerfile:
# xcaddy resolves the historical `caddy2` branch through the Go module proxy.
PROBE_URL="https://proxy.golang.org/github.com/caddyserver/forwardproxy/@v/caddy2.info"
PROBE_HOST_NAME="proxy.golang.org"

now_ms() { date +%s%3N; }

fail() { # fail <check> <reason> <started_ms>
    local check="$1" reason="$2" begin="$3" elapsed
    elapsed=$(( $(now_ms) - begin ))
    echo "PREFLIGHT FAILED: check=${check} reason=${reason} duration_ms=${elapsed}"
    exit 1
}

pass() { # pass <check> <started_ms> [extra]
    local check="$1" begin="$2" extra="${3:-}" elapsed
    elapsed=$(( $(now_ms) - begin ))
    echo "PREFLIGHT OK: check=${check} duration_ms=${elapsed}${extra}"
}

# One HTTP attempt from the host. Returns 127 when no client is available, so
# the absence of curl/wget is reported as a skip, never as a false failure.
probe_host() { # probe_host <url> <seconds>
    if command -v curl >/dev/null 2>&1; then
        curl -fsS -m "$2" -o /dev/null "$1"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -t 1 -T "$2" -O /dev/null "$1"
    else
        return 127
    fi
}

started="$(now_ms)"
timeout 15 docker info >/dev/null 2>&1 || fail docker_daemon docker_unavailable "${started}"
pass docker_daemon "${started}"

if [ -n "${IMAGE}" ]; then
    started="$(now_ms)"
    timeout 60 docker pull "${IMAGE}" >/dev/null 2>&1 || fail image_pull image_pull "${started}"
    pass image_pull "${started}" " image=${IMAGE}"

    started="$(now_ms)"
    modules="$(timeout 20 docker run --rm "${IMAGE}" caddy list-modules 2>/dev/null)" \
        || fail image_run image_run "${started}"
    grep -qx "${MODULE}" <<<"${modules}" || fail image_modules module_missing "${started}"
    pass image_modules "${started}" " source=pinned_image module=${MODULE}"
else
    # The daemon's own path. This is what `docker pull` will use in Phase 1, so
    # it must be measured separately from the container namespace below.
    started="$(now_ms)"
    probe_host "${PROBE_URL}" 10 >/dev/null 2>&1
    host_rc=$?
    if [ "${host_rc}" -eq 127 ]; then
        echo "PREFLIGHT SKIP: check=host_egress reason=no_http_client"
    elif [ "${host_rc}" -ne 0 ]; then
        fail host_egress host_network_unreachable "${started}"
    else
        pass host_egress "${started}"
    fi

    started="$(now_ms)"
    timeout 30 docker manifest inspect caddy:builder >/dev/null 2>&1 \
        || fail base_image registry_unreachable "${started}"
    pass base_image "${started}" " image=caddy:builder"

    started="$(now_ms)"
    timeout 60 docker pull caddy:builder >/dev/null 2>&1 \
        || fail builder_image image_pull "${started}"
    pass builder_image "${started}" " image=caddy:builder"

    # Resolver first: a name that does not resolve is a different defect (and a
    # different owner) than a name that resolves and is then blocked.
    started="$(now_ms)"
    timeout 20 docker run --rm --entrypoint sh caddy:builder \
        -c "nslookup ${PROBE_HOST_NAME}" >/dev/null 2>&1 \
        || fail module_dns dns_failure "${started}"
    pass module_dns "${started}"

    # Single attempt: busybox wget retries by default, which would consume the
    # whole budget and hide which layer actually failed.
    started="$(now_ms)"
    timeout 20 docker run --rm --entrypoint sh caddy:builder \
        -c "wget -q -t 1 -T 10 -O /dev/null '${PROBE_URL}'" >/dev/null 2>&1 \
        || fail module_probe module_network_timeout "${started}"
    pass module_probe "${started}" " source=source_build"
fi

echo "PREFLIGHT OK: all checks passed"
