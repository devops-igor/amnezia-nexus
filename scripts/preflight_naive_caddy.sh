#!/usr/bin/env bash
# Preflight: prove the Naive Caddy image can still be obtained, before the
# Playwright suite spends four 120-second install timeouts discovering it cannot.
#
# Why this exists (issue #680): NaiveManager.Install compiles Caddy from source on
# the target host, inside the synchronous install request. That build resolves
# github.com/caddyserver/forwardproxy@caddy2 through proxy.golang.org, and when
# that endpoint is unreachable the build fails and every multiprotocol-client
# test fails with a generic install_failed or a client timeout.
#
# The preflight checks the same inputs the build needs, one bounded step at a
# time, and prints a closed reason so the failure is attributable from the log:
#
#   PREFLIGHT OK: check=<name> duration_ms=<n>
#   PREFLIGHT FAILED: check=<name> reason=<closed> duration_ms=<n>
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

now_ms() { date +%s%3N; }

started="$(now_ms)"

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

started="$(now_ms)"
timeout 30 docker info >/dev/null 2>&1 || fail docker_daemon docker_unavailable "${started}"
pass docker_daemon "${started}"

if [ -n "${IMAGE}" ]; then
    started="$(now_ms)"
    timeout 90 docker pull "${IMAGE}" >/dev/null 2>&1 || fail image_pull image_pull "${started}"
    pass image_pull "${started}" " image=${IMAGE}"

    started="$(now_ms)"
    modules="$(timeout 60 docker run --rm "${IMAGE}" caddy list-modules 2>/dev/null)" \
        || fail image_run image_run "${started}"
    grep -qx "${MODULE}" <<<"${modules}" || fail image_modules module_missing "${started}"
    pass image_modules "${started}" " source=pinned_image module=${MODULE}"
else
    started="$(now_ms)"
    timeout 60 docker manifest inspect caddy:builder >/dev/null 2>&1 \
        || fail base_image registry_unreachable "${started}"
    pass base_image "${started}" " image=caddy:builder"

    # The Go module proxy is reached from inside the builder image, because that
    # is the network path (and DNS) the build itself uses.
    started="$(now_ms)"
    timeout 60 docker run --rm --entrypoint sh caddy:builder \
        -c "wget -qO- --timeout=15 '${PROBE_URL}' >/dev/null" >/dev/null 2>&1 \
        || fail module_probe module_network_timeout "${started}"
    pass module_probe "${started}" " source=source_build"
fi

echo "PREFLIGHT OK: all checks passed"
