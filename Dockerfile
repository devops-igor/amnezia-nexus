# =============================================================================
# Stage 1: Build Stage (Statically compiled Go binaries)
# =============================================================================
ARG GO_VERSION=1.26.10
FROM golang:${GO_VERSION}-alpine AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache ca-certificates git

# Cache Go modules first for faster incremental builds
COPY go.mod go.sum ./
RUN go mod download

# Copy Go codebase
COPY . .

# Build stripped statically linked production binary with CGO disabled
RUN CGO_ENABLED=0 go build -tags with_utls -trimpath -ldflags="-s -w" -o /build/bin/panel ./cmd/panel

# =============================================================================
# Stage 2: Production Stage (Lean Alpine runtime ~41MB)
# =============================================================================
FROM alpine:3.24

WORKDIR /app

# Install minimal runtime dependencies:
# - ca-certificates: TLS verification for remote HTTPS
# - tzdata: accurate timezone support
# - iproute2: IP & interface management for TUN devices (ip link, ip addr)
# - iptables: NAT / packet forwarding rules for VPN endpoint
# - curl: HTTP healthcheck probe
# - libgcc: dynamic loader runtime dependency for upstream native binaries (libgcc_s.so.1)
RUN apk add --no-cache \
        ca-certificates \
        tzdata \
        iproute2 \
        iptables \
        curl \
        libgcc && \
    addgroup -S -g 1000 appgroup && \
    adduser -S -u 1000 -G appgroup appuser

# Copy panel binary from builder stage and create server symlink.
COPY --from=builder /build/bin/panel /app/panel
RUN ln -s /app/panel /app/server

# Setup runtime directories and permissions:
# - /app/data: persistent SQLite database (panel.db), keyfile (.secret_key), backups
# - /var/run/amneziawg: userspace AWG control sockets
# - /dev/net: TUN device directory mount point
RUN mkdir -p /app/data /var/run/amneziawg /dev/net && \
    chown -R appuser:appgroup /app/data /var/run/amneziawg

# File capabilities for the executable, applied AFTER any chown.
#
# Order is load-bearing: a recursive chown rewrites ownership metadata and clears
# the security.capability xattr, so granting capabilities before an owning chown
# silently produces an uncapable binary — the non-root process then fails TUN and
# AF_PACKET with EPERM even though `cap_add` is set on the container.
#
# The binary is non-root (USER appuser), so BOTH capabilities are required, and
# both must also be present in the container's capability bounding set or
# execve(2) itself fails with EPERM (the kernel refuses to execute a
# capability-dumb binary whose file capabilities it cannot grant):
#   cap_net_admin -- create/configure the TUN device, iptables rules, sysctls
#   cap_net_raw   -- open the AF_PACKET socket that captures direct-WAN replies
# Grant them at runtime with `cap_add: [NET_ADMIN, NET_RAW]` (see README).
# This must remain the last operation that touches /app/panel.
RUN apk add --no-cache libcap && \
    setcap cap_net_admin,cap_net_raw+ep /app/panel && \
    apk del libcap

# Expose ports: 5000 (HTTP Web Panel & API), 51820/udp (AmneziaWG VPN Endpoint)
EXPOSE 5000/tcp
EXPOSE 51820/udp

# Healthcheck probe verifying HTTP responsiveness via dedicated health endpoint
HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=20s \
    CMD curl -sf http://127.0.0.1:5000/api/health || exit 1

# Run as non-root user (capabilities granted at container level via compose cap_add)
USER appuser

# ENTRYPOINT names the binary so `docker run <image> --flag` passes the flag to the
# panel instead of trying to exec it as a program. With only CMD, the first
# argument of `docker run` replaces CMD wholesale, which broke the image
# capability smoke (`docker run <image> --check-wan-capabilities` resolved to
# `exec --check-wan-capabilities` and failed with 127).
ENTRYPOINT ["/app/panel"]

# Default command: launch Amnezia Web Panel (arguments after the image name are
# appended to the entrypoint).
CMD []

