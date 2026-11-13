# Prebuilt Caddy with the NaiveProxy forward_proxy handler.
#
# Why this image exists (issue #680): the panel used to compile Caddy on the
# target host, inside the synchronous install request. A cold build on the arm64
# DEV runner measured 866s (749s of it in `xcaddy build`), far beyond the install
# budget, so every install was cancelled mid-build. Building it here, once, turns
# the install into a pull.
#
# Pinning:
#   * both base images are pinned by version, so a rebuild of the same commit
#     yields the same Caddy release;
#   * the forwardproxy replace target is pinned by commit. `caddyserver/
#     forwardproxy` has no `caddy2` branch, so the maintainted klzgrad fork is
#     the only valid target.
#
# Cross-compilation: the builder stage runs on the build platform and targets
# $TARGETARCH, so the arm64 image does not require QEMU emulation of the Go
# toolchain. forwardproxy is pure Go, so CGO is off and the binary is portable.
FROM --platform=$BUILDPLATFORM caddy:2.11.9-builder AS builder
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} \
    xcaddy build \
    --with github.com/caddyserver/forwardproxy@caddy2=github.com/klzgrad/forwardproxy@c096d6a00cb28e019cc1995b04bdc6a9311d8024

FROM caddy:2.11.9-alpine

COPY --from=builder /usr/bin/caddy /usr/bin/caddy

LABEL org.opencontainers.image.title="amnezia-nexus naive-caddy" \
      org.opencontainers.image.description="Caddy with NaiveProxy forward_proxy, pinned for amnezia-nexus"
