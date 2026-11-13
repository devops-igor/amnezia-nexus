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
#     forwardproxy` has no `caddy2` branch, so the maintained klzgrad fork is
#     the only valid target. The commit below is the fork's `v2.11.7-naive2`
#     tag (the `naive` branch head), which lets authenticated tunnels idle for
#     up to 24h instead of being torn down by the HTTP idle timeout. It builds
#     against stock Caddy 2.11.9: the API it calls is upstream there, so the
#     fork's own Caddy patch is not needed.
#
# Cross-compilation: the builder stage runs on the build platform and targets
# $TARGETARCH, so the arm64 image does not require QEMU emulation of the Go
# toolchain. forwardproxy is pure Go, so CGO is off and the binary is portable.
FROM --platform=$BUILDPLATFORM caddy:2.11.9-builder AS builder
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} \
    xcaddy build \
    --with github.com/caddyserver/forwardproxy@caddy2=github.com/klzgrad/forwardproxy@e747854e78743dba85c039b38ed185fb11d93667

FROM caddy:2.11.9-alpine

COPY --from=builder /usr/bin/caddy /usr/bin/caddy

LABEL org.opencontainers.image.title="amnezia-nexus naive-caddy" \
      org.opencontainers.image.description="Caddy with NaiveProxy forward_proxy, pinned for amnezia-nexus"
