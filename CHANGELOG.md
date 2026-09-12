# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-09-12

### Added

- AmneziaWG 3.1 container installer: backend installer upgraded to AmneziaWG 3.1
  using container name `amnezia-awg2` matching the official amnezia-client
  specification, eliminating "Legacy 2.0 outdated" warnings while preserving
  full backward compatibility for existing `amnezia-awg` deployments (#119, #122)
- Extended AmneziaWG protocol parameters: support for `DisableCookies`,
  `RandomTrailers`, and `HeaderProtectionKey` propagated to server configs and
  client profile generation (#117, #120)
- Interface self-healing: automated detection and recovery (`awg-quick up`) of
  downed `awg0` interfaces during configuration synchronization (#132, #134)
- Multi-language localization: complete translations across 5 languages (EN, RU,
  FR, ZH, FA) for server protocol installation and modal titles (#130, #133)

### Changed

- Modernized `/users` management page with responsive layouts, action controls,
  and user modals (#113, #114)
- Removed incomplete and deprecated settings endpoints and navigation items
  (API Documentation and Import Users) (#115, #116)
- Pinned production Docker Compose example to `v1.1.0` release image (#112)

### Fixed

- Enforced S1..S4 >= 12 floor constraint in parameter generation under Header
  Protection, preventing `awg syncconf` failures with `Invalid argument` /
  `Protocol not supported` (#132, #134)
- Fixed AWG 3.1 server public key retrieval and config generation for
  non-default containers (#117, #118)
- Hardened server config synchronization to fail loudly with actionable error
  messages instead of silently ignoring `awg syncconf` failures (#117, #120)
- Fixed hardcoded Cyrillic strings in server protocol installation modals (#130, #133)

## [1.0.0] - 2026-09-11

First public release of amnezia-nexus, a self-hosted VPN management panel
(AmneziaWG / WireGuard) with a web UI, multi-server orchestration, and a
load-balancing mode. Everything below ships in 1.0.0.

### Added

- Web panel UI: modern responsive portal with a design system, interactive
  tables, live telemetry, dashboard, VPN and user management pages (#58, #61–#65)
- Client portal: connection creation with load-balancer mode highlighted and
  AmneziaWG pre-selected; client config creation via web UI in LB mode (#13, #70)
- Backend (server) management: add, rename, and delete backends from the UI (#29, #35)
- Load balancer: backend pool with health probing, WRR balancing, sticky
  sessions with automatic failover, and session rebalancing (#32, #33, #39, #43)
- Full AmneziaWG 3.x parameter compliance: header protection (H1–H4 ranges),
  timing ranges, and systematic spec-compliance verification against
  amneziawg-go 3.1 (#25, #33, #34, #37, #38, #49)
- Server-side CAPTCHA store with rate limits on the auth and share endpoints (#84)
- VPN endpoint auto-detection with public-IP validation (#71)
- Connections gauge and live backend connection counters in the UI (#30, #54, #74)
- Leaderboard with monthly traffic snapshots (#87)
- Packet-path performance benchmarks as a baseline for routing and token-bucket
  rate limiting (#93)
- Failure-injection test matrix covering failover, reconciliation, and
  persistence paths (#88)
- TokenBucket burst-semantics documentation with sustained, idle, and
  concurrency test coverage (#94)
- CI/CD with GitHub Actions; multi-arch Docker images published to GHCR;
  branch protection on main; automated deployments to a DEV environment (#12, #14, #72)
- Comprehensive README with overview, architecture, and setup guide (#80)

### Fixed

- VPN traffic blocked from reaching the public internet through backends
  when connected via the load balancer (#36)
- Backend NAT masquerade scoping so forwarded portal traffic works (#27)
- Return-path stalls (packet queue overflow) and failed client rekeys after a
  portal restart — unstable connections despite stable handshakes (#39, #43)
- Health prober could not handshake AmneziaWG 3.1 backends using header
  protection; H1/H2 header ranges are now preserved end-to-end (#18, #49)
- Health-probe fail counts were not reset on manual backend re-enable,
  causing instant re-disable; rebalancer also drained sessions when fewer
  than one existed (threshold math bug) (#44, #50)
- Disabled backends were immediately reactivated by the health prober /
  reconnect manager (#28)
- AWG parameter key mismatches in client device creation and tunnel probes (#26)
- VPN listen-port env variable ignored by the LB listener; editing the public
  endpoint failed behind the reverse proxy (#16)
- Backend connections counter only incremented and never decremented, showing
  stale lifetime values (#30, #54)
- Periodic reconcile of backend active connections: missed decrements on
  abrupt session ends now repaired hourly, with per-path instrumentation (#78)
- Sticky failover reworked: no database I/O under the session lock and no
  sessions silently stranded during failover (#85)
- Rekey replacement counter leak fixed: stale rows are closed and counters
  migrated on session replacement (#78)
- Authenticated peers could hijack another peer's traffic by rebinding the
  forwarder's return routes from a spoofed source IP — such rebinds are now
  rejected and counted (#89)
- Silent auto-creation of phantom per-user configs on config fetch (#77)
- Infinite recursion in CSRF token retrieval crashing login with a stack
  overflow (#68)
- Non-admin users received 403 Forbidden instead of a redirect to their portal (#11)
- Leaderboard "last month" toggle returned all-time traffic instead of the
  historical snapshot (#87)

### Security

- Session cookie Secure flag was hardcoded to false at every call site —
  replaced by one centralized policy, honoring `X-Forwarded-Proto` from
  trusted proxies so secure cookies work behind TLS-terminating proxies (#83, #100)
- Server-side CAPTCHA verification with rate limits on `/api/auth/captcha`
  and `/api/share/{token}/auth` to curb credential stuffing (#84)
- TRACE removed from the CSRF safe-method list (#95)
- Load-balancer DNS defaults moved to privacy-respecting resolvers (#42)

### Changed

- Backends UI and VPN section modernized: clean tables, metrics, and action
  controls (#101)
- Connections indicator reworked into an intuitive connector symbol (#74)
- Backend capacity serialization contract documented at every mutation and
  read path, with a stress test proving correctness under concurrency (#86)