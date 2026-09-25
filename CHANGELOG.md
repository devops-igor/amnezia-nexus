# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.4.0] - Nebula - 2026-09-25

Minor release introducing server IP address modification via the Web UI, an embedded slide puzzle CAPTCHA, three-slot responder key modeling for seamless AmneziaWG rekey continuity, isolated handshake processing, atomic live forwarder route migration during session rebalancing, and robust remote peer lifecycle reconciliation.

### Added

- Server IP address editing: enabled administrators to update server host and IP addresses via the Web UI, featuring runtime tunnel endpoint propagation, SSH connection pool eviction, symmetrical state rollback on error, and live forwarder reconciliation (#278, #323).
- Embedded slide puzzle CAPTCHA: replaced legacy bitmap CAPTCHA with an embedded SVG slide puzzle challenge on the login screen, improving user experience and bot resistance without external dependencies (#181, #324).

### Fixed

- AmneziaWG rekey continuity: modeled responder transport keys with a three-slot architecture (previous, current, next), confirmed responder next key before outbound switch, consumed authenticated keepalives locally, and preserved logical VPN sessions across rekeys to ensure zero packet drop during rollover (#326, #328, #329, #330, #331, #332, #333, #335, #336).
- Handshake and transport isolation: decoupled cryptographic handshake parsing from transport packet workers in the UDP endpoint listener, ensuring established data plane traffic continues uninhibited during handshake storms or stalled handshakes (#82, #320).
- Live forwarder route migration during rebalancing: atomically migrated live forwarder routes, in-memory sessions, tunnel pool connection counters, and sticky affinities during VPN session rebalancing, eliminating traffic divergence to old backend devices and preserving connected session status (#289, #313).
- Remote peer rollback and zombie reconciliation: added automatic compensating rollback of remote peers on database failures using decoupled cleanup contexts, tracked peer lifecycles in SQLite, and implemented periodic background zombie peer cleanup with creation grace periods and per-server legacy peer adoption (#128, #318, #319).
- Data plane restart session invalidation: invalidated stale in-memory and database sessions on daemon startup before activating the data plane while preserving durable client IP leases in portal IPAM (#297, #314).
- Stale probe abortion on backend deletion: aborted stale probes and fenced mutations to tunnel generations after backend deletion, preventing deleted backends from being falsely reattached (#304, #312).
- Disabled migration target rejection: prevented the orchestrator from selecting disabled or degraded backend tunnels as migration targets following health probe cycles (#325).
- Self-healing E2E test SSH provisioning: added idempotent SSH key provisioning and credential fallback resolution in the dev server E2E test workflow (#316, #317).

## [1.3.2] - Orion · Patch 2 - 2026-09-24

Maintenance and stability patch release addressing VPN forwarder route lifecycle management, session teardown synchronization, and monotonic endpoint handshake fencing.

### Fixed

- Forwarder route retirement by session identity: replaced registration and unregistration counter balance accounting with explicit session ID matching (`BeginUnregisterSession(peerKey, sessionID)`), eliminating stale route removals from delayed teardowns of superseded sessions and ensuring forwarder routes are reliably retired after repeated rekeys (#309, #310).
- Monotonic endpoint handshake fencing under service lock: advanced and fenced peer handshake generation (`FencePeerGeneration`) under `Service.mu` before awaiting forwarder route retirement, immediately rejecting stale in-flight handshakes from older generations while route teardown waits for admitted device writes to drain (#309, #310).
- Unified two-phase fence and prune across teardown paths: coordinated generational fencing and delayed transport state pruning across all VPN teardown paths (`DisconnectSession`, `DisconnectUser`, `ReleaseClient`, and idle reaper `reapSession`), ensuring transport keys remain available for active return writes during route retirement and pruning transport state only after retirement finishes while guarding against concurrent reconnect replacement sessions (#309, #310).

## [1.3.1] - Orion · Patch 1 - 2026-09-24

Maintenance and stability patch release focusing on VPN data plane reliability, rekey rollover resilience, forwarder queue observability and safe runtime reconfiguration, session liveness tracking, and tunnel state synchronization.

### Added

- Forwarder queue observability: live buffer telemetry, per-route write metrics, queue capacity metrics, stall tracking, and oversized packet drop counters (`oversized_packet_drops`) (#296, #300).
- Handshake generation fence: monotonic peer generation fencing (`CommitHandshake`) in endpoint listener to eliminate out-of-order cryptographic state commits (#296, #300).
- Dynamic forwarder reconfiguration: safe runtime reconfiguration of route queues and payload memory budgets, rejecting populations that exceed active route limits (#296, #300).

### Fixed

- Rekey rollover keypair retention: retained previous transport keypair across WireGuard and AmneziaWG handshake rekeys to eliminate in-flight packet loss during rollover (#295, #301).
- Outbound transport nonce isolation: bound ChaCha20-Poly1305 outbound transport send counter directly to `TransportKeys` rather than per-address state, completely eliminating nonce reuse and client replay rejection during UDP endpoint roaming or NAT rebinding (#295, #301).
- Atomic timeout pruning: implemented generation-aware transport state pruning under listener lock to prevent idle sweeps from deleting newly committed replacement sessions, indexes, or addresses (#295, #301).
- Data plane session liveness: refreshed session timestamps upon successful transport decryption with a 2-second atomic CAS throttle, preventing active clients from being falsely reaped as idle (#294, #298).
- Sticky affinity retention: preserved sticky session affinity across idle sweeps, delegating lifecycle management to StickyManager TTL expiration and preventing egress IP changes on reconnect (#294, #298).
- Memory reclamation for expired affinities: implemented physical reclamation of expired sticky session records in a post-sweep hook and the gauge reconciler without lock contention (#294, #298).
- Administrative tunnel disable protection: guarded administrative disable state against concurrent health probe races using CAS updates in failure handlers (#284, #291).
- Health probe auto-disable CAS reconciliation: added `reconcileThresholdAutoDisable` helper to reconcile out-of-order failure transitions and maintain self-healing eligibility (#284, #291).
- Tunnel state version synchronization: wired tunnel status updater across both normal and TUN-unavailable management modes to synchronize state versions between in-memory pool and database (#285, #292).
- Orchestrator database fallback restriction: restricted direct database CAS fallbacks strictly to uninitialized pool errors (`tunnel.ErrTunnelNotFound`) (#285, #292).
- Endpoint listener handshake rejection telemetry: excluded unroutable non-initiation datagrams and short packets from `handshake_rejections` metric and throttled logs, confining increments strictly to genuine cryptographic handshake failures (#288, #290).
- Transport packet disambiguation: disambiguated transport packets with H4 framing before initiation parsing to prevent packet loss when payload bytes match handshake headers (#288, #290).
- Curve25519 token regex false positives: tightened Fernet token regular expression to require `^gAAAAA` prefix and minimum 70-character length, eliminating false positives on raw base64 Curve25519 private keys (#296, #300).

## [1.3.0] - Orion - 2026-09-23

Major feature release introducing backend self-healing reconciliation, sticky session affinity TTL, upstream AmneziaWG release monitoring and admin visibility, periodic server resource telemetry polling, automated Playwright E2E verification, and compatibility policy governance.

### Added

- Self-healing reconciliation: background periodic health sweeps, flap damping, and automated re-activation of healthy backend servers with persistent disable provenance and two-phase atomic state transitions (#279, #282).
- Sticky session affinity TTL: configurable session affinity duration (default 30 minutes) with automatic eviction of expired affinities to balance returning client connections (#281, #283).
- Upstream release monitoring: automated tracking of upstream amneziawg-go, amneziawg-tools, and Docker base images with admin visibility in Settings, daily scheduled monitor workflow, and GET /api/system/upstream-status endpoint (#242, #270).
- Periodic server telemetry polling: dynamic resource monitoring (CPU, RAM, disk, network) in the server dashboard via Telemetry.poll streams with tab-visibility awareness and in-flight request guards (#206, #232).
- End-to-end integration test suite: in-tree Playwright test suite covering onboarding, protocol installation, session handling, settings, and full lifecycle automation (#246, #247, #264, #265).
- Automated CI DEV verification: hardware-locked E2E verification workflow on self-hosted ARM64 runners with clean-slate volume teardown and ephemeral environment overrides (#240, #248, #266).
- Compatibility policy: formalized and adopted the Amnezia Nexus Compatibility Policy in `useful_notes/COMPATIBILITY.md`, defining HTTP API, Go internal, frontend, and data migration lifecycles (#263, #275).

### Changed

- Portal stylesheet cleanup: pruned dead CSS selectors and orphaned pulse-dot animation rules from the portal stylesheet (#250, #251, #252, #253, #254, #255, #256, #267).
- Router template shims: removed unused template compatibility shims from router initialization (#249, #269).

### Fixed

- Idle session reaper teardown: eliminated race conditions and deadlocks in the session idle reaper by removing lock inversion, synchronizing lifecycle mutations, and verifying session generation before clearing affinities (#281, #283).
- Upstream version comparison and status reporting: aligned version comparison with SemVer 2.0.0 prerelease precedence rules, fixed partial-failure cache poisoning, and added degraded health badges (#273, #274).
- Remote lock release race: eliminated concurrent `.gate` directory deletion in `remoteLockReleaseCmd` that caused flaky `ENOTEMPTY` errors and lock release failures under acquisition contention (#263, #275).
- SSH command empty password handling: avoided typed nil pointer boxing in RunSudoCommand and added defensive reflection checks in SSH session setup (#248, #266).

### Removed

- Frontend compatibility aliases: removed unused `window.apiCall`, `window.confirmModal`, and `window.DataTable` aliases in favor of `API`, `UI`, and `NexusTable` per `useful_notes/COMPATIBILITY.md` §4.2 (#257, #258, #259, #280).
- Legacy internal/vpn constructors: removed unused compatibility shims `NewService`, `NewLeastConnectionsLoadBalancer`, and type alias `LeastConnectionsLoadBalancer` per `useful_notes/COMPATIBILITY.md` (#260, #276).

## [1.2.1] - Polaris - 2026-09-21

Maintenance and stability release introducing ARM64 AWG container support, removing legacy speed limits, hardening cross-process concurrency and peer rollback, and fixing session invalidation on password changes.

### Fixed

- ARM64 AmneziaWG installation: pinned multi-arch base image v3.1.20260828-1 and added preflight port validation to prevent container failures on ARM64 hosts (#225, #231).
- Session invalidation: bumped session version on admin password reset to terminate existing user sessions across devices (#171, #228).
- AWG parameter collision: synchronized static default parameters to satisfy S1/S2 packet length difference invariants and prevent handshake failures (#227, #233, #234, #235).
- Remote process concurrency: secured multi-process execution, improved peer rollback handling, and stabilized lease re-keying (#186).
- Endpoint ordering: enforced deterministic sorting for active session snapshots (#219).

### Changed

- Speed limit removal: retired legacy client speed limiting and migrated traffic control cleanup into container execution boundaries (#225, #231).
- Active sessions UI: simplified table layout by removing unmetered traffic columns (#189, #218).

## [1.2.0] - Polaris - 2026-09-19

Feature release introducing admin load balancer session visibility, revocable user sessions with session versioning, atomic IP allocation for AmneziaWG clients, remote command shell escaping, and header protection range exclusivity.

### Added

- Admin load balancer session visibility: real-time visibility into active user sessions across backend servers, memory-authoritative session tracking, connection configuration display, monotonic traffic accounting, and peer public key identity resolution (#189, #204, #210, #214).
- Revocable user sessions: per-user session version tracking to instantly invalidate active sessions on password change, along with a dedicated logout-all endpoint (#97, #169).
- Atomic IP allocation: dedicated allocation table with concurrency locking and transaction safety to eliminate duplicate IP provisioning under concurrent requests (#126, #172).

### Security

- Remote command sanitization: strict shell escaping and argument validation across remote SSH and Docker execution boundaries (#124, #170).
- AmneziaWG header validation: enforced mutual exclusivity across H1-H4 header ranges to prevent fallback to un-obfuscated WireGuard headers (#127, #168).

### Changed

- Increased user management cards per page from 10 to 12 for three-column grid layouts (#176, #178).
- Removed deprecated and non-functional Connection Kit feature (#179, #187).

## [1.1.4] - Aurora - 2026-09-16

Amnezia Nexus 1.1.4 ("Aurora") is a patch release optimizing upstream packet forwarding
performance and buffer sizing, enforcing AmneziaWG handshake packet length invariants,
stabilizing race detector tests under CI, and migrating module imports.

### Performance

- Decoupled endpoint listener UDP read loop from transport decryption via a bounded worker pool (eliminating per-packet SetReadDeadline syscalls), enlarged VirtualTUN buffer capacity to 2048 packets, tuned backend AWG UDP socket buffers to 4 MB (SO_RCVBUF and SO_SNDBUF) via TunedBind, and added ingress drop accounting (#160).

### Fixed

- Enforced AmneziaWG S1/S2 packet length invariant (|s1 - s2| >= 10 and s2 != s1+56 && s1 != s2+56) in GenerateStandardObfuscationValues and GenerateAWGParams across all profiles, and in ValidateAWGParams, preventing cryptographic handshake failure caused by Initiation (148B) and Response (92B) packet size collisions (#125).
- Stabilized TestListener_ConcurrentHighThroughputStream delivery threshold (90%) and sender pacing (75us) under the race detector on shared 2-core CI runners (#165).

### Refactor

- Migrated Go module path and package imports across the entire repository to github.com/devops-igor/amnezia-nexus (#161).

## [1.1.3] - Aurora - 2026-09-16

Amnezia Nexus 1.1.3 ("Aurora") is a patch release improving downstream packet forwarding
performance and UDP socket buffer sizing, adding backend tunnel health check retry thresholds,
rate-limiting transport decryption failure logging, returning proper HTTP 404/400 status codes
for missing client connection configs, and sanitizing MTProxy links.

### Performance

- Downstream return queue capacity enlarged to 2048 packets and 4 MB SO_RCVBUF/SO_SNDBUF socket buffers on endpoint listener (#151); SendToPeer return hot path optimized with cached UDP addresses and pre-instantiated AEAD ciphers (#151).

### Resilience

- Backend tunnel health check retry threshold (default 3 consecutive failures) in orchestrator to prevent false failovers on transient WAN packet loss (#152).

### Fixed

- Rate-limited transport decryption failure logging and decoupled decryption failures from handshake rejection counters in endpoint listener (#148, #149); returned HTTP 404 Not Found and 400 Bad Request instead of 500 when client connection configs are not found (#150); stripped ANSI escape sequences and sanitized trailing formatting artifacts from generated MTProxy links in mtproxyl manager (#157).

## [1.1.2] — Aurora - 2026-09-15

Amnezia Nexus 1.1.2 ("Aurora") is a patch release fixing WireGuard/AmneziaWG routing
table hijack and routing loops on server reboot, Server #0 user connection configuration
deletion and retrieval, streamlining the CI/CD pipeline, and cleaning up repository history.

### Fixed

- WireGuard/AmneziaWG post-reboot routing table hijack: added `Table = off` to server
  interface configurations, automated config sanitization on disk, scoped portal peer
  AllowedIPs to portal subnet CIDR, and added defensive startup cleanup for stale
  table 51820 policy rules and route tables, preventing routing loops and packet
  loss after container or node reboots (#139, #140)
- Server #0 connection management: supported Server ID 0 (virtual cluster / auto load-balanced
  servers) in connection deletion and configuration retrieval handlers, added orphaned
  connection cleanup, and updated Web UI labeling to "Cluster (Auto)" (#138, #137)

### Changed

- Streamlined CI/CD pipeline: removed automated downstream CD/SSH deployment workflow
  in favor of focused CI validation and automated multi-arch container image publishing
  to GHCR (#141, #142)
- Repository hygiene: completely purged legacy `docs/` and `deploy/` directories from
  git history across all commits and added both to `.gitignore` (#143, #144)

## [1.1.1] — Aurora - 2026-09-13

Amnezia Nexus 1.1.1 ("Aurora") is a patch release resolving HTTP/2 connectivity
failures across VPN forwarding paths, backend enabling timeout vulnerabilities,
and server configuration parsing.

### Fixed

- HTTP/2 Path MTU black hole: enabled TCP MSS clamping (`--clamp-mss-to-pmtu`)
  on backend forward path and aligned default MTU to 1280, resolving connection
  timeouts and protocol errors on HTTP/2 traffic while preserving existing client
  configs (#136)
- Backend enabling timeout resilience: decoupled `/api/vpn/backends/{id}/enable`
  from client request cancellation with a bounded 45s deadline, bypassed redundant
  NAT rules on probe peers, and batched container routing/NAT rules into a single
  compound SSH execution (#48, #135)
- Server config parsing: stripped inline comments (`#` and `;`) and skipped
  full-line semicolon comments in `ParseServerConfig` (#129, #131)

## [1.1.0] — Aurora - 2026-09-12

Amnezia Nexus 1.1.0 ("Aurora") upgrades backend server deployments to AmneziaWG 3.1
with modern container naming (`amnezia-awg2`), preventing "Legacy 2.0 outdated" warnings
in official Amnezia clients, adds interface self-healing, multi-language localization,
and built-in release version and codename reporting.

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
- Application release reporting: `--version` / `-v` CLI flags, startup logging,
  and web UI console badges displaying the active version and codename

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