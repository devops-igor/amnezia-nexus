# Amnezia Nexus Compatibility Policy

**Document Status:** Normative Policy  
**Effective Version:** v1.2.0  
**Target Audience:** Core Maintainers, Integration Developers, System Administrators  
**Tracking Issue:** #263 (derived from Architecture Audit A-15 / PR #244)

---

## 1. Purpose & Scope

Amnezia Nexus is a specialized, self-hosted web panel and load balancer designed for AmneziaWG and anti-censorship environments. To ensure long-term maintainability, operational reliability, and seamless upgrade paths for node administrators, this document establishes the binding compatibility policy for all components of the Amnezia Nexus platform.

This policy defines:
- The public HTTP REST API stability contract, supported canonical route families, and alias retirement rules.
- The architectural boundary and zero-stability guarantee for Go internal packages (`internal/*`).
- The private scope of frontend JavaScript globals and UI implementation details (`web/*`).
- The rolling upgrade window and data preservation invariants for database migrations, configuration files, container naming, and cryptographic credentials.
- The governance and pull request process required when deprecating or retiring compatibility shims.

By formalizing these guarantees, this policy prevents accidental compatibility regressions, clarifies public integration boundaries, and unblocks targeted technical debt retirement across the codebase.

---

## 2. HTTP REST API Stability & Route Policies

### 2.1 Canonical Route Families

The Amnezia Nexus HTTP API is categorized into canonical route families. Canonical routes constitute the supported interface for external clients, automation scripts, and the official web interface:

1. **Authentication & Session Lifecycle (`/api/auth/*`)**
   - Endpoints: `/api/auth/login`, `/api/auth/setup`, `/api/auth/change-password`, `/api/auth/logout-all`, `/api/auth/captcha`.
   - Purpose: Handles initial setup, credential verification, captcha challenges, session versioning, and credential revocation.
2. **User Client Connections (`/api/connections/*`)**
   - Endpoints: `/api/connections`, `/api/connections/add`, `/api/connections/{connection_id}/config`, `/api/connections/{connection_id}/rename`, `/api/connections/{connection_id}/delete`.
   - Purpose: Authenticated self-service connection management for regular users.
3. **Administrative Server & Node Management (`/api/servers/*`, `/api/admin/*`)**
   - Endpoints: `/api/servers`, `/api/servers/add`, `/api/servers/confirm-fingerprint`, `/api/servers/{server_id}/*` (including rename, delete, reboot, clear, stats, check, install, uninstall, container toggling, reachability, and protocol configuration).
   - Purpose: Management of backend nodes, SSH credentials, remote protocol deployment, and telemetry.
4. **Administrative User Management (`/api/users/*`, `/api/admin/*`)**
   - Endpoints: `/api/users`, `/api/users/add`, `/api/users/{user_id}/update`, `/api/users/{user_id}/delete`, `/api/users/{user_id}/toggle`, `/api/users/{user_id}/connections/*`, `/api/users/{user_id}/share/setup`.
   - Purpose: Account provisioning, role assignments, quota configurations, and share link management.
5. **System & Operational Health (`/api/system/*`, `/api/health`, `/api/version`)**
   - Endpoints: `/api/system/upstream-status`, `/api/health`, `/api/version`.
   - Purpose: Upstream component tracking (amneziawg-go, amneziawg-tools, base images), liveness/readiness probes, and daemon build version metadata.
6. **VPN Load Balancing & Subsystem (`/api/vpn/*`)**
   - Endpoints: `/api/vpn/status`, `/api/vpn/sessions`, `/api/vpn/backends`, `/api/vpn/backends/{server_id}/*`, `/api/vpn/tunnels`, `/api/vpn/config`, `/api/vpn/disconnect`, `/api/vpn/my-connection`, `/api/vpn/my-config`.
   - Purpose: In-process WireGuard/AmneziaWG packet listener, session routing, tunnel management, and backend health observation.
7. **Administrative Settings & Disaster Recovery (`/api/settings/*`, `/api/admin/*`)**
   - Endpoints: `/api/settings`, `/api/settings/save`, `/api/settings/backup/download`, `/api/settings/backup/restore`.
   - Purpose: Global system settings, proxy configuration, and complete database backup/restore operations.
8. **Public & Share Portals (`/api/share/*`, `/api/leaderboard`)**
   - Endpoints: `/api/share/{token}/auth`, `/api/share/{token}/connections`, `/api/share/{token}/config/{connection_id}`, `/api/leaderboard`.
   - Purpose: Tokenized user onboarding and bandwidth utilization leaderboards.

### 2.2 Semantic Versioning Contract

All canonical routes follow Semantic Versioning 2.0.0 (`MAJOR.MINOR.PATCH`):

- **Major Releases (vX.0.0):** Breaking changes to canonical endpoints are restricted to major version bumps. Breaking changes include removing canonical routes, altering required request payloads, renaming response fields, changing HTTP response status codes, or fundamentally altering endpoint semantics.
- **Minor Releases (v1.X.0):** Additive, backward-compatible modifications occur in minor releases. These include introducing new endpoints, supporting optional request parameters, and returning additional non-breaking fields in JSON responses.
- **Patch Releases (v1.2.X):** Strictly reserved for bug fixes, performance improvements, and security patches. No functional contract modifications or route additions are introduced in patch releases.

### 2.3 Immediate Retirement of Transient Route Aliases in v1.2.0

During the rapid evolution of the panel architecture, several temporary convenience aliases were introduced alongside canonical routes:
- Duplicate root server-management routes (`POST /add`, `POST /confirm-fingerprint`, `POST /{server_id}/*` mounted directly on the root path).
- The duplicate user connection group (`/api/my/connections/*` duplicating `/api/connections/*`).

**Policy Verdict:**
These transient route aliases are scheduled for **immediate retirement in v1.2.0** without a multi-release deprecation window:
1. *Non-Contractual Nature:* These aliases were never documented or published as supported external API contracts. They existed solely as transitory shims during template refactoring.
2. *Zero Modern Frontend Consumption:* Audit verification confirms that the current web interface (`web/templates/*`, `web/static/js/*`) exclusively calls canonical routes (`/api/servers/*` and `/api/connections/*`).
3. *Security & Router Clarity:* Duplicate routing masks rate-limiting boundaries, complicates role-based authorization middleware, and introduces maintenance overhead.
4. *Unblocking Roadmap:* This decision directly unblocks Issue #260 (root server-management alias removal) and Issue #261 (`/api/my/connections/*` alias removal), addressing Finding A-13 from the portal code audit.

### 2.4 Future Deprecation Schedule

For any future planned changes to *canonical* routes:
1. The route must be marked as deprecated in `useful_notes/COMPATIBILITY.md` and `CHANGELOG.md` for at least one minor release cycle before removal.
2. Deprecated endpoints should return a standard `Warning` or `Sunset` HTTP header where feasible.
3. Automated test suites must verify both the deprecated route and its replacement during the transition window.

---

## 3. Internal Go Architecture (`internal/*`)

### 3.1 Standard Go Internal Package Boundaries

By design of the Go toolchain, any package situated under an `internal/` directory tree (for example, `internal/vpn`, `internal/service`, `internal/handlers`, `internal/database`, `internal/router`, `internal/models`, `internal/security`) cannot be imported by external Go modules.

**Policy Verdict:**
- Packages under `internal/*` provide **zero stability guarantees** to external consumers.
- Maintainers are explicitly permitted to refactor, restructure, rename, split, or remove Go packages, types, interfaces, constructors, and function signatures across minor and patch releases without notice.
- Internal code quality is governed by internal unit, integration, and race detector tests (`go test -race ./...`), rather than backward-compatibility retention.

### 3.2 Internal Legacy Construct Pruning

Over previous versions, several legacy constructor functions and type aliases were retained in `internal/vpn/vpn.go` for historical tests:
- `vpn.NewService(algo)` (legacy constructor superseded by `vpn.NewVPNService`)
- `vpn.LeastConnectionsLoadBalancer` (legacy type alias)
- `vpn.NewLeastConnectionsLoadBalancer()` (legacy constructor superseded by `loadbalancer.NewLoadBalancer`)

**Policy Verdict:**
- Because these constructors exist solely inside `internal/vpn` and are not utilized in production daemon startup (`cmd/server/main.go` and `cmd/panel/main.go`), they are classified as dead compatibility debt.
- They may be pruned immediately in a single-purpose refactoring PR, with test files updated to invoke current constructors.
- This decision directly unblocks Issue #262 (dynamic call-graph test and safe deprecation path for `internal/vpn`), addressing Finding A-12 from the portal code audit.

---

## 4. Frontend Globals & UI JavaScript Contracts

### 4.1 Private Implementation Surface

The JavaScript assets embedded in `web/static/js/*` and referenced in Go HTML templates (`web/templates/*`) constitute a private presentation layer tailored specifically for the Amnezia Nexus web interface:
- Global window namespaces: `window.UI`, `window.API`, `window.Theme`, `window.Notifications`, `window.NexusTable`, `window.Telemetry`.
- Global DOM helper functions: `escapeHtml`, `escapeJs`, `openModal`, `closeModal`, `copyToClipboard`, `formatBytes`, `downloadFile`, `showToast`.
- Global table objects and methods: `NexusTable`, `DataTable`, pagination helpers.

**Policy Verdict:**
- Frontend JavaScript objects and global variables carry **zero external contract or third-party integration stability**.
- Amnezia Nexus does not support external user scripts, custom third-party themes, or browser extension APIs relying on internal window globals.
- Maintainers may freely refactor, encapsulate, rename, or modularize frontend JavaScript as needed to optimize UI performance, security, and maintainability.

### 4.2 Maintenance vs. Pruning Guidelines

1. **Active Template Call Surface (Retain):** As identified in the code audit (Finding A-10 correction), bare global helper functions (e.g., `escapeHtml`, `openModal`, `closeModal`, `formatBytes`, `downloadFile`, `escapeJs`, `copyToClipboard`, `showToast`) are actively referenced by 160+ call sites across live server, user, connection, and VPN templates. These functions represent the active, supported template call surface and must remain intact until a structured template refactoring is scheduled.
2. **Dead Compatibility Aliases (Prune):** Unreferenced legacy aliases created for backward compatibility with older UI drafts (e.g., `root.DataTable = NexusTable` in `web/static/js/tables.js`, dead `root.confirmModal` in `web/static/js/ui.js`, and `root.apiCall` in `web/static/js/api.js`) have no live callers and may be pruned immediately.
3. **Unblocking Roadmap:** This decision directly unblocks Issue #257 (removal of `window.apiCall` and stale global aliases, Finding A-09), Issue #258 (removal of unused DOM-finding helpers, Finding A-10), and Issue #259 (removal of `DataTable` legacy alias and dead pagination methods, Finding A-11).

---

## 5. Data Storage & Migration Compatibility

### 5.1 Rolling Two-Minor-Version Upgrade Window

Amnezia Nexus guarantees seamless, direct automated upgrades across a **rolling two-minor-version window**:
- Direct upgrades to `v1.2.x` are supported from `v1.0.x` and `v1.1.x`.
- Direct upgrades to `v1.3.x` support `v1.1.x` and `v1.2.x`.
- Direct upgrades to `v1.4.x` support `v1.2.x` and `v1.3.x`.
- Upgrading across gaps larger than two minor versions (for example, upgrading from `v0.9.x` directly to `v1.2.x`) may require stepping through an intermediate minor release (such as upgrading first to `v1.1.x`).

### 5.2 SQLite Database Schema Migrations

- All database schema updates (`internal/database/schema.sql`, `internal/database/migrate.go`, and dynamic migration routines) must be strictly additive and backward-compatible throughout the two-minor-version support window.
- Schema migrations run automatically upon daemon initialization within an atomic SQLite transaction.
- Existing database columns and tables must not be renamed or dropped within the active support window. Instead, new fields must provide sensible default values or allow NULL entries to ensure compatibility with pre-existing database files (`panel.db`).

### 5.3 Legacy Data & Configuration Invariants

The following compatibility shims and data structures remain protected under the two-minor-version guarantee:
1. **Legacy `data.json` Migration:** Automated migration from the pre-SQLite `data.json` flat-file format is maintained on daemon startup when an existing JSON data file is detected without an initialized SQLite database.
2. **Cryptographic Password Hash Compatibility:** The authentication subsystem must continue to support verifying legacy password hashes (including legacy PBKDF2/SHA256 from earlier implementations, bcrypt, and argon2id). Upon successful authentication with a legacy hash format, the credential is automatically and transparently re-hashed using the current Argon2id security standard without disrupting the user session.
3. **Container Naming Invariants (`amnezia-awg` and `amnezia-awg2`):** Modern AmneziaWG 3.1 containers deploy under the container name `amnezia-awg2` to avoid legacy client warnings. The server management subsystem must continue to discover, manage, inspect, and cleanly uninstall legacy `amnezia-awg` containers on existing nodes across the two-minor-version window.
4. **Protocol & Obfuscation Aliases:** Legacy protocol identifiers (such as `amnezia-wireguard`, `awg`) and legacy obfuscation parameter mappings must remain recognized during server configuration rendering and parsing across the support window.

---

## 6. PR & Governance Process

To prevent accidental regressions and maintain documentation integrity, all future pull requests that alter, deprecate, or remove compatibility shims must adhere to the following governance rules:

1. **Explicit Policy Citation:** Any pull request removing a route alias, deprecating an endpoint, pruning internal compatibility constructors, or cleaning up frontend globals must explicitly reference `useful_notes/COMPATIBILITY.md` and cite the applicable policy section in the PR description.
2. **Changelog Documentation:** Every change altering an external boundary or retiring a compatibility alias must include a clear, descriptive entry under the appropriate section in `CHANGELOG.md` (`Removed`, `Deprecated`, `Changed`, or `Added`).
3. **Automated Test Validation:** PRs retiring route aliases must include automated tests asserting that retired paths return HTTP 404 (or appropriate deprecation response) and that canonical routes continue to function flawlessly.
4. **Compilation & Quality Gate Compliance:** All changes must pass all compilation gates cleanly with exit code 0:
   - `go fmt ./...`
   - `go vet ./...`
   - `go build ./...`
   - `go test -race ./...`
   - `golangci-lint run ./...`
   - `gosec -quiet ./...`
   - `govulncheck ./...`
5. **Invariant Adherence:**
   - Zero em dash characters in code, commits, task files, or documentation (use normal hyphens, colons, or parentheses).
   - Zero real server IP addresses (use logical identifiers such as Server 1, DEV, or standard documentation RFC ranges).
   - Zero absolute local filesystem paths (always use repository-relative paths).

---

## 7. Compatibility Policy Summary Matrix

| Subsystem | Surface | Stability Contract | Retirement Policy | Blocked Issues Unblocked |
| :--- | :--- | :--- | :--- | :--- |
| **HTTP REST API** | Canonical route families (`/api/auth/*`, `/api/connections/*`, `/api/servers/*`, `/api/users/*`, `/api/settings/*`, `/api/system/*`, `/api/vpn/*`, `/api/share/*`) | SemVer 2.0.0 (breaking changes require major version bump) | Deprecation warning for at least 1 minor release prior to removal | Standard API lifecycle |
| **HTTP Route Aliases** | Transient root server routes (`POST /add`, etc.) and `/api/my/connections/*` | No external contract; transient shims | Immediate retirement in v1.2.0 | #260 (root server aliases), #261 (`/api/my/connections/*`) |
| **Internal Go Packages** | All code under `internal/*` (`internal/vpn`, `internal/service`, `internal/handlers`, etc.) | Zero stability guarantee; strictly private to module | Refactored or pruned freely across minor and patch releases | #262 (pruning `internal/vpn` legacy constructors) |
| **Frontend Globals** | Global window namespaces (`window.UI`, `window.API`, `window.DataTable`, etc.) | Zero external contract; private presentation layer | Dead aliases pruned immediately; live globals maintained for templates | #257 (`window.apiCall`), #258 (dead DOM helpers), #259 (`DataTable` alias) |
| **Data & Storage** | SQLite schemas, `data.json` migration, password hashes, container names | Guaranteed direct upgrade across rolling 2 minor versions | Retained for minimum 2 minor versions | Continuous automated upgrade guarantee |
