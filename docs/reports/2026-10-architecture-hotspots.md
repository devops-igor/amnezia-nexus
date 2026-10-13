# Architecture Hotspots and Maintainability Inventory Report

**Repository**: amnezia-nexus  
**Baseline Metric Ceilings**: Strict Ceiling = 1,000 lines | Warning Threshold = 500 lines  
**Total Tracked Non-Task Files**: 480 | **Total Analyzed Lines**: 213,742  

---

## 1. Executive Summary

This inventory establishes an empirical baseline of oversized monolithic files, dependency concentration, and change churn frequency across the repository. It supports **Epic #475** (*Incremental decomposition of monolithic Go, frontend, and test files*) by pinpointing files that present the highest risk of merge conflicts, cognitive overload, and regression velocity.

| Metric Category | Value | Percentage | Description |
|---|---:|---:|---|
| **Ceiling Violations (>=1,000 lines)** | **43** | 9.0% | Presumptive merge-blocker candidates requiring decomposition |
| **Warning Threshold (500-999 lines)** | **85** | 17.7% | Approaching ceiling; ratcheted against further expansion |
| **Nominal (<500 lines)** | **352** | 73.3% | Healthy modular files meeting maintainability standards |
| **Total Evaluated Files** | **480** | 100.0% | Excluding tasks/, test-artifacts/, .venv/, node_modules |

### Risk Tier Distribution

- **CRITICAL Risk (13 files)**: Monoliths with high 30d/90d churn or extreme line counts (>=4,000 lines). Urgent decomposition targets.
- **HIGH Risk (44 files)**: Files exceeding 1,000 lines or 500+ line files undergoing frequent changes.
- **MEDIUM Risk (109 files)**: Moderately sized files (500-1,000 lines) or smaller active modules.
- **LOW Risk (314 files)**: Well-contained modules with stable change frequency.

---

## 2. Component Inventory Breakdown

| Component | Total Files | Total Lines | Ceiling Violations (>=1k) | Warning (500-999) | 30d Churn | 90d Churn | Largest File (Lines) |
|---|---:|---:|---:|---:|---:|---:|---|
| **Test Suites** | 278 | 129,758 | 27 | 51 | 798 | 1084 | `internal/vpn/vpn_test.go` (6,739) |
| **Go Core VPN** | 46 | 20,433 | 4 | 8 | 297 | 353 | `internal/vpn/vpn.go` (4,950) |
| **Web Templates** | 13 | 10,957 | 3 | 3 | 65 | 125 | `web/templates/vpn.html` (3,758) |
| **Go Production (Database & Infra)** | 33 | 10,748 | 3 | 4 | 129 | 191 | `internal/models/models.go` (1,175) |
| **Go Production (WireGuard Manager)** | 23 | 9,802 | 2 | 2 | 47 | 114 | `internal/manager/awg/awg.go` (3,287) |
| **Go Production (Handlers & Router)** | 18 | 7,260 | 1 | 5 | 96 | 149 | `internal/handlers/servers.go` (1,169) |
| **Scripts & Tooling** | 9 | 3,989 | 1 | 2 | 48 | 49 | `scripts/run_non_netstack_client_qualification.sh` (1,025) |
| **Packet Forwarder** | 12 | 3,869 | 1 | 0 | 80 | 88 | `internal/vpn/forwarder/forwarder.go` (1,886) |
| **CSS Styles** | 1 | 3,008 | 1 | 0 | 2 | 12 | `web/static/css/style.css` (3,008) |
| **Go Production (Services)** | 10 | 4,502 | 0 | 3 | 36 | 56 | `internal/service/upstream/service.go` (810) |
| **Translations** | 5 | 3,560 | 0 | 5 | 160 | 230 | `web/translations/fr.json` (712) |
| **Frontend JavaScript** | 6 | 2,096 | 0 | 2 | 4 | 12 | `web/static/js/tables.js` (783) |
| **Documentation** | 8 | 1,814 | 0 | 0 | 50 | 59 | `docs/telemetry.md` (438) |
| **Other** | 15 | 1,358 | 0 | 0 | 41 | 61 | `.github/workflows/upstream-monitor.yml` (370) |
| **Go Production (CLI & Entrypoints)** | 3 | 588 | 0 | 0 | 21 | 31 | `cmd/panel/main.go` (262) |

---

## 3. Top 25 Repository Hotspots (Ranked by Risk Score)

Risk score combines normalized line count with 30-day and 90-day git churn velocity:
$$\text{Risk Score} = \left(\frac{\text{Lines}}{1000}\right) \times \left(1 + 0.5 \times \text{Churn}_{30d} + 0.2 \times \text{Churn}_{90d}\right)$$

| Rank | File Path | Component | Lines | Bytes | 30d Churn | 90d Churn | Risk Score | Risk Tier | Status |
|---:|---|---|---:|---:|---:|---:|---:|:---:|:---:|
| 1 | `internal/vpn/vpn.go` | Go Core VPN | 4,950 | 174,621 | 73 | 96 | 280.67 | **CRITICAL** | `VIOLATION` |
| 2 | `web/vpn_diagnostics_test.go` | Test Suites | 6,295 | 281,086 | 43 | 43 | 195.77 | **CRITICAL** | `VIOLATION` |
| 3 | `internal/vpn/vpn_test.go` | Test Suites | 6,739 | 224,434 | 30 | 49 | 173.87 | **CRITICAL** | `VIOLATION` |
| 4 | `web/templates/vpn.html` | Web Templates | 3,758 | 206,725 | 54 | 62 | 151.82 | **CRITICAL** | `VIOLATION` |
| 5 | `internal/manager/awg/awg.go` | Go Production (WireGuard Manager) | 3,287 | 120,209 | 20 | 35 | 59.17 | **CRITICAL** | `VIOLATION` |
| 6 | `internal/vpn/diagnostics.go` | Go Core VPN | 1,423 | 60,377 | 47 | 47 | 48.24 | **CRITICAL** | `VIOLATION` |
| 7 | `web/web_test.go` | Test Suites | 2,485 | 79,949 | 21 | 38 | 47.46 | **CRITICAL** | `VIOLATION` |
| 8 | `internal/vpn/forwarder/forwarder.go` | Packet Forwarder | 1,886 | 70,459 | 28 | 35 | 41.49 | **CRITICAL** | `VIOLATION` |
| 9 | `internal/vpn/diagnostics_test.go` | Test Suites | 2,491 | 83,949 | 18 | 18 | 33.88 | **CRITICAL** | `VIOLATION` |
| 10 | `internal/manager/awg/awg_test.go` | Test Suites | 2,544 | 84,226 | 12 | 20 | 27.98 | **HIGH** | `VIOLATION` |
| 11 | `internal/models/models.go` | Go Production (Database & Infra) | 1,175 | 44,765 | 19 | 30 | 19.39 | **CRITICAL** | `VIOLATION` |
| 12 | `web/translations/fr.json` | Translations | 712 | 36,889 | 32 | 46 | 18.65 | **HIGH** | `WARNING` |
| 13 | `web/translations/en.json` | Translations | 712 | 33,999 | 32 | 46 | 18.65 | **HIGH** | `WARNING` |
| 14 | `web/translations/zh.json` | Translations | 712 | 33,443 | 32 | 46 | 18.65 | **HIGH** | `WARNING` |
| 15 | `web/translations/ru.json` | Translations | 712 | 49,256 | 32 | 46 | 18.65 | **HIGH** | `WARNING` |
| 16 | `web/translations/fa.json` | Translations | 712 | 44,252 | 32 | 46 | 18.65 | **HIGH** | `WARNING` |
| 17 | `internal/handlers/servers_test.go` | Test Suites | 2,588 | 92,020 | 8 | 11 | 18.63 | **HIGH** | `VIOLATION` |
| 18 | `internal/service/orchestrator/orchestrator_test.go` | Test Suites | 2,170 | 68,654 | 9 | 15 | 18.45 | **HIGH** | `VIOLATION` |
| 19 | `internal/database/vpn.go` | Go Production (Database & Infra) | 1,039 | 36,105 | 19 | 25 | 16.10 | **CRITICAL** | `VIOLATION` |
| 20 | `internal/handlers/vpn_test.go` | Test Suites | 1,228 | 43,140 | 15 | 22 | 15.84 | **CRITICAL** | `VIOLATION` |
| 21 | `internal/handlers/servers.go` | Go Production (Handlers & Router) | 1,169 | 35,250 | 16 | 20 | 15.20 | **CRITICAL** | `VIOLATION` |
| 22 | `tests/e2e/test_vpn_diagnostics.py` | Test Suites | 936 | 37,795 | 19 | 19 | 13.38 | **HIGH** | `WARNING` |
| 23 | `web/static/css/style.css` | CSS Styles | 3,008 | 63,291 | 2 | 12 | 13.24 | **HIGH** | `VIOLATION` |
| 24 | `internal/vpn/tunnel/pool.go` | Go Core VPN | 891 | 29,461 | 15 | 21 | 11.32 | **HIGH** | `WARNING` |
| 25 | `internal/vpn/tunnel/pool_test.go` | Test Suites | 1,336 | 47,112 | 9 | 12 | 10.55 | **HIGH** | `VIOLATION` |

---

## 4. Hotspots by Target Component

### Go Core VPN
*internal/vpn/ core engine and state machines*

| File Path | Lines | Bytes | 30d Churn | 90d Churn | Risk Score | Tier | Ceiling Status |
|---|---:|---:|---:|---:|---:|:---:|:---:|
| `internal/vpn/vpn.go` | 4,950 | 174,621 | 73 | 96 | 280.67 | CRITICAL | `VIOLATION` |
| `internal/vpn/diagnostics.go` | 1,423 | 60,377 | 47 | 47 | 48.24 | CRITICAL | `VIOLATION` |
| `internal/vpn/tunnel/pool.go` | 891 | 29,461 | 15 | 21 | 11.32 | HIGH | `WARNING` |
| `internal/vpn/peer_sync.go` | 1,303 | 56,059 | 10 | 10 | 10.42 | HIGH | `VIOLATION` |
| `internal/vpn/tunnel/health.go` | 1,322 | 36,746 | 6 | 15 | 9.25 | HIGH | `VIOLATION` |
| `internal/vpn/diagnostics_history.go` | 668 | 23,924 | 18 | 18 | 9.08 | HIGH | `WARNING` |
| `internal/vpn/virtualtun/virtualtun.go` | 870 | 34,188 | 7 | 7 | 5.13 | MEDIUM | `WARNING` |
| `internal/vpn/ingress_engine.go` | 517 | 20,296 | 12 | 12 | 4.86 | HIGH | `WARNING` |
| `internal/vpn/tunnel/awgdevice.go` | 464 | 14,940 | 7 | 13 | 3.29 | MEDIUM | `OK` |
| `internal/vpn/loadbalancer/sticky.go` | 601 | 20,497 | 4 | 7 | 2.64 | MEDIUM | `WARNING` |

### Packet Forwarder
*High-throughput packet forwarder and queue pipeline*

| File Path | Lines | Bytes | 30d Churn | 90d Churn | Risk Score | Tier | Ceiling Status |
|---|---:|---:|---:|---:|---:|:---:|:---:|
| `internal/vpn/forwarder/forwarder.go` | 1,886 | 70,459 | 28 | 35 | 41.49 | CRITICAL | `VIOLATION` |
| `internal/vpn/forwarder/client_write.go` | 312 | 10,402 | 9 | 9 | 2.28 | MEDIUM | `OK` |
| `internal/vpn/forwarder/routes.go` | 224 | 7,736 | 10 | 10 | 1.79 | MEDIUM | `OK` |
| `internal/vpn/forwarder/rates.go` | 213 | 7,750 | 10 | 10 | 1.70 | MEDIUM | `OK` |
| `internal/vpn/forwarder/traffic_telemetry.go` | 268 | 9,013 | 6 | 6 | 1.39 | MEDIUM | `OK` |
| `internal/vpn/forwarder/generation.go` | 210 | 7,918 | 5 | 5 | 0.94 | MEDIUM | `OK` |
| `internal/vpn/forwarder/return_path.go` | 167 | 6,742 | 4 | 4 | 0.63 | LOW | `OK` |
| `internal/vpn/forwarder/accounting.go` | 228 | 5,399 | 1 | 2 | 0.43 | LOW | `OK` |
| `internal/vpn/forwarder/route_pressure.go` | 125 | 4,416 | 2 | 2 | 0.30 | LOW | `OK` |
| `internal/vpn/forwarder/queue_dwell.go` | 102 | 3,176 | 2 | 2 | 0.24 | LOW | `OK` |

### Web Templates
*Server-rendered HTML templates*

| File Path | Lines | Bytes | 30d Churn | 90d Churn | Risk Score | Tier | Ceiling Status |
|---|---:|---:|---:|---:|---:|:---:|:---:|
| `web/templates/vpn.html` | 3,758 | 206,725 | 54 | 62 | 151.82 | CRITICAL | `VIOLATION` |
| `web/templates/server.html` | 1,796 | 92,322 | 4 | 10 | 8.98 | HIGH | `VIOLATION` |
| `web/templates/users.html` | 1,310 | 70,120 | 2 | 6 | 4.19 | HIGH | `VIOLATION` |
| `web/templates/my_connections.html` | 726 | 36,008 | 1 | 7 | 2.11 | MEDIUM | `WARNING` |
| `web/templates/base.html` | 564 | 35,277 | 0 | 11 | 1.80 | MEDIUM | `WARNING` |
| `web/templates/settings.html` | 531 | 31,111 | 2 | 6 | 1.70 | MEDIUM | `WARNING` |
| `web/templates/index.html` | 469 | 21,015 | 1 | 4 | 1.08 | LOW | `OK` |
| `web/templates/login.html` | 349 | 18,375 | 1 | 6 | 0.94 | LOW | `OK` |
| `web/templates/icons.html` | 282 | 15,085 | 0 | 6 | 0.62 | LOW | `OK` |
| `web/templates/change_password.html` | 365 | 14,908 | 0 | 2 | 0.51 | LOW | `OK` |

### Test Suites
*Go unit/integration and Python E2E test suites*

| File Path | Lines | Bytes | 30d Churn | 90d Churn | Risk Score | Tier | Ceiling Status |
|---|---:|---:|---:|---:|---:|:---:|:---:|
| `web/vpn_diagnostics_test.go` | 6,295 | 281,086 | 43 | 43 | 195.77 | CRITICAL | `VIOLATION` |
| `internal/vpn/vpn_test.go` | 6,739 | 224,434 | 30 | 49 | 173.87 | CRITICAL | `VIOLATION` |
| `web/web_test.go` | 2,485 | 79,949 | 21 | 38 | 47.46 | CRITICAL | `VIOLATION` |
| `internal/vpn/diagnostics_test.go` | 2,491 | 83,949 | 18 | 18 | 33.88 | CRITICAL | `VIOLATION` |
| `internal/manager/awg/awg_test.go` | 2,544 | 84,226 | 12 | 20 | 27.98 | HIGH | `VIOLATION` |
| `internal/handlers/servers_test.go` | 2,588 | 92,020 | 8 | 11 | 18.63 | HIGH | `VIOLATION` |
| `internal/service/orchestrator/orchestrator_test.go` | 2,170 | 68,654 | 9 | 15 | 18.45 | HIGH | `VIOLATION` |
| `internal/handlers/vpn_test.go` | 1,228 | 43,140 | 15 | 22 | 15.84 | CRITICAL | `VIOLATION` |
| `tests/e2e/test_vpn_diagnostics.py` | 936 | 37,795 | 19 | 19 | 13.38 | HIGH | `WARNING` |
| `internal/vpn/tunnel/pool_test.go` | 1,336 | 47,112 | 9 | 12 | 10.55 | HIGH | `VIOLATION` |

### CSS Styles
*Frontend styling and design system stylesheets*

| File Path | Lines | Bytes | 30d Churn | 90d Churn | Risk Score | Tier | Ceiling Status |
|---|---:|---:|---:|---:|---:|:---:|:---:|
| `web/static/css/style.css` | 3,008 | 63,291 | 2 | 12 | 13.24 | HIGH | `VIOLATION` |

### Go Production Packages
*Managers, services, handlers, router, and database infrastructure*

| File Path | Lines | Bytes | 30d Churn | 90d Churn | Risk Score | Tier | Ceiling Status |
|---|---:|---:|---:|---:|---:|:---:|:---:|
| `internal/manager/awg/awg.go` | 3,287 | 120,209 | 20 | 35 | 59.17 | CRITICAL | `VIOLATION` |
| `internal/models/models.go` | 1,175 | 44,765 | 19 | 30 | 19.39 | CRITICAL | `VIOLATION` |
| `internal/database/vpn.go` | 1,039 | 36,105 | 19 | 25 | 16.10 | CRITICAL | `VIOLATION` |
| `internal/handlers/servers.go` | 1,169 | 35,250 | 16 | 20 | 15.20 | CRITICAL | `VIOLATION` |
| `internal/database/database.go` | 1,037 | 31,127 | 11 | 15 | 9.85 | HIGH | `VIOLATION` |
| `internal/config/config.go` | 476 | 14,100 | 26 | 30 | 9.52 | MEDIUM | `OK` |
| `internal/manager/awg/params.go` | 1,274 | 40,676 | 5 | 17 | 8.79 | HIGH | `VIOLATION` |
| `internal/service/upstream/service.go` | 810 | 19,190 | 11 | 11 | 7.05 | HIGH | `WARNING` |
| `internal/handlers/server_connections.go` | 809 | 24,645 | 10 | 11 | 6.63 | HIGH | `WARNING` |
| `internal/handlers/vpn.go` | 447 | 14,571 | 16 | 23 | 6.08 | MEDIUM | `OK` |

---

## 5. Git Churn Velocity Analysis (30-Day vs. 90-Day)

High-churn files experience frequent modifications, creating heightened vulnerability to merge collisions, concurrent agent race conditions, and accidental regression of delicate invariants.

| Top Churn File | Component | Lines | 30d Commits | 90d Commits | Velocity Trend | Assessment |
|---|---|---:|---:|---:|:---:|---|
| `internal/vpn/vpn.go` | Go Core VPN | 4,950 | 73 | 96 | `ACCELERATING` | Severe concurrency hazard: oversized + hyper-active |
| `web/templates/vpn.html` | Web Templates | 3,758 | 54 | 62 | `ACCELERATING` | Severe concurrency hazard: oversized + hyper-active |
| `internal/vpn/diagnostics.go` | Go Core VPN | 1,423 | 47 | 47 | `ACCELERATING` | Severe concurrency hazard: oversized + hyper-active |
| `web/vpn_diagnostics_test.go` | Test Suites | 6,295 | 43 | 43 | `ACCELERATING` | Severe concurrency hazard: oversized + hyper-active |
| `web/translations/fr.json` | Translations | 712 | 32 | 46 | `ACCELERATING` | Active modular file |
| `web/translations/en.json` | Translations | 712 | 32 | 46 | `ACCELERATING` | Active modular file |
| `web/translations/zh.json` | Translations | 712 | 32 | 46 | `ACCELERATING` | Active modular file |
| `web/translations/ru.json` | Translations | 712 | 32 | 46 | `ACCELERATING` | Active modular file |
| `web/translations/fa.json` | Translations | 712 | 32 | 46 | `ACCELERATING` | Active modular file |
| `internal/vpn/vpn_test.go` | Test Suites | 6,739 | 30 | 49 | `ACCELERATING` | Severe concurrency hazard: oversized + hyper-active |
| `internal/vpn/forwarder/forwarder.go` | Packet Forwarder | 1,886 | 28 | 35 | `ACCELERATING` | Severe concurrency hazard: oversized + hyper-active |
| `README.md` | Documentation | 270 | 26 | 32 | `ACCELERATING` | Active modular file |

---

## 6. Candidate Decomposition Workstreams for Epic #475

Based on the empirical inventory, the following decomposition workstreams are prioritized by maintainability risk and change churn:

### Workstream 1: Go Core VPN Service Monolith (`internal/vpn/vpn.go`)
- **Current Metrics**: 4,950 lines, 73 commits in 30d, 96 commits in 90d (Risk Score: 280.67, CRITICAL).
- **Structural Responsibilities**: Centralizes lifecycle orchestration, peer synchronization, session cleanup, handshake monitoring, iptables/routing setup, device creation, and status polling.
- **Decomposition Strategy**:
  1. Extract peer synchronization loop to `internal/vpn/vpn_peer_sync.go`.
  2. Extract session allocation and IPAM bridge to `internal/vpn/vpn_session_manager.go`.
  3. Extract iptables and tunnel network configuration to `internal/vpn/vpn_netconfig.go`.
  4. Target size per module: < 800 lines.

### Workstream 2: Frontend VPN Dashboard Monolith (`web/templates/vpn.html`)
- **Current Metrics**: 3,758 lines, 54 commits in 30d, 62 commits in 90d (Risk Score: 151.82, CRITICAL).
- **Structural Responsibilities**: Houses inline JavaScript, SVG sparklines, status badges, diagnostics modals, peer troubleshooting drawers, route tables, and telemetry widgets in a single template.
- **Decomposition Strategy**:
  1. Extract JavaScript controller logic to `web/static/js/vpn_dashboard.js`.
  2. Decompose sub-components into partial templates (`web/templates/partials/vpn_health_card.html`, `web/templates/partials/vpn_routes_table.html`, `web/templates/partials/vpn_sessions_modal.html`).
  3. Target main template size: < 600 lines.

### Workstream 3: Monolithic Web & VPN Test Suites (`web/vpn_diagnostics_test.go`, `internal/vpn/vpn_test.go`)
- **Current Metrics**: `vpn_test.go` = 6,739 lines (Risk Score: 173.87); `vpn_diagnostics_test.go` = 6,295 lines (Risk Score: 195.77).
- **Structural Responsibilities**: Multi-scenario DOM test cases, mocked backend responses, large JSON inline fixtures, and multi-threaded stress tests all co-located in two giant test files.
- **Decomposition Strategy**:
  1. Split `web/vpn_diagnostics_test.go` by DOM component: `vpn_diagnostics_sparklines_test.go`, `vpn_diagnostics_routes_test.go`, `vpn_diagnostics_i18n_test.go`.
  2. Split `internal/vpn/vpn_test.go` by feature domain: `vpn_lifecycle_test.go`, `vpn_session_test.go`, `vpn_tunnel_failover_test.go`.
  3. Keep all extracted test suites strictly below 1,000 lines.

### Workstream 4: WireGuard Manager Monolith (`internal/manager/awg/awg.go`)
- **Current Metrics**: 3,287 lines, 20 commits in 30d, 35 commits in 90d (Risk Score: 59.17, CRITICAL).
- **Structural Responsibilities**: Handles config generation, remote SSH command execution, atomic lock management, and CIDR/NAT IP allocation.
- **Decomposition Strategy**:
  1. Separate SSH command execution and IPC into `internal/manager/awg/awg_client.go`.
  2. Separate config serialization and key parsing into `internal/manager/awg/awg_config_builder.go`.
  3. Target module size: < 750 lines.

### Workstream 5: Monolithic Stylesheet (`web/static/css/style.css`)
- **Current Metrics**: 3,008 lines, 10 commits in 30d, 18 commits in 90d (Risk Score: 28.88, HIGH).
- **Structural Responsibilities**: Single giant CSS file containing layout grids, component styles, dark theme overrides, animations, and diagnostics table styling.
- **Decomposition Strategy**:
  1. Split into modular CSS imports: `base.css`, `components/cards.css`, `components/tables.css`, `themes/dark.css`, `pages/vpn.css`.
  2. Bundle or link via template asset loaders.

### Workstream 6: Packet Forwarder Core (`internal/vpn/forwarder/forwarder.go`)
- **Current Metrics**: 1,886 lines, 28 commits in 30d, 35 commits in 90d (Risk Score: 41.49, CRITICAL).
- **Structural Responsibilities**: Forwarder packet routing, ring buffer queues, drop tracking atomics, route pressure windows, and worker pool coordination.
- **Decomposition Strategy**:
  1. Extract route pressure window calculation to `forwarder_pressure.go`.
  2. Extract worker pool scheduling and epoch lifecycle to `forwarder_workers.go`.
  3. Target main forwarder module: < 800 lines.

---

## 7. Proposed Ratcheting Ceilings & Enforcement Policy

To prevent further regression into monolithic files, the team adopts a **ratcheting ceiling policy**:

1. **Strict Review Ceiling (1,000 Lines)**:
   - Any new file introduced must not exceed 1,000 lines.
   - Any PR that pushes an existing file from below 1,000 lines to above 1,000 lines is subject to automatic rejection per code-review quality gates.

2. **Warning Threshold (500 Lines)**:
   - Files crossing 500 lines enter the architectural watch list.
   - Contributors are encouraged to extract cohesive sub-responsibilities before reaching the 1,000-line ceiling.

3. **Ratcheting Ceiling on Legacy Monoliths**:
   - For the 43 legacy files exceeding 1,000 lines, their current line count serves as an absolute ceiling.
   - PRs touching these files must **never increase** their total line count.
   - Each decomposition PR ratchets the ceiling downward to the new line count.
   - Once a file drops below 1,000 lines, it permanently locks into the 1,000-line ceiling rule.

4. **Continuous Quality Gate Integration**:
   - `scripts/inventory_hotspots.py --json` can be executed in CI to verify that no ceiling is breached and no existing ratchet is violated.

