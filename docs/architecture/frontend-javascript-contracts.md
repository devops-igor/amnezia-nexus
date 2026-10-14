# Frontend JavaScript Architecture Contracts and Module Boundaries

## 1. Overview & Architectural Role

The administrative frontend of Amnezia Nexus relies on server-rendered Go templates (`web/templates/*.html`) paired with vanilla JavaScript, modern DOM manipulation, and dynamic REST polling. Prior to the modularization program defined under Phase 3 (Epic #475, Issues #495–#505 and #542), substantial portions of interactive logic reside as monolithic inline `<script>` blocks embedded directly inside templates:

- `web/templates/vpn.html`: 3,758 total lines, containing ~3,256 lines of inline JavaScript (lines 501–3757).
- `web/templates/server.html`: 1,796 total lines, containing ~1,198 lines of inline JavaScript (lines 598–1795).
- `web/templates/users.html`: 1,309 total lines, containing ~834 lines of inline JavaScript across two blocks (lines 421–1134 [714 lines] and lines 1190–1309 [120 lines]).

Extracting these monolithic inline scripts into modular, cacheable static JavaScript files (`web/static/js/vpn/*.js`, `web/static/js/server/*.js`, and `web/static/js/users.js`) is necessary to eliminate duplication, isolate failure domains, improve maintainability, and enforce strict Content Security Policies (CSP).

### Line Ceiling & Incremental Extraction Rules (Finding 1)
- **Static JavaScript Files**: Every newly extracted static JavaScript module must strictly adhere to the project line ceiling of under 1,000 lines. Monolithic modules exceeding this threshold must be partitioned into cohesive submodules prior to extraction.
- **Transitional Template Sizes**: Monolithic templates (most notably `vpn.html` at 3,758 lines) will shrink progressively across extraction waves. The sub-1,000 line ceiling applies strictly to newly created static files throughout the migration, while HTML templates shrink wave-by-wave until reaching their final thin-template targets (<600 lines).
- **Atomic Staging**: Script loading tags (`<script src="...">`) and test fixture updates (`extractJSFunction`) must land in the same pull request as the extracted code during each wave to guarantee continuous test passability without broken intermediate states.

This document establishes the authoritative architectural contract, global state inventory, Go-template interpolation rules, DOM event ownership, polling lifecycles, and test harness mappings. Every extraction step in Phase 3 MUST preserve the behavioral invariants documented herein.

---

## 2. Inline JavaScript Responsibility & Target Module Maps

### 2.1 VPN Dashboard (`web/templates/vpn.html`)

The inline script in `web/templates/vpn.html` spans lines 501–3757 (~3,256 lines) and performs distinct responsibilities. Because `vpnRenderForwarderHealth` and its associated health-rendering machinery alone spans 1,308 lines (`vpn.html:2327-3634`), health rendering cannot reside in a single file without violating the sub-1,000 line ceiling. Under Phase 3 (Issues #495–#500), health rendering is partitioned into two cohesive submodules (`health_summary.js` and `health_problems.js`), resulting in five feature modules and one page bootstrap orchestrator:

```
+---------------------------------------------------------------------------------------------------+
|                                      web/templates/vpn.html                                       |
|                                 (Thin markup-only template #500)                                  |
+---------------------------------------------------------------------------------------------------+
       |                    |                     |                     |                    |
       v                    v                     v                     v                    v
+--------------+   +-------------------+  +--------------------+  +--------------+   +--------------+
| vpn/         |   | vpn/              |  | vpn/               |  | vpn/         |   | vpn/         |
| sessions.js  |   | health_summary.js |  | health_problems.js |  | charts.js    |   | backends.js  |
| (#495)       |   | (#496a)           |  | (#496b)            |  | (#497)       |   | (#498)       |
|              |   |                   |  |                    |  |              |   |              |
| - Sessions   |   | - Forwarder Hdr   |  | - Problem Cards    |  | - Sparklines |   | - Backends   |
|   Table      |   | - KPI Status Bar  |  | - Condition Parsers|  |   SVG Math   |   |   Table DOM  |
| - Drilldown  |   | - Headline Status |  | - Entity Extraction|  | - 1m..24h    |   | - Add/Edit   |
|   Rows       |   | - Route Tooltips  |  | - Severity Badges  |  |   Window Tgl |   |   Modal      |
| - Stale      |   | - Nested          |  | - Tech Details     |  | - Tooltips & |   | - Quick Ping |
|   Banner     |   |   Formatters      |  |   Accordion        |  |   Hover Pres |   |   SSH Check  |
| - Problem    |   |   (fmtBps/fmtPps) |  | - Diag Panels 1-4  |  | - Series     |   | - Endpoint   |
|   Filter     |   |                   |  |                    |  |   Rendering  |   |   Modal      |
| - Rate       |   |                   |  |                    |  |              |   |              |
|   Formatters |   |                   |  |                    |  |              |   |              |
|   (Top-Level)|   |                   |  |                    |  |              |   |              |
+--------------+   +-------------------+  +--------------------+  +--------------+   +--------------+
       \                    \                     /                     /                    /
        \                    \                   /                     /                    /
         +--------------------+--------+--------+---------------------+--------------------+
                                       |
                                       v
                            +--------------------+
                            |    vpn/page.js     |
                            |    (Issue #499)    |
                            |                    |
                            | - DOMContentLoaded |
                            | - Telemetry.poll   |
                            | - Multi-API Fetch  |
                            | - Error Fallback   |
                            | - Cleanup/Teardown |
                            +--------------------+
```

#### Module Specifications for VPN Subsystem:

1. **`web/static/js/vpn/sessions.js` (Target Issue #495 — ~520 lines)**:
   - **Responsibilities**: Session troubleshooting table rendering, row drilldown generation, accordion toggling, problem-only filtering, stale session state handling, sorting/filtering via `NexusTable`.
   - **Primary Functions**: `renderSessions`, `vpnRenderSessionRow`, `vpnCreateSessionDrilldownRow`, `vpnToggleSessionDrilldown`, `vpnSyncExpandedDrilldowns`, `vpnToggleSessionsProblemFilter`, `vpnRenderSessionsStaleBanner`, `vpnFindSessionById`, `vpnFindRouteForSession`, `vpnWrapSessionsTableRender`, `vpnFormatBytes`, `fmtBps` (top-level rate formatter), `fmtPps` (top-level packet rate formatter).
   - **Rate Formatter Scoping Contract (Dual-Scope Invariant — Finding 1)**: In `web/templates/vpn.html`, two distinct scopes of rate formatters exist:
     * *Top-Level Formatters (`vpn.html:1027–1040`)*: Globally defined functions `fmtBps(bps)` and `fmtPps(pps)`. These are actively invoked by the sessions table traffic cell renderer (`tdTraffic.textContent = ↓ ${fmtBps(rx)} ↑ ${fmtBps(tx)}` at line 1186) and the session drilldown row renderer (lines 1311–1314: `fmtPps(trf.rx_pps)`, `fmtBps(...)`). They are assigned to `web/static/js/vpn/sessions.js` (or a shared formatting utility loaded before sessions), ensuring sessions rendering retains formatter availability throughout progressive migration waves.
     * *Health-Nested Shadowing Formatters (`vpn.html:2328–2339`)*: Identically named helpers defined locally inside `function vpnRenderForwarderHealth(status)` for forwarder headline and KPI summary rendering. These health-local shadowing formatters remain encapsulated within `web/static/js/vpn/health_summary.js`.
   - **State Ownership**: `vpnSessionsTableInstance`, `vpnLastSessions`, `vpnSessionsStale`, `vpnSessionsFilterOnlyProblems`, `vpnExpandedSessionIds`.

2. **`web/static/js/vpn/health_summary.js` (Target Issue #496a — ~450 lines)**:
   - **Responsibilities**: Forwarder health status banner, forwarder headline status, KPI summary bar (throughput, routes/sessions, queue pressure, packet loss, client engine, peer sync, healthy backends, slow writes), route tooltip generation, duration and rate formatting helpers.
   - **Primary Functions**: `vpnRenderForwarderHealth` (top-level orchestration and summary sections), `routeTooltip`, `fmtBps` (health-nested shadowing bps formatter, `vpn.html:2328–2334`), `fmtPps` (health-nested shadowing pps formatter, `vpn.html:2335–2340`), `fmtDurationSec`, `vpnFormatCountersSince`.
   - **State Ownership**: `vpnShowAllRoutes`, reads `vpnLastStatus`.

3. **`web/static/js/vpn/health_problems.js` (Target Issue #496b — ~850 lines)**:
   - **Responsibilities**: Active actionable problem cards, tech diagnostics progressive disclosure accordion (`#vpn-fwd-tech-details`), diagnostic cards 1–4 (Data Plane, Traffic Drops, Route Integrity, Fleet Resources), condition parsing and entity extraction, severity badge rendering, peer key formatting, loss reason labels, diagnostic dictionary lookups.
   - **Primary Functions**: `createSeverityBadge`, `deriveStableConditionCode`, `parseConditionMessage`, `preserveCountPhrase`, `extractConditionEntities`, `vpnFormatPeerKey`, `vpnFormatTime`, `vpnLossReasonLabels`, `vpnDiagText`.
   - **State Ownership**: `vpnLastActiveProblemKeys`, `vpnLastActiveProblemCount`.

4. **`web/static/js/vpn/charts.js` (Target Issue #497 — ~520 lines)**:
   - **Responsibilities**: Historical telemetry trend rendering, sparkline SVG path calculations, window toggle selection (1m, 5m, 15m, 1h, 6h, 24h), chart hover interactions, peak and current calculation, time axis labels, backend series filtering.
   - **Primary Functions**: `vpnRenderHistoryCharts`, `vpnGenerateSparklineSVG`, `vpnSetHistoryWindow`, `vpnDisposeChartInteractions`, `computeCurrentPeak`, `vpnFmtThroughput`, `vpnFmtDrops`, `vpnFmtQueue`, `vpnFmtLatency`, `renderBadges`, `renderTimeAxis`, `attachInteraction`, `renderSeries`, `renderSelectedBackend`.
   - **Dependency Invariant**: `vpnSetHistoryWindow` directly reads `vpnLastStatus` (`vpn.html:2304-2305`) to immediately re-render history charts when the user switches horizons.
   - **State Ownership**: `vpnHistoryWindow`, `window._vpnActiveChartHover` containing `{ chartId, clientX, clientY, pageX, pageY }` (matching `vpn.html:2013-2019`).

5. **`web/static/js/vpn/backends.js` (Target Issue #498 — ~480 lines)**:
   - **Responsibilities**: Backend fleet table rendering, backend enable/disable toggle, backend deletion, add backend modal stepper and server selection, quick ping/SSH check, public endpoint modal and submission, status badge formatting.
   - **Primary Functions**: `vpnRenderBackendRow`, `vpnToggleBackend`, `vpnDeleteBackend`, `vpnOpenAddBackendModal`, `vpnResetAddModal`, `vpnOnServerSelected`, `vpnTriggerQuickCheck`, `vpnSubmitAddBackend`, `vpnOpenEditEndpointModal`, `vpnSubmitEditEndpoint`, `vpnStatusBadgeClass`, `vpnStatusLabel`, `vpnSetListenerBadge`, `vpnServerHasAwg`, `vpnFormatApiError`.
   - **State Ownership & Mutability**: `vpnCurrentBackends`, `vpnCachedServers` (primed on initial page load, and refetched and mutated whenever `vpnOpenAddBackendModal` is opened in `vpn.html:790-803`), `vpnConfiguredPublicEndpoint`, `vpnTableInstance`.

6. **`web/static/js/vpn/page.js` (Target Issue #499 — ~200 lines)**:
   - **Responsibilities**: Page initialization, `DOMContentLoaded` listener, server metadata pre-caching, telemetry polling coordination via `NexusTelemetry.poll('vpn-status')`, multi-endpoint fetch orchestration (`/api/vpn/status`, `/api/vpn/config`, `/api/vpn/backends`, `/api/vpn/sessions`), error boundary handling, and page teardown registration.
   - **Primary Functions**: `vpnLoadData`, top-level event listener attachment.
   - **State Ownership**: Orchestrates data distribution to `sessions.js`, `health_summary.js`, `health_problems.js`, `charts.js`, and `backends.js`.

7. **`web/templates/vpn.html` (Target Issue #500 — ~500 lines)**:
   - **Responsibilities**: Markup-only template loading static assets via standard `<script src="/static/js/vpn/*.js">` tags, retaining HTML structure, static i18n placeholders (`{{ _ "key" }}`), and modal containers.

---

### 2.2 Server Details & Management (`web/templates/server.html`)

The inline script in `web/templates/server.html` spans lines 598–1795 (~1,198 lines) and handles server administration, protocol lifecycle, telemetry polling, host/name editing, and client connection management.

#### Breaking Dependency Cycles (Finding 2)
In the existing monolithic script:
- Server actions call `checkServer` (`server.html:989`) upon container toggles.
- Monitoring's `checkServer` calls `getProtoTitle` (`server.html:771`) and `updateProtocolCard` (`server.html:766`).
- `updateProtocolCard` dynamically constructs DOM nodes with action handlers (`uninstallProtocol`, `selectProtocolForConns`, `toggleContainer`, `showServerConfig` in `server.html:883–966`) and directly invokes `showConnectionsSection()` (`server.html:898`).

If `showConnectionsSection` remains in monitoring, this introduces a reverse dependency cycle: `monitoring.js` -> `shared.js` -> `monitoring.js`. Furthermore, directly wiring action handlers creates tight coupling from the card builder into both `actions.js` and `monitoring.js`.

Under Phase 3, these dependency cycles are broken by establishing a strictly unidirectional architecture anchored by `web/static/js/server/shared.js`:
1. **Shared Section-Visibility Primitives**: Move `showConnectionsSection` (`server.html:1035–1038`) and `hideConnectionsSection` (`server.html:1040–1051`) into `web/static/js/server/shared.js`. Because section visibility is a shared DOM primitive, `updateProtocolCard` invokes `showConnectionsSection` entirely within `server/shared.js`. Both `server/monitoring.js` (`checkServer:782` calling `hideConnectionsSection`) and `server/actions.js` consume section visibility directly from `server/shared.js`.
2. **Action Callback Registration & Event Dispatch Interface**: Decouple protocol card buttons from direct module functions via an explicit action registry and event dispatch contract:
   - `server/shared.js` provides `registerProtocolActionHandler(action, handler)` and `dispatchProtocolAction(action, proto)` (or delegates via custom DOM events on `#protocolCardsGrid`: `nexus:protocol-action` with detail `{ action, proto }`).
   - `server/monitoring.js` registers its handler for `selectProtocolForConns` (`action === 'select-conns'`).
   - `server/actions.js` registers handlers for `uninstallProtocol` (`action === 'uninstall'`), `toggleContainer` (`action === 'toggle'`), and `showServerConfig` (`action === 'config'`).
   - When actions complete (e.g. after container toggle or uninstall), `server/actions.js` dispatches a `nexus:server-refresh` event (or calls `ServerShared.requestServerCheck()`) that `monitoring.js` subscribes to, eliminating direct cyclic calls into `checkServer`.
3. **Strictly Acyclic Directed Graph**:
   - `server/shared.js` is an independent leaf module with **ZERO outgoing dependencies** on `monitoring.js` or `actions.js`.
   - `server/monitoring.js` depends downward on `server/shared.js` (for card building, protocol metadata, section visibility, and action registration).
   - `server/actions.js` depends downward on `server/shared.js` (for section visibility, date formatting, action registration, and event notification).
   - All dependency arrows point strictly downward to `server/shared.js`.

```
+-----------------------------------------------------------------------------+
|                          web/templates/server.html                          |
|                       (Thin markup-only template #503)                      |
|                                                                             |
|   Bootstrap: const SERVER_ID = {{ .server_id }};                            |
|              data-server-id="{{ .server.ID }}"                              |
|              data-server-host="{{ .server.Host }}"                          |
|              data-server-name="{{ .server.Name }}"                          |
+-----------------------------------------------------------------------------+
          |                                                   |
          v                                                   v
+----------------------------------+        +----------------------------------+
|     server/actions.js            |        |     server/monitoring.js         |
|       (Issue #501)               |        |       (Issue #502)               |
|                                  |        |                                  |
| - Protocol Installation Stepper  |        | - Background Telemetry Polling   |
| - Protocol Uninstall Handler     |        | - Reachability Auto-Trial Badges |
| - Container Toggle Handler       |        | - Protocol Card Live Status      |
| - Server Config View / Save      |        | - Client Connections Table Fetch |
| - Server Rename Modal            |        | - Telemetry.poll Registration    |
| - Edit Host Modal (RFC/IP check) |        | - In-memory connectionsStore     |
| - Reboot / Clear / Remove Ops    |        | - Registers selectProtocolForConns|
| - Connection Add/Edit/Delete     |        | - Subscribes to server-refresh   |
| - Dispatches nexus:server-refresh|        | - Consumes shared visibility     |
| - QR Code & Config Tab Switching |        |                                  |
+----------------------------------+        +----------------------------------+
          \                                                   /
           \                                                 /
            +-----------------------+-----------------------+
                                    |
                                    v
                     +-----------------------------+
                     |      server/shared.js       |
                     |       (Issue #501a)         |
                     |                             |
                     | - Protocol Titles & Metas   |
                     |   (getProtoTitle)           |
                     | - Card Builders & Formatters|
                     |   (updateProtocolCard)      |
                     | - Section Visibility Roots  |
                     |   (show/hideConnectionsSec) |
                     | - Action Registry & Dispatch|
                     |   (registerActionHandler)   |
                     | - Status Count Summaries    |
                     | - Date/Time Formatters      |
                     +-----------------------------+
```

#### Module Specifications for Server Subsystem:

1. **`web/static/js/server/shared.js` (~200 lines)**:
   - **Responsibilities**: Shared protocol metadata definitions, protocol title formatting (`getProtoTitle`), protocol status card generator (`updateProtocolCard`), shared section visibility primitives (`showConnectionsSection`, `hideConnectionsSection`), protocol action callback registration and event dispatch hooks (`registerProtocolActionHandler`, `dispatchProtocolAction`), status count calculation (`updateStatusCounts`), and shared date/time formatting (`formatDate`).
   - **Primary Functions**: `getProtoTitle`, `updateProtocolCard`, `showConnectionsSection`, `hideConnectionsSection`, `registerProtocolActionHandler`, `dispatchProtocolAction`, `updateStatusCounts`, `formatDate`.
   - **State Ownership**: `installedProtocols`.

2. **`web/static/js/server/actions.js` (Target Issue #501 — ~580 lines)**:
   - **Responsibilities**: Protocol installation modal with animated step progress, protocol parameter configuration (AWG port, MTU, CPS protocol, Telemt secret/domain), container toggle, configuration editor modal (`/api/servers/${SERVER_ID}/server_config`), server operations (reboot, clear, remove), server rename modal, edit host modal with client-side RFC 1123 hostname and IPv4/IPv6 address validation, client connection CRUD operations (add, edit, remove, toggle, mimicry rotation, copy config, QR code display), action registration with `server/shared.js`, and dispatching `nexus:server-refresh` after container/protocol mutations.
   - **Primary Functions**: `switchCategory`, `toggleContainer`, `showServerConfig`, `saveServerConfig`, `openInstallModal`, `installProtocol`, `uninstallProtocol`, `openRenameServerModal`, `closeRenameServerModal`, `submitRenameServer`, `isValidHost`, `openEditHostModal`, `closeEditHostModal`, `submitEditHost`, `rebootServer`, `clearServer`, `removeServer`, `openAddConnectionModal`, `addConnection`, `editConnection`, `removeConnection`, `toggleConnection`, `rotateClientMimicry`, `copyConnectionConfig`, `showConnectionConfig`, `switchConfigTab`, `generateQR`.
   - **Pre-existing Technical Debt (Finding 4)**: In `server.html:1116-1145`, the install progress interval (`progressInterval`) is cleared on success, but the `catch (err)` handler fails to invoke `clearInterval(progressInterval)`. During extraction, this timer cleanup MUST be moved to a `finally` block or guaranteed on error exit.
   - **State Ownership**: `currentInstallProto`, `currentConfig`, `currentVpnLink`, `currentConfigName`, `serverConfigFilename`, `isEditingConn`, `editingClientId`, `renameServerId`, `editHostServerId`.

3. **`web/static/js/server/monitoring.js` (Target Issue #502 — ~420 lines)**:
   - **Responsibilities**: Background telemetry polling coordination, server system statistics retrieval (`/api/servers/${SERVER_ID}/stats`), network reachability evaluation (`/api/servers/${SERVER_ID}/reachability`), auto-trial protocol badge rendering (TLS, QUIC, DNS, SIP), server health check invocation (`checkServer`), client connections listing and table population (`/api/servers/${SERVER_ID}/connections?protocol=${proto}`), registering `selectProtocolForConns` via `server/shared.js`, and subscribing to `nexus:server-refresh` events. Consumes section visibility primitives (`showConnectionsSection`, `hideConnectionsSection`) from `server/shared.js`.
   - **Primary Functions**: `loadServerStats`, `updateReachability`, `checkServer`, `selectProtocolForConns`, `loadConnections`.
   - **State Ownership**: `SERVER_ID`, `STATS_REFRESH_INTERVAL_MS`, `connectionsTableInstance`, `window.connectionsStore`.

4. **`web/templates/server.html` (Target Issue #503 — ~600 lines)**:
   - **Responsibilities**: Thin template containing HTML layout, protocol cards, modal containers, and minimal bootstrap script defining `SERVER_ID` and loading external static modules (`server/shared.js`, `server/monitoring.js`, `server/actions.js`).

---

### 2.3 User Administration (`web/templates/users.html`)

`web/templates/users.html` contains 1,309 total lines with two inline `<script>` blocks and intervening modal markup:
- **Block 1** (lines 421–1134, 714 lines): User grid management, role filters, search, pagination, user CRUD, connection assignment, config/QR modals. Contains **10 Go-template actions** across lines 435–438:
  * Line 435: `{{ .servers | json }}` (1 action)
  * Line 436: `{{ if .current_user }}{{ .current_user.Username }}{{ end }}` (3 actions)
  * Line 437: `{{ if has_role .current_user "admin" }}true{{ else }}false{{ end }}` (3 actions)
  * Line 438: `{{ if .current_user }}{{ .current_user.ID }}{{ end }}` (3 actions)
- **Intervening HTML** (lines 1135–1189, 55 lines): Share user modal markup containing **11 Go-template actions** across 10 lines (`{{ _ "share_access" }}`, `{{ _ "cancel" }}`, `{{ _ "enable_public_access" }}`, `{{ _ "share_password_label" }}`, `{{ _ "new_password_hint" }}`, `{{ _ "share_password_hint" }}`, `{{ _ "public_link_label" }}`, two instances of `{{ _ "copy" }}`, `{{ _ "cancel" }}`, `{{ _ "save" }}`).
- **Block 2** (lines 1190–1309, 120 lines): User editing and public share access setup. Contains **0 Go-template actions** (pure JavaScript).
- **Audited Region vs. Template Scope (Finding 5)**: Exactly **21 Go-template actions** reside across the audited JavaScript migration region (10 in script block 1, 0 in script block 2, and 11 in the intervening share modal markup). In contrast, the complete `web/templates/users.html` template contains **141 total Go-template actions** across its full HTML markup, navigation bars, user tables, and modal structures.

#### Base Asset Dependencies & Load Order (Finding 5)
`web/templates/base.html` loads prerequisite libraries in `<head>` in strict order before page-level scripts execute:
1. Inline theme initialization snippet
2. `/static/js/qrcode.min.js` (QR code generation)
3. `/static/js/api.js` (REST client & CSRF injection)
4. `/static/js/ui.js` (Modals, toasts, confirm dialogs)
5. `/static/js/tables.js` (`NexusTable` component)
6. `/static/js/telemetry.js` (`NexusTelemetry` background polling)

#### CSRF Token Contract (Finding 5)
All state-modifying REST calls (`POST`, `PUT`, `DELETE`, `PATCH`) in `users.js` rely on `api.js` (`web/static/js/api.js:20-29, 63-68`). The helper `getCsrfToken()` reads the token from `<meta name="csrf-token" content="...">` or cookie `csrftoken` and auto-attaches the `X-CSRF-Token` header.

#### DOM Event Bindings & Admin Action Guards (Finding 5)
- **Concrete DOM Event Bindings (`users.html:695-717`)**:
  - `newUserServer` `change`: invokes `updateProtocols` and toggles visibility of `#newUserConnNameGroup`.
  - `newUserProtocol` `change`: toggles visibility of `#newUserMimicryGroup` when protocol is `'awg'`.
  - `ucServer` `change`: invokes `updateProtocols` for `#ucProtocol` and calls `fetchExistingClients()` if `#ucMode` is `'existing'`.
  - `ucProtocol` `change`: toggles visibility of `#ucAwgMimicryGroup` for AWG and calls `fetchExistingClients()` if `#ucMode` is `'existing'`.
- **Admin Action Guards**:
  - `currentIsAdmin` gates administrative actions (e.g., delete user, toggle user status, edit limits).
  - `currentUserID` enforces self-preservation: users cannot delete or revoke their own active administrative account.

```
+-----------------------------------------------------------------------------+
|                          web/templates/users.html                           |
|                                                                             |
|   Bootstrap:                                                                |
|     const serversData = {{ .servers | json }};                              |
|     const currentAdminUsername = '{{ if .current_user }}...{{ end }}';      |
|     const currentIsAdmin = {{ if has_role ... }}true{{ else }}false{{ end }};|
|     const currentUserID = '{{ if .current_user }}...{{ end }}';             |
+-----------------------------------------------------------------------------+
                                       |
                                       v
+-----------------------------------------------------------------------------+
|                           web/static/js/users.js                            |
|                            (Target Issue #542)                              |
|                                                                             |
| - User Directory: refreshUsersList, handleSearch (300ms debounce),          |
|   clearUserSearch, setRoleFilter, changePage (12 users/page), traffic bars  |
| - User CRUD: addUser, openEditUser, saveEditUser, deleteUser, toggleUser    |
| - Connection Management: openAddConnectionForUser, toggleUCMode,            |
|   fetchExistingClients, doAddUserConnection, viewUserConnections,           |
|   unlinkUserConnection, copyUserConnectionDirect, showUserConnectionConfig   |
| - Cascades & Modals: updateProtocols, switchConfigTab, generateQR           |
| - Share Management: openShareModal, updateShareSetup, saveShareSetup,       |
|   copyShareLink                                                             |
+-----------------------------------------------------------------------------+
```

#### Module Specification for Users Subsystem:

1. **`web/static/js/users.js` (Target Issue #542 — ~840 lines)**:
   - **Responsibilities**: All user management interactions, debounced live search (300 ms matching `users.html:446-450`), pagination control, role filtering, client connection provisioning and unlinking, QR code generation, config display, and public share link lifecycle.
   - **Primary Functions**: `handleSearch`, `clearUserSearch`, `setRoleFilter`, `changePage`, `refreshUsersList`, `updateProtocols`, `addUser`, `deleteUser`, `toggleUser`, `openAddConnectionForUser`, `toggleUCMode`, `fetchExistingClients`, `doAddUserConnection`, `viewUserConnections`, `copyUserConnectionDirect`, `unlinkUserConnection`, `switchConfigTab`, `generateQR`, `showUserConnectionConfig`, `openEditUser`, `saveEditUser`, `openShareModal`, `updateShareSetup`, `saveShareSetup`, `copyShareLink`.
   - **State Ownership**: `currentUserId`, `currentUsername`, `currentConfig`, `currentVpnLink`, `currentConfigName`, `currentPage`, `pageSize`, `searchQuery`, `selectedRole`, `searchTimeout`, `userConnsTableInstance`, `currentSharedUser`.

---

## 3. Named Global State & Shared Functions Table

The table below catalogs every variable and function exposed on `window` or residing in top-level script scope across `vpn.html`, `server.html`, and `users.html`. It documents component origins, external consumers, and mutability lifecycles.

| Identifier | Type | Origin Template | Consumers & External Call Sites | Mutability Lifecycle & Scope Rules |
|---|---|---|---|---|
| `vpnCachedServers` | `Array<Object>` | `vpn.html:504` | `vpnLoadData`, `vpnRenderBackendRow`, `vpnOpenAddBackendModal` | Primed on boot via GET `/api/servers`; refetched and mutated when opening add-backend modal (`vpnOpenAddBackendModal` in `vpn.html:790-803`). |
| `vpnCurrentBackends` | `Array<Object>` | `vpn.html:505` | `vpnLoadData`, `vpnToggleBackend`, `vpnDeleteBackend` | Updated on each 5s poll of `/api/vpn/backends`. |
| `vpnConfiguredPublicEndpoint` | `string` | `vpn.html:506` | `vpnLoadData`, `vpnOpenEditEndpointModal` | Updated on poll of `/api/vpn/config`; mutated on modal submit. |
| `vpnTableInstance` | `NexusTable` | `vpn.html:507` | `vpnLoadData` (`#vpnBackendsTable`) | Instantiated on first load; refreshed on subsequent polls. |
| `vpnSessionsTableInstance` | `NexusTable` | `vpn.html:508` | `renderSessions` (`#vpnSessionsTable`) | Instantiated on first load; refreshed on session changes. |
| `vpnLastSessions` | `Object` | `vpn.html:514` | `vpnLoadData`, `renderSessions`, `vpnRenderSessionsStaleBanner` | Updated on poll; preserved across fetch errors to prevent UI flashing. |
| `vpnSessionsStale` | `boolean` | `vpn.html:515` | `vpnLoadData`, `renderSessions`, `vpnRenderSessionsStaleBanner` | Set `false` on `/api/vpn/sessions` success, `true` on fetch failure. |
| `vpnSessionsFilterOnlyProblems` | `boolean` | `vpn.html:516` | `vpnToggleSessionsProblemFilter`, `renderSessions` | Toggled by user click on `#vpn-sessions-toggle-problems-btn`. |
| `vpnHistoryWindow` | `string` | `vpn.html:517` | `vpnSetHistoryWindow`, `vpnRenderHistoryCharts` | Default `'15m'`; updated on user click of window chips; `vpnSetHistoryWindow` directly reads `vpnLastStatus` (`vpn.html:2304-2305`). |
| `vpnShowAllRoutes` | `boolean` | `vpn.html:518` | `vpnToggleShowAllRoutes`, `vpnRenderForwarderHealth` | Default `false`; toggled by user click on `#vpn-routes-toggle-all-btn`. |
| `vpnLastStatus` | `Object` | `vpn.html:519` | `vpnRenderForwarderHealth`, `vpnSetHistoryWindow`, `vpnToggleShowAllRoutes` | Updated on each 5s poll of `/api/vpn/status`. |
| `vpnExpandedSessionIds` | `Set<string>` | `vpn.html:520` | `vpnToggleSessionDrilldown`, `vpnSyncExpandedDrilldowns` | Retains expanded accordion row IDs across table re-renders. |
| `vpnLastActiveProblemKeys` | `Set<string>` | `vpn.html:521` | `vpnRenderForwarderHealth` | Updated on poll; triggers `#vpn-fwd-tech-details.open = true` on new keys. |
| `vpnLastActiveProblemCount` | `number` | `vpn.html:522` | `vpnRenderForwarderHealth` | Updated on poll; triggers auto-expansion when count increases. |
| `window._vpnActiveChartHover` | `Object` | `vpn.html:2013` | `attachInteraction`, `vpnDisposeChartInteractions`, `renderSeries` | Tracks `{ chartId, clientX, clientY, pageX, pageY }` (matching `vpn.html:2013-2019`); preserved across polls. |
| `fmtBps` (top-level) | `function` | `vpn.html:1027` | `renderSessions` (`vpn.html:1186`), `vpnCreateSessionDrilldownRow` (`vpn.html:1313-1314`) | Top-level rate formatter (bps/Kbps/Mbps/Gbps); assigned to `web/static/js/vpn/sessions.js` to ensure sessions rendering retains formatter availability throughout migration waves. |
| `fmtPps` (top-level) | `function` | `vpn.html:1035` | `vpnCreateSessionDrilldownRow` (`vpn.html:1311-1312`) | Top-level packet rate formatter (pps/Kpps/Mpps); assigned to `web/static/js/vpn/sessions.js` for drilldown packet rate rendering. |
| `fmtBps` (health-nested) | `function` | `vpn.html:2328` | Internal to `vpnRenderForwarderHealth` (`vpn.html:2352+`) | Locally scoped shadowing helper inside `vpnRenderForwarderHealth`; assigned to `web/static/js/vpn/health_summary.js`. |
| `fmtPps` (health-nested) | `function` | `vpn.html:2335` | Internal to `vpnRenderForwarderHealth` | Locally scoped shadowing helper inside `vpnRenderForwarderHealth`; assigned to `web/static/js/vpn/health_summary.js`. |
| `SERVER_ID` | `number` | `server.html:599` | All API calls in `server.html` | Immutable constant injected via Go template (`{{ .server_id }}`). |
| `STATS_REFRESH_INTERVAL_MS` | `number` | `server.html:600` | `Telemetry.poll` registrations | Constant: `30000` (30 seconds). |
| `currentInstallProto` | `string` | `server.html:601` | `openInstallModal`, `installProtocol` | Default `'awg'`; set when opening protocol install modal. |
| `currentConfig` | `string` | `server.html:602`, `users.html:424` | `copyConnectionConfig`, `showConnectionConfig`, UI copy buttons | Primed when opening config modal; contains WireGuard config text. |
| `currentVpnLink` | `string` | `server.html:603`, `users.html:425` | `copyConnectionConfig`, `showConnectionConfig`, UI copy buttons | Primed when opening config modal; contains `vpn://...` URL. |
| `currentConfigName` | `string` | `server.html:604`, `users.html:426` | Config download buttons (`UI.downloadFile`) | Default `'connection'`; set to connection name on modal open. |
| `installedProtocols` | `Object` | `server.html:605` | `checkServer`, `updateProtocolCard` | Updated when server check completes. |
| `connectionsTableInstance` | `NexusTable` | `server.html:606` | `loadConnections` (`#connectionsTableContainer`) | Instantiated on connection table load; refreshed on filter change. |
| `showConnectionsSection` | `function` | `server.html:1035` | `updateProtocolCard` (`server.html:898`), `actions.js` | Section visibility primitive displaying `#connectionsSection`; assigned to `web/static/js/server/shared.js`. |
| `hideConnectionsSection` | `function` | `server.html:1040` | `checkServer` (`server.html:782`) | Section visibility and protocol reset primitive; assigned to `web/static/js/server/shared.js`. |
| `serverConfigFilename` | `string` | `server.html:827` | `showServerConfig`, download button | Default `'server.conf'`; updated based on inspected protocol. |
| `window.connectionsStore` | `Object` | `server.html:1214` | `loadConnections`, `editConnection` | In-memory map of `clientId -> userData` for editing connections. |
| `isEditingConn` | `boolean` | `server.html:1446` | `openAddConnectionModal`, `addConnection` | Flag distinguishing connection addition from in-place edit. |
| `editingClientId` | `string` | `server.html:1447` | `openAddConnectionModal`, `addConnection` | Set to client ID during connection edit; `null` during add. |
| `renameServerId` | `number` | `server.html:1678` | `openRenameServerModal`, `submitRenameServer` | Tracks target server ID for rename operation. |
| `editHostServerId` | `number` | `server.html:1718` | `openEditHostModal`, `submitEditHost` | Tracks target server ID for host address modification. |
| `currentUserId` | `string` | `users.html:422` | `openAddConnectionForUser`, `doAddUserConnection` | Set to user ID when opening connection modal for a user. |
| `currentUsername` | `string` | `users.html:423` | `openAddConnectionForUser`, `viewUserConnections` | Set to username when opening connection modal for a user. |
| `currentPage` | `number` | `users.html:428` | `changePage`, `refreshUsersList` | Tracks active pagination page (1-indexed). |
| `pageSize` | `number` | `users.html:429` | `refreshUsersList` | Constant: `12` users per page. |
| `searchQuery` | `string` | `users.html:430` | `handleSearch`, `clearUserSearch`, `refreshUsersList` | Debounced query string for user filtering. |
| `selectedRole` | `string` | `users.html:431` | `setRoleFilter`, `refreshUsersList` | Active role filter: `'all'`, `'admin'`, `'support'`, or `'user'`. |
| `searchTimeout` | `number` | `users.html:432` | `handleSearch`, `clearUserSearch` | Timer handle for 300ms search input debouncing (matching `users.html:446-450`). |
| `userConnsTableInstance` | `NexusTable` | `users.html:433` | `viewUserConnections` (`#userConnsTableContainer`) | Instantiated on user connections modal display; refreshed on reload. |
| `serversData` | `Object` | `users.html:435` | `updateProtocols` | Go-template JSON map of servers and available protocols (`{{ .servers \| json }}`). |
| `currentAdminUsername` | `string` | `users.html:436` | User row action visibility | Injected Go string: username of logged-in administrator. |
| `currentIsAdmin` | `boolean` | `users.html:437` | User row action visibility | Injected Go boolean: admin role check. |
| `currentUserID` | `string` | `users.html:438` | User row self-edit guard | Injected Go string: ID of logged-in user. |
| `currentSharedUser` | `string` | `users.html:1191` | `openShareModal`, `saveShareSetup` | Tracks target user ID for public share link configuration. |

---

## 4. Go-Template Interpolation & Escaping Contracts

### 4.1 Template Action Audit across Script Blocks

A critical security and stability requirement for modularization is isolating Go template interpolations (`{{ ... }}`) from JavaScript code. Embedding raw template tags inside `<script>` blocks couples markup rendering to runtime logic, prevents static script caching, and complicates Content Security Policies (CSP).

The repository displays three distinct interpolation patterns:

1. **`web/templates/vpn.html` (Zero Embedded Script Interpolations)**:
   - Audit across lines 501–3757 verifies **ZERO Go-template actions** inside `<script>`.
   - All dynamic state is fetched asynchronously via REST APIs (`/api/vpn/status`, `/api/vpn/config`, `/api/vpn/backends`, `/api/vpn/sessions`, `/api/servers`).
   - All user-facing strings are resolved dynamically using `window._(key)` against `window.I18N` or via `vpnDiagText()`.
   - *Modularization Impact*: Script blocks in `vpn.html` can be migrated byte-for-byte to static `.js` files with zero Go template data extraction required.

2. **`web/templates/server.html` (Single Primitive Constant & Inline Attributes)**:
   - Script line 599: `const SERVER_ID = {{ .server_id }};`
   - *Escaping Contract*: `.server_id` is an integer (`int64`). Injected as an unquoted numeric literal.
   - *HTML Attribute Injections*: Lines 62 and 68 interpolate Go values into inline `onclick` handlers:
     ```html
     onclick="openRenameServerModal({{ .server.ID }}, '{{ .server.Name }}')"
     onclick="openEditHostModal({{ .server.ID }}, '{{ .server.Host }}')"
     ```
     *Escaping Behavior & Architectural Decoupling (Finding 3)*: Go's `html/template` provides contextual auto-escaping within JavaScript attributes (escaping single quotes as `\u0027`), which safely mitigates string breakouts. However, embedding dynamic expressions inside inline event handlers couples HTML rendering directly to JavaScript function signatures and violates strict CSP directives.
     *Remediation Contract (Issue #501/#503)*: Migrate parameters to DOM data-attributes on the triggering elements:
     ```html
     data-server-id="{{ .server.ID }}"
     data-server-name="{{ .server.Name }}"
     data-server-host="{{ .server.Host }}"
     ```
     Handlers read these values via `this.dataset.serverId`, `this.dataset.serverName`, and `this.dataset.serverHost`, cleanly decoupling HTML attributes from JavaScript invocation.

3. **`web/templates/users.html` (Four Global Data Injections & One Embedded Partial)**:
   - **Script Block 1 (lines 435–438)** contains **10 Go-template actions**:
     ```javascript
     const serversData = {{ .servers | json }};
     const currentAdminUsername = '{{ if .current_user }}{{ .current_user.Username }}{{ end }}';
     const currentIsAdmin = {{ if has_role .current_user "admin" }}true{{ else }}false{{ end }};
     const currentUserID = '{{ if .current_user }}{{ .current_user.ID }}{{ end }}';
     ```
   - **Script Block 2 (lines 1190–1309)** contains **0 Go-template actions** (pure JavaScript).
   - **Intervening Share Modal HTML (lines 1135–1189)** contains **11 Go-template actions** across 10 lines (`{{ _ "share_access" }}`, `{{ _ "cancel" }}`, `{{ _ "enable_public_access" }}`, `{{ _ "share_password_label" }}`, `{{ _ "new_password_hint" }}`, `{{ _ "share_password_hint" }}`, `{{ _ "public_link_label" }}`, two instances of `{{ _ "copy" }}`, `{{ _ "cancel" }}`, `{{ _ "save" }}`).
   - **Audited Region vs. Template Scope (Finding 5)**: Exactly **21 Go-template actions** reside across the audited JavaScript migration region (10 in script block 1, 0 in script block 2, and 11 in the intervening share modal markup). In contrast, the complete `web/templates/users.html` file contains **141 total Go-template actions** across its complete HTML markup, navigation, user table, and modal templates.
   - *Escaping Contracts*:
     * `{{ .servers | json }}`: Serialized via Go's trusted JSON helper, wrapping output as `template.JS` safe for assignment to a JavaScript variable.
     * `currentAdminUsername` / `currentUserID`: String values wrapped in single quotes, contextually escaped by Go's `html/template`.
     * `currentIsAdmin`: Evaluates strictly to boolean literals `true` or `false`.
   - *Remediation Contract (Issue #542)*:
     * Retain a 5-line inline bootstrap block in `users.html` exposing `window.NEXUS_USER_PAGE_DATA = { servers: {{ .servers | json }}, adminUsername: ..., isAdmin: ..., userId: ... };` or set standard data-attributes on `<main id="users-page" data-user-id="..." data-is-admin="...">`.
     * Move the Share Modal markup out of the script boundary and relocate all JavaScript from both blocks into `web/static/js/users.js`.

---

## 5. DOM Event Listeners, Timers & Polling Ownership

### 5.1 DOM Event Bindings & Accordion Disclosures

The administrative interface coordinates user actions via three mechanisms:
1. **Delegated / Inline `onclick` and `onchange` attributes**: Declared in templates, invoking named global functions.
2. **Dynamic DOM Event Listeners**: Attached at runtime during initialization and table rendering:
   - Concrete `change` listeners attached to 4 selects in `users.html:695-717` (`#newUserServer`, `#newUserProtocol`, `#ucServer`, `#ucProtocol`) for dynamic protocol cascades and mimicry toggling.
   - Drilldown row toggles and chart hover listeners attached dynamically in VPN and Server views.
3. **Progressive Disclosure Accordions**: Native HTML `<details>` and `<summary>` elements manipulated by both user clicks and diagnostic polling.

#### Accordion & Disclosure State Invariants:

- **Technical Diagnostics Accordion (`#vpn-fwd-tech-details`)**:
  * Default state: Closed (`open = false`).
  * Auto-disclosure rule: When `vpnRenderForwarderHealth` detects an active problem condition that was NOT in `vpnLastActiveProblemKeys`, or when active problem count increases (`activeProblemsCount > vpnLastActiveProblemCount`), it automatically sets `techDetails.open = true`.
  * Manual override contract: If a user manually collapses the accordion while existing problem keys remain unchanged, subsequent polls MUST respect the user's closure and not re-expand it until a *new* problem key or higher count occurs.
- **Route Queue Details Accordion (`#vpn-fwd-routes-details`)**:
  * Auto-disclosure rule: When `routeHasPressure === true` (any route has queue occupancy > 0, drops > 0, or pressure note), `detailsElem.open = true` is set.
- **Troubleshooting Table Row Accordions (`.vpn-drilldown-row`)**:
  * Toggled via `vpnToggleSessionDrilldown(session, rowElement)`.
  * Persistence invariant: Expanded session IDs are stored in `vpnExpandedSessionIds = new Set()`. When `renderSessions` re-renders table rows during periodic polling or filter changes, `vpnSyncExpandedDrilldowns()` re-creates drilldown rows for all active IDs in the Set, preventing open accordions from collapsing on poll cycles.

---

### 5.2 Polling Lifecycles, Timers & Teardown Contracts

Polling across Amnezia Nexus is managed by the `NexusTelemetry` engine (`web/static/js/telemetry.js`).

| Page / Subsystem | Stream Key | Base Interval | Polling Callback | Endpoints Polled | Error Backoff & Teardown Rules |
|---|---|---|---|---|---|
| **VPN Dashboard** | `'vpn-status'` | 5,000 ms (5s) | `vpnLoadData` | `/api/vpn/status`<br>`/api/vpn/config`<br>`/api/vpn/backends`<br>`/api/vpn/sessions` | Multi-fetch via `Promise.all`. If `/api/vpn/sessions` fails, `vpnSessionsStale = true` is set and `vpnLastSessions` is retained (stale warning banner shown; never flashes empty table). Automatically pauses on tab blur (`document.visibilityState === 'hidden'`). Stopped via `NexusTelemetry.stop('vpn-status')`. |
| **Server Details** | `'server-stats-' + SERVER_ID` | 30,000 ms (30s) | `loadServerStats` | `/api/servers/${SERVER_ID}/stats` | Silent fetch (`silent: true`). Exponential backoff on HTTP error (multiplier $2\times$, capped at 60,000 ms / 60s per `telemetry.js:157-159, 205-208`). Pauses when hidden. Stopped via `Telemetry.stop('server-stats-' + SERVER_ID)`. |
| **Server Details** | `'server-reachability-' + SERVER_ID` | 30,000 ms (30s) | `updateReachability` | `/api/servers/${SERVER_ID}/reachability` | Silent fetch (`silent: true`). Renders auto-trials for TLS, QUIC, DNS, SIP. Exponential backoff capped at 60,000 ms. Pauses when hidden. Stopped via `Telemetry.stop('server-reachability-' + SERVER_ID)`. |
| **Users Page** | N/A (On-demand) | N/A | `refreshUsersList` | `/api/users?search=...&role=...` | Invoked on `DOMContentLoaded`, on role filter switch, page navigation, and after add/edit/delete/toggle actions. Search input is debounced by 300 ms via `searchTimeout` (matching `users.html:446-450`). |

#### Timer Technical Debt & Teardown Distinction (Finding 4):
1. **Pre-existing Install Progress Timer Debt**:
   In `web/templates/server.html:1116-1145`, protocol installation initializes `progressInterval = setInterval(...)`. The interval is cleared via `clearInterval(progressInterval)` upon successful completion of the POST request. However, if the request fails and enters `catch (err)`, `clearInterval` is not invoked, leaving the timer ticking indefinitely in the background. During extraction of `server/actions.js`, this must be resolved by guaranteeing interval cleanup on both success and error paths (e.g., via `finally`).
2. **Current vs. Desired Future Teardown**:
   Existing monolithic templates do NOT unregister active timers or polling streams on view transitions. Target static modules must provide explicit teardown hooks (`Telemetry.stop(...)`) on page unload or single-page navigation to prevent background goroutine and memory accumulation.

---

## 6. Existing Test Baseline & Harness Mapping

### 6.1 Test Suites Breakdown (`web/vpn_diagnostics_test.go`)

`web/vpn_diagnostics_test.go` contains 33 verified Go test functions. The test suite comprises five distinct verification harnesses (Finding 4):
- **Pure Go Dictionary Checks (2 functions)**: Tests 8 and 25 verify translation key parity, completeness, and `{placeholder}` consistency across all 5 JSON locale files without any DOM or Node.js execution.
- **Token-Based String Verification (1 function)**: Test 16 (`TestVPNDiagnosticsPollingContract`) is a static token-checking test. It reads `templates/vpn.html` via `TemplatesFS.ReadFile` and uses Go string counts (`strings.Count`, `strings.Contains`) to assert the literal presence of polling and handler tokens (`NexusTelemetry.poll('vpn-status'`, `API.get('/api/vpn/status')`, `vpnRenderForwarderHealth(status)`), without executing Node.js or JSDOM.
- **Go HTML-Parser DOM Tests (1 function)**: Test 32 (`TestVPNDashboardSectionOrder`) parses `templates/vpn.html` using Go's `golang.org/x/net/html` (`xhtml.Parse`) to assert visual container sibling order (`stats-grid -> backends card -> sessions card -> vpn-forwarder-card`, visual order: `stats -> backends -> sessions -> forwarder`) and verifies rejection of decoy HTML comments.
- **Node.js with Custom DOM Mock (27 functions)**: Tests 1–7, 9–15, 17–24, 26–27, 29, 31, and 33 extract target JavaScript functions from `vpn.html` and execute them inside Node.js against a lightweight Go-synthesized mock DOM (`vpnDOMMock`) implementing element structures, attributes, and class lists. Specifically, Test 15 (`TestVPNDiagnosticsTemplateDOMOracle`) uses this Node/custom DOM mock harness to verify that mutated element IDs fail the DOM oracle check against the template's element registry.
- **Headless JSDOM Environment (2 functions)**: Tests 28 and 30 execute in Node.js using the full headless `jsdom` npm package to validate complete browser DOM lifecycles, event dispatching, and `NexusTable` sorting and accordion state persistence.

| # | Test Function Name | Test Type | Tested Function / UI Component | Key Invariants Verified |
|---|---|---|---|---|
| 1 | `TestVPNDiagnosticsHealthAndStructure` | Node.js (vpnDOMMock) | `vpnRenderForwarderHealth`, DOM structure | Validates banner status, forwarder headline, badges, and card hierarchies. |
| 2 | `TestVPNHistoryChartLatencyAvailability` | Node.js (vpnDOMMock) | `vpnRenderHistoryCharts`, `renderBadges` | Verifies latency badge reflects availability flags without NaN rendering. |
| 3 | `TestVPNCompleteRouteTooltipContract` | Node.js (vpnDOMMock) | `routeTooltip`, `vpnFormatPeerKey` | Validates tooltip text for healthy, pressure, and error route states. |
| 4 | `TestVPNOperationalDiagnosticsCardsContract` | Node.js (vpnDOMMock) | Cards 1–4 diagnostic panels | Verifies CPU, memory, FD, queue occupancy, drop categories, and rate strings. |
| 5 | `TestVPNCompleteHistoryAllWindowRenderers` | Node.js (vpnDOMMock) | `vpnRenderHistoryCharts`, window toggles | Exercises 1m, 5m, 15m, 1h, 6h, 24h historical chart transformations. |
| 6 | `TestVPNUnavailableForwarderClearsStaleHistoryState` | Node.js (vpnDOMMock) | `vpnRenderForwarderHealth`, charts | Ensures unavailable forwarder clears stale canvas/SVG series. |
| 7 | `TestVPNPanelRateAvailability` | Node.js (vpnDOMMock) | `vpnDiagText`, rate formatters | Tests availability toggling across throughput, drops, and latency rates. |
| 8 | `TestVPNDiagnosticsLocalizationDictionaries` | Pure Go Dictionary | i18n dictionaries (`en`, `ru`, `fa`, etc.) | Pure Go dictionary check verifying key presence, count equality, and placeholder parity across JSON files without DOM or Node. |
| 9 | `TestVPNDiagnosticsLocalization` | Node.js (vpnDOMMock) | `vpnRenderForwarderHealth`, `_()` | Asserts correct language translation rendering in Node/DOM mock across all 5 locales. |
| 10 | `TestVPNDiagnosticsLocalizationMutations` | Node.js (vpnDOMMock) | i18n mutations | Checks fault-injection resilience when translation keys are missing or malformed. |
| 11 | `TestVPNBackendDeviceKPIAlarmCoverage` | Node.js (vpnDOMMock) | KPI Summary Bar | Validates color alarms (danger/warning) on backend drop rates and stalls. |
| 12 | `TestVPNBackendDeviceKPIAlarmMutations` | Node.js (vpnDOMMock) | KPI alarm state transitions | Ensures transitions between healthy, warning, and critical preserve DOM classes. |
| 13 | `TestVPNBackendDeviceUnattributedConditionRendering`| Node.js (vpnDOMMock) | Condition synthesis | Validates fallback rendering when condition entities lack backend IDs. |
| 14 | `TestVPNDiagnosticsCurrentObservations` | Node.js (vpnDOMMock) | Current vs cumulative metrics | Asserts live horizon (`Current / Live`) vs reset horizon (`Since Startup / Reset`). |
| 15 | `TestVPNDiagnosticsTemplateDOMOracle` | Node.js (vpnDOMMock) | Static HTML DOM validation | Executes Node.js with custom `vpnDOMMock` to verify that mutating template element IDs is caught by the DOM oracle. |
| 16 | `TestVPNDiagnosticsPollingContract` | Token String Check | Polling string tokens | Checks literal presence of `NexusTelemetry.poll`, `API.get`, and health handlers via `strings.Count`/`strings.Contains` without DOM or Node. |
| 17 | `TestVPNForwarderHealthDecouplingAndHorizon` | Node.js (vpnDOMMock) | Horizon decoupling | Verifies decoupling of forwarder status from peer-sync availability. |
| 18 | `TestVPNProgressiveDisclosureAndActiveProblems` | Node.js (vpnDOMMock) | `#vpn-fwd-tech-details` | Verifies auto-expansion on new problem keys and preservation of manual closure. |
| 19 | `TestVPNConnectionTroubleshootingTableAndCorrelation`| Node.js (vpnDOMMock) | `renderSessions`, `vpnFindRouteForSession`| Verifies session-to-route correlation and diagnostic badge display. |
| 20 | `TestVPNHorizonWindowToggles1mAnd5m` | Node.js (vpnDOMMock) | `vpnSetHistoryWindow` | Verifies 1m and 5m short-horizon window toggling and SVG regeneration. |
| 21 | `TestVPNSummaryHeaderCountsAndProblemCardOnset` | Node.js (vpnDOMMock) | Problem card onset | Verifies onset timestamps and problem counter in summary header. |
| 22 | `TestVPNForwarderCombinedActionableAndGenericConditions`| Node.js (vpnDOMMock) | Condition rendering | Tests mixed actionable conditions and generic fallback condition rendering. |
| 23 | `TestVPNForwarderStaleHandshakeActionableProblemDOM` | Node.js (vpnDOMMock) | Stale handshake synthesis | Verifies DOM output when peer handshakes exceed timeout thresholds. |
| 24 | `TestVPNForwarderStaleHandshakeEmptySnapshotMatchingCountsDOM`| Node.js (vpnDOMMock) | Empty snapshot handling | Ensures stale handshake logic handles zero-peer snapshots gracefully. |
| 25 | `TestVPNTranslationKeyParity` | Pure Go Dictionary | Translation dictionaries | Strict 100% key parity check across all supported translation files against en.json without DOM or Node. |
| 26 | `TestVPNPacketLossCellDecoupledFromQueuePressure` | Node.js (vpnDOMMock) | Sessions table loss cell | Ensures packet loss cell is decoupled from queue pressure calculations. |
| 27 | `TestVPNReconnectSessionIDMismatchShowsUnroutable` | Node.js (vpnDOMMock) | Route drilldown | Displays unroutable badge when session ID does not match active route ID. |
| 28 | `TestVPNNexusTableLifecycleDrilldownAndConfigDedup`| Headless JSDOM | `vpnCreateSessionDrilldownRow` | Asserts drilldown DOM lifecycle, action buttons, and config deduplication using Node with jsdom. |
| 29 | `TestVPNForwarderRoutesTableFormatting` | Node.js (vpnDOMMock) | Route formatting | Asserts numeric formatting, bytes/sec, and packet rates in routes table. |
| 30 | `TestVPNSessionsTableSortingAndAccordionPersistence`| Headless JSDOM | `NexusTable`, `vpnExpandedSessionIds`| Tests sorting by bytes/loss and validates accordion persistence across sort using Node with jsdom. |
| 31 | `TestVPNRoutingConsistencyBadgeSeverityAware` | Node.js (vpnDOMMock) | Severity badge logic | Tests CRITICAL, DEGRADED, and WARNING severity badge color assignment. |
| 32 | `TestVPNDashboardSectionOrder` | Go HTML-Parser (xhtml.Parse) | Visual DOM section ordering | Validates layout order: stats-grid -> backends card -> sessions card -> vpn-forwarder-card (visual order: stats -> backends -> sessions -> forwarder); rejects decoy comments. |
| 33 | `TestVPNHistoricalChartsContract` | Node.js (vpnDOMMock) | `vpnRenderHistoryCharts` | Full contract test verifying chart canvases, axes, legends, and series. |

---

### 6.2 Test Harness Function Extraction & Atomic Staging (Findings 1 & 6)

`web/vpn_fixture_test.go` extracts target functions for execution inside Node.js/JSDOM:
```go
// web/vpn_fixture_test.go:295
for _, fn := range opts.ExtractedFuncs {
    code, err := extractJSFunction(f.TemplateHTML, "function "+fn)
    if err != nil {
        f.t.Fatalf("extractJSFunction %s failed: %v", fn, err)
    }
    extracted.WriteString(code + "\n")
}
```

#### Extractor Mechanics (Finding 6)
`extractJSFunction` (defined in `web/vpn_fixture_test.go:598-622`) uses `strings.Index` to find the function signature and opening brace, and tracks brace nesting depth (`depth++` on `{`, `depth--` on `}`) to identify the function boundary. It does **NOT** use regular expressions.

#### Atomic Staging Mandate (Finding 1)
When extracting functions from `web/templates/vpn.html` into static JavaScript files:
1. **No Deferred Script Tags**: Asset loading tags (`<script src="/static/js/vpn/....js"></script>`) MUST land in the HTML template within the **exact same PR** as each static module extraction, rather than waiting for the final template PR.
2. **Atomic Fixture Adaptation**: Prior to or in conjunction with the first wave of function extraction, `VPNTestFixture` and `extractJSFunction` must be updated to inspect both `web/templates/vpn.html` and extracted static files (`web/static/js/vpn/*.js`), or load static files directly. If a function is deleted from `vpn.html` without updating the fixture loader in the same PR, JSDOM tests will fail immediately with `function <name> not found in source`.

---

### 6.3 Domain & Embedded Web Test Suites

The table below maps tests in `web/*_test.go` that inspect frontend templates and scripts:

| Test File | Test Function Name | Inspected File / Feature | Verified Contract |
|---|---|---|---|
| `web/web_server_users_test.go` | `TestPhase4DashboardAndServerModernization` | `server.html`, `server.go` | Verifies protocol badges, server statistics rendering, and container actions. |
| `web/web_server_users_test.go` | `TestIssue113UsersUIModernization` | `users.html` | Asserts user list structure, search bar, role filter chips, and pagination controls. |
| `web/web_server_users_test.go` | `TestIssue115_RemoveApiDocsAndImportUsers` | `users.html` | Verifies removal of deprecated API docs links and presence of user import seams. |
| `web/web_server_users_test.go` | `TestServerTemplateI18nAndTranslations` | `server.html` | Verifies i18n key interpolation across server forms and status modals. |
| `web/web_server_users_test.go` | `TestUsersTemplateServerZeroHandling` | `users.html` | Validates handling when no servers are configured for user connection assignment. |
| `web/web_server_users_test.go` | `TestUsersTemplatePageSize` | `users.html` | Asserts pagination constant `pageSize = 12`. |
| `web/web_server_users_test.go` | `TestServerTemplate_TelemetryPolling` | `server.html` | Asserts presence of `Telemetry.poll` for stats and reachability with 30s interval. |
| `web/web_server_users_test.go` | `TestIssue278EditServerHostUIAndTranslations` | `server.html` | Validates host editing modal DOM, labels, and translations. |
| `web/web_server_users_test.go` | `TestClientSideHostValidation` | `server.html:isValidHost` | Validates client-side validation regex for IPv4, IPv6, and FQDN hostnames. |
| `web/web_vpn_test.go` | `TestPhase5VPNAndUsersModernization` | `vpn.html` | Verifies modernized layout, KPI cards, and backends table. |
| `web/web_vpn_test.go` | `TestLoadBalancerHighlightAndAwgPreselection` | `vpn.html` | Verifies AWG protocol preselection and load balancer highlight indicators. |
| `web/web_vpn_test.go` | `TestModernClientDashboardPage` | `vpn.html` | Validates client dashboard responsiveness and design system alignment. |
| `web/web_vpn_test.go` | `TestIssue101VPNModernization` | `vpn.html` | Asserts VPN configuration display, QR code, and public endpoint modal. |
| `web/web_vpn_test.go` | `TestIssue101ShowConfigIconRework` | `vpn.html` | Validates config icon rendering and click interactions. |
| `web/web_vpn_test.go` | `TestIssue101VPNPolishRework` | `vpn.html` | Asserts UI polish, spacing tokens, and color variables. |
| `web/web_vpn_test.go` | `TestIssue109VPNTableFullWidth` | `vpn.html`, `style.css` | Asserts full-width responsive layout for VPN backends and sessions tables. |
| `web/web_embedded_test.go` | `TestEmbeddedStaticAndTemplates` | `web/static/**/*`, `web/templates/*` | Ensures all static assets and HTML templates are embedded via `embed.FS`. |
| `web/web_test.go` | `TestModernJavaScriptAndInteractiveComponents`| Static JS libraries | Validates `api.js`, `ui.js`, `tables.js`, and `telemetry.js` exports. |
| `web/web_test.go` | `TestPhase3TablesAndTelemetryEngine` | `tables.js`, `telemetry.js` | Verifies `NexusTable` pagination/sorting and `NexusTelemetry` polling engine. |

---

### 6.4 Playwright End-to-End (E2E) Test Suites

The repository contains Playwright integration suites in `tests/e2e/*.py` that execute in real browsers against a live server:

1. **`tests/e2e/test_vpn_diagnostics.py`**:
   - `test_vpn_dashboard_navigation_and_banner`: Navigates to `/vpn`, validates live banner, public endpoint auto-detection.
   - `test_vpn_kpi_summary_bar`: Validates all 8 KPI tiles and live metric updates.
   - `test_vpn_diagnostic_panels`: Validates Data Plane, Traffic Drops, Route Integrity, and Fleet Resources panels.
   - `test_vpn_sparklines_window_toggle`: Interacts with window chips (1m, 5m, 15m, 1h, 6h, 24h) and checks active classes.
   - `test_vpn_historical_charts_interaction_and_kpis`: Tests chart hover tooltips and dynamic KPI value updates.
   - `test_vpn_historical_charts_hover_preserved_across_live_polling`: Verifies hover state survives 5s polling updates without jitter.
   - `test_vpn_problem_routes_toggle`: Toggles `#vpn-routes-toggle-all-btn` and checks table row count transitions.
   - `test_vpn_sessions_problems_toggle`: Toggles `#vpn-sessions-toggle-problems-btn` and verifies problem filtering.
   - `test_vpn_routes_table_mobile_containment_and_scrolling`: Asserts table responsiveness under mobile viewports.
   - `test_vpn_dashboard_sections_visual_order_and_vertical_layout`: Validates strict visual vertical ordering of sections (stats -> backends -> sessions -> forwarder).

2. **`tests/e2e/test_servers.py`**:
   - `test_server_list_loads`: Validates server grid rendering.
   - `test_server_detail_page`: Loads `/server/{id}`, validates stats, reachability badges, protocol cards.
   - `test_server_check`: Clicks check button, validates live spinner and status badge update.
   - `test_server_install`: Exercises protocol install modal stepper and form validation.
   - `test_server_stats`: Asserts CPU, memory, and disk telemetry display.
   - `test_server_edit_host_ui_validation`: Tests client-side validation on host edit input (RFC 1123 / IP regex).
   - `test_server_edit_host_ui_lifecycle`: Full lifecycle: open modal -> enter host -> submit -> verify displayed host updates.

3. **`tests/e2e/test_users.py`**:
   - `test_user_list_loads`: Validates user card grid and filter chips.
   - `test_add_user`: Adds a user via modal, asserts grid refresh and notification toast.
   - `test_edit_user`: Edits user limits/roles, asserts persistence.
   - `test_toggle_user`: Disables and enables user, verifies badge status.
   - `test_add_user_connection`: Provisions a connection, verifies QR code and WireGuard configuration download.
   - `test_delete_user`: Exercises delete modal confirmation.
   - `test_xss_prevention`: Enters malicious HTML/JS payloads in username and connection name; asserts proper DOM escaping.

---

## 7. Phased Extraction & Migration Plan (Phase 3 & #542)

To maintain reviewability, prevent regression risk, and satisfy the project guideline of remaining strictly below 1,000 lines per PR, Phase 3 modularization is structured into sequential waves.

### Sizing and Line Ceiling Protocol (Finding 1 & Finding 3)
- **Per-File Physical Line Ceiling**: Every newly created static JavaScript module must strictly adhere to the project line ceiling of under 1,000 physical lines (`health_summary.js` is ~450 physical lines; `health_problems.js` is ~850 physical lines).
- **PR Diff Lines vs. Physical File Lines (Finding 3)**: PR diff line counts during file extractions reflect code movement (e.g. adding ~1,300 lines of static JS and deleting ~1,300 lines of inline template script). PR diff line counts must not be confused with physical file line limits; the sub-1,000 line rule governs the physical size of individual source files.
- **Monolithic HTML templates** (e.g. `vpn.html` at 3,758 lines) shrink progressively across the waves. They are exempt from the sub-1,000 line rule during transitional states until reaching their final thin template PR (<600 lines).
- **Atomic Loading & Harness Updates**: Each wave atomically updates the template's script inclusion tags and the test fixture function extractor to ensure all tests remain green at every PR boundary.

```
Wave 1: Test Harness & Contract Prerequisites
  [x] #478 (This Document: docs/architecture/frontend-javascript-contracts.md)
  [x] #484 (Reusable Node/JSDOM test fixture for VPN diagnostics)
  [ ] #485 (Split web/vpn_diagnostics_test.go into focused test files — in-flight verified PR #555 awaiting merge)
       |
       v
Wave 2: VPN Feature Controllers Extraction (Atomic Script & Fixture Updates)
  [ ] Step 1: #495  -> web/static/js/vpn/sessions.js (~520 lines, includes top-level fmtBps/fmtPps)
  [ ] Step 2a: #496b -> web/static/js/vpn/health_problems.js (~850 lines, leaf problem & diagnostic helpers extracted first while inline template orchestrator calls them)
  [ ] Step 2b: #496a -> web/static/js/vpn/health_summary.js (~450 lines, headline & KPI orchestrator invoking health_problems delegates; OR atomic two-file extraction for #496)
  [ ] Step 3: #497  -> web/static/js/vpn/charts.js (~520 lines)
  [ ] Step 4: #498  -> web/static/js/vpn/backends.js (~480 lines)
       |
       v
Wave 3: VPN Page Bootstrap & Template Finalization
  [ ] Step 5: #499 -> web/static/js/vpn/page.js (~200 lines)
  [ ] Step 6: #500 -> web/templates/vpn.html (Thin markup template, ~500 lines)
       |
       v
Wave 4: Users Page Modularization
  [ ] Step 7: #542 -> web/static/js/users.js (~840 lines) & thin web/templates/users.html
       |
       v
Wave 5: Server Page Modularization (Cycle Break & Timer Fix)
  [ ] Step 8: #501a -> web/static/js/server/shared.js (~200 lines, breaks actions/monitoring cycle)
  [ ] Step 9: #501b -> web/static/js/server/actions.js (~580 lines, fixes progressInterval leak)
  [ ] Step 10: #502 -> web/static/js/server/monitoring.js (~420 lines, 60s backoff cap)
  [ ] Step 11: #503 -> web/templates/server.html (Thin markup template, ~600 lines)
       |
       v
Wave 6: Stylesheet Partitioning
  [ ] Step 12: #504 (CSS selector & ownership audit)
  [ ] Step 13: #505 (Split web/static/css/style.css into theme/layout/components)
```

---

### 7.1 Detailed Step-by-Step Execution Plan

#### Step 1: Issue #495 — Extract VPN Sessions & Troubleshooting Controller
- **Destination**: `web/static/js/vpn/sessions.js` (~520 lines).
- **Scope**: Extract `renderSessions`, `vpnRenderSessionRow`, `vpnCreateSessionDrilldownRow`, `vpnToggleSessionDrilldown`, `vpnSyncExpandedDrilldowns`, `vpnToggleSessionsProblemFilter`, `vpnRenderSessionsStaleBanner`, `vpnFindSessionById`, `vpnFindRouteForSession`, top-level rate formatters (`fmtBps`, `fmtPps`), and formatting helpers (`vpnFormatBytes`).
- **Contract Guardrails**: Preserve all DOM IDs (`#vpn-sessions-tbody`, `#vpnSessionsStaleBanner`, `#vpn-sessions-toggle-problems-btn`), `NexusTable` sorting on traffic/packet loss, and expanded accordion persistence across poll cycles (`vpnExpandedSessionIds`). Top-level rate formatters `fmtBps` and `fmtPps` (`vpn.html:1027–1040`) are extracted with `sessions.js` to ensure `renderSessions` (line 1186) and session drilldown rows (lines 1311–1314) retain access throughout migration waves. The health module retains its independent shadowing definitions (`vpn.html:2328–2339`).
- **Atomic Staging**: Add `<script src="/static/js/vpn/sessions.js"></script>` to `vpn.html` and update `extractJSFunction`/`VPNTestFixture` atomically in this PR.
- **Test Baseline**: Verify `TestVPNSessionsTableSortingAndAccordionPersistence`, `TestVPNConnectionTroubleshootingTableAndCorrelation`, and `TestVPNPacketLossCellDecoupledFromQueuePressure`.

#### Step 2a: Issue #496b — Extract VPN Health Problems & Technical Diagnostics Controller
- **Destination**: `web/static/js/vpn/health_problems.js` (~850 lines).
- **Transitional Scope**: Extract active actionable problem cards, condition parsers (`deriveStableConditionCode`, `parseConditionMessage`), entity extractors (`extractConditionEntities`), severity badge generators (`createSeverityBadge`), tech diagnostics accordion disclosure logic (`#vpn-fwd-tech-details`), and diagnostic cards 1–4.
- **Transitional Contract (Finding 3)**: Extracting `health_problems.js` first in Wave 2 leaves the top-level orchestrator `vpnRenderForwarderHealth` inline in `web/templates/vpn.html` directly invoking the extracted functions loaded via `<script src="/static/js/vpn/health_problems.js"></script>`. This guarantees continuous test passability with zero missing delegates.
- **Contract Guardrails**: Strictly enforce sub-1,000 physical line ceiling (~850 lines). Preserve auto-disclosure of `#vpn-fwd-tech-details` on new problem keys and manual collapse preservation. Retain message parsing and entity extraction byte-for-byte.
- **Atomic Staging**: Add `<script src="/static/js/vpn/health_problems.js"></script>` to `vpn.html` and update `VPNTestFixture` atomically.
- **Test Baseline**: Verify all diagnostic and progressive disclosure tests (`TestVPNProgressiveDisclosureAndActiveProblems`, `TestVPNOperationalDiagnosticsCardsContract`).

#### Step 2b: Issue #496a — Extract VPN Health Headline & KPI Summary Controller
- **Destination**: `web/static/js/vpn/health_summary.js` (~450 lines).
- **Scope**: Extract top-level `vpnRenderForwarderHealth` headline orchestration, KPI summary bar rendering (throughput, routes/sessions, queue pressure, packet loss, client engine, peer sync, healthy backends, slow writes), route tooltip generator (`routeTooltip`), and health-nested shadowing formatters (`fmtBps`, `fmtPps`, `fmtDurationSec`, `vpnFormatCountersSince`).
- **Transitional Contract (Finding 3)**: Because `health_problems.js` was already extracted and loaded in Step 2a, `vpnRenderForwarderHealth` seamlessly invokes delegates in `health_problems.js` without broken dependencies.
- **Alternative Atomic Two-File Staging (Finding 3)**: If preferred during PR implementation, Step 2 can land atomically as a single PR for Issue #496 containing both `health_summary.js` (~450 lines) and `health_problems.js` (~850 lines). Both files individually comply with the sub-1,000 physical line ceiling, while aggregate PR diff line additions and deletions reflect standard file relocation.
- **Contract Guardrails**: Enforce sub-1,000 physical line ceiling (~450 lines). Scoped helpers `fmtBps` and `fmtPps` (`vpn.html:2328–2339`) shadow top-level formatters for health summary calculations.
- **Atomic Staging**: Add `<script src="/static/js/vpn/health_summary.js"></script>` to `vpn.html` and update `VPNTestFixture` atomically.
- **Test Baseline**: Verify `TestVPNDiagnosticsHealthAndStructure`, `TestVPNBackendDeviceKPIAlarmCoverage`, and route tooltip contracts.

#### Step 3: Issue #497 — Extract Historical Telemetry Charts & Controls
- **Destination**: `web/static/js/vpn/charts.js` (~520 lines).
- **Scope**: Extract `vpnRenderHistoryCharts`, `vpnGenerateSparklineSVG`, `vpnSetHistoryWindow`, window toggle handlers, tooltip interaction listeners, and hover state preservation (`window._vpnActiveChartHover`).
- **Contract Guardrails**: Preserve SVG path math, zero NaN occurrences on missing series, hover coordinate retention across live 5s polling sweeps (`{ chartId, clientX, clientY, pageX, pageY }`), read dependency of `vpnSetHistoryWindow` on `vpnLastStatus`, and timer/listener disposal on window switches.
- **Atomic Staging**: Add `<script src="/static/js/vpn/charts.js"></script>` to `vpn.html` and update `VPNTestFixture` atomically.
- **Test Baseline**: Verify `TestVPNHistoricalChartsContract`, `TestVPNHistoryChartLatencyAvailability`, `TestVPNCompleteHistoryAllWindowRenderers`, and `test_vpn_historical_charts_hover_preserved_across_live_polling`.

#### Step 4: Issue #498 — Extract VPN Backend Management Actions
- **Destination**: `web/static/js/vpn/backends.js` (~480 lines).
- **Scope**: Extract backend fleet table row rendering (`vpnRenderBackendRow`), toggle/delete actions, add backend modal stepper, quick host check, and public endpoint modal.
- **Contract Guardrails**: Retain identical API endpoint paths (`/api/vpn/backends`, `/api/vpn/config`), HTTP verbs, payload shapes, and confirmation prompts. Correctly manage `vpnCachedServers` mutability lifecycle (re-fetching servers and re-assigning when opening the modal per `vpn.html:790-803`).
- **Atomic Staging**: Add `<script src="/static/js/vpn/backends.js"></script>` to `vpn.html` and update `VPNTestFixture` atomically.
- **Test Baseline**: Verify `TestLoadBalancerHighlightAndAwgPreselection`, `TestPhase5VPNAndUsersModernization`, and backend status badge assertions.

#### Step 5: Issue #499 — Isolate VPN Page Bootstrap & Polling Coordinator
- **Destination**: `web/static/js/vpn/page.js` (~200 lines).
- **Scope**: Extract `vpnLoadData`, `DOMContentLoaded` initialization, server pre-caching, and `NexusTelemetry.poll('vpn-status')` registration.
- **Contract Guardrails**: Coordinate data flow into `sessions.js`, `health_summary.js`, `health_problems.js`, `charts.js`, and `backends.js`. Guarantee single initializer execution and register clean teardown handlers.
- **Atomic Staging**: Add `<script src="/static/js/vpn/page.js"></script>` to `vpn.html` atomically.
- **Test Baseline**: Verify `TestVPNDiagnosticsPollingContract` (token checking) and `test_vpn_dashboard_navigation_and_banner`.

#### Step 6: Issue #500 — Finalize Thin `vpn.html` Template
- **Destination**: `web/templates/vpn.html` (~500 lines markup).
- **Scope**: Remove remaining inline `<script>` contents from `vpn.html`. Finalize script tag structure:
  ```html
  {{ define "scripts" }}
  <script src="/static/js/vpn/backends.js"></script>
  <script src="/static/js/vpn/charts.js"></script>
  <script src="/static/js/vpn/health_problems.js"></script>
  <script src="/static/js/vpn/health_summary.js"></script>
  <script src="/static/js/vpn/sessions.js"></script>
  <script src="/static/js/vpn/page.js"></script>
  {{ end }}
  ```
- **Contract Guardrails**: Ensure `web/web_embedded_test.go` verifies asset resolution via `embed.FS`. Finalize `VPNTestFixture` in `web/vpn_fixture_test.go`.
- **Acceptance Gate**: Full CI test run (`CI=true go test -count=1 ./web/...`) and Playwright E2E suite (`pytest tests/e2e/test_vpn_diagnostics.py`).

#### Step 7: Issue #542 — Extract Users Page JavaScript (`web/static/js/users.js`)
- **Destination**: `web/static/js/users.js` (~840 lines) and thin `web/templates/users.html`.
- **Scope**: Merge both inline script blocks (714 + 120 lines) into `web/static/js/users.js`. Relocate Share Modal HTML out of the script boundary.
- **Contract Guardrails**: Account for all 21 Go template actions across the audited script and share-modal region (10 in block 1, 0 in block 2, 11 in share modal markup; out of 141 total actions across `users.html`). Retain minimal Go-template bootstrap for `serversData`, `currentAdminUsername`, `currentIsAdmin`, and `currentUserID`. Retain `pageSize = 12` and 300 ms search debounce. Wire DOM event listeners for selects (`users.html:695-717`). Rely on `api.js` for `X-CSRF-Token` injection.
- **Test Baseline**: Verify `TestIssue113UsersUIModernization`, `TestUsersTemplatePageSize`, and `tests/e2e/test_users.py`.

#### Step 8: Issue #501a — Extract Server Shared Helpers & Protocol Layer
- **Destination**: `web/static/js/server/shared.js` (~200 lines).
- **Scope**: Extract `getProtoTitle`, `updateProtocolCard`, shared section-visibility primitives (`showConnectionsSection`, `hideConnectionsSection`), `updateStatusCounts`, `formatDate`, and the protocol action callback registration and event dispatch interface (`registerProtocolActionHandler`, `dispatchProtocolAction`) to eliminate circular dependencies between actions and monitoring.
- **Contract Guardrails**: Must be loaded before `actions.js` and `monitoring.js`. Card builders delegate action clicks through registered callbacks or `nexus:protocol-action` custom DOM events. Section visibility is owned by `server/shared.js`.

#### Step 9: Issue #501b — Extract Server Management Forms & Actions
- **Destination**: `web/static/js/server/actions.js` (~580 lines).
- **Scope**: Extract protocol install/uninstall wizard, AWG options, container toggles, server config view/save, reboot/clear/remove actions, rename modal, host edit modal (with `isValidHost` validation), and connection CRUD actions. Fix uncleared `progressInterval` in install catch handler.
- **Contract Guardrails**: Migrate inline attribute interpolations (`onclick="openRenameServerModal({{ .server.ID }}, ...)"`) to standard DOM data-attributes (`data-server-id`). Clear `progressInterval` in a `finally` block on error.
- **Test Baseline**: Verify `TestClientSideHostValidation`, `TestIssue278EditServerHostUIAndTranslations`, and `tests/e2e/test_servers.py`.

#### Step 10: Issue #502 — Extract Server Telemetry & Background Polling
- **Destination**: `web/static/js/server/monitoring.js` (~420 lines).
- **Scope**: Extract `loadServerStats`, `updateReachability`, protocol status updates, reachability auto-trial badge rendering, and connection list polling. Consumes section-visibility primitives (`showConnectionsSection`, `hideConnectionsSection`) from `server/shared.js`, registers `selectProtocolForConns` via the shared action registry, and subscribes to `nexus:server-refresh` events.
- **Contract Guardrails**: Maintain 30s polling intervals for `server-stats` and `server-reachability` with exponential backoff capped at 60,000 ms. Retain `connectionsStore` caching.
- **Test Baseline**: Verify `TestServerTemplate_TelemetryPolling` and `test_server_stats`.

#### Step 11: Issue #503 — Finalize Thin `server.html` Template
- **Destination**: `web/templates/server.html` (~600 lines markup).
- **Scope**: Remove inline `<script>` blocks from `server.html`. Add script tags loading `server/shared.js`, `server/monitoring.js`, and `server/actions.js`.
- **Contract Guardrails**: Verify embedded asset delivery and CSRF token handling.
- **Test Baseline**: Run full Go web test suite and Playwright server suite.

#### Steps 12–13: Issues #504 & #505 — Stylesheet Audit & Modular Partitioning
- **Scope**: Audit 3,008 lines of `web/static/css/style.css`. Partition into `base.css` (tokens, typography, resets), `layout.css` (nav, grid, cards, responsive containers), and feature components (`vpn.css`, `server.css`, `users.css`).

---

## 8. Summary of Quality & Architecture Invariants

1. **Strict Line Count Discipline (Finding 1)**: Every newly extracted static JavaScript file must remain strictly below 1,000 lines. Monolithic HTML templates shrink progressively across extraction waves until reaching thin template status (<600 lines).
2. **Zero Behavior Modification in Structural PRs**: Pure mechanical extraction. No redesign, no new frameworks, no altered API endpoints or response structures.
3. **Impersonal Voice**: Strictly adhere to `repository-identity-hygiene`. No personal names or bot identifiers.
4. **Context-Safe Escaping & Decoupling (Finding 3)**: Go's `html/template` contextually escapes interpolations, while JSON helpers wrap output as `template.JS`. Decouple inline handler expressions to DOM `data-*` attributes (`data-server-id`, `data-server-name`, `data-server-host`) to simplify CSP compliance and separate markup from logic.
5. **Timer & Polling Discipline (Finding 4)**: Ensure all timer intervals (e.g. `progressInterval` in server installation) are reliably cleared on all exit paths (success and failure). Enforce 60,000 ms max error backoff on telemetry streams. Distinguish existing background timers from desired future teardown hooks.
6. **Stale State UI Invariant**: Retain last successful API payloads across network hiccups (e.g., `vpnLastSessions` and `vpnSessionsStale`) to prevent empty-state flickering.
7. **Atomic Staging & Test Passability (Findings 1 & 6)**: Script loading tags and test harness function extractors (`extractJSFunction` using brace depth counting) must update atomically with each extraction wave so that both token string checks and JSDOM unit tests pass continuously without broken intermediate states.
