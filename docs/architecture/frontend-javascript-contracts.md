# Frontend JavaScript Architecture Contracts and Module Boundaries

## 1. Overview & Architectural Role

The administrative frontend of Amnezia Nexus relies on server-rendered Go templates (`web/templates/*.html`) paired with vanilla JavaScript, modern DOM manipulation, and dynamic REST polling. Prior to the modularization program defined under Phase 3 (Epic #475, Issues #495–#505 and #542), substantial portions of interactive logic reside as monolithic inline `<script>` blocks embedded directly inside templates:

- `web/templates/vpn.html`: 3,758 total lines, containing ~3,256 lines of inline JavaScript (lines 501–3757).
- `web/templates/server.html`: 1,796 total lines, containing ~1,198 lines of inline JavaScript (lines 598–1795).
- `web/templates/users.html`: 1,309 total lines, containing ~834 lines of inline JavaScript across two blocks (lines 421–1134 [714 lines] and lines 1190–1309 [120 lines]).

Extracting these monolithic inline scripts into modular, cacheable static JavaScript files (`web/static/js/vpn/*.js`, `web/static/js/server/*.js`, and `web/static/js/users.js`) is necessary to eliminate duplication, isolate failure domains, improve maintainability, and enforce strict Content Security Policies (CSP).

This document establishes the authoritative architectural contract, global state inventory, Go-template interpolation rules, DOM event ownership, polling lifecycles, and test harness mappings. Every extraction step in Phase 3 MUST preserve the behavioral invariants documented herein.

---

## 2. Inline JavaScript Responsibility & Target Module Maps

### 2.1 VPN Dashboard (`web/templates/vpn.html`)

The inline script in `web/templates/vpn.html` spans lines 501–3757 (~3,256 lines) and performs five distinct responsibilities. Under Phase 3 (Issues #495–#500), this script is partitioned into four feature controllers and one page bootstrap orchestrator:

```
+-----------------------------------------------------------------------------------------+
|                                    web/templates/vpn.html                               |
|                               (Thin markup-only template #500)                          |
+-----------------------------------------------------------------------------------------+
       |                         |                         |                         |
       v                         v                         v                         v
+------------------+     +------------------+     +------------------+     +------------------+
| vpn/sessions.js  |     |   vpn/health.js  |     |   vpn/charts.js  |     |  vpn/backends.js |
|   (Issue #495)   |     |   (Issue #496)   |     |   (Issue #497)   |     |   (Issue #498)   |
|                  |     |                  |     |                  |     |                  |
| - Sessions Table |     | - Forwarder Hdr  |     | - Sparklines SVG |     | - Backends Table |
| - Drilldown Rows |     | - KPI Status Bar |     | - 1m..24h Window |     | - Add/Edit Modal |
| - Stale Banner   |     | - Problem Cards  |     | - Tooltips/Hover |     | - Host Quick-Chk |
| - Problem Filter |     | - Tech Details   |     | - Backend Series |     | - Toggle/Delete  |
| - Sort/Search    |     | - Diag Panels    |     | - Peak/Rate Calc |     | - Endpoint Edit  |
+------------------+     +------------------+     +------------------+     +------------------+
       \                         /                         \                         /
        \                       /                           \                       /
         +---------------------+-----------------------------+---------------------+
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
   - **Primary Functions**: `renderSessions`, `vpnRenderSessionRow`, `vpnCreateSessionDrilldownRow`, `vpnToggleSessionDrilldown`, `vpnSyncExpandedDrilldowns`, `vpnToggleSessionsProblemFilter`, `vpnRenderSessionsStaleBanner`, `vpnFindSessionById`, `vpnFindRouteForSession`, `vpnWrapSessionsTableRender`, `vpnFormatBytes`, `fmtBps`, `fmtPps`.
   - **State Ownership**: `vpnSessionsTableInstance`, `vpnLastSessions`, `vpnSessionsStale`, `vpnSessionsFilterOnlyProblems`, `vpnExpandedSessionIds`.

2. **`web/static/js/vpn/health.js` (Target Issue #496 — ~980 lines)**:
   - **Responsibilities**: Forwarder health status banner, KPI summary bar (throughput, routes/sessions, queue pressure, packet loss, client engine, peer sync, healthy backends, slow writes), active actionable problem condition cards, tech diagnostics progressive disclosure accordion (`#vpn-fwd-tech-details`), diagnostic cards 1–4 (Data Plane, Traffic Drops, Route Integrity, Fleet Resources), condition parsing and entity extraction, route tooltip generation.
   - **Primary Functions**: `vpnRenderForwarderHealth`, `routeTooltip`, `createSeverityBadge`, `deriveStableConditionCode`, `parseConditionMessage`, `preserveCountPhrase`, `extractConditionEntities`, `vpnFormatPeerKey`, `vpnFormatCountersSince`, `vpnFormatTime`, `fmtDurationSec`, `vpnLossReasonLabels`, `vpnDiagText`.
   - **State Ownership**: `vpnShowAllRoutes`, `vpnLastActiveProblemKeys`, `vpnLastActiveProblemCount`.

3. **`web/static/js/vpn/charts.js` (Target Issue #497 — ~520 lines)**:
   - **Responsibilities**: Historical telemetry trend rendering, sparkline SVG path calculations, window toggle selection (1m, 5m, 15m, 1h, 6h, 24h), chart hover interactions, peak and current calculation, time axis labels, backend series filtering.
   - **Primary Functions**: `vpnRenderHistoryCharts`, `vpnGenerateSparklineSVG`, `vpnSetHistoryWindow`, `vpnDisposeChartInteractions`, `computeCurrentPeak`, `vpnFmtThroughput`, `vpnFmtDrops`, `vpnFmtQueue`, `vpnFmtLatency`, `renderBadges`, `renderTimeAxis`, `attachInteraction`, `renderSeries`, `renderSelectedBackend`.
   - **State Ownership**: `vpnHistoryWindow`, `window._vpnActiveChartHover`.

4. **`web/static/js/vpn/backends.js` (Target Issue #498 — ~480 lines)**:
   - **Responsibilities**: Backend fleet table rendering, backend enable/disable toggle, backend deletion, add backend modal stepper and server selection, quick ping/SSH check, public endpoint modal and submission, status badge formatting.
   - **Primary Functions**: `vpnRenderBackendRow`, `vpnToggleBackend`, `vpnDeleteBackend`, `vpnOpenAddBackendModal`, `vpnResetAddModal`, `vpnOnServerSelected`, `vpnTriggerQuickCheck`, `vpnSubmitAddBackend`, `vpnOpenEditEndpointModal`, `vpnSubmitEditEndpoint`, `vpnStatusBadgeClass`, `vpnStatusLabel`, `vpnSetListenerBadge`, `vpnServerHasAwg`, `vpnFormatApiError`.
   - **State Ownership**: `vpnCurrentBackends`, `vpnCachedServers`, `vpnConfiguredPublicEndpoint`, `vpnTableInstance`.

5. **`web/static/js/vpn/page.js` (Target Issue #499 — ~200 lines)**:
   - **Responsibilities**: Page initialization, `DOMContentLoaded` listener, server metadata pre-caching, telemetry polling coordination via `NexusTelemetry.poll('vpn-status')`, multi-endpoint fetch orchestration (`/api/vpn/status`, `/api/vpn/config`, `/api/vpn/backends`, `/api/vpn/sessions`), error boundary handling.
   - **Primary Functions**: `vpnLoadData`, top-level event listener attachment.
   - **State Ownership**: Orchestrates data distribution to `sessions.js`, `health.js`, `charts.js`, and `backends.js`.

6. **`web/templates/vpn.html` (Target Issue #500 — ~500 lines)**:
   - **Responsibilities**: Markup-only template loading static assets via standard `<script src="/static/js/vpn/*.js">` tags, retaining HTML structure, static i18n placeholders (`{{ _ "key" }}`), and modal containers.

---

### 2.2 Server Details & Management (`web/templates/server.html`)

The inline script in `web/templates/server.html` spans lines 598–1795 (~1,198 lines) and handles server administration, protocol lifecycle, telemetry polling, host/name editing, and client connection management. Under Phase 3 (Issues #501–#503), this script is partitioned into two modules and one thin template:

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
| - Protocol Uninstall & Toggles   |        | - Reachability Auto-Trial Badges |
| - Server Config View / Save      |        | - Protocol Card Live Status      |
| - Server Rename Modal            |        | - Client Connections Table Fetch |
| - Edit Host Modal (RFC/IP check) |        | - Telemetry.poll Registration    |
| - Reboot / Clear / Remove Ops    |        | - In-memory connectionsStore     |
| - Connection Add/Edit/Delete     |        | - Section Visibility Toggles     |
| - QR Code & Config Tab Switching |        | - Date/Time Formatters           |
+----------------------------------+        +----------------------------------+
```

#### Module Specifications for Server Subsystem:

1. **`web/static/js/server/actions.js` (Target Issue #501 — ~680 lines)**:
   - **Responsibilities**: Protocol installation modal with animated step progress, protocol parameter configuration (AWG port, MTU, CPS protocol, Telemt secret/domain), container toggle, configuration editor modal (`/api/servers/${SERVER_ID}/server_config`), server operations (reboot, clear, remove), server rename modal, edit host modal with client-side RFC 1123 hostname and IPv4/IPv6 address validation, client connection CRUD operations (add, edit, remove, toggle, mimicry rotation, copy config, QR code display).
   - **Primary Functions**: `switchCategory`, `getProtoTitle`, `toggleContainer`, `showServerConfig`, `saveServerConfig`, `openInstallModal`, `installProtocol`, `uninstallProtocol`, `openRenameServerModal`, `closeRenameServerModal`, `submitRenameServer`, `isValidHost`, `openEditHostModal`, `closeEditHostModal`, `submitEditHost`, `rebootServer`, `clearServer`, `removeServer`, `openAddConnectionModal`, `addConnection`, `editConnection`, `removeConnection`, `toggleConnection`, `rotateClientMimicry`, `copyConnectionConfig`, `showConnectionConfig`, `switchConfigTab`, `generateQR`.
   - **State Ownership**: `currentInstallProto`, `currentConfig`, `currentVpnLink`, `currentConfigName`, `serverConfigFilename`, `isEditingConn`, `editingClientId`, `renameServerId`, `editHostServerId`.

2. **`web/static/js/server/monitoring.js` (Target Issue #502 — ~520 lines)**:
   - **Responsibilities**: Background telemetry polling coordination, server system statistics retrieval (`/api/servers/${SERVER_ID}/stats`), network reachability evaluation (`/api/servers/${SERVER_ID}/reachability`), auto-trial protocol badge rendering (TLS, QUIC, DNS, SIP), protocol status card reflection (`updateProtocolCard`, `updateStatusCounts`), server health check invocation, client connections listing and table population (`/api/servers/${SERVER_ID}/connections?protocol=${proto}`).
   - **Primary Functions**: `loadServerStats`, `updateReachability`, `checkServer`, `updateStatusCounts`, `updateProtocolCard`, `selectProtocolForConns`, `loadConnections`, `showConnectionsSection`, `hideConnectionsSection`, `formatDate`.
   - **State Ownership**: `SERVER_ID`, `STATS_REFRESH_INTERVAL_MS`, `installedProtocols`, `connectionsTableInstance`, `window.connectionsStore`.

3. **`web/templates/server.html` (Target Issue #503 — ~600 lines)**:
   - **Responsibilities**: Thin template containing HTML layout, protocol cards, modal containers, and minimal bootstrap script defining `SERVER_ID` and loading external static modules.

---

### 2.3 User Administration (`web/templates/users.html`)

`web/templates/users.html` contains 1,309 total lines with two inline `<script>` blocks:
- Block 1 (lines 421–1134, 714 lines): User grid management, role filters, search, pagination, user CRUD, connection assignment, config/QR modals.
- Block 2 (lines 1190–1309, 120 lines): User editing and public share access setup.
- Intervening HTML (lines 1135–1189, 55 lines): Share user modal markup containing 14 Go-template action blocks.

Under Issue #542 (NEW-WEB-1), both script blocks are unified into `web/static/js/users.js`:

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
| - User Directory: refreshUsersList, handleSearch, clearUserSearch,          |
|   setRoleFilter, changePage (12 users/page), traffic bar / expiry rendering |
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
   - **Responsibilities**: All user management interactions, debounced live search, pagination control, role filtering, client connection provisioning and unlinking, QR code generation, config display, and public share link lifecycle.
   - **Primary Functions**: `handleSearch`, `clearUserSearch`, `setRoleFilter`, `changePage`, `refreshUsersList`, `updateProtocols`, `addUser`, `deleteUser`, `toggleUser`, `openAddConnectionForUser`, `toggleUCMode`, `fetchExistingClients`, `doAddUserConnection`, `viewUserConnections`, `copyUserConnectionDirect`, `unlinkUserConnection`, `switchConfigTab`, `generateQR`, `showUserConnectionConfig`, `openEditUser`, `saveEditUser`, `openShareModal`, `updateShareSetup`, `saveShareSetup`, `copyShareLink`.
   - **State Ownership**: `currentUserId`, `currentUsername`, `currentConfig`, `currentVpnLink`, `currentConfigName`, `currentPage`, `pageSize`, `searchQuery`, `selectedRole`, `searchTimeout`, `userConnsTableInstance`, `currentSharedUser`.

---

## 3. Named Global State & Shared Functions Table

The table below catalogs every variable and function exposed on `window` or residing in top-level script scope across `vpn.html`, `server.html`, and `users.html`. It documents component origins, external consumers, and mutability lifecycles.

| Identifier | Type | Origin Template | Consumers & External Call Sites | Mutability Lifecycle & Scope Rules |
|---|---|---|---|---|
| `vpnCachedServers` | `Array<Object>` | `vpn.html:504` | `vpnLoadData`, `vpnRenderBackendRow`, `vpnOpenAddBackendModal` | Primed on boot via GET `/api/servers`; read-only afterwards. |
| `vpnCurrentBackends` | `Array<Object>` | `vpn.html:505` | `vpnLoadData`, `vpnToggleBackend`, `vpnDeleteBackend` | Updated on each 5s poll of `/api/vpn/backends`. |
| `vpnConfiguredPublicEndpoint` | `string` | `vpn.html:506` | `vpnLoadData`, `vpnOpenEditEndpointModal` | Updated on poll of `/api/vpn/config`; mutated on modal submit. |
| `vpnTableInstance` | `NexusTable` | `vpn.html:507` | `vpnLoadData` (`#vpnBackendsTable`) | Instantiated on first load; refreshed on subsequent polls. |
| `vpnSessionsTableInstance` | `NexusTable` | `vpn.html:508` | `renderSessions` (`#vpnSessionsTable`) | Instantiated on first load; refreshed on session changes. |
| `vpnLastSessions` | `Object` | `vpn.html:514` | `vpnLoadData`, `renderSessions`, `vpnRenderSessionsStaleBanner` | Updated on poll; preserved across fetch errors to prevent UI flashing. |
| `vpnSessionsStale` | `boolean` | `vpn.html:515` | `vpnLoadData`, `renderSessions`, `vpnRenderSessionsStaleBanner` | Set `false` on `/api/vpn/sessions` success, `true` on fetch failure. |
| `vpnSessionsFilterOnlyProblems` | `boolean` | `vpn.html:516` | `vpnToggleSessionsProblemFilter`, `renderSessions` | Toggled by user click on `#vpn-sessions-toggle-problems-btn`. |
| `vpnHistoryWindow` | `string` | `vpn.html:517` | `vpnSetHistoryWindow`, `vpnRenderHistoryCharts` | Default `'15m'`; updated on user click of window toggle chips. |
| `vpnShowAllRoutes` | `boolean` | `vpn.html:518` | `vpnToggleShowAllRoutes`, `vpnRenderForwarderHealth` | Default `false`; toggled by user click on `#vpn-routes-toggle-all-btn`. |
| `vpnLastStatus` | `Object` | `vpn.html:519` | `vpnRenderForwarderHealth`, `vpnToggleShowAllRoutes` | Updated on each 5s poll of `/api/vpn/status`. |
| `vpnExpandedSessionIds` | `Set<string>` | `vpn.html:520` | `vpnToggleSessionDrilldown`, `vpnSyncExpandedDrilldowns` | Retains expanded accordion row IDs across table re-renders. |
| `vpnLastActiveProblemKeys` | `Set<string>` | `vpn.html:521` | `vpnRenderForwarderHealth` | Updated on poll; triggers `#vpn-fwd-tech-details.open = true` on new keys. |
| `vpnLastActiveProblemCount` | `number` | `vpn.html:522` | `vpnRenderForwarderHealth` | Updated on poll; triggers auto-expansion when count increases. |
| `window._vpnActiveChartHover` | `Object` | `vpn.html:1770` | `attachInteraction`, `vpnDisposeChartInteractions`, `renderSeries` | Tracks `{ seriesId, entryIndex, clientX, clientY }`; preserved across polls. |
| `SERVER_ID` | `number` | `server.html:599` | All API calls in `server.html` | Immutable constant injected via Go template (`{{ .server_id }}`). |
| `STATS_REFRESH_INTERVAL_MS` | `number` | `server.html:600` | `Telemetry.poll` registrations | Constant: `30000` (30 seconds). |
| `currentInstallProto` | `string` | `server.html:601` | `openInstallModal`, `installProtocol` | Default `'awg'`; set when opening protocol install modal. |
| `currentConfig` | `string` | `server.html:602`, `users.html:424` | `copyConnectionConfig`, `showConnectionConfig`, UI copy buttons | Primed when opening config modal; contains WireGuard config text. |
| `currentVpnLink` | `string` | `server.html:603`, `users.html:425` | `copyConnectionConfig`, `showConnectionConfig`, UI copy buttons | Primed when opening config modal; contains `vpn://...` URL. |
| `currentConfigName` | `string` | `server.html:604`, `users.html:426` | Config download buttons (`UI.downloadFile`) | Default `'connection'`; set to connection name on modal open. |
| `installedProtocols` | `Object` | `server.html:605` | `checkServer`, `updateProtocolCard` | Updated when server check completes. |
| `connectionsTableInstance` | `NexusTable` | `server.html:606` | `loadConnections` (`#connectionsTableContainer`) | Instantiated on connection table load; refreshed on filter change. |
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
| `searchTimeout` | `number` | `users.html:432` | `handleSearch`, `clearUserSearch` | Timer handle for 250ms search input debouncing. |
| `userConnsTableInstance` | `NexusTable` | `users.html:433` | `viewUserConnections` (`#userConnsTableContainer`) | Instantiated on user connections modal display; refreshed on reload. |
| `serversData` | `Object` | `users.html:435` | `updateProtocols` | Go-template JSON map of servers and available protocols. |
| `currentAdminUsername` | `string` | `users.html:436` | User row action visibility | Injected Go string: username of logged-in administrator. |
| `currentIsAdmin` | `boolean` | `users.html:437` | User row action visibility | Injected Go boolean: admin role check. |
| `currentUserID` | `string` | `users.html:438` | User row self-edit guard | Injected Go string: ID of logged-in user. |
| `currentSharedUser` | `string` | `users.html:1191` | `openShareModal`, `saveShareSetup` | Tracks target user ID for public share link configuration. |

---

## 4. Go-Template Interpolation & Escaping Contracts

### 4.1 Template Action Audit across Script Blocks

A critical security and stability requirement for modularization is isolating Go template interpolations (`{{ ... }}`) from JavaScript code. Embedding raw template tags inside `<script>` blocks introduces syntax breakage risks, escaping hazards, and prevents script files from being served as cacheable static assets.

The repository displays three distinct interpolation patterns:

1. **`web/templates/vpn.html` (Zero Embedded Script Interpolations)**:
   - Audit across lines 501–3757 verifies **ZERO Go-template actions** inside `<script>`.
   - All dynamic state is fetched asynchronously via REST APIs (`/api/vpn/status`, `/api/vpn/config`, `/api/vpn/backends`, `/api/vpn/sessions`, `/api/servers`).
   - All user-facing strings are resolved dynamically using `window._(key)` against `window.I18N` or via `vpnDiagText()`.
   - *Modularization Impact*: Script blocks in `vpn.html` can be migrated byte-for-byte to static `.js` files with zero Go template data extraction required.

2. **`web/templates/server.html` (Single Primitive Constant)**:
   - Script line 599: `const SERVER_ID = {{ .server_id }};`
   - *Escaping Contract*: `.server_id` is an integer (`int64`). Injected as an unquoted numeric literal.
   - *HTML Attribute Injections*: Lines 33 and 39 interpolate Go values into inline `onclick` handlers:
     ```html
     onclick="openRenameServerModal({{ .server.ID }}, '{{ .server.Name }}')"
     onclick="openEditHostModal({{ .server.ID }}, '{{ .server.Host }}')"
     ```
     *Hazard*: If `.server.Name` or `.server.Host` contains a single quote or special character, the inline JavaScript expression breaks.
     *Remediation Contract (Issue #501/#503)*: Migrate parameters to DOM data-attributes on the triggering elements:
     ```html
     data-server-id="{{ .server.ID }}"
     data-server-name="{{ .server.Name }}"
     data-server-host="{{ .server.Host }}"
     ```
     Handlers read these values via `this.dataset.serverId`, `this.dataset.serverName`, and `this.dataset.serverHost`, eliminating string quoting in markup.

3. **`web/templates/users.html` (Four Global Data Injections & One Embedded Partial)**:
   - Script lines 435–438:
     ```javascript
     const serversData = {{ .servers | json }};
     const currentAdminUsername = '{{ if .current_user }}{{ .current_user.Username }}{{ end }}';
     const currentIsAdmin = {{ if has_role .current_user "admin" }}true{{ else }}false{{ end }};
     const currentUserID = '{{ if .current_user }}{{ .current_user.ID }}{{ end }}';
     ```
   - *Escaping Contracts*:
     * `{{ .servers | json }}`: Serialized via Go `json.Marshal`, safe for direct assignment to a JS variable.
     * `currentAdminUsername` / `currentUserID`: String values wrapped in single quotes. Must be sanitized against quote breakout.
     * `currentIsAdmin`: Evaluates strictly to boolean literals `true` or `false`.
   - *Embedded Partial Inversion (lines 1135–1189)*:
     The modal markup for `shareUserModal` is situated between `<script>` block 1 and `<script>` block 2. It contains 14 Go-template i18n calls (`{{ _ "share_access" }}`, `{{ _ "cancel" }}`, etc.).
   - *Remediation Contract (Issue #542)*:
     * Retain a 5-line inline bootstrap block in `users.html` exposing `window.NEXUS_USER_PAGE_DATA = { servers: {{ .servers | json }}, adminUsername: ..., isAdmin: ..., userId: ... };` or set standard data-attributes on `<main id="users-page" data-user-id="..." data-is-admin="...">`.
     * Move the Share Modal markup out of the script boundary and relocate all JavaScript from both blocks into `web/static/js/users.js`.

---

## 5. DOM Event Listeners, Timers & Polling Ownership

### 5.1 DOM Event Bindings & Accordion Disclosures

The administrative interface coordinates user actions via three mechanisms:
1. **Delegated / Inline `onclick` and `onchange` attributes**: Declared in templates, invoking named global functions.
2. **Dynamic DOM Event Listeners**: Attached at runtime during row rendering (e.g., drilldown triggers, hover tracking).
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
| **Server Details** | `'server-stats-' + SERVER_ID` | 30,000 ms (30s) | `loadServerStats` | `/api/servers/${SERVER_ID}/stats` | Silent fetch (`silent: true`). Exponential backoff on HTTP error (multiplier $2\\times$, capped at 30s). Pauses when hidden. Stopped via `Telemetry.stop('server-stats-' + SERVER_ID)`. |
| **Server Details** | `'server-reachability-' + SERVER_ID` | 30,000 ms (30s) | `updateReachability` | `/api/servers/${SERVER_ID}/reachability` | Silent fetch (`silent: true`). Renders auto-trials for TLS, QUIC, DNS, SIP. Pauses when hidden. Stopped via `Telemetry.stop('server-reachability-' + SERVER_ID)`. |
| **Users Page** | N/A (On-demand) | N/A | `refreshUsersList` | `/api/users?search=...&role=...` | Invoked on `DOMContentLoaded`, on role filter switch, page navigation, and after add/edit/delete/toggle actions. Search input is debounced by 250ms via `searchTimeout`. |

#### Strict Extraction Invariant for Polling:
When extracting `vpn/page.js` (Issue #499) and `server/monitoring.js` (Issue #502):
- Do NOT introduce duplicate `Telemetry.poll` or `setInterval` calls.
- Teardown handlers MUST unregister active streams (`Telemetry.stop(...)`) on page unload or view swap to prevent background goroutine / memory leaks.

---

## 6. Existing Test Baseline & Harness Mapping

### 6.1 JSDOM Test Suites (`web/vpn_diagnostics_test.go`)

`web/vpn_diagnostics_test.go` contains 33 verified Go test functions running simulated frontend environments via Node.js and JSDOM. These tests directly inspect and evaluate JavaScript functions extracted from `web/templates/vpn.html`.

| # | Test Function Name | Tested Function / UI Component | Key Invariants Verified |
|---|---|---|---|
| 1 | `TestVPNDiagnosticsHealthAndStructure` | `vpnRenderForwarderHealth`, DOM structure | Validates banner status, forwarder headline, badges, and card hierarchies. |
| 2 | `TestVPNHistoryChartLatencyAvailability` | `vpnRenderHistoryCharts`, `renderBadges` | Verifies latency badge reflects availability flags without NaN rendering. |
| 3 | `TestVPNCompleteRouteTooltipContract` | `routeTooltip`, `vpnFormatPeerKey` | Validates tooltip text for healthy, pressure, and error route states. |
| 4 | `TestVPNOperationalDiagnosticsCardsContract` | Cards 1–4 diagnostic panels | Verifies CPU, memory, FD, queue occupancy, drop categories, and rate strings. |
| 5 | `TestVPNCompleteHistoryAllWindowRenderers` | `vpnRenderHistoryCharts`, window toggles | Exercises 1m, 5m, 15m, 1h, 6h, 24h historical chart transformations. |
| 6 | `TestVPNUnavailableForwarderClearsStaleHistoryState` | `vpnRenderForwarderHealth`, charts | Ensures unavailable forwarder clears stale canvas/SVG series. |
| 7 | `TestVPNPanelRateAvailability` | `vpnDiagText`, rate formatters | Tests availability toggling across throughput, drops, and latency rates. |
| 8 | `TestVPNDiagnosticsLocalizationDictionaries` | i18n dictionaries (`en`, `ru`, `fa`, etc.) | Verifies presence of all required diagnostics keys in localization files. |
| 9 | `TestVPNDiagnosticsLocalization` | `vpnRenderForwarderHealth`, `_()` | Asserts correct language translation rendering in JSDOM across all 5 locales. |
| 10 | `TestVPNDiagnosticsLocalizationMutations` | i18n mutations | Checks fault-injection resilience when translation keys are missing or malformed. |
| 11 | `TestVPNBackendDeviceKPIAlarmCoverage` | KPI Summary Bar | Validates color alarms (danger/warning) on backend drop rates and stalls. |
| 12 | `TestVPNBackendDeviceKPIAlarmMutations` | KPI alarm state transitions | Ensures transitions between healthy, warning, and critical preserve DOM classes. |
| 13 | `TestVPNBackendDeviceUnattributedConditionRendering`| Condition synthesis | Validates fallback rendering when condition entities lack backend IDs. |
| 14 | `TestVPNDiagnosticsCurrentObservations` | Current vs cumulative metrics | Asserts live horizon (`Current / Live`) vs reset horizon (`Since Startup / Reset`). |
| 15 | `TestVPNDiagnosticsTemplateDOMOracle` | Static HTML DOM validation | Oracle testing verifying that template DOM matches expected ID structure. |
| 16 | `TestVPNDiagnosticsPollingContract` | Polling callback integration | Asserts that `vpnLoadData` updates UI without throwing exceptions in JSDOM. |
| 17 | `TestVPNForwarderHealthDecouplingAndHorizon` | Horizon decoupling | Verifies decoupling of forwarder status from peer-sync availability. |
| 18 | `TestVPNProgressiveDisclosureAndActiveProblems` | `#vpn-fwd-tech-details` | Verifies auto-expansion on new problem keys and preservation of manual closure. |
| 19 | `TestVPNConnectionTroubleshootingTableAndCorrelation`| `renderSessions`, `vpnFindRouteForSession`| Verifies session-to-route correlation and diagnostic badge display. |
| 20 | `TestVPNHorizonWindowToggles1mAnd5m` | `vpnSetHistoryWindow` | Verifies 1m and 5m short-horizon window toggling and SVG regeneration. |
| 21 | `TestVPNSummaryHeaderCountsAndProblemCardOnset` | Problem card onset | Verifies onset timestamps and problem counter in summary header. |
| 22 | `TestVPNForwarderCombinedActionableAndGenericConditions`| Condition rendering | Tests mixed actionable conditions and generic fallback condition rendering. |
| 23 | `TestVPNForwarderStaleHandshakeActionableProblemDOM` | Stale handshake synthesis | Verifies DOM output when peer handshakes exceed timeout thresholds. |
| 24 | `TestVPNForwarderStaleHandshakeEmptySnapshotMatchingCountsDOM`| Empty snapshot handling | Ensures stale handshake logic handles zero-peer snapshots gracefully. |
| 25 | `TestVPNTranslationKeyParity` | Translation dictionaries | Strict parity check across all supported translation files. |
| 26 | `TestVPNPacketLossCellDecoupledFromQueuePressure` | Sessions table loss cell | Ensures packet loss cell is decoupled from queue pressure calculations. |
| 27 | `TestVPNReconnectSessionIDMismatchShowsUnroutable` | Route drilldown | Displays unroutable badge when session ID does not match active route ID. |
| 28 | `TestVPNNexusTableLifecycleDrilldownAndConfigDedup`| `vpnCreateSessionDrilldownRow` | Asserts drilldown DOM lifecycle, action buttons, and config deduplication. |
| 29 | `TestVPNForwarderRoutesTableFormatting` | Route formatting | Asserts numeric formatting, bytes/sec, and packet rates in routes table. |
| 30 | `TestVPNSessionsTableSortingAndAccordionPersistence`| `NexusTable`, `vpnExpandedSessionIds`| Tests sorting by bytes/loss and validates accordion persistence across sort. |
| 31 | `TestVPNRoutingConsistencyBadgeSeverityAware` | Severity badge logic | Tests CRITICAL, DEGRADED, and WARNING severity badge color assignment. |
| 32 | `TestVPNDashboardSectionOrder` | Visual DOM section ordering | Validates layout order: KPI summary -> cards -> troubleshooting -> backends. |
| 33 | `TestVPNHistoricalChartsContract` | `vpnRenderHistoryCharts` | Full contract test verifying chart canvases, axes, legends, and series. |

---

### 6.2 Test Harness Function Extraction Hazard (`web/vpn_fixture_test.go`)

A critical dependency exists in `web/vpn_fixture_test.go`:
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

The test fixture parses `f.TemplateHTML` (`web/templates/vpn.html`) using regex to extract functions by name (`"function " + fn`) and evals them inside Node.js/JSDOM.

**Extraction Invariant for Phase 3**:
When extracting functions from `web/templates/vpn.html` into static JS files (`web/static/js/vpn/*.js`), `extractJSFunction` or the `VPNTestFixture` MUST be updated to read from the target static JS files (or both template and static files). If a function is removed from `vpn.html` before the harness is updated to load static assets, all 33 JSDOM tests will fail with `extractJSFunction <name> failed: function not found`.

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
   - `test_vpn_dashboard_sections_visual_order_and_vertical_layout`: Validates strict visual vertical ordering of sections.

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

```
Wave 1: Test Harness & Contract Prerequisites
  [x] #478 (This Document: docs/architecture/frontend-javascript-contracts.md)
  [x] #484 (Reusable Node/JSDOM test fixture for VPN diagnostics)
  [x] #485 (Split web/vpn_diagnostics_test.go into focused test files)
       |
       v
Wave 2: VPN Feature Controllers Extraction
  [ ] Step 1: #495 -> web/static/js/vpn/sessions.js (~520 lines)
  [ ] Step 2: #496 -> web/static/js/vpn/health.js (~980 lines)
  [ ] Step 3: #497 -> web/static/js/vpn/charts.js (~520 lines)
  [ ] Step 4: #498 -> web/static/js/vpn/backends.js (~480 lines)
       |
       v
Wave 3: VPN Page Bootstrap & Template Finalization
  [ ] Step 5: #499 -> web/static/js/vpn/page.js (~200 lines)
  [ ] Step 6: #500 -> web/templates/vpn.html (Thin markup template, ~500 lines)
       |
       v
Wave 4: Users Page Modularization
  [ ] Step 7: #542 -> web/static/js/users.js & thin web/templates/users.html (~840 lines)
       |
       v
Wave 5: Server Page Modularization
  [ ] Step 8: #501 -> web/static/js/server/actions.js (~680 lines)
  [ ] Step 9: #502 -> web/static/js/server/monitoring.js (~520 lines)
  [ ] Step 10: #503 -> web/templates/server.html (Thin markup template, ~600 lines)
       |
       v
Wave 6: Stylesheet Partitioning
  [ ] Step 11: #504 (CSS selector & ownership audit)
  [ ] Step 12: #505 (Split web/static/css/style.css into theme/layout/components)
```

---

### 7.1 Detailed Step-by-Step Execution Plan

#### Step 1: Issue #495 — Extract VPN Sessions & Troubleshooting Controller
- **Destination**: `web/static/js/vpn/sessions.js` (~520 lines).
- **Scope**: Extract `renderSessions`, `vpnRenderSessionRow`, `vpnCreateSessionDrilldownRow`, `vpnToggleSessionDrilldown`, `vpnSyncExpandedDrilldowns`, `vpnToggleSessionsProblemFilter`, `vpnRenderSessionsStaleBanner`, `vpnFindSessionById`, `vpnFindRouteForSession`, and formatting helpers.
- **Contract Guardrails**: Preserve all DOM IDs (`#vpn-sessions-tbody`, `#vpnSessionsStaleBanner`, `#vpn-sessions-toggle-problems-btn`), `NexusTable` sorting on traffic/packet loss, and expanded accordion persistence across poll cycles (`vpnExpandedSessionIds`).
- **Test Baseline**: Verify `TestVPNSessionsTableSortingAndAccordionPersistence`, `TestVPNConnectionTroubleshootingTableAndCorrelation`, and `TestVPNPacketLossCellDecoupledFromQueuePressure`.

#### Step 2: Issue #496 — Extract VPN Health & Condition Controllers
- **Destination**: `web/static/js/vpn/health.js` (~980 lines).
- **Scope**: Extract `vpnRenderForwarderHealth`, condition code parsers (`deriveStableConditionCode`, `parseConditionMessage`), entity extractors, severity badge generators, route tooltips, KPI summary bar binders, and tech diagnostics accordion logic.
- **Contract Guardrails**: Preserve auto-disclosure of `#vpn-fwd-tech-details` on new problem keys and manual collapse preservation. Retain message parsing and entity extraction byte-for-byte.
- **Test Baseline**: Verify all 33 JSDOM tests in `web/vpn_diagnostics_test.go` and E2E tests in `tests/e2e/test_vpn_diagnostics.py`.

#### Step 3: Issue #497 — Extract Historical Telemetry Charts & Controls
- **Destination**: `web/static/js/vpn/charts.js` (~520 lines).
- **Scope**: Extract `vpnRenderHistoryCharts`, `vpnGenerateSparklineSVG`, `vpnSetHistoryWindow`, window toggle handlers, tooltip interaction listeners, and hover state preservation (`window._vpnActiveChartHover`).
- **Contract Guardrails**: Preserve SVG path math, zero NaN occurrences on missing series, hover coordinate retention across live 5s polling sweeps, and timer/listener disposal on window switches.
- **Test Baseline**: Verify `TestVPNHistoricalChartsContract`, `TestVPNHistoryChartLatencyAvailability`, `TestVPNCompleteHistoryAllWindowRenderers`, and `test_vpn_historical_charts_hover_preserved_across_live_polling`.

#### Step 4: Issue #498 — Extract VPN Backend Management Actions
- **Destination**: `web/static/js/vpn/backends.js` (~480 lines).
- **Scope**: Extract backend fleet table row rendering (`vpnRenderBackendRow`), toggle/delete actions, add backend modal stepper, quick host check, and public endpoint modal.
- **Contract Guardrails**: Retain identical API endpoint paths (`/api/vpn/backends`, `/api/vpn/config`), HTTP verbs, payload shapes, and confirmation prompts.
- **Test Baseline**: Verify `TestLoadBalancerHighlightAndAwgPreselection`, `TestPhase5VPNAndUsersModernization`, and backend status badge assertions.

#### Step 5: Issue #499 — Isolate VPN Page Bootstrap & Polling Coordinator
- **Destination**: `web/static/js/vpn/page.js` (~200 lines).
- **Scope**: Extract `vpnLoadData`, `DOMContentLoaded` initialization, server pre-caching, and `NexusTelemetry.poll('vpn-status')` registration.
- **Contract Guardrails**: Coordinate data flow into `sessions.js`, `health.js`, `charts.js`, and `backends.js`. Guarantee single initializer execution and clean teardown without duplicate event listeners.
- **Test Baseline**: Verify `TestVPNDiagnosticsPollingContract` and `test_vpn_dashboard_navigation_and_banner`.

#### Step 6: Issue #500 — Finalize Thin `vpn.html` Template
- **Destination**: `web/templates/vpn.html` (~500 lines markup).
- **Scope**: Remove inline `<script>` contents from `vpn.html`. Add script tags in correct load order:
  ```html
  {{ define "scripts" }}
  <script src="/static/js/vpn/backends.js"></script>
  <script src="/static/js/vpn/charts.js"></script>
  <script src="/static/js/vpn/health.js"></script>
  <script src="/static/js/vpn/sessions.js"></script>
  <script src="/static/js/vpn/page.js"></script>
  {{ end }}
  ```
- **Contract Guardrails**: Ensure `web/web_embedded_test.go` verifies asset resolution via `embed.FS`. Update `VPNTestFixture` in `web/vpn_fixture_test.go` to load static files.
- **Acceptance Gate**: Full CI test run (`CI=true go test -count=1 ./web/...`) and Playwright E2E suite (`pytest tests/e2e/test_vpn_diagnostics.py`).

#### Step 7: Issue #542 — Extract Users Page JavaScript (`web/static/js/users.js`)
- **Destination**: `web/static/js/users.js` (~840 lines) and thin `web/templates/users.html`.
- **Scope**: Merge both inline script blocks (714 + 120 lines) into `web/static/js/users.js`. Move Share Modal HTML out of the script boundary.
- **Contract Guardrails**: Retain minimal Go-template bootstrap for `serversData`, `currentAdminUsername`, `currentIsAdmin`, and `currentUserID`. Retain `pageSize = 12`. Update token assertions in `web/web_server_users_test.go` to inspect `users.js`.
- **Test Baseline**: Verify `TestIssue113UsersUIModernization`, `TestUsersTemplatePageSize`, and `tests/e2e/test_users.py`.

#### Step 8: Issue #501 — Extract Server Management Forms & Actions
- **Destination**: `web/static/js/server/actions.js` (~680 lines).
- **Scope**: Extract protocol install/uninstall wizard, AWG options, container toggles, server config view/save, reboot/clear/remove actions, rename modal, host edit modal (with `isValidHost` validation), and connection CRUD actions.
- **Contract Guardrails**: Migrate inline attribute interpolations (`onclick="openRenameServerModal({{ .server.ID }}, ...)"`) to standard DOM data-attributes (`data-server-id`).
- **Test Baseline**: Verify `TestClientSideHostValidation`, `TestIssue278EditServerHostUIAndTranslations`, and `tests/e2e/test_servers.py`.

#### Step 9: Issue #502 — Extract Server Telemetry & Background Polling
- **Destination**: `web/static/js/server/monitoring.js` (~520 lines).
- **Scope**: Extract `loadServerStats`, `updateReachability`, protocol status updates, reachability auto-trial badge rendering, and connection list polling.
- **Contract Guardrails**: Maintain 30s polling intervals for `server-stats` and `server-reachability`. Retain `connectionsStore` caching.
- **Test Baseline**: Verify `TestServerTemplate_TelemetryPolling` and `test_server_stats`.

#### Step 10: Issue #503 — Finalize Thin `server.html` Template
- **Destination**: `web/templates/server.html` (~600 lines markup).
- **Scope**: Remove inline `<script>` blocks from `server.html`. Add script tags loading `actions.js` and `monitoring.js`.
- **Contract Guardrails**: Verify embedded asset delivery and CSRF token handling.
- **Test Baseline**: Run full Go web test suite and Playwright server suite.

#### Steps 11–12: Issues #504 & #505 — Stylesheet Audit & Modular Partitioning
- **Scope**: Audit 3,008 lines of `web/static/css/style.css`. Partition into `base.css` (tokens, typography, resets), `layout.css` (nav, grid, cards, responsive containers), and feature components (`vpn.css`, `server.css`, `users.css`).

---

## 8. Summary of Quality & Architecture Invariants

1. **Strict Line Count Discipline**: Every extracted static file and modified template MUST remain strictly below 1,000 lines.
2. **Zero Behavior Modification in Structural PRs**: Pure mechanical extraction. No redesign, no new frameworks, no altered API endpoints or response structures.
3. **Impersonal Voice**: Strictly adhere to `repository-identity-hygiene`. No personal names or bot identifiers.
4. **Context-Safe Escaping**: Prohibit unescaped Go template string interpolations in JavaScript or HTML event attributes. Use JSON serialization or HTML data-attributes.
5. **No Duplicate Event Registration**: Ensure single-owner initialization for event listeners and background telemetry polls.
6. **Stale State UI Invariant**: Retain last successful API payloads across network hiccups (e.g., `vpnLastSessions` and `vpnSessionsStale`) to prevent empty-state flickering.
7. **Test-First Verification**: All existing JSDOM unit tests and Playwright E2E tests must pass before and after each extraction wave.
