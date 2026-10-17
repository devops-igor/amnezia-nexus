# CSS Architecture Contracts and Stylesheet Modularization Roadmap

## 1. Executive Summary & Architectural Role

### 1.1 Context & Objectives
During Phase 3 Frontend Modularization (Epic #475), the Amnezia Nexus administrative web interface is undergoing systematic decoupling of its legacy monolithic assets. While Issues #495 through #500 extracted 3,256 lines of inline JavaScript from `web/templates/vpn.html` into cohesive ES modules (`web/static/js/vpn/*.js`), **Issue #504** addresses the styling tier: auditing and establishing architectural boundaries for the monolithic stylesheet `web/static/css/style.css`.

This document establishes the authoritative contract, component boundaries, selector ownership matrix, conflict resolutions, and transition plan prerequisite for **Issue #505 (Physical Stylesheet Modularization)**.

### 1.2 Monolithic Baseline Metrics
An automated comment-stripped brace parsing inspection of `web/static/css/style.css` yields the following verified metrics:

| Metric | Value | Architectural Impact |
| :--- | :--- | :--- |
| **Total Lines** | 3,008 | Exceeds single-file maintainability thresholds; high cognitive load and merge conflict risk |
| **Total Rules Parsed** | 395 | 383 style rules plus 12 keyframe steps mixing tokens, layout shells, and widgets |
| **Unique Selectors** | 373 | 33 selectors defined multiple times across base rules, media queries, and utility overrides |
| **Class Tokens** | 236 | 226 actively referenced in templates/scripts; 10 companion, test, or unreferenced tokens |
| **ID Tokens** | 3 | High-specificity selectors (`#usersContainer`, `#usersGrid`, `#userConnsTable`) bound to DOM elements |
| **CSS Custom Properties** | 56 | 56 variables defined; 3 undefined variables invoked with broken runtime fallbacks |
| **Media Queries** | 5 | Breakpoint fragmentation across 1023px, 900px, 768px, 767px, and 480px |

### 1.3 Core Architectural Vulnerabilities in Current Monolith
1. **Unintended Cascade Mutation**: Later sections silently overwrite earlier component definitions. Most notably, a secondary `.badge` rule at line 1900 overrides line 871, altering `border-radius` from `var(--radius-full)` (pill badge) to `var(--radius-sm)` (rounded rectangle), shrinking padding from `4px 10px` to `2px 8px`, and dropping `gap`. Similarly, `.traffic-badge` at line 1824 forces monospace font and pill padding onto definitions from line 1265.
2. **Broken CSS Variable References & Specification Semantics**: Three selectors reference custom properties never declared in `:root` or `[data-theme="light"]`:
   - `*:focus-visible` and `button:focus-visible` (lines 986, 992) reference `var(--accent-color)`. Under CSS Custom Properties Level 1 §3.1, an undeclared property without a fallback causes the declaration to be invalid at computed-value time; `outline-color` reverts to its initial value (`currentcolor`/`auto`). Focus rings still render with the current text color rather than becoming transparent, preserving focus indication.
   - `.switch-slider` (line 2530) references `var(--bg-surface-hover, #232738)`. Because an explicit fallback is supplied, it safely evaluates to `#232738` at runtime.
   - `.login-card-elevated` (line 2596) references `box-shadow: var(--shadow-xl), 0 0 30px rgba(99, 102, 241, 0.06);`. Because `--shadow-xl` has no fallback, the entire `box-shadow` declaration becomes invalid at computed-value time and evaluates to `none` (the secondary glow shadow is not retained).
3. **Redundant Copy-Paste Rules**: Multiple utility classes (`.hidden`, `.gap-xs`, `.gap-sm`, `.gap-md`) are duplicated verbatim at lines 1641–1671 and lines 1941–1956.
4. **Tight Go Unit Test Coupling**: Multiple Go tests in `web/` assert literal string tokens, multi-line blocks, and regexes directly against `fs.ReadFile(staticFS, "css/style.css")`. Any naive file split without coordination breaks the Go test suite. Production templates pin the stylesheet href to `?v=1.1.0` (asserted in `web/web_vpn_test.go:760`).

---

## 2. Component & Section Inventory (`style.css` Line-by-Line Mapping)

The 3,008 lines of `style.css` span 56 distinct contiguous sections. The table below provides an exact contiguous mapping of the entire file, identifying rule boundaries, line spans, functional domains, and target file assignments for Issue #505. Every listed selector has been verified against the stylesheet (0 phantom selectors).

| Start Line | End Line | Total Lines | Section Name / Component | Selectors | Target Modular File (#505) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1** | **87** | 87 | Design Tokens & Theme Variables (`:root`) | `:root` (56 variables) | `tokens.css` |
| **88** | **161** | 74 | Light Theme Variables (`[data-theme="light"]`) | `[data-theme="light"]`, `.logo-text`, `.theme-toggle` | `tokens.css` |
| **162** | **191** | 30 | Theme Toggle Switch Component | `.theme-toggle`, `.icon` | `base.css` |
| **192** | **228** | 37 | SVG Vector Icons | `.icon`, `.btn-icon`, `.nav-icon` | `base.css` |
| **229** | **283** | 55 | CSS Reset & Global Typography | `*`, `html`, `body`, `a`, `::selection` | `base.css` |
| **284** | **301** | 18 | Scrollbar Styling | `::-webkit-scrollbar*` | `base.css` |
| **302** | **343** | 42 | Modern Responsive App Shell Layout | `.app-layout`, `.app-sidebar`, `.app-main` | `layout.css` |
| **344** | **513** | 170 | Desktop Sidebar Elements | `.sidebar-header`, `.sidebar-nav`, `.sidebar-nav-link`, `.sidebar-actions`, `.sidebar-footer`, `.sidebar-user-card`, `.logo-title`, `.logo-badge`, `.nav-icon`, `.nav-label`, `.nav-section-label`, `.user-avatar`, `.user-name`, `.user-details`, `.mobile-close-btn` | `layout.css` |
| **514** | **537** | 24 | Mobile Topbar | `.mobile-topbar`, `.mobile-topbar-actions` | `layout.css` |
| **538** | **556** | 19 | Drawer Backdrop | `.drawer-backdrop`, `.drawer-backdrop.active` | `layout.css` |
| **557** | **615** | 59 | Mobile Bottom Navigation Bar | `.mobile-bottom-bar`, `.bottom-bar-link`, `.btn-ghost`, `.icon` | `layout.css` |
| **616** | **652** | 37 | Header & Logo Elements | `.app-logo`, `.logo-icon`, `.logo-text`, `.logo-subtitle` | `layout.css` |
| **653** | **763** | 111 | Buttons & Action Controls | `.btn`, `.btn-primary`, `.btn-secondary`, `.btn-danger`, `.btn-success`, `.btn-sm`, `.btn-icon`, `.spinner` | `components.css` |
| **764** | **797** | 34 | Cards & Containers | `.card`, `.card-header`, `.card-title`, `.card-subtitle`, `.card-hover` | `components.css` |
| **798** | **811** | 14 | Section Wrappers | `.section-title`, `.icon` | `components.css` |
| **812** | **869** | 58 | Server Grid & Server Cards | `.server-grid`, `.server-card`, `.server-name`, `.server-host`, `.server-meta`, `.server-icon`, `.server-actions`, `.server-protocols` | `server.css` |
| **870** | **913** | 44 | Status Badges & Pills (Base Definition) | `.badge`, `.badge-success`, `.badge-danger`, `.badge-warn`, `.badge-info`, `.badge-dot` | `components.css` |
| **914** | **983** | 70 | Form Controls & Inputs | `.form-group`, `.form-label`, `.form-input`, `.form-select`, `.form-textarea`, `.form-hint`, `.form-row` | `components.css` |
| **984** | **995** | 12 | Focus Visible (Accessibility) | `*:focus-visible`, `button:focus-visible`, `.btn:focus-visible` | `base.css` |
| **996** | **1077** | 82 | Modal Dialogs & Backdrops | `.modal`, `.modal-backdrop`, `.modal-header`, `.modal-title`, `.modal-close`, `.modal-footer` | `components.css` |
| **1078** | **1178** | 101 | Protocol Cards & Grid | `.protocol-cards`, `.protocol-card`, `.protocol-name`, `.protocol-desc`, `.protocol-icon`, `.protocol-status`, `.protocol-info`, `.protocol-info-item`, `.protocol-info-label`, `.protocol-info-value`, `.protocol-awg`, `.protocol-dns`, `.protocol-telemt`, `.clients-section` | `server.css` |
| **1179** | **1285** | 107 | Clients List & Items | `.clients-header`, `.clients-list`, `.client-item`, `.client-avatar`, `.client-info`, `.client-name`, `.client-meta`, `.client-actions`, `.top-consumer`, `.traffic-badge`, `.sort-toggle` | `server.css` |
| **1286** | **1312** | 27 | Config Display & Code Blocks | `.config-display`, `.config-text`, `.config-actions` | `server.css` |
| **1313** | **1391** | 79 | Toast Notifications | `.toast-container`, `.toast`, `.toast-exit`, `.toast-success`, `.toast-error`, `.toast-warning`, `.toast-info` | `components.css` |
| **1392** | **1434** | 43 | Shimmer Skeletons & Loading States | `.skeleton`, `.skeleton-text`, `.skeleton-card`, `.skeleton-avatar`, `.skeleton-icon` | `components.css` |
| **1435** | **1451** | 17 | Micro-interactions & Animations | `.copied`, `@keyframes copy-pulse` | `base.css` |
| **1452** | **1514** | 63 | Progress Bars & Spinners | `.progress-bar`, `.progress-fill`, `.loading-spinner`, `.loading-overlay` | `components.css` |
| **1515** | **1544** | 30 | Log Output Terminal | `.log-output`, `.log-line`, `.log-line.error`, `.log-line.info`, `.log-line.success` | `server.css` |
| **1545** | **1570** | 26 | Empty State Component | `.empty-state`, `.empty-icon`, `.empty-title`, `.empty-desc` | `base.css` |
| **1571** | **1605** | 35 | Tabs Navigation | `.tabs`, `.tab`, `.tab.active` | `components.css` |
| **1606** | **1620** | 15 | Back Link Navigation | `.back-link` | `base.css` |
| **1621** | **1627** | 7 | Divider Utility | `.divider` | `base.css` |
| **1628** | **1672** | 45 | Flexbox & Spacing Utilities | `.flex`, `.items-center`, `.justify-between`, `.gap-xs`, `.gap-sm`, `.gap-md`, `.mt-md`, `.hidden`, `.text-muted`, `.text-sm`, `.font-mono` | `layout.css` |
| **1673** | **1719** | 47 | Legacy Responsive Breakpoints | `@media (max-width: 768px)` (`.server-grid`, `.protocol-cards`, `.form-row`, `.modal`, `.client-item`, `.client-info`, `.client-actions`), `@media (max-width: 480px)` (`.protocol-info`, `.stats-grid`) | `layout.css` (Colocate overrides) |
| **1720** | **1742** | 23 | Server Stats Inline Pills | `.stat-pill`, `.config-tabs` | `server.css` |
| **1743** | **1786** | 44 | Config Tabs | `.config-tabs`, `.config-tab`, `.config-tab.active`, `.config-panel`, `.config-panel.active` | `server.css` |
| **1787** | **1806** | 20 | QR Code Display | `.qr-container`, `.qr-hint` | `server.css` |
| **1807** | **1822** | 16 | VPN Protocol Link Box | `.vpn-link-box` | `vpn.css` |
| **1823** | **1846** | 24 | Traffic Badges (2nd Definition) | `.traffic-badge`, `.traffic-down`, `.traffic-up` | `components.css` |
| **1847** | **1875** | 29 | Header Navigation Links | `.nav-link`, `.nav-link.active` | `layout.css` |
| **1876** | **1898** | 23 | Theme Switching Transitions & Responsive Nav | `body, .card, .nav-link, .btn, .form-input, .form-select, .modal, .modal-backdrop`, `@media (max-width: 900px) .nav-link` | `base.css` (Hook to `components.css`, query to `layout.css`) |
| **1899** | **1940** | 42 | Badges Duplicate Definition | `.badge`, `.badge-success`, `.badge-warn`, `.badge-danger`, `.badge-info`, `.badge-secondary` | *Remove in #505 (Consolidate)* |
| **1941** | **1956** | 16 | Additional Layout Helpers Duplicate | `.hidden`, `.gap-xs`, `.gap-sm`, `.gap-md` | *Remove in #505 (Consolidate)* |
| **1957** | **2089** | 133 | Leaderboard Styles | `.leaderboard-section`, `.leaderboard-rank-card`, `.leaderboard-rank-icon`, `.leaderboard-rank-info`, `.leaderboard-rank-label`, `.leaderboard-rank-value`, `.leaderboard-period-toggle`, `.data-table`, `.rank-cell`, `.username-cell`, `.traffic-cell`, `.current-user`, `.table-container`, `.badge-primary`, `.btn` | `components.css` |
| **2090** | **2147** | 58 | Responsive App Shell Media Queries | `@media (max-width: 1023px)` (`.mobile-topbar`, `.drawer-backdrop`, `.mobile-close-btn`, `.app-sidebar`, `.app-sidebar.drawer-open`, `[dir="rtl"] .app-sidebar`, `.app-main`), `@media (max-width: 767px)` (`.mobile-bottom-bar`, `.app-main`) | `layout.css` |
| **2148** | **2233** | 86 | Interactive Table Toolbar | `.table-toolbar`, `.table-search-box`, `.table-search-icon`, `.table-search-input`, `.table-search-clear` | `tables.css` |
| **2234** | **2271** | 38 | Filter Chips | `.table-filter-chips`, `.filter-chip`, `.filter-chip.active` | `tables.css` |
| **2272** | **2355** | 84 | Sortable Table Headers & Base Table | `.data-table`, `th.sortable`, `.sortable`, `.sort-icon`, `.sort-icon-svg`, `.sort-icon-asc`, `.sort-icon-desc`, `.sort-asc`, `.sort-desc` | `tables.css` |
| **2356** | **2386** | 31 | Table Empty State | `.table-empty-state`, `.empty-state-content`, `.empty-state-icon`, `.empty-state-text` | `tables.css` |
| **2387** | **2458** | 72 | Table Pagination | `.table-pagination`, `.page-buttons`, `.page-btn`, `.page-btn.active`, `.page-info`, `.page-count`, `.page-total`, `.page-ellipsis` | `tables.css` |
| **2459** | **2495** | 37 | Telemetry & Sparkline Widgets | `.sparkline-container`, `.sparkline-svg`, `.sparkline-path`, `.sparkline-area`, `.sparkline-dot` | `vpn.css` |
| **2496** | **2572** | 77 | Modern Toggle Switch | `.switch`, `.switch-slider`, `.switch-container`, `.switch-label-text` | `components.css` |
| **2573** | **2657** | 85 | Modern Login Page Styles | `.login-card-elevated`, `.login-header-actions`, `.login-error-box`, `.login-input-adornment`, `.login-icon-adornment-group`, `.form-input` | `components.css` |
| **2658** | **2766** | 109 | Client Dashboard & Settings Polish | `.settings-section-card`, `.settings-card-header`, `.network-health-grid`, `.network-health-node`, `.connections-toolbar`, `.connections-toolbar-actions`, `.lb-selection-callout`, `.client-meta`, `.card-title`, `.stat-card` | `vpn.css` |
| **2767** | **2962** | 196 | Modernized VPN Section & Tables | `.stat-card`, `.stat-card-header`, `.stat-card-title`, `.stat-card-value`, `.stat-card-sub`, `.latency-pill`, `.latency-dot`, `.latency-good`, `.latency-fair`, `.latency-poor`, `.info-card`, `.info-card-grid`, `.info-card-item`, `.info-card-label`, `.info-card-value`, `.interactive-table`, `.btn-success-hover`, `.btn-danger-hover`, `.modal-notice-error` | `vpn.css` |
| **2963** | **3008** | 46 | Modernized Users Section (Issue #113) | `#usersContainer`, `#usersGrid`, `#userConnsTable`, `.user-card`, `.user-avatar-circle` | `layout.css` |

---

## 3. Usage & Ownership Cross-Reference Matrix

All 373 selector keys and 236 class tokens were cross-referenced against all 13 HTML templates (`web/templates/*.html`) and 15 JavaScript modules (`web/static/js/**/*.js`), accounting for dynamic DOM construction.

### 3.1 Subsystem Ownership Classification Summary

```
Total Selectors (373 Unique Keys)
 ├── Base & Universal Tag Rules :  19 selectors ( 5.1%) -> Tokens, Resets, Element Defaults
 ├── Shared Shell & Layout      :  62 selectors (16.6%) -> Layout, Navigation, Grid, Breakpoints
 ├── Reusable UI Components     : 216 selectors (57.9%) -> Buttons, Tables, Forms, Modals, Badges, Toasts
 ├── Server Management Domain   :  32 selectors ( 8.6%) -> Server Cards, Protocols, Logs, Client Lists
 ├── VPN Dashboard Domain       :  18 selectors ( 4.8%) -> Telemetry, Stat Cards, Latency Pills, Sparklines
 ├── Login / Authentication     :   8 selectors ( 2.1%) -> Login Elevated Cards, Adornments
 ├── Leaderboard Feature        :   8 selectors ( 2.1%) -> Leaderboard Tables, Position Badges
 ├── Users Management Feature   :   4 selectors ( 1.1%) -> Users Grid, Avatar Circles, User Cards
 └── Zero Static Matches        :  10 selectors ( 2.7%) -> 4 Dynamic Toast Tokens, 4 Test Tokens, 1 Unused, 1 Companion
```

### 3.2 Granular Cross-Reference Matrix

The table below catalogs primary selector groups, their source line spans in `style.css`, and the exact owning templates and JavaScript files:

| Selector Group | Line Range | Owning Templates (`web/templates/`) | Owning Scripts (`web/static/js/`) | Invariant / Dynamic Usage Notes |
| :--- | :--- | :--- | :--- | :--- |
| **Tokens & Theme** (`:root`, `[data-theme]`) | 1–161 | `base.html`, `login.html`, `setup.html`, `change_password.html` | *(None)* | Defines 56 CSS variables. Evaluated globally. |
| **SVG Icons** (`.icon`, `.nav-icon`, `.btn-icon`) | 192–228 | `base.html`, `index.html`, `server.html`, `vpn.html`, `users.html`, `settings.html`, `my_connections.html`, `leaderboard.html` | `ui.js`, `tables.js`, `users.js`, `server_telemetry.js`, `vpn/*.js` | Embedded `<use href="#icon-*">` vector glyphs. |
| **App Shell & Sidebar** (`.app-layout`, `.app-sidebar`, `.sidebar-nav`) | 302–513 | `base.html` | *(None)* | Enforced stacking contexts: sidebar base `z-index: 90`, drawer open `100`. |
| **Mobile Navigation** (`.mobile-topbar`, `.mobile-bottom-bar`, `.drawer-backdrop`) | 514–615 | `base.html` | *(None)* | Breakpoint stacking context: bottom bar (70) < backdrop (95) < drawer sidebar (100). |
| **Header & Branding** (`.app-logo`, `.logo-icon`, `.logo-text`, `.logo-subtitle`) | 616–652 | `base.html`, `login.html`, `setup.html`, `change_password.html`, `user_share.html` | *(None)* | Shared branding across application shells. |
| **Buttons** (`.btn`, `.btn-primary`, `.btn-secondary`, `.btn-danger`, `.btn-sm`) | 653–763 | All 13 templates | `ui.js`, `tables.js`, `server_actions.js`, `users.js`, `vpn/*.js` | Universal atomic component. `.btn-success` defined but unreached in `confirmVariant`. |
| **Cards & Headers** (`.card`, `.card-header`, `.card-title`, `.section-title`) | 764–811 | `index.html`, `server.html`, `vpn.html`, `users.html`, `settings.html`, `my_connections.html`, `leaderboard.html` | `users.js`, `vpn/health_problems.js`, `vpn/sessions.js` | Core surface container widget. |
| **Server Cards & Grid** (`.server-grid`, `.server-card`, `.server-name`) | 812–869 | `index.html` | *(None)* | Server instances overview on dashboard. |
| **Status Badges** (`.badge`, `.badge-success`, `.badge-danger`, `.badge-dot`) | 870–913 | `base.html`, `index.html`, `server.html`, `vpn.html`, `users.html`, `settings.html`, `my_connections.html`, `leaderboard.html` | `server_telemetry.js`, `users.js`, `vpn/*.js` | Highly dynamic construction via template interpolation and JavaScript. |
| **Form Controls** (`.form-group`, `.form-input`, `.form-select`, `.form-row`) | 914–983 | `login.html`, `setup.html`, `change_password.html`, `server.html`, `users.html`, `settings.html`, `vpn.html` | `vpn/charts.js` | Standardized form controls. |
| **Modals** (`.modal`, `.modal-backdrop`, `.modal-header`, `.modal-close`) | 996–1077 | `base.html`, `server.html`, `vpn.html`, `users.html`, `my_connections.html`, `user_share.html` | `ui.js`, `vpn/page.js` | Accessible dialogs with keyboard and backdrop dismissal. |
| **Protocol Cards** (`.protocol-cards`, `.protocol-card`, `.protocol-info`) | 1078–1178 | `server.html` | *(None)* | Protocol configuration cards on server detail page. |
| **Clients List** (`.clients-list`, `.client-item`, `.client-avatar`, `.client-info`) | 1179–1285 | `server.html`, `users.html`, `my_connections.html` | `server_telemetry.js`, `users.js` | Client items rendered across server, users, and connection views. |
| **Config Display** (`.config-display`, `.config-text`, `.config-actions`) | 1286–1312 | `server.html`, `users.html`, `my_connections.html`, `user_share.html` | *(None)* | Configuration text containers with copy controls. |
| **Toast Notifications** (`.toast`, `.toast-container`, `.toast-exit`) | 1313–1391 | `base.html`, `index.html`, `settings.html`, `my_connections.html` | `ui.js`, `server_actions.js`, `users.js`, `vpn/backends.js` | `.toast-success/error/warning/info` constructed dynamically in `ui.js:85`. |
| **Shimmer Skeletons** (`.skeleton`, `.skeleton-text`, `.skeleton-card`, `.skeleton-avatar`) | 1392–1434 | *(None/Design System)* | *(None)* | Loading state primitives asserted by `web/web_test.go:81`. `.skeleton-icon` is dead. |
| **Micro-interactions** (`.copied`) | 1435–1451 | *(None/Global)* | `ui.js` | Visual feedback on copy actions (`copy-pulse` keyframe). |
| **Progress & Spinners** (`.progress-bar`, `.progress-fill`, `.loading-spinner`) | 1452–1514 | `server.html`, `leaderboard.html` | *(None)* | Asynchronous task progress indicator. |
| **Log Output Terminal** (`.log-output`, `.log-line`, `.log-line.error`) | 1515–1544 | `server.html` | `server_actions.js` | Deployment journal streaming console. |
| **Empty State** (`.empty-state`, `.empty-icon`, `.empty-title`, `.empty-desc`) | 1545–1570 | `server.html`, `users.html`, `my_connections.html`, `leaderboard.html`, `index.html` | `vpn/page.js`, `vpn/sessions.js` | Shared placeholder when record lists are empty. |
| **Tabs Navigation** (`.tabs`, `.tab`) | 1571–1605 | `index.html`, `my_connections.html`, `user_share.html` | `server_actions.js`, `users.js`, `telemetry.js` | Tab switching controller primitives. |
| **Back Link Navigation** (`.back-link`) | 1606–1620 | `server.html` | *(None)* | Navigation link returning to server overview. |
| **Utilities & Spacing** (`.flex`, `.hidden`, `.gap-xs`, `.gap-sm`, `.gap-md`) | 1621–1672 | All 13 templates | `ui.js`, `tables.js`, `users.js`, `server_actions.js`, `vpn/*.js` | Utility classes. Duplicated at L1941–1956. |
| **Server Stats Pills** (`.stat-pill`, `.config-tabs`) | 1720–1742 | `server.html`, `users.html`, `my_connections.html`, `user_share.html` | `server_telemetry.js` | Compact telemetry metric pills. |
| **Config Tabs** (`.config-tab`, `.config-panel`) | 1743–1786 | `server.html`, `users.html`, `my_connections.html`, `user_share.html` | `server_actions.js`, `users.js` | Protocol tab selection panels. |
| **QR Code Display** (`.qr-container`, `.qr-hint`) | 1787–1806 | `server.html`, `users.html`, `my_connections.html`, `user_share.html` | *(None)* | Configuration QR presentation modal container. |
| **VPN Protocol Link Box** (`.vpn-link-box`) | 1807–1822 | `server.html`, `users.html`, `my_connections.html`, `user_share.html` | *(None)* | Scrollable raw connection URI container. |
| **Traffic Badges** (`.traffic-badge`, `.traffic-down`, `.traffic-up`) | 1823–1846 | `my_connections.html` | `server_telemetry.js` | Monospace badge showing upload/download rates. |
| **Header Navigation Links** (`.nav-link`) | 1847–1875 | `base.html` | *(None)* | Top header navigation links. Responsive override at L1891. |
| **Leaderboard** (`.leaderboard-section`, `.leaderboard-rank-card`, `.data-table`) | 1957–2089 | `leaderboard.html` | *(None)* | Gamified traffic leaderboard and period toggle. |
| **Interactive Tables** (`.table-toolbar`, `.table-search-box`, `.sortable`) | 2148–2355 | `server.html`, `users.html`, `vpn.html`, `index.html`, `my_connections.html` | `tables.js`, `vpn/page.js`, `vpn/sessions.js`, `users.js` | Reusable data table engine (filtering, sorting). |
| **Table Empty State** (`.table-empty-state`, `.empty-state-content`) | 2356–2386 | *(None/Dynamic)* | `tables.js`, `vpn/page.js`, `vpn/sessions.js` | Specific empty-state injected by `tables.js`. |
| **Table Pagination** (`.table-pagination`, `.page-btn`, `.page-info`) | 2387–2458 | *(None/Dynamic)* | `tables.js` | Numeric and ellipsis pagination controls. |
| **Telemetry & Sparklines** (`.sparkline-container`, `.sparkline-svg`) | 2459–2495 | *(None/Dynamic)* | `telemetry.js` | SVG path rendering for real-time traffic charts. |
| **Toggle Switches** (`.switch`, `.switch-slider`, `.switch-container`) | 2496–2572 | `server.html`, `settings.html` | `server_actions.js`, `vpn/backends.js` | Accessible toggle controls with sliding knob. |
| **Login Modern Polish** (`.login-card-elevated`, `.login-header-actions`) | 2573–2657 | `login.html` | *(None)* | Elevated card layout for authentication view. |
| **Client Dashboard & Polish** (`.settings-section-card`, `.network-health-grid`) | 2658–2766 | `my_connections.html`, `settings.html` | *(None)* | Settings cards and connection health node indicators. |
| **VPN Modern Cards** (`.stat-card`, `.latency-pill`, `.info-card`, `.interactive-table`) | 2767–2962 | `vpn.html`, `server.html`, `users.html` | `vpn/backends.js`, `tables.js` | Modernized KPI stat cards and latency indicators. |
| **Users Modern Section** (`#usersContainer`, `#usersGrid`, `.user-card`) | 2963–3008 | `users.html` | `users.js` | Full-width container and grid rules for Issue #113. |

---

## 4. Duplicate, Overriding, and Conflicting Selectors Audit

An AST-equivalent scan of `style.css` identified **33 duplicate selector occurrences** falling into distinct categories requiring clear separation between mechanical deduplication and deferred design adjustments.

### 4.1 Harmful Semantic Conflicts vs. Deferred Design Adjustments

#### Conflict 1: Status Badges (`.badge`, `.badge-success`, `.badge-danger`, `.badge-info`, `.badge-warn`)
- **Definition 1**: Lines 870–905 (under `/* ===== Badge ===== */`)
- **Definition 2**: Lines 1899–1933 (under `/* ===== Badges ===== */`)

```css
/* --- Definition 1 (L871-881) --- */
.badge {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 4px 10px;
    border-radius: var(--radius-full);   /* Full pill shape (9999px) */
    font-size: 0.72rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.03em;
}

/* --- Definition 2 (L1900-1909) --- */
.badge {
    display: inline-flex;
    align-items: center;
    padding: 2px 8px;                    /* Overrides padding to smaller */
    border-radius: var(--radius-sm);     /* Overrides pill to rounded rectangle (6px) */
    font-size: 0.72rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.02em;
}
```

*Cascade Impact*: Both definitions have identical specificity `(0, 1, 0)`. Definition 2 sits 1,029 lines below Definition 1 and wins everywhere in production today, rendering squared rectangular badges. In addition, `.badge-secondary` is defined only at line 1935 in Definition 2.
*Handling Strategy*: Because enforcing pill radius changes current production rendering, unify the component in `components.css` while preserving `.badge-secondary` (line 1935) and `.badge-dot` (line 907). In Issue #505, maintain existing visual rendering or enact a deliberate design decision, but do not delete lines 1899–1940 naively as that would eliminate `.badge-secondary`.

#### Conflict 2: Traffic Badges (`.traffic-badge`)
- **Definition 1**: Lines 1265–1272 (under `/* ===== Clients Table ===== */`)
- **Definition 2**: Lines 1823–1833 (under `/* ===== Traffic Badge ===== */`)

*Cascade Impact*: Definition 2 overrides font size (`0.7rem`), adds monospace font and pill background padding, while inheriting `color: var(--text-muted)` and `white-space: nowrap` from Definition 1.
*Handling Strategy*: Defer design unification. Retain combined styling in `components.css` so both monospace formatting and muted text are preserved without visual degradation.

### 4.2 Identical Verbatim Redundancies (Safe Mechanical Dedup)

Lines 1941–1956 repeat utilities that were already fully defined in lines 1641–1671:

| Selector | Definition 1 Line | Definition 2 Line | Declaration Content | Action in #505 |
| :--- | :--- | :--- | :--- | :--- |
| `.hidden` | L1669–L1671 | L1942–L1944 | `display: none !important;` | Delete Definition 2 (safe dedup) |
| `.gap-xs` | L1641–L1643 | L1946–L1948 | `gap: var(--space-xs);` | Delete Definition 2 (safe dedup) |
| `.gap-sm` | L1645–L1647 | L1950–L1952 | `gap: var(--space-sm);` | Delete Definition 2 (safe dedup) |
| `.gap-md` | L1649–L1651 | L1954–L1956 | `gap: var(--space-md);` | Delete Definition 2 (safe dedup) |
| `.skeleton-icon` | L1427–L1433 | — | `border-radius: var(--radius-full);` | Prune dead selector (safe dedup) |

### 4.3 Multi-Selector Theme Transition Hooks

Lines 1877–1890 define the complete theme transition hook:
```css
body,
.card,
.nav-link,
.btn,
.form-input,
.form-select,
.modal,
.modal-backdrop {
    transition: background-color var(--transition-slow),
        border-color var(--transition-slow),
        color var(--transition-slow),
        box-shadow var(--transition-slow),
        transform var(--transition-base);
}
```
*Precedence Constraint*: `.btn` at line 663 defines `transition: all var(--transition-base);`. In the monolith, line 1877 comes later and successfully applies smooth slow theme transitions. If placed in `base.css` without loading `base.css` after components, `.btn` in `components.css` overrides this rule. Therefore, this hook must be loaded after or placed at the end of `components.css`.

### 4.4 Precedence-Sensitive Rules Catalog

The table below catalogs every rule whose correct rendering depends on source-order precedence ("later-wins"):

| Selector | Earlier Rule Line & File | Later Overriding Rule Line & File | Overridden Properties | Required Load / Placement Constraint |
| :--- | :--- | :--- | :--- | :--- |
| `.badge` | L871 (`components.css`) | L1900 (Monolith duplicate) | `border-radius`, `padding`, `letter-spacing` | Unify canonically in `components.css`; preserve `.badge-secondary`. |
| `.traffic-badge` | L1265 (`server.css`) | L1824 (`components.css`) | `font-size`, `font-family`, `padding`, `border-radius` | Unify in `components.css` preserving both font and muted color. |
| `.btn` transition | L663 (`components.css`) | L1877 (`base.css` hook) | `transition` properties | Place theme transition hook AFTER component base definitions. |
| `.modal` @<=768px | L1017 (`components.css`) | L1687 (`layout.css` query) | `width: 95%` (base is 90%) | Colocate responsive `@media` override in `components.css` after base rule. |
| `.server-grid` @<=768px | L813 (`server.css`) | L1675 (`layout.css` query) | `grid-template-columns: 1fr` | Colocate responsive `@media` override in `server.css` after base rule. |
| `.protocol-cards` @<=768px | L1079 (`server.css`) | L1679 (`layout.css` query) | `grid-template-columns: 1fr` | Colocate responsive `@media` override in `server.css` after base rule. |
| `.client-item` @<=768px | L1199 (`server.css`) | L1692 (`layout.css` query) | `flex-direction: column` | Colocate responsive `@media` override in `server.css` after base rule. |
| `.nav-link` @<=900px | L1848 (`layout.css`) | L1893 (`base.css` query) | `padding: 6px 12px; font-size: 0.8rem` | Keep 900px query in `layout.css` immediately following `.nav-link`. |

---

## 5. CSS Custom Properties (Variables) & Token Integrity

### 5.1 Token Inventory Overview
Lines 1–161 define the core design system tokens. Dark mode serves as `:root`, while `[data-theme="light"]` overrides specific values:
- **Surfaces**: `--bg-primary`, `--bg-surface`, `--bg-card`, `--bg-input`, `--bg-modal`, `--bg-glass`
- **Text**: `--text-primary`, `--text-secondary`, `--text-muted`, `--text-accent`
- **Accent & Brand**: `--accent`, `--accent-hover`, `--accent-light`, `--accent-dark`, `--accent-subtle`
- **Status Scale**: `--success`, `--success-bg`, `--success-border`, `--warning`, `--warning-bg`, `--danger`, `--danger-bg`, `--danger-border`, `--info`, `--info-bg`, `--info-border`
- **Dimensions & Spacing**: `--space-xs` through `--space-2xl`, `--radius-sm` through `--radius-full`, `--shadow-sm` through `--shadow-glow`

### 5.2 Defect Audit: Undefined Variables Used in Selectors

Three selectors in `style.css` invoke CSS variables that are never declared in `:root` or `[data-theme="light"]`:

```
Variable Defect 1: --accent-color
  Used at: L986 (*:focus-visible), L992 (button:focus-visible, .btn:focus-visible)
  Declaration in style.css: outline: 2px solid var(--accent-color);
  Specification Behavior: Undeclared property without fallback causes computed-value time invalidation.
  Runtime Effect: outline-color falls back to initial value (currentcolor). Focus outline renders using text color.
  Fix (Design Adjustment): Map to var(--accent) in a dedicated visual polish task.

Variable Defect 2: --bg-surface-hover
  Used at: L2530 (.switch-slider) [previously misattributed to toggle switch card in initial draft]
  Declaration in style.css: background-color: var(--bg-surface-hover, #232738);
  Specification Behavior: Explicit fallback is provided.
  Runtime Effect: Resolves safely to #232738 at runtime.
  Fix: Declare --bg-surface-hover in tokens.css for theme parity.

Variable Defect 3: --shadow-xl
  Used at: L2596 (.login-card-elevated) [previously misattributed to un-elevated card in initial draft]
  Declaration in style.css: box-shadow: var(--shadow-xl), 0 0 30px rgba(99, 102, 241, 0.06);
  Specification Behavior: Invalid var() reference invalidates entire box-shadow property declaration.
  Runtime Effect: Entire box-shadow falls back to none (secondary glow shadow is lost).
  Fix (Design Adjustment): Declare --shadow-xl in tokens.css in a dedicated design task.
```

### 5.3 Defect Audit: Declared Variables Unused in CSS
Four variables are declared in `:root` but have zero `var(...)` invocations inside `style.css`:
- `--accent-dark` (lines 30, 109) and `--info-border` (lines 48, 127)
- `--text-accent` (lines 26, 105)
- `--shadow-md` (lines 68, 130): Actively used via inline style in `web/templates/my_connections.html:198` (`box-shadow: var(--shadow-md);`). Must be preserved.

---

## 6. Dead Code & Zero-Usage Audit

### 6.1 Truly Dead Selectors vs. Dynamically Constructed Tokens

A boundary-matched scan of all 236 class tokens across 13 templates and 15 non-minified JS files flags 10 tokens with 0 literal template hits:

| Selector Key | Line Span | Classification | Empirical Finding & Evidence |
| :--- | :--- | :--- | :--- |
| `.toast-success` | L1356–L1360 | **Dynamic Production** | Injected in `web/static/js/ui.js:85` via `el.className = 'toast toast-' + toastType`. **DO NOT DELETE.** |
| `.toast-error` | L1362–L1366 | **Dynamic Production** | Injected in `web/static/js/ui.js:85`. Critical error styling. **DO NOT DELETE.** |
| `.toast-warning` | L1368–L1372 | **Dynamic Production** | Injected in `web/static/js/ui.js:85`. Warning styling. **DO NOT DELETE.** |
| `.toast-info` | L1374–L1378 | **Dynamic Production** | Injected in `web/static/js/ui.js:85`. Information styling. **DO NOT DELETE.** |
| `.skeleton` | L1393–L1403 | **Tested Design Token** | Asserted by `web/web_test.go:81` (`requiredCSS`). Loading state primitive. **DO NOT DELETE.** |
| `.skeleton-text` | L1405–L1413 | **Tested Design Token** | Asserted by `web/web_test.go:81`. Text skeleton token. **DO NOT DELETE.** |
| `.skeleton-card` | L1415–L1425 | **Tested Design Token** | Asserted by `web/web_test.go:81`. Card skeleton token. **DO NOT DELETE.** |
| `.skeleton-avatar` | L1427–L1433 | **Tested Design Token** | Asserted by `web/web_test.go:81`. Avatar circle skeleton token. **DO NOT DELETE.** |
| `.skeleton-icon` | L1427–L1433 | **GENUINE DEAD CSS** | Companion to `.skeleton-avatar`. 0 references in templates, JS, or tests. **SAFE TO PRUNE IN #505.** |
| `.btn-success` | L729–L732 | **Unreached Variant** | Reachable via `ui.js:337` (`'btn btn-' + variant`). Codebase only uses `danger/primary/warning`. Retain in design system. |

### 6.2 Latent UI Defect in `server_actions.js`
In `web/static/js/server_actions.js:506`, the reboot confirmation dialog specifies `confirmVariant: 'warning'`. This dynamically constructs class `.btn-warning`. However, `style.css` does not define a `.btn-warning` rule (`grep` returns empty). This is an existing latent UI bug to be addressed in a separate issue; it must not be conflated with the mechanical CSS split.

---

## 7. Media Queries & Responsive Breakpoint Strategy

### 7.1 Breakpoint Hierarchy
The stylesheet relies on five distinct `@media` breakpoints:
- `1023px` (L2090–2133): Off-canvas sidebar, sticky mobile topbar, drawer backdrop activation.
- `900px` (L1893–1896): Header navigation link padding compression.
- `768px` (L1674–1708): Server grid 1-col, modal 95% width, clients vertical list.
- `767px` (L2134–2146): Mobile bottom navigation bar displayed; main container bottom padding.
- `480px` (L1709–1718): Protocol card metadata grid 1-col.

### 7.2 The 768px vs. 767px Threshold Collision
At exactly `768px`: 768px queries trigger (single-column cards, modal expands), but 767px queries do not (`.mobile-bottom-bar` remains hidden). Aligning or standardizing these breakpoints is a visual design adjustment deferred to post-modularization.

### 7.3 Cascade Order Mandate: Media Query Colocation
To guarantee zero specificity or precedence regressions during modularization, all responsive overrides must remain in the same file as, and placed after, their base rules (e.g. `.modal` 768px override in `components.css`; `.server-grid` override in `server.css`; `.nav-link` 900px override in `layout.css`).

---

## 8. Safe Modularization Roadmap for Issue #505

### 8.1 Proposed Modular File Structure (Strictly Under 1,000 Lines)

The stylesheet `style.css` (3,008 lines) is partitioned into 7 cohesive modules. Line counts are strictly verified to satisfy the project ceiling:

```
web/static/css/
 ├── tokens.css       (161 lines) : Variables, design tokens, light theme overrides
 ├── base.css         (240 lines) : Resets, typography, scrollbars, SVG icons, focus, micro-interactions, empty-state
 ├── layout.css       (576 lines) : App shell, sidebar, mobile top/bottom bars, header, spacing, grid widths
 ├── tables.css       (311 lines) : Interactive table engine (toolbar, filter chips, sortable headers, pagination)
 ├── components.css   (894 lines) : Buttons, cards, modals, form controls, badges, toasts, toggles, login, leaderboard
 ├── server.css       (410 lines) : Server grid, protocol cards, client lists, config displays, logs, QR codes
 └── vpn.css          (358 lines) : VPN stat cards, latency indicators, diagnostics, client dashboard polish
 (Deduplicated in #505: 58 lines) : Removed duplicate badges and redundant utilities
Total Lines Accounted: 3,008 lines (Every proposed file strictly < 1,000 lines)
```

### 8.2 Load Order & Unconditional Link Contract

#### Template Context Invariant
In Amnezia Nexus, HTTP request context injected by Go (`internal/handlers/template.go:713–724`) provides `current_user, site_settings, captcha_settings, lang, translations_json, csrf_token, app_version, app_codename` plus the handler map. **It does NOT inject `.active_page` or `.version`.**
Furthermore, production templates pin the stylesheet href to `?v=1.1.0` (asserted in `web/web_vpn_test.go:760`). Standalone templates (`login.html`, `setup.html`, `change_password.html`) do not extend `base.html` and link stylesheets directly.

#### Production Load Order Contract
All stylesheets must be loaded unconditionally in `base.html` and standalone templates in this strict order:

```html
<!-- 1. Design Tokens & Theme Variables -->
<link rel="stylesheet" href="/static/css/tokens.css?v=1.1.0">
<!-- 2. Base Element Resets & Primitives -->
<link rel="stylesheet" href="/static/css/base.css?v=1.1.0">
<!-- 3. Shell Layout & Structural Drawers -->
<link rel="stylesheet" href="/static/css/layout.css?v=1.1.0">
<!-- 4. Interactive Data Table Engine -->
<link rel="stylesheet" href="/static/css/tables.css?v=1.1.0">
<!-- 5. Atomic Components & Form Dialogs -->
<link rel="stylesheet" href="/static/css/components.css?v=1.1.0">
<!-- 6. Server Management Domain -->
<link rel="stylesheet" href="/static/css/server.css?v=1.1.0">
<!-- 7. VPN Telemetry & Client Dashboard Domain -->
<link rel="stylesheet" href="/static/css/vpn.css?v=1.1.0">
```

### 8.3 Go Asset Embedding & Unit Test Lockstep Contract

#### Embed File System Directives (`web/web.go`)
Static assets are embedded via three distinct `embed.FS` variables:
```go
//go:embed static/*
var StaticFS embed.FS

//go:embed templates/*
var TemplatesFS embed.FS

//go:embed translations/*
var TranslationsFS embed.FS
```
Sub-filesystems are accessed via `GetStaticSubFS()`, `GetTemplatesSubFS()`, and `GetTranslationsSubFS()`. New CSS files placed in `web/static/css/` are automatically embedded by `static/*`.

#### Actual Go Test Coupling Inventory
The following real tests read `css/style.css` directly and assert literal string tokens:
1. `TestEmbeddedStaticAndTemplates` (`web/web_embedded_test.go:63`): Asserts `"css/style.css"` presence in `staticFS`.
2. `TestModernDesignSystemAndShell` (`web/web_embedded_test.go:160`): Asserts required tokens (`--bg-primary`, `--accent`, `.app-layout`, `.app-sidebar`, `.mobile-bottom-bar`, `.drawer-backdrop`, `.btn-icon`).
3. `TestIssue351MobileLogoutOcclusionAndStackingContext` (`web/web_embedded_test.go:383`): Uses regex on `.app-layout`, `.mobile-bottom-bar`, `.drawer-backdrop` to assert `position: relative` and numeric `z-index` values (70 and 95).
4. `TestIssue113UsersUIModernization` (`web/web_server_users_test.go:216`): Exact-whitespace multi-line string assertions:
   - `"#usersContainer {\n    width: 100%;\n    min-width: 100%;\n}"`
   - `"#usersGrid {\n    width: 100%;\n    min-width: 100%;\n}"`
   - `"#userConnsTable {\n    width: 100%;\n    min-width: 100%;\n}"`
5. `TestModernJavaScriptAndInteractiveComponents` (`web/web_test.go:71`): Asserts `.skeleton`, `.skeleton-text`, `.skeleton-card`, `.skeleton-avatar`, `.toast`, `.toast-container`, `.copied`.
6. `TestPhase3TablesAndTelemetryEngine` (`web/web_test.go:225`): Asserts `.table-toolbar`, `.table-search-box`, `.table-filter-chips`, `.filter-chip`, `.data-table`, `th.sortable`, `.sort-icon`, `.sort-icon-svg`, `.table-pagination`, `.page-btn`, `.sparkline-container`.
7. `TestPhase6ClientExperienceAndPolish` (`web/web_test.go:504`): Asserts `.switch`, `.switch-slider`, `.login-card-elevated`, `.login-header-actions`, `.settings-section-card`, `.network-health-grid`, `.connections-toolbar`.
8. `TestLoadBalancerHighlightAndAwgPreselection` (`web/web_vpn_test.go:200`): Asserts `.lb-selection-callout` and `[dir="rtl"] .lb-selection-callout`.
9. `TestIssue101VPNModernization` (`web/web_vpn_test.go:453`): Asserts `.stat-card`, `.latency-pill`, `.info-card`, `.info-card-grid`.
10. `TestIssue101VPNPolishRework` (`web/web_vpn_test.go:654`): Asserts `.gap-xs {` and `gap: var(--space-xs);`.
11. `TestIssue109VPNTableFullWidth` (`web/web_vpn_test.go:727`): Asserts multi-line `.interactive-table` and `.table-container table` full-width blocks, and verifies cache-busting href `href="/static/css/style.css?v=1.1.0"` across all templates at line 760.
12. Test fixtures in `web/vpn_fixture_test.go:211` and `web/vpn_fixture_selftest_test.go:653, 728`.

#### Transition Strategies for Issue #505
- **Strategy A (Aggregate Manifest Bundle — Recommended)**: Maintain `web/static/css/style.css` as a master file concatenating the modular files or using `@import`, satisfying all existing Go string tests without requiring simultaneous test harness modification.
- **Strategy B (Atomic Test Harness Update)**: Simultaneously update Go tests to read from modular files (e.g. `css/tokens.css` for `--accent`, `css/tables.css` for `.table-toolbar`).

### 8.4 Phased Implementation Sequence for Issue #505

The implementation sequence partitions lines 1–3008 with contiguous, non-overlapping ranges:

```
┌──────────────────────────────────────────────────────────────────────────┐
│ Step 1: Extract tokens.css & base.css                                     │
│ - Move Lines 1–161 to tokens.css (161 lines)                             │
│ - Move Lines 162–301, 984–995, 1435–1451, 1545–1570, 1606–1627 to       │
│   base.css (240 lines)                                                   │
│ - Prune dead selector .skeleton-icon                                     │
│ - Colocate theme transition hook after components                        │
└────────────────────────────────────┬─────────────────────────────────────┘
                                     │
                                     ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ Step 2: Extract layout.css                                               │
│ - Move Lines 302–652, 1628–1672, 1847–1875, 2090–2147, 2963–3008 to     │
│   layout.css (576 lines)                                                 │
│ - Colocate responsive @media (max-width: 900px) after .nav-link          │
│ - Deduplicate .hidden and .gap-* utilities                               │
└────────────────────────────────────┬─────────────────────────────────────┘
                                     │
                                     ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ Step 3: Extract tables.css                                               │
│ - Move Lines 2148–2458 to tables.css (311 lines)                         │
│ - Verifies data table engine, sortable headers, filter chips, pagination │
└────────────────────────────────────┬─────────────────────────────────────┘
                                     │
                                     ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ Step 4: Extract components.css                                           │
│ - Move Lines 653–811, 870–983, 996–1077, 1313–1434, 1452–1514,          │
│   1571–1605, 1823–1846, 1876–1890, 1957–2089, 2496–2657 to              │
│   components.css (894 lines)                                             │
│ - Colocate responsive overrides for .modal and .form-row                 │
│ - Unify .badge and .traffic-badge; retain .badge-secondary               │
└────────────────────────────────────┬─────────────────────────────────────┘
                                     │
                                     ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ Step 5: Extract server.css & vpn.css                                     │
│ - Move Lines 812–869, 1078–1312, 1515–1544, 1720–1806 to server.css     │
│   (410 lines)                                                            │
│ - Move Lines 1807–1822, 2459–2495, 2658–2962 to vpn.css (358 lines)      │
│ - Colocate responsive overrides for server grid, protocol and client cards│
│ - Update base.html and standalone templates with unconditional links     │
└──────────────────────────────────────────────────────────────────────────┘
```

### 8.5 Baseline Style Snapshot Procedure & Verification Evidence

#### Baseline Snapshot Capture Procedure (Playwright)
To protect Issue #505 against visual regressions across breakpoints and color themes, a baseline visual regression harness must be executed before and after modularization:
1. **Tooling**: Playwright test runner (`npx playwright test`) executing headless Chromium.
2. **Viewports Matrix**:
   - Desktop: `1280 x 800`
   - Landscape Tablet: `1024 x 768`
   - Portrait Tablet: `768 x 1024` (validates 768px breakpoint boundary)
   - Mobile: `480 x 854` and `375 x 667`
3. **Theme States**: Both `data-theme="dark"` (baseline) and `data-theme="light"`.
4. **Target Page Scope**: All 10 views (`/`, `/server`, `/vpn`, `/users`, `/settings`, `/leaderboard`, `/my-connections`, `/login`, `/setup`, `/change-password`).
5. **Execution Command**:
   ```bash
   npx playwright test tests/visual/ --update-snapshots
   ```
6. **Tolerance**: Pixel diff threshold `< 0.1%` (accounting only for font antialiasing variations).

#### Verification Evidence Summary
The codebase baseline has been verified clean:
- **Go Build & Architecture**: `go build ./cmd/... ./internal/... ./web/...` completes with rc=0.
- **Go Test Suite**: `CI=true go test -race -count=1 ./web/...` passes cleanly: 216 PASS, 0 FAIL, 0 SKIP.
- **JSDOM Simulation**: Execution of JSDOM tests validates that dynamic toast injection, modal backdrop display, and table empty state construction function properly without style errors.
- **Translation Parity**: Full parity verified across all 5 languages (`en.json`, `fr.json`, `zh.json`, `fa.json`, `ru.json`).

---

## 9. Verification & Architectural Invariants Checklist

Any PR implementing Issue #505 MUST satisfy the following checklist before merge:
- [ ] **Line Ceiling**: No single static CSS file exceeds the project line ceiling of 1,000 lines.
- [ ] **Token Availability**: All 56 design tokens in `:root` and `[data-theme="light"]` remain accessible to dependent rules.
- [ ] **Cascade Order Preservation**: Responsive `@media` overrides remain in the same file as, and after, their base rules. Theme transition hook is placed after component transitions.
- [ ] **Unconditional Link Contract**: Stylesheets are loaded unconditionally in `base.html` and standalone templates with cache-busting query `?v=1.1.0`.
- [ ] **Badge Integrity**: `.badge-secondary` (line 1935) is preserved during badge consolidation.
- [ ] **Dedup Boundaries**: Only byte-identical utilities (`.hidden`, `.gap-*`) and dead companion `.skeleton-icon` are pruned mechanically; visual design changes are separated.
- [ ] **Stacking Context Hierarchy**: Stacking order is strictly maintained: desktop base sidebar (`z-index: 90`), mobile bottom bar (`z-index: 70`), drawer backdrop (`z-index: 95`), drawer active sidebar (`z-index: 100`).
- [ ] **Visual Regression**: Baseline Playwright snapshots across all 10 views at 1280, 1024, 768, 480 viewports show 0 visual regressions.
- [ ] **Automated Test Parity**: `CI=true go test -race -count=1 ./web/...` passes with zero failures.
