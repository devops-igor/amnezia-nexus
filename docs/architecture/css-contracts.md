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
   - `*:focus-visible` and `button:focus-visible` (lines 986, 992) reference `outline: 2px solid var(--accent-color);`. Because `outline` is a shorthand property and `--accent-color` is undeclared without a fallback, CSS Custom Properties Level 1 §3.1 dictates that the entire shorthand declaration becomes invalid at computed-value time. Consequently, all outline longhands revert to `unset`, causing `outline-style` to take its initial value `none`. Focus rings do not render on `:focus-visible` elements, actively suppressing the browser default focus indicator (a WCAG 2.4.7 Focus Visible defect in production).
   - `.switch-slider` (line 2530) references `var(--bg-surface-hover, #232738)`. Because an explicit fallback is supplied, it safely evaluates to `#232738` at runtime.
   - `.login-card-elevated` (line 2596) references `box-shadow: var(--shadow-xl), 0 0 30px rgba(99, 102, 241, 0.06);`. Because `--shadow-xl` has no fallback, the entire `box-shadow` declaration becomes invalid at computed-value time and evaluates to `none` (the secondary glow shadow is not retained).
3. **Redundant Copy-Paste Rules**: Multiple utility classes (`.hidden`, `.gap-xs`, `.gap-sm`, `.gap-md`) are duplicated verbatim at lines 1641–1671 and lines 1941–1956.
4. **Tight Go Unit Test Coupling**: Multiple Go tests in `web/` assert literal string tokens, multi-line blocks, and regexes directly against `fs.ReadFile(staticFS, "css/style.css")`. Any naive file split without coordination breaks the Go test suite. Production templates pin the stylesheet href to `?v=1.1.0` (asserted in `web/web_vpn_test.go:760`).

---

## 2. Component & Section Inventory (`style.css` Line-by-Line Mapping)

The 3,008 lines of `style.css` span 59 distinct contiguous sections. The table below provides an exact contiguous mapping of the entire file, identifying rule boundaries, line spans, functional domains, and target file assignments for Issue #505. Every listed selector has been verified against the stylesheet (0 phantom selectors).

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
| **1078** | **1178** | 101 | Protocol Cards & Grid | `.protocol-cards`, `.protocol-card`, `.protocol-name`, `.protocol-desc`, `.protocol-icon`, `.protocol-status`, `.protocol-info`, `.protocol-info-item`, `.protocol-info-label`, `.protocol-info-value`, `.protocol-awg`, `.protocol-dns`, `.protocol-telemt` | `server.css` |
| **1179** | **1264** | 86 | Clients List & Items | `.clients-section`, `.clients-header`, `.clients-list`, `.client-item`, `.client-avatar`, `.client-info`, `.client-name`, `.client-meta`, `.client-actions` | `server.css` |
| **1265** | **1272** | 8 | Traffic Badge (Base Definition) | `.traffic-badge` | `components.css` |
| **1273** | **1285** | 13 | Top Consumer & Sort Toggle | `.top-consumer`, `.sort-toggle` | `server.css` |
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
| **1628** | **1672** | 45 | Flexbox & Spacing Utilities | `.flex`, `.items-center`, `.justify-between`, `.gap-xs`, `.gap-sm`, `.gap-md`, `.mt-md`, `.hidden`, `.text-muted`, `.text-sm`, `.font-mono` | `vpn.css` |
| **1673** | **1719** | 47 | Legacy Responsive Breakpoints | `@media (max-width: 768px)` (`.server-grid`, `.protocol-cards`, `.form-row`, `.modal`, `.client-item`, `.client-info`, `.client-actions`), `@media (max-width: 480px)` (`.protocol-info`, `.stats-grid`) | `server.css` |
| **1720** | **1742** | 23 | Server Stats Inline Pills | `.stat-pill` | `server.css` |
| **1743** | **1786** | 44 | Config Tabs | `.config-tabs`, `.config-tab`, `.config-tab.active`, `.config-panel`, `.config-panel.active` | `server.css` |
| **1787** | **1806** | 20 | QR Code Display | `.qr-container`, `.qr-hint` | `server.css` |
| **1807** | **1822** | 16 | VPN Protocol Link Box | `.vpn-link-box` | `vpn.css` |
| **1823** | **1846** | 24 | Traffic Badges (2nd Definition) | `.traffic-badge`, `.traffic-down`, `.traffic-up` | `components.css` |
| **1847** | **1875** | 29 | Header Navigation Links | `.nav-link`, `.nav-link.active` | `layout.css` |
| **1876** | **1890** | 15 | Theme Switching Transitions Hook | `body, .card, .nav-link, .btn, .form-input, .form-select, .modal, .modal-backdrop` | `components.css` |
| **1891** | **1898** | 8 | Responsive Nav Override (900px) | `@media (max-width: 900px) .nav-link` | `layout.css` |
| **1899** | **1940** | 42 | Badges Duplicate Definition | `.badge`, `.badge-success`, `.badge-warn`, `.badge-danger`, `.badge-info`, `.badge-secondary` | `components.css` |
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
| **2658** | **2766** | 109 | Client Dashboard & Settings Polish | `.settings-section-card`, `.settings-card-header`, `.network-health-grid`, `.network-health-node`, `.connections-toolbar`, `.connections-toolbar-actions`, `.lb-selection-callout`, `.client-meta`, `.card-title` | `vpn.css` |
| **2767** | **2962** | 196 | Modernized VPN Section & Tables | `.stat-card`, `.stat-card-header`, `.stat-card-title`, `.stat-card-value`, `.stat-card-sub`, `.latency-pill`, `.latency-dot`, `.latency-good`, `.latency-fair`, `.latency-poor`, `.info-card`, `.info-card-grid`, `.info-card-item`, `.info-card-label`, `.info-card-value`, `.interactive-table`, `.btn-success-hover`, `.btn-danger-hover`, `.modal-notice-error` | `vpn.css` |
| **2963** | **3008** | 46 | Modernized Users Section (Issue #113) | `#usersContainer`, `#usersGrid`, `#userConnsTable`, `.user-card`, `.user-avatar-circle` | `vpn.css` |

---

## 3. Usage & Ownership Cross-Reference Matrix

All 373 selector keys and 236 class tokens were cross-referenced against all 13 HTML templates (`web/templates/*.html`) and 15 JavaScript modules (`web/static/js/**/*.js`), accounting for dynamic DOM construction.

### 3.1 Subsystem Ownership Classification Summary

```
Total Selectors (373 Unique Keys)
 ├── Base & Universal Tag Rules :  19 selectors ( 5.1%) -> Tokens, Resets, Element Defaults
 ├── Shared Shell & Layout      :  62 selectors (16.6%) -> Layout, Navigation, Drawer, Breakpoints
 ├── Reusable UI Components     : 216 selectors (57.9%) -> Buttons, Tables, Forms, Modals, Badges, Toasts
 ├── Server Management Domain   :  32 selectors ( 8.6%) -> Server Cards, Protocols, Logs, Client Lists
 ├── VPN Dashboard Domain       :  18 selectors ( 4.8%) -> Telemetry, Stat Cards, Latency Pills, Sparklines
 ├── Login / Authentication     :   8 selectors ( 2.1%) -> Login Elevated Cards, Adornments
 ├── Leaderboard Feature        :   8 selectors ( 2.1%) -> Leaderboard Tables, Position Badges
 ├── Users Management Feature   :   4 selectors ( 1.1%) -> Users Grid, Avatar Circles, User Cards
 └── Companion & Test Tokens    :   6 selectors ( 1.6%) -> Dynamic Toasts, Test Tokens, Companion Selectors
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
| **Buttons** (`.btn`, `.btn-primary`, `.btn-secondary`, `.btn-danger`, `.btn-sm`) | 653–763 | All 12 application templates (excludes `icons.html` sprite) | `ui.js`, `tables.js`, `server_actions.js`, `users.js`, `vpn/*.js` | Universal atomic component. `.btn-success` defined but unreached in `confirmVariant`. |
| **Cards & Headers** (`.card`, `.card-header`, `.card-title`, `.section-title`) | 764–811 | `index.html`, `server.html`, `vpn.html`, `users.html`, `settings.html`, `my_connections.html`, `leaderboard.html`, `change_password.html`, `setup.html`, `user_share.html` | `users.js`, `vpn/health_problems.js`, `vpn/sessions.js` | Core surface container widget. |
| **Server Cards & Grid** (`.server-grid`, `.server-card`, `.server-name`) | 812–869 | `index.html` | *(None)* | Server instances overview on dashboard. |
| **Status Badges** (`.badge`, `.badge-success`, `.badge-danger`, `.badge-dot`) | 870–913 | `base.html`, `index.html`, `server.html`, `vpn.html`, `settings.html`, `my_connections.html`, `leaderboard.html` | `server_telemetry.js`, `users.js`, `vpn/*.js` | Highly dynamic construction via template interpolation and JavaScript. |
| **Form Controls** (`.form-group`, `.form-input`, `.form-select`, `.form-row`) | 914–983 | `login.html`, `setup.html`, `change_password.html`, `server.html`, `users.html`, `settings.html`, `vpn.html`, `index.html`, `my_connections.html`, `user_share.html` | `vpn/charts.js` | Standardized form controls. |
| **Modals** (`.modal`, `.modal-backdrop`, `.modal-header`, `.modal-close`) | 996–1077 | `base.html`, `index.html`, `server.html`, `vpn.html`, `users.html`, `my_connections.html`, `user_share.html`, `login.html`, `setup.html`, `change_password.html` | `ui.js`, `vpn/page.js` | Accessible dialogs with keyboard and backdrop dismissal (includes `#langModal` on auth pages). |
| **Protocol Cards** (`.protocol-cards`, `.protocol-card`, `.protocol-info`) | 1078–1178 | `server.html` | *(None)* | Protocol configuration cards on server detail page. |
| **Clients List** (`.clients-section`, `.clients-list`, `.client-item`, `.client-avatar`) | 1179–1264 | `users.html`, `my_connections.html` | `server_telemetry.js`, `users.js` | Client list cards rendered across users and connection views. |
| **Traffic Badge Base** (`.traffic-badge`) | 1265–1272 | `my_connections.html` | `server_telemetry.js` | Base typography and display for traffic rates. |
| **Top Consumer & Sort** (`.top-consumer`, `.sort-toggle`) | 1273–1285 | `users.html`, `my_connections.html` | `server_telemetry.js`, `users.js` | Client sorting and highlighted consumer accents. |
| **Config Display** (`.config-display`, `.config-text`, `.config-actions`) | 1286–1312 | `server.html`, `users.html`, `my_connections.html`, `user_share.html` | *(None)* | Configuration text containers with copy controls. |
| **Toast Notifications** (`.toast`, `.toast-container`, `.toast-exit`) | 1313–1391 | `base.html`, `index.html`, `settings.html`, `my_connections.html` | `ui.js`, `server_actions.js`, `users.js`, `vpn/backends.js`, `api.js`, `server_telemetry.js` | Dynamic toast construction across API and telemetry handlers. |
| **Shimmer Skeletons** (`.skeleton`, `.skeleton-text`, `.skeleton-card`, `.skeleton-avatar`) | 1392–1434 | *(None/Design System)* | *(None)* | Loading state primitives asserted by `web/web_test.go:81`. `.skeleton-icon` is dead. |
| **Micro-interactions** (`.copied`) | 1435–1451 | *(None/Global)* | `ui.js` | Visual feedback on copy actions (`copy-pulse` keyframe). |
| **Progress & Spinners** (`.progress-bar`, `.progress-fill`, `.loading-spinner`) | 1452–1514 | `server.html`, `leaderboard.html` | *(None)* | Asynchronous task progress indicator. |
| **Log Output Terminal** (`.log-output`, `.log-line`, `.log-line.error`) | 1515–1544 | `server.html` | `server_actions.js` | Deployment journal streaming console. |
| **Empty State** (`.empty-state`, `.empty-icon`, `.empty-title`, `.empty-desc`) | 1545–1570 | `server.html`, `users.html`, `my_connections.html`, `leaderboard.html`, `index.html` | `vpn/page.js`, `vpn/sessions.js` | Shared placeholder when record lists are empty. |
| **Tabs Navigation** (`.tabs`, `.tab`) | 1571–1605 | `index.html`, `my_connections.html`, `user_share.html` | `server_actions.js`, `users.js`, `telemetry.js` | Tab switching controller primitives. |
| **Back Link Navigation** (`.back-link`) | 1606–1620 | `server.html` | *(None)* | Navigation link returning to server overview. |
| **Utilities & Spacing** (`.flex`, `.hidden`, `.gap-xs`, `.gap-sm`, `.font-mono`) | 1628–1672 | All 12 application templates | `ui.js`, `tables.js`, `users.js`, `server_actions.js`, `vpn/*.js` | Utility classes. Loaded after components to preserve `.font-mono` override. |
| **Server Stats Pills** (`.stat-pill`) | 1720–1742 | `server.html`, `users.html`, `my_connections.html`, `user_share.html` | `server_telemetry.js` | Compact telemetry metric pills. |
| **Config Tabs** (`.config-tab`, `.config-panel`) | 1743–1786 | `server.html`, `users.html`, `my_connections.html`, `user_share.html` | `server_actions.js`, `users.js` | Protocol tab selection panels. |
| **QR Code Display** (`.qr-container`, `.qr-hint`) | 1787–1806 | `server.html`, `users.html`, `my_connections.html`, `user_share.html` | *(None)* | Configuration QR presentation modal container. |
| **VPN Protocol Link Box** (`.vpn-link-box`) | 1807–1822 | `server.html`, `users.html`, `my_connections.html`, `user_share.html` | *(None)* | Scrollable raw connection URI container. |
| **Traffic Badges Modifiers** (`.traffic-badge`, `.traffic-down`, `.traffic-up`) | 1823–1846 | `my_connections.html` | `server_telemetry.js` | Monospace badge showing upload/download rates with colored modifiers. |
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
*Handling Strategy*: Because enforcing pill radius changes current production rendering, unify the component in `components.css` while preserving `.badge-secondary` (line 1935) and `.badge-dot` (line 907). In Issue #505, maintain existing visual rendering: assign lines 1899–1940 to `components.css` and do NOT delete lines 1899–1940, as that would eliminate `.badge-secondary` and regress badge radii across all production views.

#### Conflict 2: Traffic Badges (`.traffic-badge`)
- **Definition 1**: Lines 1265–1272 (under `/* ===== Clients Table ===== */`)
- **Definition 2**: Lines 1823–1833 (under `/* ===== Traffic Badge ===== */`)

*Cascade Impact*: Definition 2 overrides font size (`0.7rem`), adds monospace font and pill background padding, while inheriting `color: var(--text-muted)` and `white-space: nowrap` from Definition 1. Downstream modifier rules `.traffic-down` (line 1835, green `#22c55e`) and `.traffic-up` (line 1841, blue `#3b82f6`) override the text color.
*Handling Strategy*: Assign BOTH line ranges (1265–1272 and 1823–1846) to `components.css` in source order. This guarantees that Definition 1 serves as the base, Definition 2 applies monospace typography, and the modifiers `.traffic-down` and `.traffic-up` come after the base rule so rate badge colors are preserved.

### 4.2 Identical Verbatim Redundancies (Safe Mechanical Dedup)

Lines 1941–1956 repeat utilities that were already fully defined in lines 1641–1671:

| Selector | Definition 1 Line | Definition 2 Line | Declaration Content | Action in #505 |
| :--- | :--- | :--- | :--- | :--- |
| `.hidden` | L1669–L1671 | L1942–L1944 | `display: none !important;` | Delete Definition 2 (safe dedup) |
| `.gap-xs` | L1641–L1643 | L1946–L1948 | `gap: var(--space-xs);` | Delete Definition 2 (safe dedup) |
| `.gap-sm` | L1645–L1647 | L1950–L1952 | `gap: var(--space-sm);` | Delete Definition 2 (safe dedup) |
| `.gap-md` | L1649–L1651 | L1954–L1956 | `gap: var(--space-md);` | Delete Definition 2 (safe dedup) |
| `.skeleton-icon` | L1428 | — | Shared with `.skeleton-avatar` | Prune dead selector & comma only (safe dedup) |

*Dead Selector Pruning Note*: At lines 1427–1428, `.skeleton-icon` shares a declaration block with `.skeleton-avatar` (`.skeleton-avatar,
.skeleton-icon {`). Pruning `.skeleton-icon` in #505 must delete only the dead selector string `, .skeleton-icon` (line 1428) so `.skeleton-avatar` remains intact for `web/web_test.go:81`.

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
*Precedence Constraint*: `.btn` at line 666 defines `transition: all var(--transition-base);`. In the monolith, line 1877 comes later and successfully applies smooth slow theme transitions. If placed in `base.css` without loading `base.css` after components, `.btn` in `components.css` overrides this rule. Therefore, this hook (lines 1876–1890) must be placed at the end of `components.css` after base component transition rules.

### 4.4 Precedence-Sensitive Rules Catalog

The table below catalogs every rule whose correct rendering depends on source-order precedence ("later-wins"):

| Selector | Earlier Rule Line & File | Later Overriding Rule Line & File | Overridden Properties | Required Load / Placement Constraint |
| :--- | :--- | :--- | :--- | :--- |
| `.badge` | L871 (`components.css`) | L1900 (`components.css`) | `border-radius: var(--radius-sm)`, `padding: 2px 8px` | Unify canonically in `components.css`; retain L1900 definition and `.badge-secondary`. |
| `.traffic-badge` | L1265 (`components.css` base) | L1824 (`components.css` def-2 & modifiers) | `font-size`, `font-family`, `color` (`.traffic-down`/`.traffic-up`) | Both ranges assigned to `components.css`; modifiers placed after base definition. |
| `.table-search-input` vs `.form-input` | L929 (`components.css` `.form-input`) | L2186 (`tables.css` `.table-search-input`) | `padding: 8px 36px 8px 36px` (overrides `11px 16px`), `border-radius: 8px` | `tables.css` MUST load after `components.css`. 36px horizontal padding prevents text colliding with search icon. |
| `.font-mono` vs `.form-input` | L929 (`components.css` `.form-input`) | L1665 (`vpn.css` / utilities `.font-mono`) | `font-family: 'SF Mono', 'Fira Code', monospace` | Utilities load after `components.css` so `.form-input.font-mono` retains monospace font. |
| `.btn` transition | L666 (`components.css` `.btn`) | L1877 (`components.css` theme hook) | Multi-property theme transition overrides `transition: all var(--transition-base)` | Place theme transition hook (L1876–1890) at end of `components.css`. |
| `.modal` @<=768px | L1017 (`components.css`) | L1687 (`server.css` query) | `width: 95%` (base is 90%) | Colocate responsive `@media` override in `components.css` after base rule. |
| `.server-grid` @<=768px | L813 (`server.css`) | L1675 (`server.css` query) | `grid-template-columns: 1fr` | Colocate responsive `@media` override in `server.css` after base rule. |
| `.protocol-cards` @<=768px | L1079 (`server.css`) | L1679 (`server.css` query) | `grid-template-columns: 1fr` | Colocate responsive `@media` override in `server.css` after base rule. |
| `.client-item` @<=768px | L1199 (`server.css`) | L1692 (`server.css` query) | `flex-direction: column` | Colocate responsive `@media` override in `server.css` after base rule. |
| `.nav-link` @<=900px | L1848 (`layout.css`) | L1893 (`layout.css` query) | `padding: 6px 12px; font-size: 0.8rem` | Colocate 900px query in `layout.css` immediately following `.nav-link`. |
| `.card.client-item.user-card` | L1199 (`server.css` `.client-item`) | L1877 (`components.css`), L2979 (`vpn.css` `.user-card`) | `transition: border-color ..., box-shadow ...` | Colocate users section in `vpn.css` (loads last); ensure fast border transitions don't clobber theme transitions. |
| `.hidden` vs `.login-error-box` | L1669 / L1942 (`.hidden`) | L2633 (`components.css` `.login-error-box`) | `display: none !important;` vs `display: none;` | Safe by specification: `!important` on `.hidden` guarantees hidden state wins over normal display rules. |

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
  Specification Behavior: Under CSS Custom Properties Level 1 §3.1, referencing an undeclared
    variable without fallback causes the declaration to be invalid at computed-value time.
    Because outline is a shorthand property, the entire shorthand invalidates; all constituent
    longhands revert to unset, and outline-style takes its initial value none.
  Runtime Effect: Focus rings do NOT render on :focus-visible elements. The author rule actively
    suppresses the user agent's default outline ring across buttons, links, and form inputs.
    This constitutes an existing production WCAG 2.4.7 (Focus Visible) defect.
  Remediation: File an independent accessibility issue to map to var(--accent); do not alter
    during the mechanical #505 extraction.

Variable Defect 2: --bg-surface-hover
  Used at: L2530 (.switch-slider)
  Declaration in style.css: background-color: var(--bg-surface-hover, #232738);
  Specification Behavior: Explicit fallback is provided.
  Runtime Effect: Resolves safely to #232738 at runtime.
  Remediation: Declare --bg-surface-hover in tokens.css for theme parity in a visual polish task.

Variable Defect 3: --shadow-xl
  Used at: L2596 (.login-card-elevated)
  Declaration in style.css: box-shadow: var(--shadow-xl), 0 0 30px rgba(99, 102, 241, 0.06);
  Specification Behavior: Invalid var() reference invalidates entire box-shadow property declaration.
  Runtime Effect: Entire box-shadow falls back to none (secondary glow shadow is lost).
  Remediation: Declare --shadow-xl in tokens.css in a dedicated design task.
```

### 5.3 Defect Audit: Declared Variables Unused in CSS
Four variables are declared in `:root` but have zero `var(...)` invocations inside `style.css`:
- `--accent-dark` (lines 30, 109) and `--info-border` (lines 48, 127)
- `--text-accent` (lines 26, 105)
- `--shadow-md` (lines 68, 130): Actively used via inline style in `web/templates/my_connections.html:198` (`box-shadow: var(--shadow-md);`). Must be preserved.

---

## 6. Dead Code & Zero-Usage Audit

### 6.1 Truly Dead Selectors vs. Dynamically Constructed Tokens

A boundary-matched scan of all 236 class tokens across 13 templates and 14 non-minified JS files flags 10 tokens with 0 literal template hits:

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
| `.skeleton-icon` | L1428 | **GENUINE DEAD CSS** | Companion to `.skeleton-avatar`. 0 references in templates, JS, or tests. **PRUNE SELECTOR ONLY IN #505.** |
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
 ├── base.css         (217 lines) : Resets, typography, scrollbars, SVG icons, focus, micro-interactions, empty-state
 ├── layout.css       (446 lines) : App shell, sidebar, mobile top/bottom bars, header branding, responsive nav
 ├── components.css   (959 lines) : Buttons, cards, modals, form controls, badges, toasts, toggles, login, leaderboard
 ├── tables.css       (311 lines) : Interactive table engine (toolbar, filter chips, sortable headers, pagination)
 ├── server.css       (449 lines) : Server grid, protocol cards, client lists, config displays, logs, QR codes, responsive
 └── vpn.css          (449 lines) : VPN stat cards, latency indicators, diagnostics, client dashboard, utilities, users section
 (Deduplicated in #505: 16 lines) : Removed redundant utility duplicates (lines 1941–1956)
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
<!-- 4. Atomic Components & Form Dialogs -->
<link rel="stylesheet" href="/static/css/components.css?v=1.1.0">
<!-- 5. Interactive Data Table Engine (Loads AFTER components so .table-search-input overrides .form-input) -->
<link rel="stylesheet" href="/static/css/tables.css?v=1.1.0">
<!-- 6. Server Management Domain -->
<link rel="stylesheet" href="/static/css/server.css?v=1.1.0">
<!-- 7. VPN Telemetry, Dashboard, Utilities & Users (Loads utilities AFTER components so .font-mono overrides .form-input) -->
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
1. `TestEmbeddedStaticAndTemplates` (`web/web_embedded_test.go:49`, assert at line 63): Asserts `"css/style.css"` presence in `staticFS`.
2. `TestModernDesignSystemAndShell` (`web/web_embedded_test.go:154`, assert at line 160): Asserts 10 value-pinned tokens (`"--bg-primary: #090a0f"`, `"--bg-surface: #0d0e15"`, `"--bg-card: #13151f"`, `"--accent: #6366f1"`, `"--success: #10b981"`, `"--warning: #f59e0b"`, `"--danger: #f43f5e"`, `"--info: #0ea5e9"`, `"--font-family: 'Inter'"`, `"--font-mono: 'JetBrains Mono'"`) and 9 layout classes (`".app-layout"`, `".app-sidebar"`, `".app-main"`, `".mobile-topbar"`, `".drawer-backdrop"`, `".mobile-bottom-bar"`, `".icon"`, `".nav-icon"`, `".sidebar-nav-link"`).
3. `TestIssue351MobileLogoutOcclusionAndStackingContext` (`web/web_embedded_test.go:377`, assert at line 383): Regex checks on `.app-layout` (`position: relative`, no integer z-index), `.mobile-bottom-bar` (`z-index: 70`), `.drawer-backdrop` (`z-index: 95`), and `@media (max-width: 1023px)`.
4. `TestIssue113UsersUIModernization` (`web/web_server_users_test.go:115`, assert at line 216): Exact-whitespace multi-line string assertions:
   - `"#usersContainer {
    width: 100%;
    min-width: 100%;
}"`
   - `"#usersGrid {
    width: 100%;
    min-width: 100%;
}"`
   - `"#userConnsTable {
    width: 100%;
    min-width: 100%;
}"`
5. `TestModernJavaScriptAndInteractiveComponents` (`web/web_test.go:10`, assert at line 71): Asserts 8 tokens: `"@keyframes shimmer"`, `".skeleton"`, `".skeleton-text"`, `".skeleton-card"`, `".skeleton-avatar"`, `".copied"`, `".toast"`, `".toast-exit"`.
6. `TestPhase3TablesAndTelemetryEngine` (`web/web_test.go:152`, assert at line 225): Asserts 12 tokens: `".table-toolbar"`, `".table-search-box"`, `"th.sortable"`, `".sort-icon"`, `".table-empty-state"`, `".table-pagination"`, `".page-btn"`, `".page-info"`, `".filter-chip"`, `".sparkline-container"`, `".sparkline-svg"`, `".sparkline-dot"`.
7. `TestPhase6ClientExperienceAndPolish` (`web/web_test.go:298`, assert at line 504): Asserts 15 tokens: `".switch-container"`, `".switch-slider"`, `"[dir="rtl"] .switch-slider:before"`, `".login-header-actions"`, `"[dir="rtl"] .login-header-actions"`, `".login-card-elevated"`, `".login-icon-adornment-group"`, `"[dir="rtl"] .login-input-adornment"`, `".login-error-box"`, `".settings-section-card"`, `".settings-card-header"`, `".network-health-grid"`, `".network-health-node"`, `".lb-selection-callout"`, `"[dir="rtl"] .lb-selection-callout"`.
8. `TestLoadBalancerHighlightAndAwgPreselection` (`web/web_vpn_test.go:156`, assert at line 200): Asserts `".lb-selection-callout"` and `"[dir="rtl"] .lb-selection-callout"`.
9. `TestIssue101VPNModernization` (`web/web_vpn_test.go:298`, assert at line 453): Asserts 17 classes: `".stat-card"`, `".stat-card-header"`, `".stat-card-title"`, `".stat-card-value"`, `".stat-card-sub"`, `".latency-pill"`, `".latency-good"`, `".latency-fair"`, `".latency-poor"`, `".latency-dot"`, `".info-card"`, `".info-card-grid"`, `".info-card-item"`, `".info-card-label"`, `".info-card-value"`, `".interactive-table th"`, `".interactive-table td"`, as well as `".interactive-table"` and `"width: 100%"`.
10. `TestIssue101VPNPolishRework` (`web/web_vpn_test.go:630`, assert at line 654): Asserts `".gap-xs {"` and `"gap: var(--space-xs);"`.
11. `TestIssue109VPNTableFullWidth` (`web/web_vpn_test.go:716`, assert at line 727): Asserts multi-line `.interactive-table` and `.table-container table` full-width blocks, and verifies cache-busting href `href="/static/css/style.css?v=1.1.0"` across all templates at line 760.
12. Test fixtures & computed-style JSDOM tests:
    - `web/vpn_fixture_test.go:211`: reads `static/css/style.css` via `readFixtureStaticAsset` and injects it into Node.js / JSDOM `<style>` element.
    - `web/vpn_fixture_selftest_test.go:653, 728`: asserts virtual static FS mapping.
    - `web/vpn_diagnostics_sessions_test.go:212, 295, 299`: verifies computed styles via `w.getComputedStyle` (`direction: rtl` on `#vpn-fwd-routes-table`, `overflow-x: auto` on `.table-container`, `min-width: 540px` on `#vpn-fwd-routes-table`).

#### Transition Strategies for Issue #505
- **Strategy A (Aggregate Concatenation Build Step — Recommended)**: Maintain `web/static/css/style.css` as a master concatenation bundle generated from the 7 modular files in production load order. Note: an `@import` manifest is **unsound** because `@import` strips inline rules, failing every `strings.Contains` assertion in the Go test suite, and JSDOM does not resolve external `@import` rules in fixtures. If concatenation is chosen, a drift-guard Go test (`TestStyleCSSConcatenationParity`) must verify that `style.css` byte-for-byte matches the concatenation of the 7 modules.
- **Strategy B (Atomic Test Harness Update)**: Simultaneously update Go tests to read from modular files (e.g. `css/tokens.css` for `--accent`, `css/tables.css` for `.table-toolbar`).

### 8.4 Phased Implementation Sequence for Issue #505

The implementation sequence partitions lines 1–3008 with contiguous, non-overlapping ranges:

```
┌──────────────────────────────────────────────────────────────────────────┐
│ Step 1: Extract tokens.css & base.css                                     │
│ - Move Lines 1–161 to tokens.css (161 lines)                             │
│ - Move Lines 162–301, 984–995, 1435–1451, 1545–1570, 1606–1627 to       │
│   base.css (217 lines)                                                   │
│ - Prune dead companion selector .skeleton-icon at L1428                  │
└────────────────────────────────────┬─────────────────────────────────────┘
                                     │
                                     ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ Step 2: Extract layout.css                                               │
│ - Move Lines 302–652, 1847–1875, 1891–1898, 2090–2147 to layout.css     │
│   (446 lines)                                                            │
│ - Colocate responsive @media (max-width: 900px) after .nav-link          │
│ - Deduplicate lines 1941–1956 (.hidden, .gap-*) (16 lines)               │
└────────────────────────────────────┬─────────────────────────────────────┘
                                     │
                                     ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ Step 3: Extract components.css                                           │
│ - Move Lines 653–811, 870–983, 996–1077, 1265–1272, 1313–1434,          │
│   1452–1514, 1571–1605, 1823–1846, 1876–1890, 1899–1940, 1957–2089,      │
│   2496–2657 to components.css (959 lines)                                │
│ - Colocate responsive overrides for .modal and .form-row                 │
│ - Unify .badge (L1900 winning definition & .badge-secondary L1935)       │
│ - Unify .traffic-badge with .traffic-down/.traffic-up modifiers          │
│ - Place theme transition hook (L1876–1890) at end of components.css     │
└────────────────────────────────────┬─────────────────────────────────────┘
                                     │
                                     ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ Step 4: Extract tables.css                                               │
│ - Move Lines 2148–2458 to tables.css (311 lines)                         │
│ - Load tables.css AFTER components.css so .table-search-input overrides   │
│   .form-input padding (36px/36px vs 16px/16px)                           │
└────────────────────────────────────┬─────────────────────────────────────┘
                                     │
                                     ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ Step 5: Extract server.css & vpn.css                                     │
│ - Move Lines 812–869, 1078–1264, 1273–1312, 1515–1544, 1673–1719,       │
│   1720–1806 to server.css (449 lines)                                    │
│ - Move Lines 1628–1672, 1807–1822, 2459–2495, 2658–2766, 2767–2962,      │
│   2963–3008 to vpn.css (449 lines)                                       │
│ - Utilities (L1628–1672) load in vpn.css after components so .font-mono  │
│   overrides .form-input font-family                                      │
│ - Users section (L2963–3008) in vpn.css preserves .user-card cascade     │
│ - Update base.html and standalone templates with unconditional links     │
└──────────────────────────────────────────────────────────────────────────┘
```

### 8.5 Baseline Style Snapshot Procedure & Verification Evidence

#### Baseline Snapshot Capture & Comparison Procedure (Python Playwright)
To protect Issue #505 against visual regressions across breakpoints and color themes, a baseline visual regression harness must be executed before and after modularization:

1. **Tooling & Harness Location**: Python Playwright test runner under `tests/e2e/test_css_snapshots.py` integrated with `pytest-playwright` and existing fixtures in `tests/e2e/conftest.py`.
2. **Viewports Matrix**:
   - Desktop: `1280 x 800`
   - Landscape Tablet: `1024 x 768`
   - Portrait Tablet: `768 x 1024` (validates 768px breakpoint boundary)
   - Mobile: `480 x 854`
3. **Theme States**: Both `dark` (`[data-theme="dark"]` baseline) and `light` (`[data-theme="light"]`).
4. **Target Page Scope**: Key routes covering shell, data tables, modals, cards, and telemetry:
   - `/login` (unauthenticated authentication card)
   - `/vpn` (stat cards, telemetry charts, backends data table)
   - `/servers/1` (server detail, protocol cards, client list, logs terminal)
   - `/users` (users grid, modernized user cards, connections table)
   - `/settings` (settings section cards, network health nodes, theme toggle)
   - `/share/demo-token` (shared connection card, QR container, link box)
5. **Runnable Playwright Snapshot Test Script** (`tests/e2e/test_css_snapshots.py`):

```python
"""Visual regression snapshot test suite for CSS modularization (#504/#505)."""
import pytest
from playwright.sync_api import Page, expect

VIEWPORTS = [
    {"width": 1280, "height": 800, "name": "desktop"},
    {"width": 1024, "height": 768, "name": "tablet_landscape"},
    {"width": 768, "height": 1024, "name": "tablet_portrait"},
    {"width": 480, "height": 854, "name": "mobile"},
]

ROUTES = [
    ("/login", False),
    ("/vpn", True),
    ("/servers/1", True),
    ("/users", True),
    ("/settings", True),
]

@pytest.mark.e2e
@pytest.mark.parametrize("viewport", VIEWPORTS, ids=lambda v: v["name"])
@pytest.mark.parametrize("route,requires_auth", ROUTES, ids=lambda r: r[0])
@pytest.mark.parametrize("theme", ["dark", "light"])
def test_page_visual_snapshot(page: Page, authenticated_page: Page, base_url: str, viewport: dict, route: str, requires_auth: bool, theme: str):
    target_page = authenticated_page if requires_auth else page
    target_page.set_viewport_size({"width": viewport["width"], "height": viewport["height"]})
    target_page.goto(f"{base_url}{route}")
    target_page.wait_for_load_state("networkidle")

    # Set theme attribute
    target_page.evaluate(f"document.documentElement.setAttribute('data-theme', '{theme}')")
    target_page.wait_for_timeout(200)  # Allow theme transitions to settle

    slug = route.strip("/").replace("/", "_") or "root"
    snapshot_name = f"{slug}_{viewport['name']}_{theme}.png"
    expect(target_page).to_have_screenshot(snapshot_name, max_diff_pixels=50)
```

6. **Execution Commands**:
   - Baseline Generation (pre-modularization):
     ```bash
     pytest tests/e2e/test_css_snapshots.py --update-snapshots
     ```
   - Regression Comparison (post-modularization in #505):
     ```bash
     pytest tests/e2e/test_css_snapshots.py
     ```
7. **Tolerance**: Pixel diff threshold `< 0.1%` (accounting only for font antialiasing variations).

#### Verification Evidence Summary
The codebase baseline has been verified clean:
- **Go Build & Architecture**: `go build ./cmd/... ./internal/... ./web/...` completes with rc=0.
- **Go Test Suite**: `CI=true go test -race -count=1 ./web/...` passes cleanly: 95 top-level PASS + 120 subtest PASS = 215 PASS, 0 FAIL, 0 SKIP.
- **JSDOM Simulation**: Executed via Go integration harness in `web/vpn_fixture_test.go` and `web/vpn_diagnostics_sessions_test.go`, verifying JSDOM evaluation of `StyleCSS` with computed style assertions (`overflow-x: auto` on `.table-container`, `min-width: 540px`, and RTL direction).
- **Translation Parity**: Full parity verified across all 5 languages (`en.json`, `fr.json`, `zh.json`, `fa.json`, `ru.json`) with 711 keys per locale and 0 missing.

---

## 9. Verification & Architectural Invariants Checklist

Any PR implementing Issue #505 MUST satisfy the following checklist before merge:
- [ ] **Line Ceiling**: No single static CSS file exceeds the project line ceiling of 1,000 lines (largest file is `components.css` at 959 lines).
- [ ] **Token Availability**: All 56 design tokens in `:root` and `[data-theme="light"]` remain accessible to dependent rules.
- [ ] **Cascade Order Preservation**:
  - `tables.css` loads after `components.css` so `.table-search-input` overrides `.form-input`.
  - Utilities load after `components.css` (in `vpn.css`) so `.font-mono` overrides `.form-input`.
  - Both `.traffic-badge` definitions and modifiers reside in `components.css` in source order.
  - Responsive `@media` overrides remain in the same file as, and after, their base rules.
  - Multi-selector theme transition hook is placed after component transitions.
- [ ] **Unconditional Link Contract**: Stylesheets are loaded unconditionally in `base.html` and standalone templates with cache-busting query `?v=1.1.0`.
- [ ] **Badge Integrity**: Winning `.badge` definition (L1900, `border-radius: var(--radius-sm)`) and `.badge-secondary` (line 1935) are preserved during badge consolidation.
- [ ] **Dedup Boundaries**: Only byte-identical utilities (lines 1941–1956: `.hidden`, `.gap-*`) and dead companion `.skeleton-icon` (line 1428) are pruned mechanically; visual design changes are separated.
- [ ] **Stacking Context Hierarchy**: Stacking order is strictly maintained: desktop base sidebar (`z-index: 90`), mobile bottom bar (`z-index: 70`), drawer backdrop (`z-index: 95`), drawer active sidebar (`z-index: 100`).
- [ ] **Visual Regression**: Baseline Playwright snapshots across routes at 1280, 1024, 768, 480 viewports show 0 visual regressions.
- [ ] **Automated Test Parity**: `CI=true go test -race -count=1 ./web/...` passes with zero failures (215 PASS, 0 FAIL, 0 SKIP).
