# CSS Architecture Contracts and Stylesheet Modularization Roadmap

## 1. Executive Summary & Architectural Role

### 1.1 Context & Objectives
During Phase 3 Frontend Modularization (Epic #475), the Amnezia Nexus administrative web interface is undergoing systematic decoupling of its legacy monolithic assets. While Issues #495 through #500 focused on extracting 3,256 lines of inline JavaScript from `web/templates/vpn.html` into cohesive ES modules (`web/static/js/vpn/*.js`), **Issue #504** addresses the styling tier: auditing and establishing architectural boundaries for the monolithic stylesheet `web/static/css/style.css`.

This document establishes the authoritative contract, component boundaries, selector ownership matrix, conflict resolutions, and transition plan prerequisite for **Issue #505 (Physical Stylesheet Modularization)**.

### 1.2 Monolithic Baseline Metrics
A complete automated and manual inspection of `web/static/css/style.css` yields the following verified metrics:

| Metric | Value | Architectural Impact |
| :--- | :--- | :--- |
| **Total Lines** | 3,008 | Exceeds single-file maintainability thresholds; high cognitive load and merge conflict risk |
| **Total Rules Parsed** | 389 | Dense rule declarations mixing design tokens, layout shells, and page-specific widgets |
| **Unique Selectors** | 373 | 33 selectors defined multiple times across base rules, media queries, and utility overrides |
| **Class Tokens** | 236 | 231 actively referenced in templates/scripts; 5 dynamically constructed or companion tokens |
| **ID Tokens** | 3 | High-specificity selectors (`#usersContainer`, `#usersGrid`, `#userConnsTable`) bound to DOM elements |
| **CSS Custom Properties** | 56 | 56 variables defined; 3 undefined variables invoked with broken runtime fallbacks |
| **Media Queries** | 5 | Breakpoint fragmentation across 1023px, 900px, 768px, 767px, and 480px |

### 1.3 Core Architectural Vulnerabilities in Current Monolith
1. **Unintended Cascade Mutation**: Later sections silently overwrite earlier component definitions. Most notably, a secondary `.badge` rule at line 1900 overrides line 871, altering `border-radius` from `var(--radius-full)` (pill badge) to `var(--radius-sm)` (rounded rectangle), shrinking padding, and dropping `gap`.
2. **Broken CSS Variable References**: Three selectors reference custom properties that are never declared in `:root`:
   - `*:focus-visible` and `button:focus-visible` (lines 986, 992) reference `var(--accent-color)`. Because `:root` defines `--accent: #6366f1` (not `--accent-color`), keyboard focus outlines silently collapse to transparent/invalid.
   - `.toggle-switch-card:hover` (line 2530) references `--bg-surface-hover`.
   - `.login-card` (line 2596) references `--shadow-xl`.
3. **Redundant Copy-Paste Rules**: Multiple utility classes (`.hidden`, `.gap-xs`, `.gap-sm`, `.gap-md`) are duplicated verbatim at lines 1641–1671 and lines 1942–1956.
4. **Tight Go Unit Test Coupling**: Multiple unit tests in `web/` (`web_embedded_test.go`, `web_test.go`, `web_vpn_test.go`, `web_server_users_test.go`) assert specific string tokens directly against `fs.ReadFile(staticFS, "css/style.css")`. Any naive file split without coordination breaks the Go test suite.

---

## 2. Component & Section Inventory (`style.css` Line-by-Line Mapping)

The 3,008 lines of `style.css` span 56 distinct sections. The table below provides an exact contiguous mapping of the entire file, identifying rule boundaries, line spans, functional domains, and target file assignments for Issue #505.

| Start Line | End Line | Total Lines | Section Name / Component | Selectors | Target Modular File (#505) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1** | **87** | 87 | Design Tokens & Theme Variables (`:root`) | `:root` (56 variables) | `tokens.css` |
| **88** | **161** | 74 | Light Theme Variables (`[data-theme="light"]`) | `[data-theme="light"]`, scrollbars, body pseudo | `tokens.css` |
| **162** | **191** | 30 | Theme Toggle Switch Component | `.theme-toggle`, `.theme-toggle-slider`, etc. | `components.css` |
| **192** | **228** | 37 | SVG Vector Icons | `.icon`, `.icon-xs`, `.icon-sm`, `.icon-lg`, etc. | `base.css` |
| **229** | **283** | 55 | CSS Reset & Global Typography | `*`, `html`, `body`, `a`, `::selection` | `base.css` |
| **284** | **301** | 18 | Scrollbar Styling | `::-webkit-scrollbar*` | `base.css` |
| **302** | **343** | 42 | Modern Responsive App Shell Layout | `.app-layout`, `.app-sidebar`, `.app-main` | `layout.css` |
| **344** | **513** | 170 | Desktop Sidebar Navigation | `.sidebar-header`, `.sidebar-nav`, `.nav-item`, `.brand` | `layout.css` |
| **514** | **537** | 24 | Mobile Topbar | `.mobile-topbar`, `.hamburger-btn`, `.mobile-brand` | `layout.css` |
| **538** | **556** | 19 | Drawer Backdrop | `.drawer-backdrop` | `layout.css` |
| **557** | **615** | 59 | Mobile Bottom Navigation Bar | `.mobile-bottom-bar`, `.bottom-bar-link` | `layout.css` |
| **616** | **652** | 37 | Page Header & Controls | `.header`, `.page-header`, `.page-title`, `.user-pill` | `layout.css` |
| **653** | **763** | 111 | Buttons & Action Controls | `.btn`, `.btn-primary`, `.btn-secondary`, `.btn-danger` | `components.css` |
| **764** | **797** | 34 | Cards & Containers | `.card`, `.card-grid`, `.card-header`, `.card-body` | `components.css` |
| **798** | **811** | 14 | Section Wrappers | `.section`, `.section-header`, `.section-title` | `components.css` |
| **812** | **869** | 58 | Server Grid & Server Cards | `.server-grid`, `.server-card`, `.server-name` | `server.css` |
| **870** | **913** | 44 | Status Badges & Pills (Base Definition) | `.badge`, `.badge-success`, `.badge-danger`, `.badge-dot` | `components.css` |
| **914** | **983** | 70 | Form Controls & Inputs | `.form-group`, `.form-label`, `.form-input`, `.form-select` | `components.css` |
| **984** | **995** | 12 | Focus Visible (Accessibility) | `*:focus-visible`, `button:focus-visible` | `base.css` |
| **996** | **1077** | 82 | Modal Dialogs & Backdrops | `.modal-backdrop`, `.modal`, `.modal-header`, `.modal-footer`| `components.css` |
| **1078** | **1178** | 101 | Protocol Cards & Grid | `.protocol-cards`, `.protocol-card`, `.protocol-header` | `server.css` |
| **1179** | **1285** | 107 | Clients Table / List | `.clients-table`, `.client-item`, `.client-avatar` | `server.css` |
| **1286** | **1312** | 27 | Config Display & Code Blocks | `.config-box`, `.config-code`, `.copy-btn` | `server.css` |
| **1313** | **1391** | 79 | Toast Notifications | `.toast-container`, `.toast`, `.toast-icon`, `.toast-exit` | `components.css` |
| **1392** | **1434** | 43 | Shimmer Skeletons & Loading States | `.skeleton`, `.skeleton-text`, `.skeleton-card`, `.skeleton-avatar` | `components.css` |
| **1435** | **1451** | 17 | Micro-interactions & Animations | `.btn-press`, `.fade-in`, `@keyframes pulse` | `base.css` |
| **1452** | **1514** | 63 | Progress Bars & Spinners | `.progress-bar`, `.progress-fill`, `.spinner` | `components.css` |
| **1515** | **1544** | 30 | Log Output Terminal | `.log-terminal`, `.log-line`, `.log-line-error` | `server.css` |
| **1545** | **1570** | 26 | Empty State Component | `.empty-state`, `.empty-icon`, `.empty-title`, `.empty-text` | `components.css` |
| **1571** | **1605** | 35 | Tabs Navigation | `.tabs`, `.tab-btn`, `.tab-content` | `components.css` |
| **1606** | **1620** | 15 | Back Link Navigation | `.back-link` | `components.css` |
| **1621** | **1627** | 7 | Divider Utility | `.divider` | `layout.css` |
| **1628** | **1672** | 45 | Flexbox & Spacing Utilities | `.flex`, `.flex-col`, `.gap-xs`, `.gap-sm`, `.gap-md`, `.hidden` | `layout.css` |
| **1673** | **1719** | 47 | Legacy Responsive Breakpoints | `@media (max-width: 768px)` & `(max-width: 480px)` | `layout.css` |
| **1720** | **1742** | 23 | Server Stats Inline Pills | `.server-stat`, `.stat-value`, `.stat-label` | `server.css` |
| **1743** | **1786** | 44 | Config Tabs | `.config-tab`, `.config-tab-btn`, `.config-panel` | `server.css` |
| **1787** | **1806** | 20 | QR Code Display | `.qr-container`, `.qr-hint` | `components.css` (or `server.css`) |
| **1807** | **1822** | 16 | VPN Protocol Link Box | `.vpn-link-box` | `components.css` (shared modal) |
| **1823** | **1846** | 24 | Traffic Badges (2nd Definition) | `.traffic-badge`, `.traffic-down`, `.traffic-up` | `components.css` |
| **1847** | **1875** | 29 | Header Navigation Links | `.nav-links`, `.nav-link` | `layout.css` |
| **1876** | **1898** | 23 | Theme Switching Transitions | `body, .card, .btn, .form-input, .modal...` | `base.css` |
| **1899** | **1940** | 42 | Badges Duplicate Definition | `.badge`, `.badge-success`, `.badge-warn`, `.badge-secondary` | *Remove in #505 (Consolidate)* |
| **1941** | **1956** | 16 | Additional Layout Helpers Duplicate | `.hidden`, `.gap-xs`, `.gap-sm`, `.gap-md` | *Remove in #505 (Consolidate)* |
| **1957** | **2089** | 133 | Leaderboard Styles | `.leaderboard-section`, `.leaderboard-card`, `.leaderboard-table` | `components.css` |
| **2090** | **2147** | 58 | Responsive App Shell Media Queries | `@media (max-width: 1023px)` & `(max-width: 767px)` | `layout.css` |
| **2148** | **2233** | 86 | Interactive Table Toolbar | `.table-toolbar`, `.table-search-box`, `.table-filters` | `components.css` |
| **2234** | **2271** | 38 | Filter Chips | `.filter-chips`, `.filter-chip`, `.filter-chip.active` | `components.css` |
| **2272** | **2355** | 84 | Sortable Table Headers & Base Table | `.table`, `.table th`, `.sortable-header`, `.sort-indicator` | `components.css` |
| **2356** | **2386** | 31 | Table Empty State | `.table-empty-state`, `.table-empty-icon` | `components.css` |
| **2387** | **2458** | 72 | Table Pagination | `.table-pagination`, `.pagination-btn`, `.pagination-info` | `components.css` |
| **2459** | **2495** | 37 | Telemetry & Sparkline Widgets | `.sparkline-container`, `.sparkline-svg`, `.telemetry-card` | `vpn.css` |
| **2496** | **2572** | 77 | Modern Toggle Switch | `.toggle-switch`, `.toggle-switch-card`, `.toggle-slider` | `components.css` |
| **2573** | **2657** | 85 | Modern Login Page Styles | `.login-container`, `.login-card`, `.login-brand`, `.login-footer` | `components.css` (or `login.css`) |
| **2658** | **2766** | 109 | Client Dashboard & Settings Polish | `.client-card`, `.lb-selection-callout`, `.settings-grid` | `components.css` |
| **2767** | **2962** | 196 | Modernized VPN Section & Tables | `.stat-card`, `.kpi-card`, `.latency-indicator`, `.info-card` | `vpn.css` |
| **2963** | **3008** | 46 | Modernized Users Section (Issue #113) | `#usersContainer`, `#usersGrid`, `#userConnsTable`, `.user-card` | `components.css` (or `users.css`) |

---

## 3. Usage & Ownership Cross-Reference Matrix

All 373 individual selector keys and 236 class tokens were cross-referenced against all 13 HTML templates (`web/templates/*.html`) and 15 JavaScript modules (`web/static/js/**/*.js`), accounting for dynamic DOM construction.

### 3.1 Subsystem Ownership Classification Summary

```
Total Selectors (373 Unique Keys)
 ├── Base & Universal Tag Rules :  19 selectors ( 5.1%) -> Tokens, Resets, Element Defaults
 ├── Shared Shell & Layout      :  62 selectors (16.6%) -> Layout, Navigation, Grid, Breakpoints
 ├── Reusable UI Components     : 216 selectors (57.9%) -> Buttons, Tables, Forms, Modals, Badges, Toasts
 ├── Server Management Domain   :  32 selectors ( 8.6%) -> Server Cards, Protocols, Logs, Client Lists
 ├── VPN Dashboard Domain       :  18 selectors ( 4.8%) -> Telemetry, Stat Cards, Latency Pills, Sparklines
 ├── Login / Authentication     :   8 selectors ( 2.1%) -> Login Container, Cards, Split Panels
 ├── Leaderboard Feature        :   8 selectors ( 2.1%) -> Leaderboard Tables, Position Badges
 ├── Users Management Feature   :   4 selectors ( 1.1%) -> Users Grid, Avatar Circles, User Cards
 └── Zero Static Matches        :   6 selectors ( 1.6%) -> 4 Dynamic Toast Tokens, 1 Skeleton Companion, 1 Unused
```

### 3.2 Granular Cross-Reference Matrix

The table below catalogs primary selector groups, their source line spans in `style.css`, and the exact owning templates and JavaScript files:

| Selector Group | Line Range | Owning Templates (`web/templates/`) | Owning Scripts (`web/static/js/`) | Invariant / Dynamic Usage Notes |
| :--- | :--- | :--- | :--- | :--- |
| **Tokens & Theme** (`:root`, `[data-theme]`) | 1–161 | All templates via `base.html` | `ui.js` (theme toggle handler) | Defines 56 CSS variables. Evaluated globally. |
| **SVG Icons** (`.icon`, `.icon-sm`, etc.) | 192–228 | `base.html`, `icons.html`, `server.html`, `vpn.html`, `users.html` | `ui.js`, `vpn/backends.js`, `server_actions.js` | Embedded `<use href="#icon-*">` references. |
| **App Shell & Sidebar** (`.app-layout`, `.app-sidebar`, `.nav-item`) | 302–513 | `base.html` | `ui.js` (drawer toggling) | Rigid stacking context enforced by `web_embedded_test.go`. |
| **Mobile Navigation** (`.mobile-topbar`, `.mobile-bottom-bar`, `.drawer-backdrop`) | 514–615 | `base.html` | `ui.js` | `z-index` order: bottom bar (70) < backdrop (95) < drawer (100). |
| **Buttons** (`.btn`, `.btn-primary`, `.btn-icon`) | 653–763 | All templates | `ui.js`, `tables.js`, `server_actions.js`, `users.js`, `vpn/*.js` | Universal atomic component. |
| **Cards & Headers** (`.card`, `.card-grid`, `.card-title`) | 764–811 | `index.html`, `server.html`, `vpn.html`, `users.html`, `settings.html` | `users.js`, `vpn/page.js` | Core structural surface widget. |
| **Server Cards & Grid** (`.server-grid`, `.server-card`) | 812–869 | `index.html`, `server.html` | `server_actions.js`, `server_telemetry.js` | Exclusive to multi-server index and server page. |
| **Status Badges** (`.badge`, `.badge-success`, `.badge-dot`) | 870–913 | All templates | `users.js` (`badge ${roleClass}`), `vpn/health_problems.js`, `server_telemetry.js` | Heavily constructed dynamically via string interpolation. |
| **Form Controls** (`.form-group`, `.form-input`, `.form-select`) | 914–983 | `login.html`, `setup.html`, `server.html`, `users.html`, `settings.html` | `users.js`, `vpn/backends.js` | Standardized form layout. |
| **Modals** (`.modal`, `.modal-backdrop`, `.modal-header`) | 996–1077 | `server.html`, `vpn.html`, `users.html`, `my_connections.html` | `ui.js` (`UI.openModal`, `UI.closeModal`) | Accessible keyboard/backdrop dismissal in `ui.js`. |
| **Protocol Cards** (`.protocol-cards`, `.protocol-card`) | 1078–1178 | `server.html` | `server_actions.js` | Exclusive to protocol configuration view. |
| **Clients List** (`.clients-table`, `.client-item`) | 1179–1285 | `server.html`, `my_connections.html` | `server_telemetry.js`, `server_actions.js` | Precursor client list on server management view. |
| **Config Display** (`.config-box`, `.config-code`) | 1286–1312 | `server.html`, `user_share.html`, `my_connections.html` | `ui.js` (copy to clipboard) | Read-only configuration container. |
| **Toast Notifications** (`.toast`, `.toast-icon`, `.toast-exit`) | 1313–1391 | `base.html` (`#toastContainer`) | `ui.js` (`UI.toast`), `server_actions.js`, `users.js`, `vpn/backends.js` | Dynamic classes `.toast-success`, `.toast-error`, `.toast-warning`, `.toast-info`. |
| **Shimmer Skeletons** (`.skeleton`, `.skeleton-text`, `.skeleton-card`) | 1392–1434 | *(Design system token)* | Tested by `web/web_test.go:78–88` | Foundation tokens for asynchronous polling loading states. |
| **Progress & Spinners** (`.progress-bar`, `.spinner`) | 1452–1514 | `setup.html`, `server.html` | `ui.js`, `server_actions.js` | Asynchronous operations and installation feedback. |
| **Log Terminal** (`.log-terminal`, `.log-line`) | 1515–1544 | `server.html` | `server_actions.js` | Server deployment and runtime journal streaming. |
| **Empty State** (`.empty-state`, `.empty-icon`) | 1545–1570 | `server.html`, `users.html`, `vpn.html` | `tables.js` (`renderEmptyState`) | Displayed when table search/filter returns zero records. |
| **Tabs Navigation** (`.tabs`, `.tab-btn`, `.tab-content`) | 1571–1605 | `server.html`, `settings.html`, `my_connections.html` | `ui.js` | Tab switching controller in vanilla JS. |
| **Interactive Tables** (`.table-toolbar`, `.sortable-header`, `.table-pagination`) | 2148–2458 | `server.html`, `vpn.html`, `users.html` | `tables.js` (`NexusTable`) | Standalone reusable table engine (sort, search, pagination). |
| **Toggle Switches** (`.toggle-switch`, `.toggle-switch-card`) | 2496–2572 | `server.html`, `vpn.html`, `settings.html` | `server_actions.js`, `vpn/backends.js` | Accessible CSS toggle controls. |
| **Login Modern Polish** (`.login-container`, `.login-card`) | 2573–2657 | `login.html`, `setup.html`, `change_password.html` | `captcha.js` | Isolated auth shell; never loaded on authenticated dashboard. |
| **Client Dashboard** (`.client-card`, `.lb-selection-callout`) | 2658–2766 | `my_connections.html`, `user_share.html` | Inline scripts | User-facing self-service connection management. |
| **VPN Modern Cards** (`.stat-card`, `.latency-pill`, `.info-card`) | 2767–2962 | `vpn.html` | `vpn/backends.js`, `vpn/charts.js`, `vpn/health_summary.js` | Modernized KPI stat cards, sparklines, and latency badges. |
| **Users Modern Section** (`#usersContainer`, `#usersGrid`, `.user-card`) | 2963–3008 | `users.html` | `web/static/js/users.js` | Full-width container and grid rules for Issue #113. |

---

## 4. Duplicate, Overriding, and Conflicting Selectors Audit

An AST-equivalent scan of `style.css` identified **33 duplicate selector occurrences**. They fall into five concrete categories:

```
33 Duplicate Occurrences
 ├── 1. Harmful Semantic Conflicts (5 selectors: .badge, .badge-*, .traffic-badge)
 ├── 2. Identical Verbatim Redundancies (4 selectors: .hidden, .gap-xs, .gap-sm, .gap-md)
 ├── 3. Multi-Selector Theme Transition Hooks (8 selectors in 1 grouped rule)
 ├── 4. Progressive Enhancement Extensions (2 selectors: .form-select, .form-textarea)
 └── 5. Responsive Media Query Overrides (14 selectors across 5 breakpoints)
```

### 4.1 Harmful Semantic Conflicts (Requires Resolution in #505)

#### Conflict 1: Status Badges (`.badge`, `.badge-success`, `.badge-danger`, `.badge-info`, `.badge-warn`)
- **First Definition**: Lines 870–905 (under `/* ===== Badge ===== */`)
- **Second Definition**: Lines 1899–1933 (under `/* ===== Badges ===== */`)

```css
/* --- Definition 1 (L871-881) --- */
.badge {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 4px 10px;
    border-radius: var(--radius-full);   /* <--- Full pill shape (9999px) */
    font-size: 0.72rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.03em;
}

/* --- Definition 2 (L1900-1909) --- */
.badge {
    display: inline-flex;
    align-items: center;
    padding: 2px 8px;                    /* <--- Overrides padding (smaller) */
    border-radius: var(--radius-sm);     /* <--- OVERRIDES PILL TO RECTANGLE (6px) */
    font-size: 0.72rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.02em;              /* <--- Overrides letter spacing */
    /* gap: 4px is omitted here, but retained from cascade */
}
```

*Cascade Impact*: Definition 2 sits 1,029 lines below Definition 1. Because both have identical specificity `(0, 1, 0)`, Definition 2 wins everywhere in the app shell. Every `.badge` in the UI is rendered as a squared rectangle (`var(--radius-sm)` = 6px) instead of the intended pill design system token (`var(--radius-full)`), and loses 2px vertical padding. Furthermore, `.badge-secondary` (line 1935) was only defined in Definition 2.

*Resolution Recommendation for #505*:
Consolidate into a single canonical badge component in `components.css`. Enforce `border-radius: var(--radius-full)` as default pill badges. Retain `.badge-dot` (line 907) and `.badge-secondary` (line 1935). Delete lines 1899–1933 entirely.

---

#### Conflict 2: Traffic Badges (`.traffic-badge`)
- **First Definition**: Lines 1265–1272 (under `/* ===== Clients Table ===== */`)
- **Second Definition**: Lines 1823–1833 (under `/* ===== Traffic Badge ===== */`)

```css
/* --- Definition 1 (L1265-1272) --- */
.traffic-badge {
    font-size: 0.78rem;
    color: var(--text-muted);
    display: inline-flex;
    align-items: center;
    gap: var(--space-xs);
    white-space: nowrap;
}

/* --- Definition 2 (L1824-1833) --- */
.traffic-badge {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 2px 8px;                    /* <--- Adds background padding */
    border-radius: var(--radius-full);   /* <--- Turns into pill */
    font-size: 0.7rem;                   /* <--- Overrides 0.78rem to 0.7rem */
    font-weight: 500;
    font-family: 'SF Mono', 'Fira Code', monospace; /* <--- Monospace font */
}
```

*Cascade Impact*: Definition 2 forces monospace font and pill background padding onto `.traffic-badge` elements inside `my_connections.html` and `server_telemetry.js`, while retaining `color: var(--text-muted)` and `white-space: nowrap` from Definition 1.

*Resolution Recommendation for #505*:
Merge into a unified `.traffic-badge` definition in `components.css`. Move the companion directional modifiers `.traffic-down` (line 1835) and `.traffic-up` (line 1841) alongside it. Delete lines 1265–1272.

---

### 4.2 Identical Verbatim Redundancies (Dead Duplication)

Lines 1941–1956 repeat utilities that were already fully defined in lines 1641–1671:

| Selector | Definition 1 Line | Definition 2 Line | Declaration Content | Action in #505 |
| :--- | :--- | :--- | :--- | :--- |
| `.hidden` | L1669–L1671 | L1942–L1944 | `display: none !important;` | Delete Definition 2 |
| `.gap-xs` | L1641–L1643 | L1946–L1948 | `gap: var(--space-xs);` | Delete Definition 2 |
| `.gap-sm` | L1645–L1647 | L1950–L1952 | `gap: var(--space-sm);` | Delete Definition 2 |
| `.gap-md` | L1649–L1651 | L1954–L1956 | `gap: var(--space-md);` | Delete Definition 2 |

*Resolution Recommendation for #505*:
Retain these utility classes once in `layout.css` under the Utility section. Completely remove lines 1941–1956.

---

### 4.3 Multi-Selector Theme Transition Hooks

Lines 1877–1890 define a multi-selector rule:
```css
body,
.card,
.btn,
.form-input,
.form-select,
.modal,
.modal-backdrop,
.nav-link {
    transition: background-color var(--transition-slow),
        border-color var(--transition-slow),
        color var(--transition-slow);
}
```
This is NOT a conflicting override; it is an intentional progressive transition hook for smooth light/dark theme switching. In Issue #505, this rule belongs in `base.css` immediately following the theme token resets.

---

### 4.4 Progressive Form Extensions

Lines 929–942 declare shared input baseline properties:
```css
.form-input,
.form-select,
.form-textarea {
    width: 100%;
    padding: 11px 16px;
    background: var(--bg-input);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    ...
}
```
Lines 956–961 extend `.form-textarea` (`min-height: 100px; resize: vertical;`). Lines 963–970 extend `.form-select` (`appearance: none; background-image: url(...)`). This is idiomatic CSS and should remain grouped together in `components.css`.

---

### 4.5 Responsive Media Query Breakpoint Matrix

Fourteen selectors appear in both base rules and media query overrides:

| Selector | Base Rule Lines | Breakpoint Override Lines | Media Query Condition | Overridden Properties |
| :--- | :--- | :--- | :--- | :--- |
| `.app-sidebar` | L311–326 | L2106–2116 | `@media (max-width: 1023px)` | `position: fixed; transform: translateX(-100%);` |
| `[dir="rtl"] .app-sidebar`| L328–331 | L2118–2122 | `@media (max-width: 1023px)` | `transform: translateX(100%);` |
| `.app-main` | L333–342 | L2129–2131<br>L2139–2141 | `@media (max-width: 1023px)`<br>`@media (max-width: 767px)` | `padding: var(--space-lg) var(--space-md);`<br>`padding-bottom: calc(...)` |
| `.mobile-close-btn` | L380–391 | L2100–2104 | `@media (max-width: 1023px)` | `display: flex;` |
| `.mobile-topbar` | L515–530 | L2092–2094 | `@media (max-width: 1023px)` | `display: flex;` |
| `.drawer-backdrop` | L539–550 | L2096–2098 | `@media (max-width: 1023px)` | `display: block;` (when active) |
| `.mobile-bottom-bar` | L558–573 | L2135–2137 | `@media (max-width: 767px)` | `display: flex;` |
| `.server-grid` | L813–818 | L1675–1677 | `@media (max-width: 768px)` | `grid-template-columns: 1fr;` |
| `.protocol-cards` | L1079–1084 | L1679–1681 | `@media (max-width: 768px)` | `grid-template-columns: 1fr;` |
| `.form-row` | L972–976 | L1683–1685 | `@media (max-width: 768px)` | `grid-template-columns: 1fr;` |
| `.modal` | L1017–1030 | L1687–1690 | `@media (max-width: 768px)` | `width: 95%; padding: var(--space-lg);` |
| `.client-item` | L1199–1208 | L1692–1696 | `@media (max-width: 768px)` | `flex-direction: column; align-items: flex-start;` |
| `.client-info` | L1215–1221 | L1698–1700 | `@media (max-width: 768px)` | `width: 100%;` |
| `.client-actions` | L1256–1263 | L1702–1707 | `@media (max-width: 768px)` | `width: 100%; margin-left: 0;` |
| `.protocol-info` | L1153–1158 | L1711–1713 | `@media (max-width: 480px)` | `grid-template-columns: 1fr;` |
| `.nav-link` | L1848–1862 | L1893–1896 | `@media (max-width: 900px)` | `padding: 6px 12px; font-size: 0.8rem;` |

---

## 5. CSS Custom Properties (Variables) & Token Integrity

### 5.1 Token Inventory Overview
Lines 1–161 define the core design system tokens. Dark mode serves as the root baseline (`:root`), while `[data-theme="light"]` overrides specific surface and text values:

- **Surface Tokens**: `--bg-primary`, `--bg-surface`, `--bg-card`, `--bg-input`, `--bg-modal`, `--bg-glass`
- **Text Tokens**: `--text-primary`, `--text-secondary`, `--text-muted`, `--text-accent`
- **Accent & Brand**: `--accent`, `--accent-hover`, `--accent-light`, `--accent-dark`, `--accent-subtle`
- **Status & Severity**: `--success`, `--success-bg`, `--success-border`, `--warning`, `--warning-bg`, `--danger`, `--danger-bg`, `--danger-border`, `--info`, `--info-bg`, `--info-border`
- **Spacing Scale**: `--space-xs` (4px), `--space-sm` (8px), `--space-md` (16px), `--space-lg` (24px), `--space-xl` (32px), `--space-2xl` (48px)
- **Radii**: `--radius-sm` (6px), `--radius-md` (10px), `--radius-lg` (16px), `--radius-xl` (24px), `--radius-full` (9999px)
- **Shadows**: `--shadow-sm`, `--shadow-md`, `--shadow-lg`, `--shadow-glow`
- **Transitions**: `--transition-fast` (0.15s), `--transition-base` (0.2s), `--transition-slow` (0.3s)
- **Shell Dimensions**: `--sidebar-width` (260px), `--header-height` (64px), `--bottombar-height` (60px)

### 5.2 Defect Audit: Undefined Variables Used in Selectors

Three selectors in `style.css` invoke CSS variables that are never declared in `:root` or `[data-theme="light"]`:

```
Variable Defect 1: --accent-color
  Used at: L986 (*:focus-visible), L992 (button:focus-visible)
  Declaration in style.css: outline: 2px solid var(--accent-color);
  Root State: MISSING (:root defines --accent: #6366f1)
  Runtime Defect: Focus outline evaluates to transparent/invalid. Breaks WCAG 2.1 AA focus indication.
  Fix in #505: Replace var(--accent-color) with var(--accent).

Variable Defect 2: --bg-surface-hover
  Used at: L2530 (.toggle-switch-card:hover)
  Declaration in style.css: background-color: var(--bg-surface-hover, #232738);
  Root State: MISSING (Mitigated by hardcoded fallback #232738)
  Fix in #505: Declare --bg-surface-hover: #1e2235 in :root and #f1f5f9 in [data-theme="light"].

Variable Defect 3: --shadow-xl
  Used at: L2596 (.login-card)
  Declaration in style.css: box-shadow: var(--shadow-xl), 0 0 30px rgba(99, 102, 241, 0.06);
  Root State: MISSING (:root defines --shadow-lg: 0 10px 30px rgba(0, 0, 0, 0.5))
  Runtime Defect: var(--shadow-xl) evaluates to invalid, leaving only the secondary glow shadow.
  Fix in #505: Declare --shadow-xl: 0 20px 40px rgba(0, 0, 0, 0.6) in tokens.css.
```

### 5.3 Defect Audit: Declared Variables Unused in CSS
Four variables are declared in `:root` but have zero `var(...)` invocations inside `style.css`:
- `--accent-dark` (lines 30, 109): Candidate for active button states.
- `--info-border` (lines 48, 127): Candidate for info alerts.
- `--text-accent` (lines 26, 105): Candidate for highlighted text spans.
- `--shadow-md` (lines 68, 130): Actively used via inline style in `web/templates/my_connections.html:198` (`box-shadow: var(--shadow-md);`). Must be preserved.

---

## 6. Dead Code & Zero-Usage Audit

### 6.1 Truly Dead Selectors vs. Dynamically Constructed Tokens

A static scan against templates and scripts flags 6 selector rules with zero literal string hits. Analysis proves that 4 are dynamic production classes, 1 is a unit-tested design token, and 1 is genuine dead code:

| Selector Key | Line Span | Classification | Empirical Finding & Evidence |
| :--- | :--- | :--- | :--- |
| `.toast-success` | L1356–L1360 | **Dynamic Production** | Injected in `web/static/js/ui.js:85` via `el.className = 'toast toast-' + toastType`. Handles success toasts across all pages. **DO NOT DELETE.** |
| `.toast-error` | L1362–L1366 | **Dynamic Production** | Injected in `web/static/js/ui.js:85` (`type = 'error'`). Critical error notification styling. **DO NOT DELETE.** |
| `.toast-warning` | L1368–L1372 | **Dynamic Production** | Injected in `web/static/js/ui.js:85` (`type = 'warning'`). Critical warning notification styling. **DO NOT DELETE.** |
| `.toast-info` | L1374–L1378 | **Dynamic Production** | Injected in `web/static/js/ui.js:85` (`type = 'info'`). Default toast notification styling. **DO NOT DELETE.** |
| `.skeleton-avatar` | L1427–L1433 | **Tested Design Token** | Asserted directly by `web/web_test.go:81` (`requiredTokens`). Shimmer placeholder for avatar circles. **DO NOT DELETE.** |
| `.skeleton-icon` | L1427–L1433 | **GENUINE DEAD CSS** | Defined as companion to `.skeleton-avatar`: `.skeleton-avatar, .skeleton-icon { border-radius: var(--radius-full); }`. 0 references in templates, 0 in JS, 0 in tests. **SAFE TO PRUNE IN #505.** |

---

## 7. Media Queries & Responsive Breakpoint Strategy

### 7.1 Breakpoint Analysis
The stylesheet currently relies on five distinct `@media` breakpoints:

```
Breakpoint Hierarchy:
  Desktop / Tablet Boundary:  1023px  (L2090-L2133) -> Off-canvas sidebar, sticky topbar
  Navbar Compression:          900px  (L1893-L1896) -> Header nav-link padding reduction
  Tablet / Mobile Grids:       768px  (L1674-L1708) -> Server card 1-col, modal 95%, clients vertical
  Phone Viewports & Bottombar: 767px  (L2134-L2146) -> Bottom navigation bar displayed, main bottom pad
  Compact Mobile Displays:     480px  (L1709-L1718) -> Protocol card metadata grid 1-col
```

### 7.2 The 768px vs. 767px Threshold Collision
At exactly `768px` viewport width:
- The 768px queries fire: `.server-grid` collapses to single column, `.modal` expands to 95% width, and `.client-item` wraps vertically.
- However, the 767px queries DO NOT fire: `.mobile-bottom-bar` remains hidden (`display: none`), while desktop navigation may already be hidden if below 1023px.
- *Recommendation for #505*: Standardize mobile grid breakpoints to match the 767px phone threshold or align all mobile layouts to 768px.

---

## 8. Safe Modularization Roadmap for Issue #505

Issue #505 will physically divide `web/static/css/style.css` into modular, domain-owned stylesheets. To guarantee zero functional and test regressions, the following file breakdown, cascade ordering, and delivery contracts must be adhered to.

### 8.1 Proposed Modular File Structure

```
web/static/css/
 ├── tokens.css       (~160 lines) : Design tokens, CSS variables, dark/light themes
 ├── base.css         (~260 lines) : Reset, typography, scrollbars, SVG icons, focus, micro-interactions
 ├── layout.css       (~450 lines) : App shell, sidebar, mobile topbar, bottom nav bar, grid utilities
 ├── components.css   (~950 lines) : Buttons, cards, modals, forms, badges, toasts, tables, pagination
 ├── server.css       (~450 lines) : Server cards, protocol cards, client tables, config boxes, log terminals
 └── vpn.css          (~350 lines) : VPN stat cards, sparklines, latency indicators, diagnostics
```

*Note on Line Ceiling*: Every proposed modular stylesheet comfortably satisfies the Amnezia Nexus codebase ceiling of under 1,000 lines per static file.

### 8.2 Cascade Load Order & Dependency Contract

The cascade order in HTML templates MUST follow this exact sequence:

```html
<!-- 1. Tokens: Variables must be initialized first -->
<link rel="stylesheet" href="/static/css/tokens.css?v={{ .version }}">

<!-- 2. Base: Element resets and global typography -->
<link rel="stylesheet" href="/static/css/base.css?v={{ .version }}">

<!-- 3. Layout: Page structural shells, navigation drawers, and utilities -->
<link rel="stylesheet" href="/static/css/layout.css?v={{ .version }}">

<!-- 4. Components: Shared reusable UI elements (buttons, tables, modals) -->
<link rel="stylesheet" href="/static/css/components.css?v={{ .version }}">

<!-- 5. Feature Subsystem Styles (Loaded conditionally or per-template) -->
{{ if eq .active_page "vpn" }}
<link rel="stylesheet" href="/static/css/vpn.css?v={{ .version }}">
{{ else if or (eq .active_page "server") (eq .active_page "servers") }}
<link rel="stylesheet" href="/static/css/server.css?v={{ .version }}">
{{ end }}
```

### 8.3 Go Asset Embedding & Unit Test Lockstep Contract

#### Embed File System (`web/web.go`)
Static assets are embedded into the Go binary via `embed.FS`:
```go
//go:embed static/* templates/* translations/*
var embeddedFS embed.FS
```
Because the directive uses wildcard matching (`static/*`), any new CSS files placed under `web/static/css/` will automatically be embedded by the Go compiler without altering `web.go`.

#### Unit Test Assertion Invariants
The following existing Go unit tests read `css/style.css` directly and assert literal string tokens:
1. `web/web_embedded_test.go`:
   - `TestEmbeddedStaticTokens`: Asserts `--bg-primary`, `--accent`, `.app-layout`, `.app-sidebar`, `.mobile-bottom-bar`, `.drawer-backdrop`.
   - `TestAppShellLayoutStackingOrder`: Uses regex on `css/style.css` to check `z-index` of `.mobile-bottom-bar`, `.drawer-backdrop`, and `@media (max-width: 1023px)`.
   - `TestSidebarFooterEmbedded`: Checks `.sidebar-footer` in `css/style.css`.
2. `web/web_test.go`:
   - `TestWebPhase3EmbeddedStyles`: Asserts `.skeleton`, `.skeleton-text`, `.btn-press`, `.toast`, `.table-toolbar`, `.filter-chips`, `.sortable-header`.
3. `web/web_vpn_test.go`:
   - `TestVPNInteractiveTables`: Asserts `.stat-card`, `.latency-pill`, `.info-card`, `.gap-xs`, `.interactive-table`.
4. `web/web_server_users_test.go`:
   - `TestUsersContainerWidths`: Asserts `#usersContainer`, `#usersGrid`, `#userConnsTable`.

#### Safe Transition Strategies for Issue #505
To avoid breaking these tests during Issue #505, developers must choose one of two valid transition paths:
- **Strategy A (Aggregate Manifest Bundle — Recommended)**:
  Retain `web/static/css/style.css` as a master CSS `@import` manifest or concatenated build artifact:
  ```css
  /* web/static/css/style.css */
  @import "tokens.css";
  @import "base.css";
  @import "layout.css";
  @import "components.css";
  @import "server.css";
  @import "vpn.css";
  ```
  *Caveat*: Go tests using raw string matching (`strings.Contains`) do not resolve `@import` statements. If Strategy A is used without concatenation, the test assertions in `web_embedded_test.go` and `web_vpn_test.go` must be updated to target the modular files.
- **Strategy B (Atomic Test Harness Update)**:
  Replace direct `fs.ReadFile(staticFS, "css/style.css")` calls in the test files with helper functions reading the appropriate target modular files (e.g., inspecting `css/tokens.css` for `--accent`, `css/layout.css` for `.app-layout`, and `css/vpn.css` for `.stat-card`).

### 8.4 Phased Implementation Sequence for Issue #505

```
┌──────────────────────────────────────────────────────────────────────────┐
│ Step 1: Extract tokens.css & base.css                                     │
│ - Move Lines 1-161 to tokens.css                                         │
│ - Move Lines 192-301, 984-995, 1435-1451, 1876-1898 to base.css         │
│ - Fix undefined variables (--accent-color -> --accent, etc.)             │
│ - Verify tokens and base rendering across all pages                     │
└────────────────────────────────────┬─────────────────────────────────────┘
                                     │
                                     ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ Step 2: Extract layout.css                                               │
│ - Move Lines 302-652, 1621-1719, 1847-1875, 2090-2147 to layout.css      │
│ - Deduplicate .hidden and .gap-* utilities                               │
│ - Consolidate responsive app shell media queries                         │
│ - Verify desktop drawer, mobile topbar, and bottom bar interactions      │
└────────────────────────────────────┬─────────────────────────────────────┘
                                     │
                                     ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ Step 3: Extract components.css                                           │
│ - Move buttons, cards, forms, modals, tables, toasts, and toggles        │
│ - Resolve .badge conflict (enforce pill border-radius, delete L1899-1940)│
│ - Resolve .traffic-badge conflict                                        │
│ - Prune dead selector .skeleton-icon                                     │
└────────────────────────────────────┬─────────────────────────────────────┘
                                     │
                                     ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ Step 4: Extract feature stylesheets (server.css & vpn.css)               │
│ - Move Lines 812-869, 1078-1312, 1515-1544, 1720-1846 to server.css     │
│ - Move Lines 1807-1822, 2459-2495, 2767-2962 to vpn.css                  │
│ - Move Lines 2963-3008 (Users section) into components.css or users.css  │
│ - Update base.html and feature templates with modular <link> tags        │
└────────────────────────────────────┬─────────────────────────────────────┘
                                     │
                                     ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ Step 5: Test Harness Alignment & Verification                             │
│ - Run go build ./cmd/... ./internal/... ./web/...                        │
│ - Run go test ./web/...                                                  │
│ - Verify layout visual fidelity in light and dark themes                 │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 9. Verification & Architectural Invariants Checklist

Any subsequent PR implementing Issue #505 MUST satisfy the following checklist before merge:
- [ ] No single static CSS file exceeds the project line ceiling of 1,000 lines.
- [ ] All 56 design tokens in `:root` and `[data-theme="light"]` remain accessible to dependent rules.
- [ ] Defective variable references (`--accent-color`, `--bg-surface-hover`, `--shadow-xl`) are fully resolved.
- [ ] Conflicting duplicate definitions (`.badge` at L1900 and `.traffic-badge` at L1265) are permanently unified.
- [ ] Redundant utility definitions (`.hidden`, `.gap-xs`, `.gap-sm`, `.gap-md` at L1942–1956) are removed.
- [ ] Dynamic toast classes (`.toast-success`, `.toast-error`, `.toast-warning`, `.toast-info`) are preserved.
- [ ] Stacking context order (`.mobile-bottom-bar` = 70, `.drawer-backdrop` = 95, `.app-sidebar` = 100) is strictly maintained.
- [ ] All Go tests in `web/` pass with zero failures: `go test -race ./web/...`.
