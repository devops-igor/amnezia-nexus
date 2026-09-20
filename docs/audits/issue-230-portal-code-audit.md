# Portal Codebase Audit - Issue #230

Audit date: 2026-09-21
Repository: `devops-igor/amnezia-nexus`
Audited ref: `main` at `2008c86166afd8604e5bcc2c86cc6f77f5b75038`

## Executive summary

The portal is generally actively used and does not contain a large amount of obviously unreachable production code. Most of the apparent "legacy" code is deliberate compatibility logic for older installations, databases, AWG configurations, or API clients and should not be removed without an explicit compatibility policy.

The audit found three useful cleanup groups:

1. **High confidence:** an unused Go compatibility shim in `internal/router/template.go`.
2. **High confidence:** several CSS selectors and utility rules with no references in the shipped templates or JavaScript.
3. **Medium confidence:** frontend compatibility aliases and Go compatibility wrappers that have no in-repository runtime callers but may intentionally preserve external/custom integrations.

No evidence was found that the current portal has orphaned SVG symbols or an entirely unreferenced static JavaScript asset.

## Findings

| ID | Component | Finding | Confidence | Removal risk | Est. savings |
|---|---|---|---|---|---:|
| A-01 | `internal/router/template.go` | Compatibility-only wrapper around `internal/handlers`: `TemplateEngine`, `GetTemplateEngine`, `FormatBytes`, `FormatTime`, `RenderTemplate`, `CleanReferer`. No production caller exists in the repository. | High | Low | ~35 LOC |
| A-02 | `web/static/css/style.css` | Legacy selectors `.app-container` and `.app-header` have no references in current templates or JS. | High | Low | ~20 LOC |
| A-03 | `web/static/css/style.css` | Unused icon sizing helpers `.icon-sm`, `.icon-lg`, `.icon-xl`. No shipped markup/JS references them. | High | Low | ~12 LOC |
| A-04 | `web/static/css/style.css` | Legacy/unused navigation selectors `.sidebar-logo`, `.mobile-logo`, `.header-nav`, `.nav-user`, `.nav-username` have no current markup references. | High | Low | ~35 LOC |
| A-05 | `web/static/css/style.css` | `.protocol-legacy` has no current markup/JS reference. Protocol normalization now maps legacy protocol names to the current AWG implementation instead of rendering a legacy CSS state. | High | Low | ~5 LOC |
| A-06 | `web/static/css/style.css` | Unused utility selectors `.flex-col` and `.mt-lg` have no current references. | High | Low | ~6 LOC |
| A-07 | `web/static/css/style.css` | `.leaderboard-footer` and `.sparkline-tooltip` have no current markup/JS references. The sparkline implementation uses SVG `<title>` rather than a CSS tooltip element. | High | Low | ~25 LOC |
| A-08 | `web/static/css/style.css` | `.live-dot`, `.live-badge`, `.metric-card-stat`, `.stat-value`, `.stat-chart` are referenced only by `web/web_test.go`, not by shipped templates/JS. These look like stale design-system/test assertions rather than runtime styles. | Medium | Medium | ~30 LOC |
| A-09 | `web/static/js/api.js` | Global `window.apiCall` compatibility wrapper is not used by current templates. | Medium | Medium | ~8 LOC |
| A-10 | `web/static/js/ui.js` | Global compatibility exports such as `showToast`, `openModal`, `closeModal`, `copyToClipboard`, `confirmModal`, `formatBytes`, `downloadFile`, `escapeHtml`, `escapeJs` are not used by current templates; current code uses `UI.*`. | Medium | Medium | ~25 LOC |
| A-11 | `web/static/js/tables.js` | `DataTable = NexusTable` is a compatibility alias with no current caller. | Medium | Medium | ~1 LOC |
| A-12 | `internal/vpn/vpn.go` | `NewLeastConnectionsLoadBalancer`, `LeastConnectionsLoadBalancer`, and related `NewService`/legacy service surface are only exercised by legacy compatibility tests; production startup uses `NewVPNService` and `loadbalancer.NewLoadBalancer`. | Medium | Medium | ~25-40 LOC |
| A-13 | `internal/router/router.go` | Duplicate route families exist for legacy compatibility: `/api/my/connections/*` alongside `/api/connections/*`, plus root server-management aliases alongside `/api/servers/*`. Current frontend uses the standard `/api/connections` and `/api/servers` families. | Medium | High | potentially ~35-50 LOC |
| A-14 | translations | A simple static scan finds ~164 English translation keys not directly referenced by the current templates. This is **not sufficient evidence for deletion** because keys can be consumed by dynamic JavaScript, backend-generated UI, or compatibility flows. | Low | High | unknown |

## What was explicitly checked

### Frontend

- All 13 HTML templates under `web/templates/`.
- All shipped JavaScript assets:
  - `api.js`
  - `qrcode.min.js`
  - `tables.js`
  - `telemetry.js`
  - `ui.js`
- `style.css`.
- SVG symbols in `icons.html`.
- Translation dictionaries.

All 41 SVG symbols currently have at least one reference in the shipped frontend. No orphaned SVG icon was identified.

All CSS keyframes currently have an animation reference. No obviously dead keyframe was identified.

### Backend

- Router registration in `internal/router/router.go`.
- Handler package and route-facing handlers.
- Compatibility wrappers and aliases.
- VPN service compatibility surface.
- Database/model compatibility code.

A large amount of "legacy" backend logic is intentional migration support. Examples include legacy `data.json` migration, old password hashes, legacy AWG container names, legacy protocol aliases, and old database rows. These should remain unless the project establishes a minimum supported upgrade version.

### Important non-findings

The following should **not** be removed as dead code:

- `internal/database/migrate.go` legacy migration paths.
- Legacy AWG protocol/container parsing and normalization.
- Legacy password verification.
- Legacy VPN/database field migration.
- `AdoptAWGClientIPLease`.
- `AWGContainerNames`.
- SSH legacy fingerprint support.
- Compatibility tests for historical database formats.

These are active upgrade/compatibility mechanisms, not dead code.

## Prioritized cleanup plan

### PR 1 - Safe CSS cleanup

Remove only selectors confirmed to have zero runtime references:

- `.app-container`
- `.app-header`
- `.icon-sm`
- `.icon-lg`
- `.icon-xl`
- `.sidebar-logo`
- `.mobile-logo`
- `.header-nav`
- `.nav-user`
- `.nav-username`
- `.protocol-legacy`
- `.flex-col`
- `.mt-lg`
- `.leaderboard-footer`
- `.sparkline-tooltip`

Before merge, remove/update any test assertions that are specifically testing these obsolete styles.

Expected saving: roughly 100-150 lines depending on grouped rules and responsive/theme blocks.

### PR 2 - Remove obsolete frontend compatibility aliases

After confirming no documented external/custom frontend depends on them:

- Remove `window.apiCall`.
- Remove old global UI wrappers.
- Remove `DataTable` alias.

Update `web/web_test.go` so it verifies only the supported API surface.

Expected saving: roughly 30-40 lines.

### PR 3 - Remove unused router compatibility shim

Delete `internal/router/template.go` after confirming no downstream in-repository package imports it.

Move/retain all real template functionality in `internal/handlers/template.go`.

Expected saving: roughly 35 lines.

### PR 4 - Router compatibility deprecation

Do not remove immediately.

First document the supported API paths and determine whether old clients are still expected to work:

- `/api/my/connections/*` -> `/api/connections/*`
- root server-management aliases -> `/api/servers/*`

If compatibility can be retired, remove the aliases in a separate release with a changelog entry and migration note.

### PR 5 - VPN legacy API cleanup

Do not remove immediately.

The old `NewService` and load-balancer aliases are internal-only and have no production callers, but they are explicitly marked as backwards compatibility. Decide whether the project considers the `internal/vpn` package API stable for downstream/internal consumers.

If not, remove the compatibility surface and its legacy-only tests in one isolated PR.

### PR 6 - Translation inventory

Do not mass-delete the ~164 apparently unused keys.

Instead, add a small static translation-key audit tool that understands:

- Go/backend `T(...)` calls.
- Go template `_ "key"` calls.
- JavaScript `_(...) / window._(...)`.
- Dynamically assembled keys where possible.

Then delete only keys proven unreachable.

## Recommended acceptance criteria

The audit can be considered complete when:

1. Every proposed deletion has a repository-wide reference check.
2. Compatibility code is explicitly separated from dead code.
3. Each cleanup PR changes one logical category only.
4. `go test ./...`, `go vet ./...`, and the existing frontend embedding tests remain green.
5. No legacy migration path is removed without an explicit supported-upgrade-version decision.
6. The project has a documented policy for when compatibility aliases may be retired.

## Overall conclusion

The portal does **not** appear to need a broad destructive cleanup. The safest technical debt reduction is a sequence of small, mechanically verifiable removals, starting with unused CSS and the unused router compatibility shim.

The highest-value follow-up is to formalize the compatibility policy. Several items that look dead are intentionally retained for older installations or consumers, and deleting them without a support-window decision would turn a tech-debt cleanup into a compatibility regression.
