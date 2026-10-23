# Module Ownership Conventions and Refactor PR Checklist

## 1. Purpose and Scope

This is the authoritative reference for who owns what in the Amnezia Nexus repository, which packages may import which, how to decide between splitting a file and creating a package, and how to review a refactor PR. It codifies the rules learned during the modularization program (Epic #475) and is written for human contributors and AI coding agents alike.

It indexes, and does not replace, the detailed contracts:

- [VPN Service State Ownership and Lock Contracts](vpn-service-state-ownership.md)
- [Dataplane Ownership & Concurrency Contract: Forwarder](forwarder-dataplane-ownership.md)
- [Frontend JavaScript Architecture Contracts](frontend-javascript-contracts.md)
- [CSS Architecture Contracts](css-contracts.md)

Where this document and a detailed contract disagree, the detailed contract wins for its subsystem; fix this document in the same PR.

Rules are marked **MUST** (enforced by review or CI) or **SHOULD** (default unless the PR states a reason). Where the code does not yet meet a rule, the gap is listed under "Known exceptions" and is not a precedent.

## 2. Component Topology and Ownership Map

### 2.1 Entrypoints

| Path | Owns | Must not contain |
|------|------|------------------|
| `cmd/panel/` | The `panel` binary: flag/env parsing, config loading, dependency construction, service lifecycle (start/stop, signals). | Business logic, SQL, HTTP handlers. |
| `cmd/server/` | Server entrypoint wiring the same components as `cmd/panel`. | Business logic. Keep wiring in sync with `cmd/panel`. |
| `cmd/qualification-subject/` | Test subject binary used by qualification scripts under `scripts/`. | Production wiring; it is not shipped to users. |

### 2.2 Foundation packages (no operational imports)

| Path | Owns |
|------|------|
| `internal/models/` | Domain entities (`models.go`), request DTOs (`requests.go`), response DTOs (`responses.go`), and small pure helpers (`range.go`, `vpn_i1.go`). Pure types and JSON contracts. No I/O, no goroutines. |
| `internal/config/` | Configuration structs, environment parsing, validation defaults, translation loading (embedded from `web/`), platform-specific file helpers. |
| `internal/security/` | Password hashing, credential encryption, session encoding, and integrity helpers. Stdlib and crypto only. |
| `internal/captcha/` | Captcha generation and verification, embedded captcha assets. Self-contained. |

### 2.3 Persistence

| Path | Owns |
|------|------|
| `internal/database/` | SQLite persistence: schema, migrations (`migrations.go`, `migrations_legacy_alloc.go`), and per-entity query modules (`vpn.go`, `backend_tunnels.go`, ...). The only package that issues SQL. |

### 2.4 Device and remote-host managers

| Path | Owns |
|------|------|
| `internal/manager/` | Manager interfaces and shared helpers (`manager.go`). |
| `internal/manager/awg/` | Low-level WireGuard / AmneziaWG management on a remote host: CLI execution, interface and peer config generation (`peer_config.go`), remote server lock (`awg_lock.go`). Subpackages: `health/` (probes), `cps/` (obfuscation packet framing). |
| `internal/manager/ssh/` | SSH transport used by all remote managers. |
| `internal/manager/dns/`, `internal/manager/mtproxyl/` | DNS and MTProxy remote service managers. |

Managers are device abstractions. They talk to hosts; they do not know about HTTP, sessions, or the VPN service.

### 2.5 VPN service and dataplane

| Path | Owns |
|------|------|
| `internal/vpn/` | High-level VPN service orchestration (`vpn.go`, `backend_*.go`), client config generation (`client_config.go`), endpoint formatting (`endpoint.go`), ingress engine glue, and diagnostics (`diagnostics*.go`). `Service.mu` lives here. |
| `internal/vpn/tunnel/` | Backend tunnel pool and tunnel state. |
| `internal/vpn/forwarder/` | Packet forwarder dataplane: routes, queues, pumps, drop accounting (`thresholds/` holds diagnostic thresholds). |
| `internal/vpn/ingress/`, `virtualtun/`, `clientawg/` | Ingress routing, userspace virtual TUN, and non-kernel AWG client. |
| `internal/vpn/session/`, `identity/`, `auth/`, `ipam/`, `loadbalancer/` | Live sessions, peer identity, peer authentication, IP allocation, backend selection. |

### 2.6 Background services

| Path | Owns |
|------|------|
| `internal/service/` | Service bootstrap that starts background workers. Subpackages: `orchestrator/` (backend orchestration), `reconciliation/`, `supervisor/`, `upstream/` (upstream monitoring), `userops/`. |

### 2.7 HTTP layer

| Path | Owns |
|------|------|
| `internal/router/` | Route tree, static asset serving, middleware chain assembly. |
| `internal/middleware/` | Cross-cutting HTTP middleware: sessions, CSRF, rate limiting, real-IP, cookie policy, timeouts, error pages. |
| `internal/handlers/` | Web and API handlers: auth/session checks, form parsing, template rendering, JSON endpoints. Handlers translate HTTP to service calls; they do not hold VPN state. |

### 2.8 Web assets

| Path | Owns |
|------|------|
| `web/templates/` | Server-rendered Go HTML templates. Markup, translation placeholders, and script tags only (see section 7). |
| `web/static/js/` | Companion JavaScript modules, one concern per file (`web/static/js/vpn/` for the VPN dashboard). |
| `web/static/css/` | Partitioned stylesheets (`tokens.css`, `base.css`, `layout.css`, `components.css`, ...). See the CSS contracts. |
| `web/translations/` | One JSON file per locale: `en`, `fa`, `fr`, `ru`, `zh`. |
| `web/*_test.go` | Template, i18n, and Node/jsdom frontend tests. |

### 2.9 Tooling and docs

| Path | Owns |
|------|------|
| `scripts/` | Ops and CI scripts. `scripts/architecture_health/` implements the size/churn report; `scripts/architecture_baseline.json` holds the pinned ceilings. |
| `tests/` | Python tests for tooling and end-to-end suites (`tests/e2e/`). |
| `docs/architecture/` | Architecture contracts (this directory). |
| `useful_notes/` | Explanatory notes for readers (`HOW_IT_WORKS.md`). |

## 3. Dependency Direction

### 3.1 Layering

Imports point downward only. A package may import packages in a lower layer, never a higher one, and never form a cycle.

```
cmd/*
  |
  v
internal/router  ->  internal/middleware
  |
  v
internal/handlers
  |
  v
internal/service/*        internal/vpn  (and its subpackages)
  |                          |
  +------------+-------------+
               v
internal/manager/*   (awg, dns, mtproxyl, ssh)
               |
               v
internal/database
               |
               v
internal/models, internal/config, internal/security, internal/captcha, web (embedded assets)
```

Siblings in the same layer (`service/*` and `vpn`) may import each other only if the result stays acyclic and the direction is already established (today `service/orchestrator` imports `vpn/tunnel`; `vpn` does not import `service`).

### 3.2 Hard rules

1. **MUST** keep the import graph acyclic. `go build ./...` rejects cycles; do not work around one by moving a symbol into `models` to hide a real dependency.
2. **MUST** keep `models`, `security`, and `captcha` free of imports from other `internal/` packages.
3. **MUST** keep `config` free of operational imports. Its only internal import is the `web` package, for embedded translations.
4. **MUST NOT** import `internal/vpn`, `internal/handlers`, `internal/router`, `internal/middleware`, or `internal/service` from `internal/database`.
5. **MUST NOT** import `internal/vpn`, `internal/handlers`, or `internal/router` from `internal/manager/...`.
6. **MUST NOT** import `internal/handlers` or `internal/router` from `internal/vpn/...` or `internal/service/...`.
7. **MUST** keep `cmd/*` as thin wiring. Logic belongs in `internal/`.
8. **SHOULD** depend on small interfaces defined at the consumer, not on concrete types from a lower layer (the `AWGStatusProvider` and `BackendDevice` seams in `internal/vpn` are examples).

### 3.3 Known exceptions (not precedent)

| Edge | Why it exists | Rule |
|------|---------------|------|
| `internal/database` -> `internal/manager/awg` | `awg_ip_allocations.go` calls the pure helper `awg.GetNextIP`. | Do not add a second use. Prefer moving the pure helper to a neutral package when the file is next touched. |
| `internal/manager/mtproxyl` -> `internal/service/orchestrator` | MTProxy manager uses an orchestrator type. | Do not add edges from other managers to `service/`. |

Verify the current graph before you claim a rule holds:

```bash
go list -f '{{.ImportPath}}: {{join .Imports " "}}' ./internal/... ./cmd/...
```

## 4. Same-Package File Split vs New Package

### 4.1 Default: split the file inside the package

When a file is too large or mixes concerns, extract into new files in the same package.

- A same-package move changes no import path, no exported API, and no visibility, so callers and tests keep compiling untouched.
- Unexported symbols stay unexported. Do not export something only so a new package can reach it.
- Naming: `<area>_<concern>.go`, with tests in the matching `<area>_<concern>_test.go` (for example `diagnostics_health.go`, `diagnostics_health_test.go`).
- Move the tests that cover the moved code in the same PR.

### 4.2 Introduce a package only when all of these hold

1. It is an independent domain capability (for example `internal/manager/awg/cps`, `internal/vpn/tunnel`, `internal/vpn/forwarder`).
2. It has a narrow public interface that needs no access to the parent's unexported state.
3. It has a clear owner for its state and locks.
4. The new import edge fits the layering in section 3.1.

Never create a package merely to shorten a file. If extraction forces you to export many symbols or pass the parent struct around, the seam is wrong; stay in the package.

### 4.3 Size signals

- Warning at 500 physical lines, ceiling at 1,000 (`scripts/architecture_health/constants.py`).
- Line count is a discovery signal, not a goal. Do not fragment cohesive code into many tiny files to hit a number; split along concerns the contracts name.
- Mechanical moves and behavior changes **MUST** land in separate PRs.

## 5. Go Concurrency and State Authority

The detailed matrices live in the two ownership contracts. The rules every change must respect:

1. **One owner per piece of state.** Every mutable field has exactly one guarding lock or is atomic. Check the field's row in `vpn-service-state-ownership.md` before touching it; add a row when you add a field.
2. **`Service.mu`** guards tunnel pool membership, backend enable/disable, backend device maps, `cfg`, lifecycle flags (`running`, `startedAt`), and the in-memory admission state. Lock order is `Service.mu` -> `SessionManager.mu`, never the reverse.
3. **No I/O under locks (normative).** Do not run database queries, SSH or HTTP calls, STUN lookups, subprocesses, device writes, or blocking channel operations while holding `Service.mu`, `Forwarder.mu`, `aggregateQueueMu`, or any other internal mutex. Pattern: snapshot under the lock, release, do the I/O, re-acquire and re-validate (compare a generation or ID), then commit.
4. **Existing violations are debt, not license.** `vpn-service-state-ownership.md` section 3.1 inventories the database calls still made under `Service.mu`. Never add to that list; shrink it when you touch those paths.
5. **Forwarder lock graph.** `Forwarder.mu` and `sessionRoute.writeMu` are disjoint. Never call `Retirement.Wait()` while holding `Forwarder.mu` or `Service.mu`. Run callbacks and classifiers after releasing the lock.
6. **Bounded external calls.** Every operation against a remote host, database, or network peer takes a `context.Context` with an explicit timeout derived from the caller's context. Existing values to follow: 5s for per-backend health and reachability checks, 30s for registration-class operations. Do not use a bare `context.Background()` inside a request path.
7. **Fail closed with rollback.** A multi-step operation that fails midway must undo its earlier steps (best-effort compensation, logged) or leave the backend in `TunnelStatusDegraded` rather than appearing healthy. Do not report success for partial state. See the rollback semantics in `vpn-service-state-ownership.md` section 4.4.
8. **Goroutine lifecycle.** Every goroutine has a documented stop condition (context cancel or close channel) and is joined on shutdown. No fire-and-forget goroutines that capture mutable state.
9. **Race tests.** Changes under `internal/vpn/...`, `internal/handlers/...`, `internal/service/...`, or `internal/manager/...` **MUST** pass `go test -race` for the touched packages. New concurrent code needs a test that would fail under `-race` or deadlock detection if the lock discipline were broken.

## 6. Data and Persistence Rules

1. Only `internal/database` writes SQL. Use parameterized queries; never build SQL by string concatenation.
2. Schema changes go through migrations and need a migration test, including upgrade from the previous schema.
3. Keep entities in `models`; do not define persistence-only structs in `handlers`.
4. Secrets (keys, tokens, password hashes) never appear in logs, error strings, templates, or test fixtures.

## 7. Frontend Module Standards

Details are in `frontend-javascript-contracts.md` and `css-contracts.md`. Required for new and moved code:

1. **No new inline `<script>` bodies.** Behavior lives in companion modules under `web/static/js/`, loaded with `<script src>` from the template's `{{ define "scripts" }}` block. Go-template data reaches JS through `data-*` attributes or an escaped JSON bootstrap, not string interpolation into code.
2. **Event delegation.** Do not add inline `onclick`/`onchange` handlers. Mark elements with `data-action` (or a similar `data-*` hook) and bind delegated listeners in the companion module.
3. **i18n parity.** Every user-visible string is a translation key: `{{ _ "key" }}` in templates, `window._("key")` in JavaScript. A key added to `web/translations/en.json` **MUST** be added to `fa`, `fr`, `ru`, and `zh` in the same PR, with identical `{placeholder}` sets. The dictionary parity tests in `web/` enforce this.
4. **Strict CSP readiness.** Write every new line as if the page ran under a policy without `'unsafe-inline'` for scripts. The panel does not enforce such a policy yet.
5. **Ceilings.** Each static JS or CSS file stays under 1,000 lines; one concern per file; load order is declared in the template and documented in the contracts.
6. **Atomic staging.** A moved function, its `<script src>` tag, and the test fixture that extracts it land in one PR.

Known exceptions: some templates still contain inline `<script>` blocks and inline event handlers. They are tracked in the JavaScript contracts' CSP roadmap. Do not copy the pattern, and remove handlers you touch when the change is small.

## 8. Guidance for AI Coding Agents

1. **Understand why before changing.** Read the owning contract and the tests for the code you touch. If a rule here blocks the task, say so; do not route around it.
2. **Smallest complete change (Ponytail).** No speculative abstractions, options, wrappers, or unrequested rewrites. Complete every caller, test, and fixture the change affects.
3. **Fidelity in structural moves.** A move is byte-for-byte: same logic, same error handling, same validation, same comments that carry a "why". Do not tidy, rename, or reorder in the same diff. Verify with `git diff --color-moved` or by comparing function bodies.
4. **Never delete or weaken regression tests.** Do not skip, loosen assertions, or remove a test to make a gate pass. Moved tests keep their names and assertions.
5. **Add targeted tests for new seams.** A new package boundary or lock-discipline rule gets a test that fails when the rule is broken (mutation-killing), not only a happy-path test.
6. **Report honestly.** State which gates ran and their real output, what you did not run, and any spec statement you found inconsistent with the repository.
7. **Stay in scope and in the authorized branch.** No pushes, merges, or history rewrites unless the task explicitly authorizes them. Stage files by explicit path.
8. **No leaks.** Do not commit local filesystem paths, internal hostnames, RFC 1918 addresses taken from real deployments, tokens, or tool/bot identities. Use documentation-range addresses (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) in examples.

## 9. Refactor PR Review Checklist

Copy this into the PR description for any refactor, file split, or package extraction. `CONTRIBUTING.md` carries the same checklist.

### 9.1 Safeguard SG1: line-count sizing rule

> A PR must not push a file from below 1,000 lines to 1,000 or more, or grow a file that is already at or above 1,000 lines, without a stated justification.

- [ ] No file crossed the 1,000-line ceiling, and no file at or above 1,000 lines grew; **or** each exception has a written per-PR rationale in the PR description (for example a single table-driven data matrix, or a comprehensive benchmark harness that cannot be split without losing coverage).
- [ ] No blanket exemption is claimed for model, test, or script files; each is judged by the same rule.
- [ ] The split follows a documented concern boundary, not an arbitrary line count. Line count is a discovery signal, not an excuse for fragmentation.
- [ ] `scripts/architecture_baseline.json` is changed only by the downward ratchet, or the PR explains an intentional increase.

### 9.2 Structure and fidelity

- [ ] Same-package split by default; a new package meets all four conditions in section 4.2.
- [ ] Dependency direction follows section 3; `go list` shows no new upward or cyclic edge.
- [ ] Moved code is identical (error handling, validation, locking) apart from the file it lives in.
- [ ] Mechanical moves and behavior changes are in separate PRs.
- [ ] No regression test deleted, skipped, or weakened; tests moved with the code they cover.

### 9.3 Verification layers

- [ ] Compile, vet, format: `go build ./...`, `go vet ./...`, `gofmt -l .` print nothing.
- [ ] Lint and security: `golangci-lint run ./...`, `gosec -quiet ./...`, `govulncheck ./...` clean.
- [ ] Concurrency: touched packages pass `go test -race`, especially `./internal/vpn/...` and `./internal/handlers/...`.
- [ ] Locks: no new I/O under `Service.mu` or other internal mutexes; lock order unchanged; state-ownership docs updated for new fields.
- [ ] Architecture health: `python3 scripts/architecture_health.py --check --nonblocking` reports no unratcheted violation; the CI architecture-health workflow is green.
- [ ] Frontend and templates: Node/jsdom tests in `web/` run and pass with `CI=true` (a missing jsdom must fail, not skip); i18n key parity holds across all 5 locales.
- [ ] E2E and multi-backend: failover, reconnect, and lifecycle tests run when routing, session, or backend state is touched.
- [ ] Docs: affected architecture contracts and cross-references updated; Markdown files stay under 1,000 lines.

### 9.4 Leak and secret scan

- [ ] The diff contains no local filesystem paths, real hostnames, real private IPs, bot or tool identities, tokens, keys, or credentials.
- [ ] Logs and fixtures added by the PR are scrubbed.

Suggested scan:

```bash
git diff origin/main...HEAD | grep -n -E '/home/|/Users/|/mnt/[a-z]/|(^|[^0-9])(10|192\.168|172\.(1[6-9]|2[0-9]|3[01]))\.[0-9]+\.[0-9]+|BEGIN [A-Z ]*PRIVATE KEY|ghp_[A-Za-z0-9]'
```

Every hit needs a justification (for example a documentation-range address) before merge.

## 10. Maintaining This Document

- Update it in the same PR that changes a package boundary, adds a package, or changes a rule here.
- Re-verify section 3.3 whenever an import edge is added or removed.
- Keep it under 1,000 lines; move detail into a subsystem contract and link to it.
