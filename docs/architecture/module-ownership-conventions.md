# Module Ownership Conventions and Refactor PR Checklist

## 1. Purpose and Scope

This is the authoritative reference for who owns what in the Amnezia Nexus repository, which packages may import which, how to decide between splitting a file and creating a package, and how to review a refactor PR. It codifies the rules learned during the modularization program (Epic #475) and is written for human contributors and AI coding agents alike.

It indexes, and does not replace, the detailed contracts:

- [VPN Service State Ownership and Lock Contracts](vpn-service-state-ownership.md)
- [Dataplane Ownership & Concurrency Contract: Forwarder](forwarder-dataplane-ownership.md)
- [Frontend JavaScript Architecture Contracts](frontend-javascript-contracts.md)
- [CSS Architecture Contracts](css-contracts.md)

### Rule hierarchy

When rules pull in different directions, apply them in this order:

1. Preserve existing behavior, security, and data integrity.
2. Follow the owning subsystem's detailed contract.
3. Follow repository-wide architecture conventions (this document).
4. Prefer the smallest complete change (the Ponytail principle).
5. If code and documentation conflict, report the conflict. Do not silently rewrite working behavior to match a target rule.
6. Report which tests ran and which were not run.

Where this document and a detailed contract disagree, the detailed contract wins for its subsystem (rule 2); fix this document in the same PR.

Rules are marked **MUST** (enforced by review or CI) or **SHOULD** (default unless the PR states a reason). Where the code does not yet meet a rule, the gap is listed under "Known exceptions" and is not a precedent.

## 2. Component Topology and Ownership Map

### Where do I start?

Find your task, open the package, read the contract, and run the validation before review.

| Task | Package | Governing contract | Validate with |
|------|---------|--------------------|---------------|
| HTTP/API behavior | `internal/handlers/` | [Frontend JavaScript contracts](frontend-javascript-contracts.md) | Handler tests (`internal/handlers/*_test.go`); JSON schema compatibility |
| Server protocol operations | `internal/manager/` | Manager interfaces (`internal/manager/manager.go`) | Manager unit/mock tests; timeout and rollback behavior |
| VPN sessions or backends | `internal/vpn/` | [VPN service state ownership](vpn-service-state-ownership.md) | State ownership contract; `go test -race ./internal/vpn/...`; multi-backend tests |
| Dataplane and packet forwarding | `internal/vpn/forwarder/` | [Forwarder dataplane ownership](forwarder-dataplane-ownership.md) | Forwarder tests; queue/dwell tests |
| Database records or migrations | `internal/database/` | Migration conventions (section 6) | Migration tests (`database_test.go`); upgrade compatibility |
| Page behavior and UI | `web/templates/`, `web/static/js/` | [Frontend JavaScript contracts](frontend-javascript-contracts.md), [CSS contracts](css-contracts.md) | Node/jsdom tests (`web/*_test.go`); 5-locale i18n parity |

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

- One rule for every file type (Go, tests, scripts, Markdown, JavaScript, CSS). Warning at 500 physical lines, review ceiling at 1,000 (`scripts/architecture_health/constants.py`). A PR must not push a file from below 1,000 lines to 1,000 or more, or grow a file that is already at or above 1,000 lines, without a stated per-PR responsibility justification. There are no blanket exemptions. An upward change to `scripts/architecture_baseline.json` needs the same per-PR rationale.
- Line count is a discovery signal, not a goal. Do not fragment cohesive code into many tiny files to hit a number; split along concerns the contracts name.
- Mechanical moves and behavior changes **MUST** land in separate PRs.

### 4.4 Examples from this repository

- **Good same-package split:** `internal/vpn/sessions_live.go` and `internal/vpn/service_test_hooks.go` were extracted from `internal/vpn/vpn.go`. They stay in package `vpn`, so unexported state is still reachable and no caller changes.
- **Good new package:** `internal/vpn/tunnel/` is an independent tunnel pool abstraction with a narrow interface. `internal/manager/awg/cps/` is standalone obfuscation packet framing.
- **Anti-pattern:** creating a package only to reduce the line count of one file when it requires exporting private fields or creates cyclic dependency pressure. Split into files instead.

## 5. Go Concurrency and State Authority

The detailed matrices live in the two ownership contracts. This section separates three things: the target architecture (normative rules for new and modified code), the established synchronization contracts (how the code works today), and known technical debt.

### 5.1 Target architecture (normative)

1. **No I/O under locks.** Do not run database queries, SSH or HTTP calls, STUN lookups, subprocesses, device writes, or blocking channel operations while holding `Service.mu`, `Forwarder.mu`, `aggregateQueueMu`, or any other internal mutex. Pattern: snapshot under the lock, release, do the I/O, re-acquire and re-validate (compare a generation or ID), then commit.
2. **Bounded external calls.** Every operation against a remote host, database, or network peer takes a `context.Context` with an explicit timeout derived from the caller's context. Existing values to follow: 5s for per-backend health and reachability checks, 30s for registration-class operations. Do not use a bare `context.Background()` inside a request path.
3. **Fail closed with rollback.** A multi-step operation that fails midway must undo its earlier steps (best-effort compensation, logged) or leave the backend in `TunnelStatusDegraded` rather than appearing healthy. Do not report success for partial state. See the rollback semantics in `vpn-service-state-ownership.md` section 4.4.
4. **Goroutine lifecycle.** Every goroutine has a documented stop condition (context cancel or close channel) and is joined on shutdown. No fire-and-forget goroutines that capture mutable state.
5. **Race tests.** Changes under `internal/vpn/...`, `internal/handlers/...`, `internal/service/...`, or `internal/manager/...` **MUST** pass `go test -race` for the touched packages. New concurrent code needs a test that would fail under `-race` or deadlock detection if the lock discipline were broken.

### 5.2 Established synchronization contracts

These describe the code as it is. Follow them exactly; change them only through the owning contract.

1. **One owner per piece of state.** Every mutable field has exactly one guarding lock or is atomic. Check the field's row in `vpn-service-state-ownership.md` before touching it; add a row when you add a field.
2. **`Service.mu`** guards tunnel pool membership, backend enable/disable, backend device maps, `cfg`, lifecycle flags (`running`, `startedAt`), and the in-memory admission state.
3. **`SessionManager.mu`** guards the live session maps. Lock order is `Service.mu` -> `SessionManager.mu`, never the reverse.
4. **`Forwarder.mu`** guards routes, queues, and backend device maps. `Forwarder.mu` and `sessionRoute.writeMu` are disjoint. Never call `Retirement.Wait()` while holding `Forwarder.mu` or `Service.mu`. Run callbacks and classifiers after releasing the lock. The full lock graph is in `forwarder-dataplane-ownership.md` section 5.

### 5.3 Known technical debt

Existing code still makes database calls under `Service.mu`; `vpn-service-state-ownership.md` section 3.1 inventories them. This debt is not license. **MUST NOT** add to the inventory. **SHOULD** eliminate the affected calls when a PR modifies those paths. Do not rewrite working behavior outside the PR's scope to clear debt (rule 5 of the hierarchy); report it instead.

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
5. **Sizing.** JS and CSS files follow SG1 (section 4.3) like every other file type; one concern per file; load order is declared in the template and documented in the contracts.
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

The single authoritative checklist is in [`CONTRIBUTING.md`](../../CONTRIBUTING.md#refactor-pr-review-checklist). Copy it from there into the PR description for any refactor, file split, or package extraction. It is not duplicated here, so it cannot drift.

The safeguards it enforces:

- **SG1 sizing.** One rule for all file types (section 4.3). Exceptions and upward baseline changes need a per-PR rationale; no blanket exemptions.
- **Structure and fidelity.** Same-package split by default; layering holds; moved code is identical; mechanical moves and behavior changes ship separately; no test deleted or weakened.
- **Verification layers.** Compile, vet, format, lint, security, race tests, architecture health, frontend/i18n tests, and E2E where routing or backend state changed. Report what ran and what did not (rule 6 of the hierarchy).
- **Leak and secret scan.** A human or automated review for local paths, hostnames, private IPs, tokens, and credentials. The checklist's regex is a supplemental heuristic (not exhaustive) and does not replace that review.

## 10. Maintaining This Document

- Update it in the same PR that changes a package boundary, adds a package, or changes a rule here.
- Re-verify section 3.3 whenever an import edge is added or removed.
- Keep it within SG1 (section 4.3); move detail into a subsystem contract and link to it.
