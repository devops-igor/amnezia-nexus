# AGENTS.md

> **Scope**: Repository architecture and navigation conventions only. This document does not define agent profile identity, role, or operational permissions, and does not override agent system prompts, profile instructions (`SOUL.md`), hard constraints, or safety policies.

Navigation hub for AI coding assistants working in Amnezia Nexus. It is deliberately short: follow the links for detail.

## Rule hierarchy

When rules conflict, apply them in this order:

0. Never override agent profile identity, hard constraints, or system safety policies.
1. Preserve existing behavior, security, and data integrity.
2. Follow the owning subsystem's detailed contract.
3. Follow repository-wide architecture conventions.
4. Prefer the smallest complete change (Ponytail principle).
5. If code and documentation conflict, report the conflict. Do not silently rewrite working behavior to match a target rule.
6. Report which tests ran and which were not run.

## Ponytail principle

Make the smallest complete change. Fix the root cause once and update every caller, test, and fixture it touches. Add no abstraction, wrapper, option, or feature nobody asked for. Never delete or weaken a test to make a gate pass. Keep structural moves identical to the original code and ship them separately from behavior changes.

## Where do I start?

Task-based lookup (package, governing contract, validation) is in [Where do I start?](docs/architecture/module-ownership-conventions.md#where-do-i-start). In short:

| Task | Start in |
|------|----------|
| HTTP/API behavior | `internal/handlers/` |
| Server protocol operations | `internal/manager/` |
| VPN sessions or backends | `internal/vpn/` |
| Dataplane and packet forwarding | `internal/vpn/forwarder/` |
| Database records or migrations | `internal/database/` |
| Page behavior and UI | `web/templates/`, `web/static/js/` |

## Documents

- [CONTRIBUTING.md](CONTRIBUTING.md): workflow, local setup, quality gates, and the single Refactor PR Review Checklist.
- [Module ownership conventions](docs/architecture/module-ownership-conventions.md): package ownership, dependency direction, file-versus-package guidance, lock contracts, sizing rule SG1.
- Subsystem contracts (these win for their subsystem):
  - [VPN service state ownership](docs/architecture/vpn-service-state-ownership.md)
  - [Forwarder dataplane ownership](docs/architecture/forwarder-dataplane-ownership.md)
  - [Frontend JavaScript contracts](docs/architecture/frontend-javascript-contracts.md)
  - [CSS contracts](docs/architecture/css-contracts.md)

## Commands

| Command | Purpose |
|---------|---------|
| `make check` | format, vet, lint, security, race tests |
| `make test` | `go test -v ./...` |
| `make test-race` | `go test -race -v ./...` |
| `make lint` | `golangci-lint run ./...` |
| `make security` | `gosec` and `govulncheck` |

Run the full gate list in [CONTRIBUTING.md](CONTRIBUTING.md#quality-gates) before review, including `python3 scripts/architecture_health.py --check --nonblocking`.

## Hard limits

- Size rule SG1 applies to every file type: warning at 500 lines, review ceiling at 1,000. A PR must not cross or grow past the ceiling without a stated per-PR justification.
- No new I/O under `Service.mu` or other internal mutexes. Bound every external call with a context timeout.
- No new inline `<script>` or inline event handlers; every user-visible string exists in all five locales.
- Never commit secrets, real hostnames, real private IPs, or local filesystem paths.
- Stay in the authorized branch: no pushes, merges, or history rewrites unless the task says so. Stage files by explicit path.
