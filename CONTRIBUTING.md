# Contributing to Amnezia Nexus

Thanks for helping improve Nexus. This guide covers the workflow, the rules that apply to every change, and the checklist reviewers use for refactors. The full architecture rules are in [Module Ownership Conventions](docs/architecture/module-ownership-conventions.md).

## Getting started

```bash
git clone https://github.com/devops-igor/amnezia-nexus.git
cd amnezia-nexus
make build        # builds bin/panel
```

### Local setup

- **Go.** Install the Go version declared in `go.mod` (the `go` directive). Also install `golangci-lint`, `gosec`, and `govulncheck` and put `$HOME/go/bin` on `PATH`; the Make targets add it for you.
- **Node.js and jsdom.** The frontend tests in `web/` run under Node.js with `jsdom` pinned to the same version CI uses (`29.1.1`). Either install it globally:

  ```bash
  npm install -g jsdom@29.1.1
  export NODE_PATH="$(npm root -g)"
  ```

  or locally in a directory outside the repository:

  ```bash
  npm install --save-dev jsdom@29.1.1
  export NODE_PATH="$PWD/node_modules"
  ```

  Without jsdom the frontend tests skip locally; with `CI=true` they fail.
- **Docker and Trivy.** Install Docker and [Trivy](https://trivy.dev/) to build and scan the production container image locally with `make docker-scan`.
- **Python tooling.** Python 3 is needed for architecture health and its tests. Use a virtual environment outside version control or in an ignored directory (`.venv` is skipped by the scanner):

  ```bash
  python3 -m venv .venv
  . .venv/bin/activate
  python -m pip install pytest==8.3.4 pytest-cov==6.0.0   # versions CI uses
  python3 scripts/architecture_health.py --check --nonblocking
  python -m pytest tests/test_architecture_health*.py
  ```

  The health script itself needs only the standard library. Browser end-to-end tests (`tests/e2e/`) have their own requirements; see [tests/e2e/README.md](tests/e2e/README.md). Docker is needed only for end-to-end runs.

### Make targets

| Target | Runs |
|--------|------|
| `make check` | `fmt`, `vet`, `lint`, `security`, `test-race` together |
| `make test` | `go test -v ./...` |
| `make test-race` | `go test -race -v ./...` (several minutes) |
| `make lint` | `golangci-lint run ./...` |
| `make security` | `gosec` and `govulncheck` |
| `make docker-scan` | Build `amnezia-nexus:local` and scan it for HIGH and CRITICAL vulnerabilities |

Also available: `make fmt`, `make vet`, `make build`, `make test-e2e`.

### Container security scanning

Pull requests that change `Dockerfile` or `.github/workflows/docker.yml` build the local image and scan it with Trivy before any registry push. Fixed CRITICAL vulnerabilities fail the workflow; HIGH vulnerabilities are reported in the workflow summary without blocking it. Run the same local image inspection with:

```bash
make docker-scan
```

## Workflow

1. **Open or pick an issue.** Describe the problem and the expected behavior before writing code. Security problems: see "Issues and security" in the [README](README.md); do not post secrets or private keys.
2. **Branch from `main`.** Use a short descriptive name, such as `fix/<topic>-<issue>`, `feat/<topic>-<issue>`, `refactor/<topic>-<issue>`, or `docs/<topic>-<issue>`.
3. **Make the smallest complete change.** Fix the root cause once, update every caller, test, and fixture the change touches, and do not add features, options, or abstractions nobody asked for.
4. **Write tests with the change.** Bug fixes get a regression test that fails without the fix. New seams and locking rules get a test that fails when the rule is broken.
5. **Run the gates** (below) before opening the PR.
6. **Open a PR against `main`.** Link the issue, explain the why, list what you ran, and for refactors paste the checklist from this file.
7. **Review.** Address comments with new commits; do not rewrite history after review starts. Maintainers merge; do not push to `main`.

By contributing to Amnezia Nexus, you agree that your contributions will be licensed under the project's [MIT License](LICENSE).

Commit messages follow Conventional Commits with the issue number, for example:

```
fix(handlers): reject client creation on offline servers (#626)
refactor(vpn): extract backend lifecycle into its own file (#515)
docs(architecture): record module ownership conventions (#522)
```

## Core development rules

These are summarized from the [module ownership conventions](docs/architecture/module-ownership-conventions.md). Read that document before moving code between files or packages.

- **Layering.** Imports point downward: `cmd` -> `router` -> `handlers` -> `service` / `vpn` -> `manager` -> `database` -> `models` / `config` / `security`. No cycles. `models` and `config` import no operational packages. `database` and `manager` never import `vpn`, `handlers`, or `router`.
- **Split files before packages.** Extract into new files in the same package by default. Create a package only for an independent capability with a narrow public interface.
- **Mechanical moves stay mechanical.** A structural move changes no logic, error handling, or validation, and ships separately from behavior changes.
- **No I/O under locks.** Do not run database, SSH, HTTP, subprocess, or device I/O while holding `Service.mu` or another internal mutex. Snapshot, unlock, do the I/O, re-validate, commit.
- **Bound every external call** with a context timeout, and **fail closed**: on a partial failure, roll back or mark the backend degraded.
- **Never delete or weaken tests** to make a gate pass.
- **Frontend.** No new inline `<script>` bodies or inline `onclick`/`onchange` handlers. Use companion modules in `web/static/js/`, delegated listeners on `data-*` hooks, and translation keys that exist in all five locales (`en`, `fa`, `fr`, `ru`, `zh`). Write code that works under a CSP without `'unsafe-inline'`.
- **Size.** SG1 applies to every file type: warning at 500 lines, review ceiling at 1,000, no blanket exemptions. See SG1 below.
- **Secrets and privacy.** Never commit keys, tokens, passwords, real hostnames, real private IPs, or local filesystem paths. Use documentation-range addresses (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) in examples.

Related contracts: [VPN service state ownership](docs/architecture/vpn-service-state-ownership.md), [forwarder dataplane ownership](docs/architecture/forwarder-dataplane-ownership.md), [frontend JavaScript contracts](docs/architecture/frontend-javascript-contracts.md), [CSS contracts](docs/architecture/css-contracts.md).

## Quality gates

Run these from the repository root. All must be clean before review.

```bash
go build ./cmd/... ./internal/... ./web/...
go vet ./cmd/... ./internal/... ./web/...
gofmt -l .                                  # must print nothing
golangci-lint run --timeout=5m ./cmd/... ./internal/... ./web/...
gosec -quiet ./cmd/... ./internal/... ./web/...
govulncheck ./cmd/... ./internal/... ./web/...
python3 scripts/architecture_health.py --check --nonblocking
```

Then run the tests for the packages you touched with the race detector, for example:

```bash
go test -race ./internal/vpn/... ./internal/handlers/...
```

The full `go test -race ./...` takes several minutes and also runs in CI. Frontend tests need Node.js and `jsdom`; with `CI=true` a missing jsdom fails instead of skipping. Python tooling tests: `python3 -m pytest tests/test_architecture_health*.py`.

## Refactor PR Review Checklist

Copy this block into the description of any refactor, file split, or package extraction, and tick each item (or write why it does not apply).

### SG1: line-count sizing rule

> One rule for Go, tests, scripts, Markdown, JavaScript, and CSS. Warning at 500 physical lines, review ceiling at 1,000. A PR must not push a file from below 1,000 lines to 1,000 or more, or grow a file that is already at or above 1,000 lines, without a stated per-PR responsibility justification.

- [ ] No file crossed the 1,000-line ceiling and no file at or above 1,000 lines grew; **or** each exception has a written per-PR rationale (for example a single table-driven data matrix, or a benchmark harness that cannot be split without losing coverage).
- [ ] No blanket exemption is claimed for any file type (model, test, script, Markdown, JavaScript, CSS).
- [ ] Splits follow a documented concern boundary; line count is a discovery signal, not an excuse for fragmentation.
- [ ] `scripts/architecture_baseline.json` changes only by the downward ratchet, or the PR gives the same per-PR rationale for an intentional increase.

### Structure and fidelity

- [ ] Same-package split by default; any new package is an independent capability with a narrow public interface.
- [ ] Dependency direction follows the layering; no new upward or cyclic import (`go list` checked).
- [ ] Moved code is identical apart from its file; mechanical moves and behavior changes are in separate PRs.
- [ ] No regression test deleted, skipped, or weakened; tests moved with the code they cover.

### Verification layers

- [ ] Compile, vet, format: `go build ./...`, `go vet ./...`, `gofmt -l .` clean.
- [ ] Lint and security: `golangci-lint run ./...`, `gosec -quiet ./...`, `govulncheck ./...` clean.
- [ ] Concurrency: touched packages pass `go test -race`, especially `./internal/vpn/...` and `./internal/handlers/...`; no new I/O under internal mutexes; lock order unchanged.
- [ ] Architecture health: `python3 scripts/architecture_health.py --check --nonblocking` shows no unratcheted violation, and the CI architecture-health workflow is green.
- [ ] Frontend and templates: Node/jsdom tests in `web/` pass under `CI=true` without fail-open skips; i18n keys are in all 5 locales.
- [ ] E2E and multi-backend: failover, reconnect, and lifecycle tests ran when routing, session, or backend state changed.
- [ ] Docs: affected architecture contracts updated; Markdown files follow SG1 like any other file.

### Leak and secret scan

- [ ] The diff contains no local paths, real hostnames, real private IPs, bot or tool identities, tokens, keys, or credentials.
- [ ] Added logs and fixtures are scrubbed.

Suggested supplemental scan (not exhaustive):

```bash
git diff origin/main...HEAD | grep -n -E '/home/|/Users/|/mnt/[a-z]/|(^|[^0-9])(10|192\.168|172\.(1[6-9]|2[0-9]|3[01]))\.[0-9]+\.[0-9]+|BEGIN [A-Z ]*PRIVATE KEY|ghp_[A-Za-z0-9]'
```

This regex is a heuristic helper. It does not replace human or automated review for tokens, hostnames, and arbitrary credentials. Every hit needs a justification (for example a documentation-range address) before merge.

## AI-assisted contributions

Contributions written with an AI coding agent follow the same rules and the same checklist. The author is responsible for understanding every line. Agents must make the smallest complete change, keep structural moves byte-for-byte identical, preserve all tests, report real gate output (including anything not run), and stay within the authorized branch. See section 8 of the [module ownership conventions](docs/architecture/module-ownership-conventions.md) and the root [AGENTS.md](AGENTS.md).

## Documentation

Architecture contracts live in `docs/architecture/`. Update them in the same PR that changes a package boundary, lock rule, or JavaScript module contract. Markdown files follow SG1 like every other file type.
