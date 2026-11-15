# Contributing to Amnezia Nexus

Thanks for helping improve Nexus. This guide covers setup, testing and how to
submit a change. Engineering invariants live in [Module Ownership
Conventions](docs/architecture/module-ownership-conventions.md); AI agent
instructions live in [AGENTS.md](AGENTS.md).

## Getting started

```bash
git clone https://github.com/devops-igor/amnezia-nexus.git
cd amnezia-nexus
make build        # builds bin/panel
```

**Go**, at the version in `go.mod`, with `golangci-lint`, `gosec` and
`govulncheck` on `PATH`, is required for every change. Add **Node.js with
`jsdom@29.1.1`** for the `web/` frontend tests (`npm install -g jsdom@29.1.1`,
`export NODE_PATH="$(npm root -g)"` — without it they skip locally and fail with
`CI=true`), **Python 3** for `scripts/architecture_health.py`, and **Docker** for
container, scan and end-to-end work. Browser suites have their own
prerequisites: [tests/e2e/README.md](tests/e2e/README.md).

## Development workflow

1. **Open or pick an issue.** Describe the problem and the expected behavior
   before writing code. Security problems: see "Issues and security" in the
   [README](README.md); do not post secrets or private keys.
2. **Branch from `main`**: `fix/<topic>-<issue>`, `feat/...`, `refactor/...` or
   `docs/...`.
3. **Make the smallest complete change.** Fix the root cause once, update every
   caller, test and fixture it touches, and add nothing nobody asked for.
4. **Write tests with the change.** Bug fixes get a regression test that fails
   without the fix; new rules get a test that fails when the rule is broken.
   Never delete or weaken a test to make a gate pass.
5. **Run the checks that cover your change**, then open a PR that links the
   issue and states what you ran and what you could not run.
6. **Address review with new commits.** Do not rewrite history once review has
   started. Maintainers merge; do not push to `main`.

## Testing

CI runs the full required suite. Locally, run what your change touches plus the
cheap gates: for a Go change, the affected packages with `-race`, plus format,
vet and lint.

| Command | Runs |
|---------|------|
| `make build` | builds `bin/panel` |
| `make test` / `make test-race` | unit tests / with the race detector |
| `make lint` / `make security` | `golangci-lint` / `gosec` and `govulncheck` |
| `make fmt` / `make fmt-check` | formats the tree / verifies it is formatted |
| `make check` | `fmt-check`, `vet`, `lint`, `security`, full race suite |
| `make test-e2e` / `make docker-scan` | Playwright suites / Trivy image scan |

The `with_utls` build tag is required; the Make targets and CI set it through
`GOFLAGS`, so set `GOFLAGS=-tags=with_utls` yourself if you call `go` directly.
`make fmt` rewrites files and `make check` uses `fmt-check`, so a verification
run never edits the tree it is checking.

Report any check you could not run. Do not let it be implied that it passed.

## Development standards

- **Read the owning contract first.** Layering, file-versus-package
  decomposition, SG1 sizing, lock ownership, external timeouts, CSP and the
  five-locale string rule are in [Module Ownership
  Conventions](docs/architecture/module-ownership-conventions.md), which you
  update in the same PR that changes a boundary. Subsystem contracts:
  [VPN state](docs/architecture/vpn-service-state-ownership.md),
  [forwarder](docs/architecture/forwarder-dataplane-ownership.md),
  [JavaScript](docs/architecture/frontend-javascript-contracts.md),
  [CSS](docs/architecture/css-contracts.md).
- **Fail closed.** Bound every external call with a context timeout, and roll
  back or mark the backend degraded on partial failure.
- **No secrets or private infrastructure** in code, tests, commits, PR text or
  examples: no tokens, keys, real hostnames, real private IPs or local paths.
  Use documentation-range addresses (`192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24`).
- **AI-assisted contributions** follow the same rules, and the author is
  responsible for every line.

## Pull requests

Commit messages follow Conventional Commits with the issue number, e.g.
`fix(handlers): reject client creation on offline servers (#626)`.

Link the issue, explain the why, and list what you ran and what you did not.
Reviewers apply the criteria in section 9 of the [module ownership
conventions](docs/architecture/module-ownership-conventions.md#9-refactor-review-criteria).

## License

By contributing, you agree that your contributions are licensed under the
project's [MIT License](LICENSE).
