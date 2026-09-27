# AWG migration preflight (#386)

Run the standalone auditor before enabling the future upstream client-facing
engine. It reads the existing database; it does not start Nexus, bind a port,
install peers, run migrations, repair collisions, or close `vpn_sessions`.

```sh
go build -o awg-preflight ./cmd/awg-preflight
./awg-preflight -db data/panel.db -secret-key-file data/.secret_key
```

Alternatively provide the existing application `SECRET_KEY` in the environment.
The command never generates or persists a secret. Do not pass secret values on
the command line. Reports contain connection/user IDs, public keys, and assigned
IPs, but no private keys, encryption secret, client parameters, or decrypted
configuration. Treat reports as administrative data.

The database is opened with `mode=ro` and `query_only=ON`, without the normal
`database.Open` initialization/migration path. A single transaction reads config,
connections, and owners, including committed WAL data. SQLite may use its existing
WAL shared-memory sidecar for reader coordination; no application rows or schema
are changed. Use normal SQLite permissions for reading a live WAL database; do
not copy just `panel.db` from a running instance or use `immutable=1`.

## Report and exit status

- Exit **0**: `ready=true`; persisted identity and eligible peer data pass preflight.
- Exit **1**: `ready=false`; the JSON report identifies blocking validation errors.
- Exit **2**: usage, secret input, database access, or incompatible schema failure.

Each portal connection has one status:

- `valid`: eligible owner and valid, unique public key and assigned IPv4 `/32`.
- `excluded`: disabled/expired/quota-exhausted owner, or an existing
  `config_regeneration_required` / `quarantined_ip_collision` marker. These rows
  remain untouched and do not prevent other peers passing. Their incomplete
  identity is not repaired or installed. Re-enabling them requires a fresh audit.
- `invalid`: malformed or conflicting active identity, missing owner, malformed
  expiry, or invalid client parameters. These rows block readiness. Every active
  claimant of a duplicate key or IP is rejected; row order never chooses a winner.

The `peers` array contains deterministic candidate definitions ordered by
connection ID. Consumers **must check `ready` before installing any peer**; a
blocked report may still describe individually valid rows. The public-key and
`allowed_ip` fields can be rendered as UAPI through `Peer.UAPI()`.

Validation includes legacy `awg2` / `awg_legacy` protocol aliases, source ownership
within the persisted subnet, reserved network/gateway/broadcast addresses,
canonical 32-byte base64 keys and low-order public-key rejection, retained client
private/public-key agreement, and decryption/derivation of the exact portal
identity. Missing client private keys block lossless future config regeneration.
Legacy plaintext portal private keys are reported, never automatically encrypted
or substituted. Unknown/missing database schema is rejected without upgrading it.

## Scope of readiness

This is a database compatibility gate, not a wire-compatibility or production
cutover gate. No endpoint, port, H/S/header-protection value, client timing value,
key, or address is rewritten. The auditor does not prove that all AWG parameter
combinations work with upstream; unchanged-config traffic tests and the upstream
S4 fix remain separate requirements of #384/#392. Runtime session invalidation
belongs to the later controlled restart, not to this audit.

The report is a point-in-time snapshot, not a persistent authorization registry.
Re-audit immediately before activation. #387/#391 must enforce current eligibility
and synchronize changes after activation; do not use this report as a lasting
authorization cache. No second peer table or schema migration is introduced, so
the same database remains readable by the existing engine on rollback.

```sh
go test -race ./internal/vpn/preflight ./internal/database ./cmd/awg-preflight
```

Tests exercise invalid/quarantined rows, duplicate claims, deterministic output,
secret redaction, exact database preservation, legacy-reader compatibility,
uncheckpointed WAL visibility, and consistent snapshots during eligibility changes.
