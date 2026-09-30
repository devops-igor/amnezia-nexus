# Differential & Long-Duration Soak Suite Runbook

**Tracking Issue:** [#392](https://github.com/devops-igor/amnezia-nexus/issues/392)  
**Parent Epic:** [#384](https://github.com/devops-igor/amnezia-nexus/issues/384)  
**Target Engine:** Upstream Client-Facing AmneziaWG Engine (`amneziawg-go v3.1.20260828`)  

---

## 1. Overview & Architecture

The differential and long-duration compatibility suite proves that previously issued Nexus client configurations remain fully functional with the upstream client-facing AmneziaWG engine, and that Nexus routing, session pooling, and return paths maintain 100% parity with upstream WireGuard/AmneziaWG semantics.

```
+-----------------------------------------------------------------------------+
|                          Differential Test Harness                          |
|                                                                             |
|   +---------------------------------------------------------------------+   |
|   |                    Frozen Client Configuration                     |   |
|   |              (SHA-256 Hash + Redacted Evidence Schema)              |   |
|   +---------------------------------------------------------------------+   |
|                                     |                                       |
|               Sequential Execution on Same UDP Listen Port                  |
|                                     v                                       |
|     [ Phase 1: Reference Server ]       [ Phase 2: Nexus IngressEngine ]    |
|       - Standalone amneziawg-go           - Production IngressEngine       |
|       - Exact same portal keys            - Dynamic Backend Pools           |
|       - Standard WireGuard FIB            - Return Path Forwarder           |
|                                                                             |
|                                     v                                       |
|   +---------------------------------------------------------------------+   |
|   |                   Observable Parity Assertions                      |   |
|   |  * Handshake completion & timing  * Exact echo payload verification |   |
|   |  * TCP stream socket continuity   * Sequenced UDP loss & jitter     |   |
|   |  * Natural 10+ rekeys             * 0 crosstalk / 0 routing drops   |   |
|   +---------------------------------------------------------------------+   |
+-----------------------------------------------------------------------------+
```

### Core Design Rules
1. **Configuration Freezing:** Client configurations are rendered once (`svc.GenerateClientConfig`) and frozen with their SHA-256 digest before testing starts. Neither the reference server nor the Nexus subject server may regenerate client credentials.
2. **Sequential Port Binding:** The reference standalone server and Nexus `IngressEngine` run sequentially on the same localhost test port to eliminate port binding collisions while guaranteeing identical network conditions.
3. **Strict Privacy Invariants:** Zero private keys, zero raw server IPs, and zero local filesystem paths are ever written to disk, committed, or emitted into test output logs.

---

## 2. Local Fast Verification

Fast qualification suites run in under one minute and can be executed during local development without burdening system resources.

### Quick Start

```bash
# Run all baseline compatibility tests (~8s)
./scripts/run_differential_qualification.sh --suite baseline

# Run deterministic fault shim & parameter matrix tests (~35s)
./scripts/run_differential_qualification.sh --suite matrix

# Run fast bounded soak verification (~11s)
./scripts/run_differential_qualification.sh --suite soak

# Run lifecycle, backend migration & multi-peer concurrency tests (~6s)
./scripts/run_differential_qualification.sh --suite lifecycle

# Run all suites sequentially with bounded soak (~60s)
./scripts/run_differential_qualification.sh --suite all
```

### Runner CLI Reference (`scripts/run_differential_qualification.sh`)

| Option | Description | Default |
|---|---|---|
| `-s, --suite <suite>` | Test suite to execute (`baseline`, `matrix`, `soak`, `lifecycle`, `all`) | `all` |
| `--soak-full` | Run full unaccelerated 10+-rekey soak (~20-25m) instead of bounded soak | `false` |
| `--race` | Enable Go race detector (`-race`) | Auto-detected |
| `--no-race` | Force disable Go race detector | `false` |
| `-t, --timeout <dur>` | Test timeout duration (e.g. `20m`, `60m`) | `20m` (`60m` for soak-full) |
| `-o, --output-dir <p>`| Target directory for JSON evidence reports | `./test-artifacts` |
| `-v, --verbose` | Enable verbose shell execution | `false` |
| `-h, --help` | Show command line options and exit | |

> [!NOTE]
> **Host Architecture Auto-Detection**: On ARM64 Linux hosts running kernels with 39-bit Virtual Memory Addressing (VMA), Go's ThreadSanitizer does not support `-race` (`FATAL: ThreadSanitizer: unsupported VMA range`). The runner script automatically detects this constraint, logs an informational notice, and executes tests cleanly without failing. Full race detection runs on standard 48-bit VMA runners in GitHub Actions CI.

---

## 3. Long-Duration Soak Qualification

The soak qualification suite verifies protocol durability across extended operational periods with real-time stream quality and jitter measurement.

### Soak Test Modes

1. **Bounded Verification (`TestDifferential_Soak_BoundedVerification`)**:
   - Executes in standard CI and local verification (~11s).
   - Exercises the complete metrics engine, continuous TCP streaming, sequenced UDP stream, VoIP stream, and keepalive idle phase with a bounded rekey verification window.
2. **Full Unaccelerated 10+-Rekey Soak (`TestDifferential_Soak_Unaccelerated10Rekey`)**:
   - Gated behind `NEXUS_SOAK_FULL=true` or `--soak-full`.
   - Runs for ~20-25 minutes under natural production timing parameters.
   - Observes at least 10 unforced natural rekeys on both reference and subject engines.

### Running Full Soak Locally

```bash
# Execute full 10-rekey soak suite
./scripts/run_differential_qualification.sh --suite soak --soak-full --output-dir ./test-artifacts
```

### Key Metrics Monitored in Soak Reports

- **Long-Lived TCP Continuity (`tcp_continuity_passed`)**: Confirms the exact same TCP socket and connection remain open and able to exchange echo payloads across all rekey events and idle phases.
- **Sequenced UDP Stream (`sequenced_udp_stats`)**: 20 packets/sec with sequence numbers and timestamps, measuring packet delivery, loss rate, and maximum interruption gap.
- **VoIP Small-Datagram Stream (`voip_udp_stats`)**: 50 packets/sec (160-byte payload simulating G.711 / Opus voice frames) calculating RFC 3550 interarrival jitter:
  $$J = J + \frac{|D(i-1, i)| - J}{16}$$
- **Idle Keepalive Phase (`idle_phase_passed`)**: Confirms session survival and immediate traffic resumption after silent periods where only persistent keepalives are exchanged.

---

## 4. Dedicated CI Workflow Dispatch & Scheduled Runs

Long-duration soak testing is decoupled from fast PR CI (`.github/workflows/ci.yml`) to keep PR checks fast and responsive.

### Workflow Specification: `.github/workflows/differential-soak.yml`

- **Triggers**:
  1. `workflow_dispatch`: Manual on-demand execution with parameter selection.
  2. `schedule`: Recurring weekly automated soak run every Sunday at 02:00 UTC (`0 2 * * 0`).
- **Inputs**:
  - `suite`: `all`, `soak-full`, `soak-bounded`, `matrix`, `lifecycle`, `baseline` (default: `all`).
  - `race`: Boolean toggle for `-race` (default: `true`).

### Triggering Workflow via GitHub CLI (`gh`)

```bash
# Trigger full qualification with 10-rekey unaccelerated soak
gh workflow run differential-soak.yml -f suite=all -f race=true

# Trigger isolated 10-rekey soak only
gh workflow run differential-soak.yml -f suite=soak-full -f race=true

# Trigger fast bounded soak verification
gh workflow run differential-soak.yml -f suite=soak-bounded -f race=true
```

### Accessing Evidence Artifacts

Upon completion, the workflow bundles and uploads all generated JSON reports as a workflow artifact named `differential-qualification-evidence-<run_id>`:

```bash
# Download artifacts from the latest workflow run
gh run download --name "differential-qualification-evidence-*" --dir ./downloaded-evidence
```

Downloaded artifacts include:
- `qualification_summary.json` — overall qualification status, durations, and privacy audit results.
- `evidence_manifest.json` — environment details and redacted client configuration schema.
- `soak_report_reference_*.json` — reference standalone AWG soak report.
- `soak_report_subject_*.json` — Nexus IngressEngine soak report.
- `non_netstack_qualification.json` — Linux client network namespace qualification report.

---

## 5. Independent Non-Netstack Linux Client Qualification

The script `scripts/run_non_netstack_client_qualification.sh` qualifies the client-facing engine using a real Linux WireGuard/AmneziaWG interface inside an isolated Linux network namespace (`ip netns`), eliminating all netstack abstraction layers.

### Dry-Run Mode (Unprivileged / Safe Anywhere)

```bash
# Runs full preflight validation, plans commands, and emits report without root privileges
./scripts/run_non_netstack_client_qualification.sh --dry-run
```

### Live Network Namespace Mode (Root / Sudo)

```bash
# Execute real interface test in dedicated namespace
sudo ./scripts/run_non_netstack_client_qualification.sh \
  --interface awg-client0 \
  --netns nexus-client-ns \
  --server-port 51820 \
  --client-ip 10.100.9.2/32 \
  --output-dir ./test-artifacts
```

### Teardown & Isolation Guarantees
- **Strict Trap Handler (`trap cleanup EXIT INT TERM`)**: Guarantees that the network namespace and test interface are deleted upon script completion or premature termination.
- **Host Network Protection**: The interface and routes exist solely within the dedicated network namespace (`$NETNS`), preventing interference with the host's physical or docker interfaces.

---

## 6. Environment Variables Reference

| Variable | Description | Example / Allowed Values |
|---|---|---|
| `NEXUS_SOAK_FULL` | Enables full 10+-rekey unaccelerated soak testing | `true`, `false` |
| `NEXUS_ARTIFACT_DIR` | Custom directory for outputting JSON evidence manifests and soak reports | `./test-artifacts` |
| `GO_DIR` | Custom path to repository root for test scripts | `.` (current directory) |

---

## 7. Privacy & Security Invariants

All differential test suites and scripts adhere to non-negotiable privacy rules:

1. **Zero Private Keys**:
   - Private keys and raw secrets are never logged via `t.Logf`, written to files, or stored in artifacts.
   - Verification manifests record only `<present-32B>` or public keys.
2. **Zero Real Server IPs**:
   - Real production/development server IPs are strictly prohibited in tests, scripts, and logs.
   - Leak detection patterns in audit scripts are constructed dynamically to prevent scanner false positives.
3. **Zero Local Filesystem Paths**:
   - Absolute local filesystem paths are forbidden in checked-in scripts and documentation.
   - All paths must be repository-relative (`./scripts/...`, `tasks/...`).

---

## 8. Failure Triage & Troubleshooting

### Port Collision (`bind: address already in use`)
- **Cause**: Concurrent execution of test suites binding localhost UDP port 51820.
- **Fix**: Run test suites serially. Never run overlapping `go test` commands in parallel.

### ThreadSanitizer VMA Error (`FATAL: Found 39 - Supported 48`)
- **Cause**: Running with `-race` on ARM64 Linux kernels configured with 39-bit virtual addressing.
- **Fix**: The qualification runner script auto-detects this and runs with race detection disabled for local runs. Alternatively, pass `--no-race`. Full `-race` verification runs automatically in GitHub Actions CI.

### Handshake Timeout / Retransmission Failure
- **Cause**: Local firewall or packet filter dropping UDP datagrams on loopback.
- **Fix**: Ensure loopback (`lo`) interface is up and local UDP traffic on ports 50000-60000 is permitted.
