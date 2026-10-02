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
3. **Strict Privacy Invariants:** Zero private keys, zero raw server IPs, and zero local filesystem paths are ever persisted in artifacts, committed, or emitted into test output logs.

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
| `--soak-full` | Run full unaccelerated 10+-rekey soak (~40-50m total, ~20-25m each) instead of bounded soak | `false` |
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
   - Runs both Reference standalone AWG and Subject Nexus IngressEngine sequentially (~40-50m total, ~20-25m each) under natural production timing parameters.
   - Observes at least 10 unforced natural rekeys on both Reference and Subject engines.

### Running Full Soak Locally

```bash
# Execute full 10-rekey soak suite
./scripts/run_differential_qualification.sh --suite soak --soak-full --output-dir ./test-artifacts
```

### Key Metrics Monitored in Soak Reports

- **Long-Lived TCP Continuity (`tcp_continuity_passed`)**: Confirms the exact same TCP socket and connection remain open and able to exchange echo payloads across all rekey events and idle phases.
- **Sequenced UDP Stream (`sequenced_udp_stats`)**: 20 packets/sec with sequence numbers and timestamps, measuring packet delivery, loss rate, and maximum interruption gap.
- **VoIP Small-Datagram Stream (`voip_udp_stats`)**: 50 packets/sec (160-byte payload simulating G.711 / Opus voice frames) measuring Round-Trip Time (RTT) delay variation (`rtt_jitter_ns`) / RTT jitter based on consecutive response arrival variance:
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
- `qualification_summary.json`: overall qualification status, durations, and privacy audit results.
- `evidence_manifest.json`: environment details and redacted client configuration schema.
- `soak_report_reference_*.json`: reference standalone AWG soak report.
- `soak_report_subject_*.json`: Nexus IngressEngine soak report.
- `non_netstack_qualification.json`: Linux client network namespace qualification report.

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
# Execute real interface test in dedicated namespace with client configuration
sudo ./scripts/run_non_netstack_client_qualification.sh \
  --config ./client.conf \
  --output-dir ./test-artifacts

# Or specify individual credentials and server parameters
sudo ./scripts/run_non_netstack_client_qualification.sh \
  --server-public-key <server-pubkey> \
  --client-private-key <client-privkey> \
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

## 6. DEV Server E2E Qualification Workflow (`.github/workflows/e2e-dev.yml`)

The DEV Server E2E workflow integrates upstream qualification directly into the continuous DEV deployment pipeline.

### Qualification Modes

The workflow accepts a `qualification` input via `workflow_dispatch`:

| Mode | Duration | Description | Artifacts Generated |
|---|---|---|---|
| `standard` | ~15-20m | Skips extended differential qualification; runs standard DEV server build, deployment, and integration tests. | Standard DEV E2E logs |
| `bounded` (default) | ~20-25m | Runs baseline, matrix, lifecycle, and bounded soak qualification suites plus live non-netstack client qualification and fail-closed evidence verification. | Full differential suite + live client reports |
| `full` | ~60-75m | Runs all qualification suites including full unaccelerated 10+-rekey soak (~40-50m), live non-netstack client qualification, and fail-closed evidence verification. | Full soak manifests (>=10 rekeys) + live client reports |

### Execution Flow in E2E Pipeline

```
[DEV Deploy] 
    |
    v
[Directory Prep: test-artifacts/runtime & test-artifacts/public]
    |
    v
[Differential Qualification Suite (bounded or full)]
    |
    v
[Start Upstream Qualification Subject (cmd/qualification-subject)]
    |  - Initializes isolated DB & portal identity
    |  - Freezes client config to test-artifacts/runtime/frozen-client.conf (0600)
    |  - Starts netstack echo responders (TCP/UDP on port 40001)
    |  - Starts production IngressEngine on UDP 51820
    |  - Emits subject.ready JSON status file
    v
[Live Non-Netstack Client Qualification (scripts/run_non_netstack_client_qualification.sh)]
    |  - Executes in isolated netns (nexus-client-ns)
    |  - Verifies handshake, bi-directional TCP echo, UDP echo, reconnect resilience
    v
[Stop Upstream Qualification Subject (SIGTERM)]
    |
    v
[Upstream Restart Durability Rehearsal (scripts/run_upstream_restart_durability.sh)]
    |  - Executes 3 restart legs across reused SQLite DB
    |  - Verifies exact same frozen client config and port across restarts
    |  - Emits upstream_restart_durability.json (and dual_engine_rollback_rehearsal.json)
    v
[Evidence Aggregator Verification (scripts/verify_issue392_qualification.sh)]
    |  - Fail-closed validation of public reports and metrics
    v
[Upload Public Artifacts (test-artifacts/public/)]
    |
    v
[Unconditional Teardown (if: always())]
    - Terminate qualification subject process
    - Delete nexus-client-ns netns and veth/awg interfaces
    - Delete test-artifacts/runtime/ (wiping all ephemeral private keys)
```

---

## 7. Artifact Separation & Evidence Aggregator

### Strict Separation: Runtime vs. Public Artifacts

To prevent secret leakage in CI runs and uploaded artifacts, the qualification harness enforces strict physical directory separation:

1. **`test-artifacts/runtime/` (SECRET-BEARING, NEVER UPLOADED)**:
   - Contains frozen client configuration (`frozen-client.conf`) with private keys.
   - Contains ephemeral key files for `awg set`.
   - Permissions enforced: `chmod 600` / `umask 077`.
   - Wiped unconditionally during teardown (`rm -rf test-artifacts/runtime`).
2. **`test-artifacts/public/` (PUBLIC EVIDENCE, UPLOADED)**:
   - Contains only sanitized, redacted JSON reports:
     - `qualification_summary.json`
     - `evidence_manifest.json`
     - `soak_report_reference_*.json`
     - `soak_report_subject_*.json`
     - `non_netstack_qualification.json`
     - `upstream_restart_durability.json` (legacy alias: `dual_engine_rollback_rehearsal.json`)
     - `issue392_qualification_summary.json`
   - Zero private keys, zero raw server IPs, zero local paths.
   - Uploaded as GitHub Actions workflow artifact.

### Evidence Aggregator CLI (`scripts/verify_issue392_qualification.sh`)

The evidence aggregator verifies that all qualification requirements are strictly satisfied before passing CI:

```bash
# Verify bounded qualification evidence
./scripts/verify_issue392_qualification.sh \
  --artifacts-dir test-artifacts/public \
  --mode bounded \
  --expected-commit <sha>

# Verify full qualification evidence (enforces >=10 unforced rekeys, closure eligible)
./scripts/verify_issue392_qualification.sh \
  --artifacts-dir test-artifacts/public \
  --mode full \
  --expected-commit <sha>
```

### Assertions Enforced by Aggregator:
1. **Required Files**: Checks presence of all public JSON manifests.
2. **Pinned Dependency**: Validates upstream engine dependency is pinned to `golang.zx2c4.com/amneziawg v3.1.20260828`.
3. **Commit Identity**: Confirms git commit matches expected commit SHA (`--expected-commit`).
4. **Lifecycle & Matrix Results**: Verifies `status == "PASS"` across all fault shims and backend migrations.
5. **Soak Duration & Closure Eligibility**:
   - `bounded` mode: at least 1 rekey observed on both Reference and Subject engines; emits `BOUNDED PASS` (`issue392_closure_eligible: false`).
   - `full` mode: at least 10 unforced rekeys observed on both Reference and Subject engines; emits `FULL PASS` (`issue392_closure_eligible: true`).
6. **Network Quality Metrics**:
   - `tcp_continuity_passed == true` (no dropped TCP stream sockets across rekeys).
   - `idle_phase_passed == true` (keepalive recovery after silent intervals).
   - Sequenced UDP packet loss <= 0.05%.
7. **Non-Netstack Client Parity**:
   - Confirms `status == "PASS"`, handshake established, TCP echo passed, UDP echo passed, and reconnect resilience passed.
8. **Privacy Compliance Audit**:
   - Zero private keys, zero raw IP addresses, zero local filesystem paths in any public artifact.

---

## 8. Environment Variables Reference

| Variable | Description | Example / Allowed Values |
|---|---|---|
| `NEXUS_SOAK_FULL` | Enables full 10+-rekey unaccelerated soak testing | `true`, `false` |
| `NEXUS_ARTIFACT_DIR` | Custom directory for outputting JSON evidence manifests and soak reports | `./test-artifacts` |
| `GO_DIR` | Custom path to repository root for test scripts | `.` (current directory) |

---

## 9. Privacy & Security Invariants

All differential test suites and scripts adhere to non-negotiable privacy rules:

1. **Zero Private Keys & Secrets Retention**:
   - Private keys and raw secrets are never persisted in artifacts or emitted in logs (`t.Logf`, stderr, JSON manifests).
   - In live interface qualification, ephemeral 0600 temporary files may be created solely for `awg set` (which requires file inputs for keys) and are removed immediately after configuration and by the cleanup trap.
   - Verification manifests record only `<present-32B>`, `<absent>`, or public keys.
2. **Zero Real Server IPs**:
   - Real production/development server IPs are strictly prohibited in tests, scripts, and logs.
   - Leak detection patterns in audit scripts are constructed dynamically to prevent scanner false positives.
3. **Zero Local Filesystem Paths**:
   - Absolute local filesystem paths are forbidden in checked-in scripts and documentation.
   - All paths must be repository-relative (`./scripts/...`, `tasks/...`).

---

## 10. Failure Triage & Troubleshooting

### Port Collision (`bind: address already in use`)
- **Cause**: Concurrent execution of test suites binding localhost UDP port 51820.
- **Fix**: Run test suites serially. Never run overlapping `go test` commands in parallel.

### ThreadSanitizer VMA Error (`FATAL: Found 39 - Supported 48`)
- **Cause**: Running with `-race` on ARM64 Linux kernels configured with 39-bit virtual addressing.
- **Fix**: The qualification runner script auto-detects this and runs with race detection disabled for local runs. Alternatively, pass `--no-race`. Full `-race` verification runs automatically in GitHub Actions CI.

### Handshake Timeout / Retransmission Failure
- **Cause**: Local firewall or packet filter dropping UDP datagrams on loopback.
- **Fix**: Ensure loopback (`lo`) interface is up and local UDP traffic on ports 50000-60000 is permitted.

---

## 11. Upstream Engine Durability, Restart Recovery & Operational Runbook

This section provides step-by-step operational procedures for running the upstream AmneziaWG ingress engine, executing isolated canary qualification, verifying restart durability, conducting production restarts, and monitoring data-plane health.

> [!NOTE]
> Following Epic #394 (Issues #418–#423), the upstream AmneziaWG ingress engine is the sole, permanent client-facing engine in Amnezia Nexus. The legacy custom engine and dual-engine switch machinery have been decommissioned.

### 11.1 Engine Invariants & Architecture

- **Engine Standard**: The upstream AmneziaWG engine (`IngressEngine`) runs unconditionally in userspace memory using `VirtualTUN` and `forwarder.ReturnPath`.
- **Legacy TUN Bypass Invariant**: The client-facing Linux TUN device (`/dev/net/tun`) is NOT opened or attached for client traffic.
- **Zero Config Regeneration Invariant**: Client keypairs, assigned IPs, and WireGuard credentials stored in SQLite remain 100% durable across service restarts and reboots. Reissuing configurations is never required for normal restarts.
- **Clean Quiescence & Drain Invariant**: Engine shutdown fences admission, closes return paths, drains route queues, unmaps routing tables, and bounds write joins with a 5-second deadline, guaranteeing `activeRoutes == 0`, `occupancy == 0`, and `return_route_owner == "none"` upon stop.

### 11.2 Pre-Flight Checks

Before performing any deployment, upgrade, or maintenance:

1. **Verify Database Integrity**:
   ```bash
   sqlite3 /data/nexus.db "PRAGMA integrity_check;"
   # Expected output: ok
   ```
2. **Verify Client Connection Records**:
   ```bash
   sqlite3 /data/nexus.db "SELECT count(*), count(DISTINCT client_id) FROM user_connections;"
   ```
3. **Check Port Availability & Process Binding**:
   ```bash
   ss -ulpn 'sport = :51820'
   ```
4. **Baseline Health & Telemetry Check**:
   ```bash
   curl -s http://127.0.0.1:8080/api/health | jq .
   # Verify status is "ok" and active_engine: "upstream", return_route_owner are reported
   ```

### 11.3 Dedicated-Port Canary Procedure

Before cutting over major configuration changes on the primary listen port, validate in a non-disruptive canary setup:

1. **Provision Staging/Canary Environment**:
   - Clone the production database to a staging or sandbox host:
     ```bash
     sqlite3 /data/nexus.db ".backup '/data/nexus-canary.db'"
     ```
   - Set a dedicated, non-colliding listen port (e.g., `51821`):
     ```bash
     sqlite3 /data/nexus-canary.db "UPDATE vpn_config SET listen_port = 51821, public_endpoint = '198.51.100.1:51821';"
     ```
2. **Launch Canary Instance**:
   ```bash
   export DB_PATH=/data/nexus-canary.db
   docker compose -f docker-compose.canary.yml up -d
   ```
3. **Verify Canary Initialization**:
   ```bash
   docker compose -f docker-compose.canary.yml logs | grep "active client AWG engine"
   # Expected: [vpn] active client AWG engine=upstream listen_port=51821
   ```
4. **Validate With Test Client Configurations**:
   - Connect a test client using an existing configuration pointing to port `51821`.
   - Validate bidirectional data plane packet delivery (TCP stream + UDP ping).
   - Inspect `/api/vpn/status` to ensure `peer_sync.in_sync == true` and `return_route_owner == "upstream"`.
5. **Teardown Canary**:
   ```bash
   docker compose -f docker-compose.canary.yml down -v
   ```

### 11.4 Same-Port Durability Rehearsal Procedure

Verify that service restarts with the same DB and port preserve all client state and connectivity:

1. **Run Automated Same-Port Integration Rehearsal**:
   ```bash
   go test -v ./internal/vpn -run "TestUpstream_SameDBSamePortSameConfigDurability"
   ```
   *Expected outcome*: Passes all phases cleanly with transition progression:
   `none -> upstream -> none -> none -> upstream -> none -> none -> upstream -> none`.

   Or run the end-to-end Linux network namespace durability rehearsal script:
   ```bash
   sudo ./scripts/run_upstream_restart_durability.sh
   # (legacy wrapper ./scripts/run_dev_rollback_rehearsal.sh forwards here)
   ```

2. **Manual In-Situ Rehearsal (Maintenance Window)**:
   - **Step A (Record Baseline)**:
     ```bash
     # Capture frozen client config hash
     sha256sum /etc/amnezia-nexus/test-client.conf > ./client-hash.txt
     ```
   - **Step B (Restart Service)**:
     ```bash
     systemctl restart nexus-vpn
     curl -s http://127.0.0.1:8080/api/health | jq '{active_engine, return_route_owner}'
     # Expected immediately post-restart (0 active sessions):
     # {"active_engine": "upstream", "return_route_owner": "none"}
     ```
   - **Step C (Verify Client Traffic)**:
     Transmit bidirectional test packets from test client; verify 0 packet loss.
     ```bash
     curl -s http://127.0.0.1:8080/api/health | jq '{active_engine, return_route_owner}'
     # Expected after client traffic admitted:
     # {"active_engine": "upstream", "return_route_owner": "upstream"}
     ```
   - **Step D (Assert Client Config Integrity)**:
     Verify `./client-hash.txt` matches current client config.

### 11.5 Production Pre-Flight Checklist & Operational Gates

All five gates MUST be satisfied and signed off before deploying updates in production:

| Gate # | Requirement | Verification Command | Gate Pass Criteria |
|---|---|---|---|
| **Gate 1** | Database Integrity & Schema | `sqlite3 /data/nexus.db "PRAGMA integrity_check;"` | Strictly `ok`; zero orphaned rows |
| **Gate 2** | Differential Compatibility Suite | `./scripts/run_differential_qualification.sh --suite all` | 100% test pass; 0 regressions |
| **Gate 3** | Same-Port Durability Rehearsal | `go test -v ./internal/vpn -run "TestUpstream_SameDBSamePortSameConfigDurability"` | PASS; zero route or socket leaks |
| **Gate 4** | Peer Synchronization State | `curl -s http://127.0.0.1:8080/api/vpn/status \| jq .peer_sync` | `in_sync: true`, `desired == actual` |
| **Gate 5** | Telemetry Endpoint Parity | `curl -s http://127.0.0.1:8080/api/health \| jq .` | `configured_engine: "upstream"`, `active_engine: "upstream"` |

### 11.6 Production Deployment & Restart Procedure

1. **Execute Controlled Restart**:
   ```bash
   # Docker Compose deployment:
   docker compose restart nexus-vpn

   # Or systemd deployment:
   systemctl restart nexus-vpn
   ```
2. **Verify Startup Log Output**:
   Check service logs for canonical engine startup marker:
   ```bash
   docker compose logs --tail=50 nexus-vpn | grep "active client AWG engine"
   # Expected output:
   # [vpn] active client AWG engine=upstream listen_port=51820
   ```
3. **Inspect Health and Status Endpoints**:
   ```bash
   # System Health (immediately post-restart with 0 active sessions):
   curl -s http://127.0.0.1:8080/api/health | jq '{status, configured_engine, active_engine, return_route_owner, engine_running}'
   # Expected response:
   # {
   #   "status": "ok",
   #   "configured_engine": "upstream",
   #   "active_engine": "upstream",
   #   "return_route_owner": "none",
   #   "engine_running": true
   # }

   # VPN Data Plane Status (immediately post-restart with 0 active sessions):
   curl -s http://127.0.0.1:8080/api/vpn/status | jq '{configured_engine, active_engine, return_route_owner, engine_running, peer_sync}'
   # Expected response:
   # {
   #   "configured_engine": "upstream",
   #   "active_engine": "upstream",
   #   "return_route_owner": "none",
   #   "engine_running": true,
   #   "peer_sync": {
   #     "desired_peers": N,
   #     "actual_peers": N,
   #     "in_sync": true
   #   }
   # }
   ```
4. **Verify Live Data Plane Traffic**:
   - Confirm handshake completions: `[vpn/ingress] admitted peer <key>...`.
   - Verify bidirectional payload forwarding across active peers.
   - Confirm aggregate queue occupancy and route counts via `/api/vpn/status`.
   - Confirm return route owner transitions to `"upstream"` once active routes are registered:
     ```bash
     curl -s http://127.0.0.1:8080/api/health | jq '{active_engine, return_route_owner}'
     # Expected response: {"active_engine": "upstream", "return_route_owner": "upstream"}
     ```

### 11.7 Monitoring Thresholds & Operational Alerts

| Trigger ID | Failure Condition | Threshold | Monitoring Source | Remediation Action |
|---|---|---|---|---|
| **TR-01** | Synthetic Client Connectivity Failure | Known-good synthetic probe fails bidirectional traffic within `30s` or `> 3` consecutive connection timeouts | Automated synthetic probe / test client | Inspect network underlay, firewall, and backend tunnel reachability |
| **TR-02** | Unrouted / Return Route Drops | `> 10 drops/min` for active client sessions | `/api/vpn/status` (`return_counters`) | Inspect peer route registration and routing table integrity |
| **TR-03** | Peer Sync Divergence | `in_sync == false` or `desired != actual` for `> 60s` | `/api/vpn/status` (`peer_sync`) | Trigger manual reconciliation or inspect SQLite connection rows |
| **TR-04** | Client Queue Full Drops | `> 50 drops/min` across forwarder client queues | Forwarder metrics (`drops_queue_full`) | Inspect backend egress capacity or host socket buffer sizing |
| **TR-05** | Service Crash / Panic Loop | Any panic, unexpected exit, or crash restart | Systemd / Docker daemon restart logs | Review panic trace, restore from backup DB if database corruption is detected |
| **TR-06** | Packet Loss Spike | `> 5.0%` sustained UDP packet loss across active tunnels over 5-minute rolling window | Prometheus / node exporter metrics | Inspect WAN link to backend servers |

### 11.8 Incident Response & Disaster Recovery

When operational issues occur in production:

1. **Service Restarts**:
   - Upstream engine restarts are safe, zero-mutation operations. Connected client sessions are cleaned up, and clients reconnect automatically on their next keepalive or packet transmission.
2. **Database Recovery**:
   - If SQLite corruption is detected via `PRAGMA integrity_check`, restore from the most recent verified backup (`.backup`).
   - Run `PRAGMA integrity_check;` on the restored file before starting the service.
3. **Configuration Verification**:
   - Verify listening port and public endpoint via `/api/vpn/status`.
   - Verify peer sync counts match active users in `user_connections`.


