# VPN Service State Ownership and Lock Contracts

## 1. Overview & Architectural Role

The `Service` struct in `internal/vpn/vpn.go` is the central orchestrator for the VPN subsystem. It coordinates the endpoint listener, upstream client ingress engine, backend tunnel pool, dynamic load balancing, packet forwarding, session lifecycle, traffic accounting, and operational diagnostics.

Prior to decomposing `Service` into specialized sub-services and smaller components (Phase 4 / Issue #91), this document defines the canonical state ownership, synchronization hierarchy, I/O boundary contracts, and concurrency invariants across all fields and methods of `Service`.

Subsequent refactoring, method extraction, or struct decomposition MUST adhere to the invariants established in this document to prevent race conditions, deadlocks, capacity counter drift, memory leaks, and state corruption.

---

## 2. State Field Ownership & Synchronization Matrix

The table below audits every field in the `Service` struct (`internal/vpn/vpn.go`), detailing the governing synchronization primitive, mutation stages, authoritative backing store, and permissible I/O boundaries while synchronization primitives are held.

| # | Field Name | Type | Guarding Primitive | Mutation Lifecycle Paths | Authority | I/O Boundary Rules & Technical Debt |
|---|---|---|---|---|---|---|
| 1 | `retiredIngressLosses` | `ingressLossTotals` | `s.mu.Lock` | `Start`, `Stop` | In-memory | Prohibits all I/O. Memory-only accumulator for closed engine losses. |
| 2 | `mu` | `sync.RWMutex` | Self (Primitive) | Service lifecycle | Primary state synchronization | **Normative Invariant**: Prohibits all disk, database, and network I/O.<br>**Observed Technical Debt**: Multiple synchronous DB operations (`AuthenticatePeer`, `CreateVPNSession`/`CloseVPNSession`, `SetTunnelEnabled`, `RemoveTunnel`, `GetActiveVPNSessions`/failover moves, `SaveVPNConfig`, migration persistence, connection counter persistence `db.UpdateBackendTunnel`) run under lock; targeted for Phase 4 (#91) refactoring. |
| 3 | `assignmentMu` | `sync.Mutex` | Self (Primitive) | `Start`, `renderClientConfigForConnection` | In-memory lease serialization | Permits DB queries and transactions (`reservePersistedClientIPs`, `InvalidateVPNSessionsForRestart`, `UpdateConnection`). Prohibits network I/O. Disjoint from `s.mu`. |
| 4 | `db` | `*database.DB` | Read-only pointer post-init | `NewVPNService` | Persistent Database (SQLite) | DB handle. Queries executed according to caller lock context. |
| 5 | `cfg` | `*models.VPNConfig` | `s.mu` (`RLock` read / `Lock` write) | `NewVPNService`, `UpdateConfig` | Database-backed (`vpn_configs`), cached in memory | `GetConfig` is pure memory copy under `s.mu.RLock`. `UpdateConfig` persisting to DB under `s.mu.Lock` is technical debt. |
| 6 | `sessionMgr` | `*session.SessionManager` | Read-only pointer post-init | `NewVPNService` | In-memory live sessions, DB-backed | Internal locking via `SessionManager.mu`. Lock order must strictly be `s.mu` -> `SessionManager.mu`. |
| 7 | `ipam` | `*ipam.IPAM` | Read-only pointer post-init | `NewVPNService` | In-memory CIDR allocator | Pure memory operations. Allocations coordinated with DB leases under `assignmentMu`. |
| 8 | `auth` | `*auth.DBAuthenticator` | Read-only pointer post-init | `NewVPNService` | Database-backed lookup | Executes database read queries. Calling `AuthenticatePeer` in admission under `s.mu.Lock` is technical debt. |
| 9 | `pool` | `*tunnel.Pool` | Read-only pointer post-init | `NewVPNService`, `Stop` | In-memory pool, DB-backed | Pool gauge mutators (`IncrementConnections`, `DecrementConnections`, `TransferConnectionsIfActive`) run under `s.mu.Lock`. Serializes admission capacity, but migration and failover paths do not validate destination capacity (known debt). Synchronous `persistConnectionCount` and `SetConnectionCount` writes under `s.mu.Lock` are technical debt. |
| 10 | `prober` | `*tunnel.HealthProber` | `s.mu` (pointer swap) / internal | `NewVPNService`, `SetHealthProber`, `Start`, `Stop` | Runtime health evaluation | Network UDP probes run asynchronously in background prober routines outside `s.mu`. |
| 11 | `reconnectMgr` | `*tunnel.ReconnectManager` | Read-only pointer post-init | `NewVPNService`, `Start`, `Stop` | Reconnection state machine | Background reconnects execute asynchronously outside `s.mu`. |
| 12 | `balancer` | `loadbalancer.LoadBalancer` | `s.mu` (`RLock` read / `Lock` write) | `NewVPNService`, `UpdateConfig` | In-memory algorithm | Pure in-memory calculation; no I/O permitted. |
| 13 | `stickyMgr` | `*loadbalancer.StickySessionManager` | `s.mu` (pointer swap) / internal | `NewVPNService`, `UpdateConfig` | In-memory cache, DB-backed | Pruning reads pointer under `s.mu.RLock` and executes pruning outside `s.mu`. Affinities mutated under `s.mu.Lock`. |
| 14 | `forwarder` | `*forwarder.Forwarder` | Read-only pointer post-init | `NewVPNService`, `Start`, `Stop` | Dataplane routing table | Route table mutations are synchronized by internal forwarder mutexes. Network TUN packet loops run in independent goroutines. |
| 15 | `accountant` | `*forwarder.TrafficAccountant` | Read-only pointer post-init | `NewVPNService` | In-memory byte counters, DB-backed | Periodic DB flushes execute in background worker outside `s.mu`. |
| 16 | `running` | `bool` | `s.mu` (`RLock` read / `Lock` write) | `Start`, `Stop`, engine cleanup | In-memory lifecycle flag | Pure memory flag; no I/O. |
| 17 | `startedAt` | `time.Time` | `s.mu` (`RLock` read / `Lock` write) | `Start`, `Stop`, engine cleanup | In-memory baseline timestamp | Pure memory timestamp; no I/O. |
| 18 | `portalPubKey` | `string` | Read-only post-init | `NewVPNService` | Server identity | Immutable in-memory string. |
| 19 | `portalPrivKey` | `string` | Read-only post-init | `NewVPNService` | Server identity | Immutable in-memory string (never exposed via API). |
| 20 | `awgProvider` | `AWGStatusProvider` | `s.mu` (`RLock` read / `Lock` write) | `SetAWGStatusProvider` | Remote host adapter | Remote SSH/HTTP operations (`AddClient`, iptables remediation) MUST execute outside `s.mu.Lock`. |
| 21 | `ingressEngine` | `*IngressEngine` | `s.mu` (`RLock` read / `Lock` write) | `SetIngressEngine`, `Start`, `Stop` | Kernel / TUN dataplane | Device creation and start/stop occur during lifecycle transitions. Packet loops run in separate goroutines. |
| 22 | `backendDevices` | `map[int64]BackendDevice` | `s.mu.Lock` | Initialized in `NewVPNService`; mutated in `attachBackendForwarderLocked`, `disableBackendLocked`, `Stop` | In-memory device handles | Map mutation under `s.mu.Lock`. Packet reads/writes run asynchronously in pump loops outside lock. |
| 23 | `backendDeviceEndpoints` | `map[int64]string` | `s.mu.Lock` | Initialized in `NewVPNService`; mutated in `attachBackendForwarderLocked`, `disableBackendLocked`, `UpdateBackendServerHost`, `Stop` | In-memory cache | Pure memory map; no I/O. |
| 24 | `deletedServers` | `map[int64]struct{}` | `s.mu` (`RLock` read / `Lock` write) | Initialized in `NewVPNService`; populated in `DeleteServer`, cleared in `ClearServerDeletedTombstone` | In-memory tombstone set | Pure memory map; no I/O. |
| 25 | `lastLoggedDrops` | `atomic.Uint64` | Atomic primitives | Diagnostic sampling | In-memory counter | Lock-free atomic. |
| 26 | `retiredBackendDeviceDrops` | `backendDeviceDropStats` | `s.mu.Lock` | `disableBackendLocked`, `Stop`, `Start` | In-memory lifetime accumulator | Pure memory struct; direction- and reason-preserving lifetime drop accumulator. Prohibits I/O. |
| 27 | `restartInvalidatedSessions` | `atomic.Int64` | Atomic primitives | `Start` | In-memory count | Lock-free atomic. |
| 28 | `freshSessionRegistrations` | `atomic.Int64` | Atomic primitives | `ensureBackendSessionForIngress` | In-memory count | Lock-free atomic. |
| 29 | `publicIPMu` | `sync.RWMutex` | Self (Primitive) | `detectPortalHostIP` | Host public IP synchronization | Prohibits STUN/HTTP network requests while held. Requests must execute before taking write lock. Disjoint from all other locks. |
| 30 | `detectedPublicIP` | `string` | `s.publicIPMu` (`RLock` read / `Lock` write) | Lazy-initialized and cached in `detectPortalHostIP` | In-memory cache | Pure memory string. |
| 31 | `dropLogUntil` | `atomic.Int64` | Atomic primitives | `pumpBackendReturns` | In-memory rate limiter | Lock-free atomic Unix timestamp. |
| 32 | `lastReconcileTime` | `time.Time` | `s.mu.Lock` | `reconcileConnectionCounts` | In-memory timestamp | Pure memory timestamp. |
| 33 | `lastReconcileByTunnel` | `map[int64]time.Time` | `s.mu.Lock` | Lazy-initialized on first reconcile pass; mutated in `reconcileConnectionCounts`, `reapIngressSession` | In-memory map | Pure memory map. |
| 34 | `reconcilePostSnapshotHook` | `func()` | Pointer read under `s.mu.RLock` / write under test setter | Set in tests (`SetReconcilePostSnapshotHook`) | Test hook | Pointer snapshotted under `s.mu.RLock`; hook is INVOKED OUTSIDE `s.mu` before acquiring `s.mu.Lock` in `reconcileConnectionCounts`. |
| 35 | `reconcilePreApplyHook` | `func()` | Pointer read/write under `s.mu.Lock` | Set in tests (`SetReconcilePreApplyHook`) | Test hook | Invoked INSIDE `s.mu.Lock` in `reconcileConnectionCounts` prior to applying connection count changes. |
| 36 | `reconcilePreCommitHook` | `func()` | Pointer read/write under `s.mu.Lock` | Set in tests (`SetReconcilePreCommitHook`) | Test hook | Invoked INSIDE `s.mu.Lock` in `reconcileConnectionCounts` prior to committing `SetConnectionCount`. |
| 37 | `ensureDevicePreLockHook` | `func()` | Pointer read under `s.mu.RLock` / write under test setter | Set in tests (`SetEnsureDevicePreLockHook`) | Test hook | Pointer snapshotted under `s.mu.RLock`; hook is INVOKED OUTSIDE `s.mu` before acquiring `s.mu.Lock` in `ensureBackendDeviceAttached`. |
| 38 | `preCommitMigrationHookForTest` | `func()` | Pointer read/write under `s.mu.Lock` | Set in tests (`SetPreCommitMigrationHookForTest`) | Test hook | Invoked INSIDE `s.mu.Lock` in `MigrateSession` (step 4.5) prior to transferring connection counters. |
| 39 | `preAdoptHookForTest` | `func(string, string)` | Pointer read/write under `s.mu.Lock` | Set in tests (`SetPreAdoptHookForTest`) | Test hook | Invoked INSIDE `s.mu.Lock` in `ensureBackendSessionForIngress` before calling `AdoptSessionForIngress`. |
| 40 | `preIngressRouteRegistrationHookForTest` | `func()` | Pointer read/write under `s.mu.Lock` | Set in tests (`SetPreIngressRouteRegistrationHookForTest`) | Test hook | Invoked INSIDE `s.mu.Lock` in `ensureBackendSessionForIngress` prior to route registration. |
| 41 | `preRevokeCloseHookForTest` | `func(string, string)` | Pointer read/write under `s.mu.Lock` | Set in tests (`SetPreRevokeCloseHookForTest`) | Test hook | Invoked INSIDE `s.mu.Lock` in `revokeSessionDirectLocked` before session closure. |
| 42 | `postCommitRevokeHookForTest` | `func(database.PeerRevokeKind, string, string)` | Pointer read under `s.mu.RLock` / write under test setter | Set in tests (`SetPostCommitRevokeHookForTest`) | Test hook | Pointer snapshotted under `s.mu.RLock`; hook is INVOKED OUTSIDE `s.mu` in `runPostCommitRevoke` on DB commit notification. |
| 43 | `updateBackendServerHostPreLockHook` | `func()` | Pointer read under `s.mu.RLock` / write under test setter | Set in tests (`SetUpdateBackendServerHostPreLockHook`) | Test hook | Pointer snapshotted under `s.mu.RLock`; hook is INVOKED OUTSIDE `s.mu` before acquiring `s.mu.Lock` in `UpdateBackendServerHost`. |
| 44 | `updateBackendServerHostErr` | `error` | `s.mu` (`RLock` read / `Lock` write) | Set in tests (`SetUpdateBackendServerHostErrorForTest`) | Test fault injection | Read under `s.mu.RLock` in `UpdateBackendServerHost` (`vpn.go:3165`); set under `s.mu.Lock` in `SetUpdateBackendServerHostErrorForTest` (`vpn.go:927`). |
| 45 | `deleteBackendErr` | `error` | Pointer read/write under `s.mu.Lock` | Set in tests (`SetDeleteBackendErrorForTest`) | Test fault injection | Read under `s.mu.Lock` in `DeleteServer` (`vpn.go:3292`) and `DeleteBackend` (`vpn.go:3342`). |
| 46 | `syncBackendForwarderHook` | `func() error` | Pointer read/write under `s.mu.Lock` | Set in tests (`SetSyncBackendForwarderHookForTest`) | Test hook | Invoked INSIDE `s.mu.Lock` in `syncBackendForwarderOnHostUpdateLocked`. |
| 47 | `enableBackendPreAddTunnelHook` | `func()` | Pointer read under `s.mu.RLock` / write under test setter | Set in tests (`SetEnableBackendPreAddTunnelHookForTest`) | Test hook | Pointer snapshotted under `s.mu.RLock`; hook is INVOKED OUTSIDE `s.mu` before acquiring `s.mu.Lock` in `EnableBackend`. |
| 48 | `enableBackendPostAddTunnelHook` | `func()` | Pointer read under `s.mu.RLock` / write under test setter | Set in tests (`SetEnableBackendPostAddTunnelHookForTest`) | Test hook | Pointer snapshotted under `s.mu.RLock`; hook is INVOKED OUTSIDE `s.mu` after `s.mu.Unlock` in `EnableBackend`. |
| 49 | `reaperHook` | `func(context.Context, *models.VPNSession)` | Pointer read under `s.mu.RLock` / write under test setter | Set in tests (`SetSessionReaperHookForTest`) | Test hook | Pointer snapshotted under `s.mu.RLock` in `SweepTimedOutSessions`; hook is INVOKED OUTSIDE `s.mu` for each timed-out session. |
| 50 | `rollingHistory` | `*RollingHistory` | Pointer read under `s.mu.RLock` / write under `s.mu.Lock` | Lazy-initialized under `s.mu.Lock` in `startRollingHistory()` | In-memory metrics ring buffer | Synchronized via `RollingHistory.mu`. Prohibits I/O. |
| 51 | `diagRatesMu` | `sync.Mutex` | Self (Primitive) | `resetDiagnosticsGeneration`, rates sampling | Diagnostics synchronization | Prohibits all I/O. Lock order must strictly be `diagRatesMu` -> `s.mu`. Never acquire `diagRatesMu` while holding `s.mu`. |
| 52 | `diagRates` | `*diagRatesTracker` | `s.diagRatesMu` | `NewVPNService`, `resetDiagnosticsGeneration`, sampling | In-memory rates | Pure memory calculations. |
| 53 | `historyDiagRates` | `*diagRatesTracker` | `s.diagRatesMu` | Initialized in `resetDiagnosticsGeneration`, sampling | In-memory rates | Pure memory calculations. |
| 54 | `problemOnset` | `*problemOnsetTracker` | `s.mu.Lock` (lazy-init) / internal tracker mutex | Lazy-initialized under `s.mu.Lock` in `getProblemOnsetTracker()` | In-memory incident tracking | Internal mutex synchronization. Prohibits I/O. |
| 55 | `diagGeneration` | `atomic.Uint64` | Atomic primitives | Advanced via atomic increment under `diagRatesMu` in `resetDiagnosticsGeneration` during `Start()` | In-memory generation epoch | Lock-free atomic load in `currentDiagGeneration` and `diagnosticsInputsLocked`. |
| 56 | `historyPrimedGen` | `diagGeneration` | `s.diagRatesMu` | Lazy-assigned in `primeHistoryFromDrops` (`diagnostics_history.go:564`) | In-memory generation tag | Pure memory value. |
| 57 | `historyPrimed` | `bool` | `s.diagRatesMu` | Lazy-assigned in `primeHistoryFromDrops` (`diagnostics_history.go:564`) | In-memory flag | Pure memory flag. |
| 58 | `diagDeltas` | `diagDeltaTrackers` | `s.diagRatesMu` | Initialized in `resetDiagnosticsGeneration`, sampling | In-memory deltas | Pure memory calculations. |
| 59 | `historyStopCh` | `chan struct{}` | `s.mu.Lock` | Allocated under `s.mu.Lock` in `startRollingHistory()`, nil'd in `stopRollingHistory()` | In-memory worker lifecycle signal | Channel signaling only. |
| 60 | `historyDoneCh` | `chan struct{}` | `s.mu.Lock` | Allocated under `s.mu.Lock` in `startRollingHistory()`, nil'd in `stopRollingHistory()` | In-memory worker lifecycle signal | Channel signaling only. |
| -- | `obfuscationMigrationMu` | `sync.Mutex` | Package-level mutex | `ensureObfuscationParams` in `NewVPNService` | In-memory initialization gate | Serializes first-start config migration across concurrent service constructors. Permits DB read/write. Disjoint from service instance locks. |

---

## 3. Lock Hierarchies & Synchronization Contracts

### 3.1 Primary Mutex: `Service.mu` (`sync.RWMutex`)

`Service.mu` is the central synchronization barrier for VPN service topology, backend lifecycle, and peer admission.

1. **Lock Hierarchy & Nesting Rule**:
   - `s.mu` MUST always be acquired BEFORE `SessionManager.mu`. The inverse nesting (`SessionManager.mu` -> `s.mu`) is strictly forbidden and would trigger deadlocks.
   - Any hook running inside `SessionManager` (such as `ReplacementHook`) must only touch pool counters and forwarder routing without re-entering `Service.mu`. In admission paths (`EnsureBackendSessionForIngress`), `s.mu` is held throughout, nesting safely: `s.mu` -> `sessionMgr.mu`.
2. **Normative Architectural Invariant: NO I/O Under `Service.mu`**:
   - **Target Rule**: NO disk, database, or network I/O is permitted while holding `s.mu.Lock()` or `s.mu.RLock()`.
   - **Rationale**: I/O operations have unbounded latency. Holding a service-wide state lock across I/O blocks concurrent packet routing, health probes, and API requests, inducing thread pool starvation, queue overflows, and cascading watchdog timeouts.
3. **Observed Technical Debt Inventory (Phase 4 / Issue #91 Remediation Targets)**:
   Existing implementations contain database read and write operations executed directly under `s.mu.Lock()`. These call sites are explicitly classified as known technical debt to be decoupled in Phase 4:
   - **Ingress Admission (`vpn_ingress.go:124, 231–259`)**:
     * Durable peer authentication (`s.auth.AuthenticatePeer` at `vpn_ingress.go:143`): Durable user and connection lookup query executed under `s.mu.Lock()`.
     * Session lifecycle persistence (`s.sessionMgr.CreateSessionWithDeltaAndSource` at `vpn_ingress.go:231` calling `session.go:207, 243`): Executes `sm.db.CloseVPNSession` (if replacing an existing session) and `sm.db.CreateVPNSession` under `s.mu.Lock()`.
     * Connection count persistence (`s.pool.IncrementConnections` at `vpn_ingress.go:259`): Calls underlying `persistConnectionCount` (`tunnel/pool.go:672–708`), executing `db.UpdateBackendTunnel` under `s.mu.Lock()` to persist the updated `active_connections` gauge.
     * Compensation on route registration failure (`rollbackIngressSession` at `vpn_ingress.go:269`): Executes `sm.db.CloseVPNSession` under `s.mu.Lock()`.
   - **Backend Disable & Failover (`vpn.go:3009–3092`)**:
     * Administrative disable persistence (`s.pool.SetTunnelEnabled` at `vpn.go:3027`): Persists backend disabled status (`db.UpdateBackendTunnel`) under `s.mu.Lock()`.
     * Failover session reads and moves (`s.stickyMgr.HandleFailover` at `vpn.go:3063` calling `loadbalancer/sticky.go:444–520`): Executes synchronous session read `sm.db.GetActiveVPNSessions` (`sticky.go:456`) and synchronous updates `sm.persistFailoverMoves` (`sticky.go:513` calling `db.MigrateVPNSessionBackend` / `CreateVPNSession`) while holding `s.mu.Lock()`.
     * Failover counter persistence: Calls `s.pool.DecrementConnections` and `s.pool.IncrementConnections` (`vpn.go:3090–3091`), triggering underlying `persistConnectionCount` (`db.UpdateBackendTunnel` at `tunnel/pool.go:672–708`) for each migrated session under `s.mu.Lock()`.
   - **Backend Deletion (`vpn.go:3338–3438`)**:
     * In-Lock Removal (Phase 1 & Phase 2, `vpn.go:3339–3396`): `DeleteBackend` acquires `s.mu.Lock()` at line 3339, invokes `disableBackendLocked` at line 3363 (executing all the disable/failover DB I/O above), and then executes `s.pool.RemoveTunnel` (`vpn.go:3369` calling `db.DeleteBackendTunnel`) under `s.mu.Lock()`.
     * Unlocked Defensive Cleanup Sweep (Phase 3, `vpn.go:3397–3435`): `s.mu` is explicitly unlocked at line 3397 (`s.mu.Unlock()`). The subsequent orphan session lookup (`s.db.GetBackendTunnelByServerID` at line 3398, `s.db.GetActiveVPNSessions` at line 3413), session reassignment (`s.db.UpdateVPNSessionBackendTunnel` at line 3424), and leftover row deletion (`s.db.DeleteBackendTunnel` at line 3431) execute outside `s.mu`. `s.mu.Lock()` is then re-acquired at line 3435 before returning (satisfying the deferred `s.mu.Unlock()` at line 3340).
   - **Runtime Configuration Updates (`vpn.go:3476, 3553`)**:
     * `SaveVPNConfig`: Configuration persistence and compensating rollback executed under `s.mu.Lock()`.
   - **Session Migration Protocol (`vpn.go:3928, 3976, 3989`)**:
     * `MigrateSession`: Executes `db.MigrateVPNSessionBackend` and compensating `rollbackMigration` under `s.mu.Lock()`.
     * Counter transfer persistence: `s.pool.TransferConnectionsIfActive` (`vpn.go:3989` calling `tunnel/pool.go:755–807`) executes `persistConnectionCount` twice (`db.UpdateBackendTunnel`) under `s.mu.Lock()`.
   - **Periodic Connection Count Reconciliation (`vpn.go:1634, 1693`)**:
     * `reconcileConnectionCounts`: Executes `s.pool.SetConnectionCount` calling `db.UpdateBackendTunnel` under `s.mu.Lock()` during periodic gauge reconciliation passes.
4. **Phase 4 Decoupling Strategy & Synchronization Classification**:
   When decoupling database operations from `s.mu` in Phase 4, operations are partitioned into two architectural categories:
   - **Operations Requiring Ordered In-Memory Synchronization**:
     * *Ingress Session Creation & Route Commitment*: In-memory slot allocation, capacity checking, and dataplane route registration must remain atomic under lock. In Phase 4, this should follow a staged pattern: validate pre-conditions, acquire `s.mu` strictly to check capacity and reserve the in-memory slot, release `s.mu`, and execute database persistence (`CreateVPNSession`, `db.UpdateBackendTunnel`) outside the lock. If the subsequent database write fails, a compensating rollback cancels the reservation.
     * *Administrative Disable & Dataplane Teardown*: Detaching dataplane devices and disabling routes must happen synchronously under lock. However, querying active sessions (`GetActiveVPNSessions`) and persisting failover destination records (`db.MigrateVPNSessionBackend`) must be decoupled outside `s.mu` to prevent blocking live packet processing across unrelated tunnels.
   - **Operations Safely Decoupled Outside `s.mu`**:
     * *Durable Peer Authentication (`AuthenticatePeer`)*: Read-only query executed prior to acquiring `s.mu.Lock()`. A lightweight version/generation token can be verified after taking `s.mu` if state changes need detection.
     * *Active Connection Gauge Persistence (`pool.persistConnectionCount` / `SetConnectionCount`)*: Connection counts are in-memory routing weights and diagnostic telemetry; persistent counters in `backend_tunnels` are already asynchronously reconciled. These updates can be enqueued to an asynchronous persistence worker or dispatched after lock release without compromising correctness.
     * *Backend Deletion Primary Row Removal (`pool.RemoveTunnel` / `db.DeleteBackendTunnel`)*: While the Phase 3 defensive sweep (`vpn.go:3397–3435`) already executes outside `s.mu`, the primary row deletion in `s.pool.RemoveTunnel` (`vpn.go:3369`) currently executes under `s.mu.Lock()`. Moving primary persistent row deletion in `RemoveTunnel` asynchronously outside `s.mu` in Phase 4 requires an explicit **deletion/recreation synchronization mechanism** (such as an explicit per-backend deletion fence, lifecycle generation transaction, or retaining serialization until persistent DB deletion completes). Because `EnableBackend` (`vpn.go:2463–2485`) recreates tunnels reusing deterministic interface names (`awg-be-{serverID}` per `tunnel/pool.go:290–311`), and `backend_tunnels.interface_name` enforces a strict `UNIQUE` constraint (`internal/database/schema.sql:119`), `EnableBackend` must not attempt to insert a replacement database row while deletion of the previous generation is still pending in the database. Asynchronous deletion decoupling must preserve interface-name ordering guarantees, as tracked in follow-up Issue #562 (`[P3][Architecture] Preserve interface-name ordering during asynchronous backend deletion`).
     * *Configuration Persistence (`SaveVPNConfig`)*: Validate and persist configuration changes to the database before acquiring `s.mu.Lock()` for an atomic pointer swap.

### 3.2 Diagnostics Mutex: `diagRatesMu` (`sync.Mutex`)

`diagRatesMu` synchronizes diagnostics trackers, exponential rate decay accumulators, and rolling history baselines across lifecycle restarts.

1. **Ordering Contract Against `s.mu`**:
   - Whenever both locks are needed, the acquisition order MUST be `diagRatesMu` -> `s.mu`.
   - Code holding `s.mu` MUST NEVER acquire `diagRatesMu`.
   - To prevent deadlocks, `diagnosticsInputsLocked` (which runs under `s.mu`) captures the current diagnostics generation via lock-free atomic load: `s.diagGeneration.Load()`. It does NOT acquire `diagRatesMu`.
2. **I/O Boundaries**:
   - `diagRatesMu` guards CPU-bound rate calculations and ring buffer appends. Disk, database, and network operations are strictly prohibited while holding `diagRatesMu`.

### 3.3 Lease Serialization Mutex: `assignmentMu` (`sync.Mutex`)

`assignmentMu` serializes durable IPAM client allocations and restart session invalidations.

1. **Ordering Contract**:
   - `assignmentMu` and `s.mu` are disjoint locks. They are NEVER held simultaneously in any code path.
   - During `Start()`, `s.mu` is released before `assignmentMu` is acquired for restart invalidation; if invalidation fails, `assignmentMu` is released before `s.mu` is re-acquired to restore `running = false`.
   - During client config generation (`renderClientConfigForConnection`), `assignmentMu` is held to coordinate IPAM reservation with database updates (`db.UpdateConnection` / `saveOrUpdateAWGConnection`), without holding `s.mu`.
2. **I/O Boundaries**:
   - Database queries and updates (`reservePersistedClientIPs`, `InvalidateVPNSessionsForRestart`, `UpdateConnection`) are explicitly permitted and expected under `assignmentMu`. Network calls are strictly prohibited.

### 3.4 Public IP Mutex: `publicIPMu` (`sync.RWMutex`)

`publicIPMu` protects the cached detected public IP (`detectedPublicIP`).

1. **Ordering Contract**:
   - Completely disjoint from `s.mu`, `assignmentMu`, and `diagRatesMu`.
2. **I/O Boundaries**:
   - Network calls to external STUN or HTTP detection services MUST execute outside `publicIPMu`. The lock is taken as `RLock` to check cached values, released to execute network probes, and acquired as `Lock` solely to store the resolved string.

### 3.5 Package-Level Mutex: `obfuscationMigrationMu` (`sync.Mutex`)

`obfuscationMigrationMu` serializes first-start parameter generation in `ensureObfuscationParams` during `NewVPNService`.

1. **Ordering Contract**:
   - Held before the `Service` instance is created and returned. It does not nest with any instance-level locks.
2. **I/O Boundaries**:
   - Performs database configuration queries and updates (`db.GetVPNConfig`, `db.SaveVPNConfig`). Network calls are prohibited.

---

## 4. Concurrency, Capacity & Failure Invariants

### 4.1 Multi-Backend Capacity Select and Reserve Semantics (Issue #86 Invariant)

The multi-backend architecture governs tunnel capacity across admission, session replacement, live migration, and administrative failover. The guarantees provided by mutex serialization versus capacity enforcement are distinct:

1. **Serialized Admission Select-and-Reserve Guarantee**:
   Admission select-and-reserve is strictly serialized and capacity-checked under `s.mu.Lock()`. `EnsureBackendSessionForIngress` (and `HandleIncomingPeer`) acquires `s.mu.Lock()` for the entire sequence:
   $$\text{Peer Lookup} \longrightarrow \text{FilterHealthy (Capacity Check)} \longrightarrow \text{Select Backend} \longrightarrow \text{CreateSession} \longrightarrow \text{IncrementConnections} \longrightarrow \text{Route Registration}$$
   Because `s.mu` is held continuously across capacity filtering (`FilterHealthy` verifies `ActiveConnections < MaxPeersPerBackend`) and counter incrementing, no concurrent admission goroutine can observe a below-cap connection count and double-allocate. On this pure ingress admission path, active connections on any backend cannot exceed `MaxPeersPerBackend`, nor can total sessions exceed `MaxTotalPeers`.
2. **Migration and Failover Capacity Accounting (No Destination Enforcement)**:
   Mutex serialization under `s.mu` prevents concurrent memory races during counter updates, but does NOT by itself enforce backend capacity limits when sequential migration or failover paths omit capacity validation:
   - **In-Flight Session Migration (`MigrateSession`)**: Calls `tunnel.Pool.TransferConnectionsIfActive` (`internal/vpn/tunnel/pool.go:755–807`). This function verifies that the destination backend is enabled and active and checks expected state versions, but unconditionally increments `toTun.ActiveConnections` without checking `MaxPeersPerBackend`.
   - **Administrative Failover (`disableBackendLocked`)**: When a backend is disabled (`internal/vpn/vpn.go:3057–3092`), `stickyMgr.HandleFailover` (`internal/vpn/loadbalancer/sticky.go:474–499`) plans new destination backends for all degraded peers against a point-in-time snapshot of healthy tunnels (`availableTunnels`). Because selection occurs in a loop against the initial snapshot, multiple degraded sessions can be assigned to the same destination tunnel. When `disableBackendLocked` sequentially moves these sessions and invokes `s.pool.IncrementConnections(m.NewBackendTunnelID)`, the destination backend's counter can overshoot `MaxPeersPerBackend` (e.g., if destination backend $B$ has 249 active connections against a limit of 250, failing over two peers from disabled backend $A$ to $B$ drives $B$ to 251 active connections).
3. **Known Technical Debt & Invariant Scope (Phase 4 / Issue #91)**:
   - Strict capacity bounds across session migration and failover paths are **NOT currently enforced** by the runtime.
   - The capacity invariant is strictly bounded: ingress admission is guaranteed not to allocate beyond `MaxPeersPerBackend`, but administrative failover and migration transfers may temporarily exceed configured backend limits under multi-peer failover.
   - Closing this enforcement gap by adding destination capacity checking, quota-aware failover planning, and load shedding across migration/failover is tracked as known technical debt for Phase 4 / Issue #91, with stress test suites tracked under Issue #557 (multi-backend cascade failover under sustained ingress load) and Issue #559 (concurrent lease exhaustion).
4. **Exactly-Once Counter Accounting on Replacement (Issue #388 Rework D)**:
   When an incoming peer handshake matches an existing peer key, session replacement accounting is handled with mathematical precision based on `CreateSessionWithDeltaAndSource`:
   - **Fresh Admission (no prior session)**: The replacement hook does not fire; the admission path increments the selected backend counter ($+1$).
   - **Same-Backend Replacement ($A \rightarrow A$)**: The replacement hook decrements backend $A$ ($-1$) and does not increment because source equals target. The admission path restores the count by re-incrementing backend $A$ ($+1$). The peer's count on backend $A$ remains exactly 1.
   - **Cross-Backend Replacement ($A \rightarrow B$)**: The replacement hook transfers the count by decrementing $A$ ($-1$) and incrementing $B$ ($+1$). The admission path observes `delta.HasInc == true` and performs NO additional increment. Backend $B$ count remains exactly 1.

### 4.2 Peer and Assigned IP Uniqueness Guarantees

1. **Durable Lease Authority**:
   - Every peer client configuration generated or imported persists its assigned IP in `user_connections.client_params["assigned_ip"]`.
   - Startup and client generation routines pre-hydrate the in-memory `ipam.IPAM` allocator using `reservePersistedClientIPs` under `assignmentMu`.
   - Ingress admission strictly validates that the peer's assigned IP matches the durable lease in the database. If there is any discrepancy, admission fails closed; stale ownership is never repaired or rebound dynamically.
2. **Dataplane Forwarder Route Invariants**:
   - The forwarder maintains an in-memory routing table mapping IP prefixes to backend tunnels.
   - Admission follows an "admission-then-register" invariant: session creation and counter increments occur first, and `forwarder.TryRegisterSessionWithReturnPath` is checked last.
   - If route registration fails (e.g., duplicate IP or forwarder route capacity exhausted), a best-effort compensation attempt executes immediately in reverse order (see Section 4.4 for residual state semantics).

### 4.3 Reconnect, Session Failover, and Migration Race Invariants

1. **Live Session Reuse Across Upstream Rekey**:
   - An upstream WireGuard / AmneziaWG rekey updates transport-layer handshake state but does not destroy the logical session.
   - If an active session exists in `sessionMgr` with matching peer key, user ID, connected status, and assigned IP, and the target backend is healthy, `EnsureBackendSessionForIngress` invokes `AdoptSessionForIngress`.
   - Adoption refreshes `LastSeen` and updates provenance under `sessionMgr.mu` without allocating a new session ID, without mutating pool counters, and without recreating the forwarder route.
2. **Backend Administrative Disable and Failover (`disableBackendLocked`)**:
   - Executed under `s.mu.Lock()`.
   - The disabled tunnel is marked disabled in the database, its health prober is updated, and its backend UDP device is detached and closed.
   - Active sessions assigned to the disabled backend are migrated via `stickyMgr.HandleFailover` to alternative healthy backends.
   - Failover is **best-effort**: `forwarder.UpdateSessionBackend` errors are logged (e.g. when a session is already disconnected), while pool connection counts (`DecrementConnections` on the old backend, `IncrementConnections` on the target backend) proceed.
   - Peers skipped by sticky failover (e.g. no healthy backend available) are explicitly logged, leaving their unredirectable state to be retired by subsequent timeouts or reapers.
3. **Session Migration Protocol (`MigrateSession`)**:
   - Runs under `s.mu.Lock()` maintaining the lock order `s.mu` -> `SessionManager.mu`.
   - Step 1: Preflight checks ensure the target backend is administratively enabled and active.
   - Step 2: The live dataplane route is updated (`forwarder.UpdateSessionBackend`).
   - Step 3: In-memory session state is updated (`sessionMgr.UpdateSessionBackend`).
   - Step 4: The database session record is migrated (`db.MigrateVPNSessionBackend`).
   - Step 5: Connection counters are atomically transferred (`pool.TransferConnectionsIfActive`).
   - Step 6: Sticky affinity is updated (`stickyMgr.AssignPeerAffinity`).
   - Failure Handling & Rollback Boundaries: If an initial failure occurs during Step 2 (`forwarder.UpdateSessionBackend` returning an error other than `forwarder.ErrSessionNotRegistered`), `MigrateSession` aborts immediately and returns the error without invoking `rollbackMigration`, because no state mutations have yet succeeded (`internal/vpn/vpn.go:3959–3966`). Once migration state mutations have commenced (failure during Step 3 in-memory session update, Step 4 database persistence, or Step 5 counter transfer), `rollbackMigration` executes a best-effort compensation attempt in reverse order to revert modified components (see Section 4.4 for attempt budgets and residual state semantics).
4. **Reaper versus Concurrent Admission Race**:
   - The session reaper (`reapIngressSession`) runs under `s.mu.Lock()`.
   - Before retiring a route, it queries `sessionMgr.GetSessionSnapshotByPeer(sess.PeerPublicKey)`:
     * **Same Session ID Live**: A concurrent packet or rekey refreshed the session (`LastSeen` update won the race). The reaper aborts; the session and route remain intact.
     * **Different Session ID Live**: A fresh admission replaced the timed-out session. The reaper skips forwarder route retirement (the new session owns the route), but decrements the old session's pool counter (which was not moved by any replacement hook).
     * **No Live Session**: The session is cleanly retired; forwarder route is unregistered, and pool counter is decremented unless already adjusted by a periodic gauge reconciliation pass (`lastReconcileByTunnel`).

### 4.4 Best-Effort Rollback and Compensation Semantics

Compound operations spanning memory, database, and dataplane forwarders execute **best-effort compensation** rather than guaranteeing full transactional atomicity across process boundaries:

1. **Ingress Admission Rollback**:
   - If `forwarder.TryRegisterSessionWithReturnPath` fails during `ensureBackendSessionForIngress`:
     * Closes the created session via `rollbackIngressSession` (`sessionMgr.CloseSession(ctx, sess.ID, "disconnected")`). If `CloseSession` fails (e.g. DB error), the failure is logged and rollback continues without aborting.
     * Decrements the connection counter on the newly selected backend (`pool.DecrementConnections(backend.ID)`).
     * Clears newly created sticky affinity via `rollbackIngressSticky` (`stickyMgr.ClearPeerAffinity(peerKey)` if `hadSticky == false`; pre-existing affinity is preserved).
     * Releases `s.mu` before awaiting route retirement completion (`retirement.Wait()`).
   - **Residual State on Cross-Backend Replacement ($A \rightarrow B$)**: The replacement hook previously decremented backend $A$ and marked the old session disconnected. If admission subsequently fails on backend $B$, compensation decrements $B$, but does NOT resurrect the old session on $A$. The old session remains invalidated, and the admission fails closed.
2. **Migration Rollback (`rollbackMigration`)**:
   - **Invocation Triggers & Scope**: `rollbackMigration` is invoked only after state mutations have commenced (e.g. following a failure in `sessionMgr.UpdateSessionBackend`, `db.MigrateVPNSessionBackend`, or `pool.TransferConnectionsIfActive`). If the initial `forwarder.UpdateSessionBackend` call fails (with any error other than `forwarder.ErrSessionNotRegistered`), `MigrateSession` returns immediately without invoking `rollbackMigration`, as no prior state mutations were committed.
   - **Bounded Database Attempt Window**: Compensation derives a non-cancelable timeout context: `rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)`. This 5-second timeout budget is passed *only* to `db.MigrateVPNSessionBackend` (`internal/vpn/vpn.go:3886`). Subsequent rollback calls (`sessionMgr.RollbackSessionBackend` and `forwarder.UpdateSessionBackend`) do NOT accept a context deadline and block synchronously on standard mutexes (`SessionManager.mu` and `Forwarder.mu`). Thus, the 5-second deadline is a cooperative database attempt window, NOT a wall-clock completion bound on the whole rollback.
   - **Partial Failure Aggregation**: Compensation steps execute sequentially (DB session row revert, session manager revert, forwarder route revert). All encountered errors are collected and returned via `errors.Join(rollbackErrs...)`.
   - **Residual Inconsistency**: If compensation partially fails, in-memory routes and database session records may temporarily diverge. Periodic reconciliation (`reconcileConnectionCounts`) is *gauge-only* (it updates pool gauges and timestamps; does not repair forwarder routes or session backend identity). Session reaping provides *conditional idle retirement* for inactive sessions, NOT guaranteed route or database self-repair.
3. **Backend Administrative Disable Residual State (`disableBackendLocked`)**:
   - If `forwarder.UpdateSessionBackend` fails during failover migration, the error is logged while connection counter moves (`DecrementConnections` on disabled backend, `IncrementConnections` on target backend) proceed.
   - The detached backend device is closed immediately, guaranteeing no further traffic traverses the disabled backend regardless of residual route state.
4. **Backend Host Update Rollback (`UpdateBackendServerHost`)**:
   - If forwarder device synchronization fails after modifying the tunnel endpoint in memory, the endpoint is rolled back to `originalEndpoint` using a 5-second `context.WithoutCancel` attempt window.
   - If endpoint rollback fails, the method returns `ErrVPNRollbackFailed`.

### 4.5 Server Restart Durability and State Restoration

1. **Session Discard on Restart**:
   - Ephemeral transport keys, forwarder kernel routes, and UDP client endpoints do not survive process restarts.
   - In `Start()`, `db.InvalidateVPNSessionsForRestart` executes under `assignmentMu`, marking all previously active sessions in the database as disconnected.
   - Startup fails loudly if restart invalidation cannot be committed, preventing the dataplane from operating with orphaned or falsely connected records.
2. **Backend Health Reset**:
   - `pool.ResetEnabledHealthForStartup` transitions all enabled tunnels to `"connecting"` status.
   - An initial synchronous prober sweep (`prober.ProbeAll`) executes before the endpoint listener is activated, ensuring no client traffic is routed to unverified backends.
3. **IPAM Re-Hydration**:
   - Prior to accepting connections or generating configs, `reservePersistedClientIPs` runs under `assignmentMu` to reload all durable client leases from `user_connections` into `ipam.IPAM`.
4. **Generational Diagnostics Isolation**:
   - Every execution of `Start()` increments `diagGeneration` under `diagRatesMu`.
   - All rate trackers, deltas, and rolling history baselines are reset and re-primed into the new generation. Diagnostics snapshots straddling a restart are rejected by generation checks, preventing counter wraparound or negative rates from skewing health scores.

---

## 5. Coverage & Gap Analysis

### 5.1 Verification Cross-Check Against Test Suites

The table below maps the documented state invariants against verified unit, race, and integration test functions declared in the repository:

| Invariant Category | Documented Contract | Validating Test Suites & Specific Test Cases |
|---|---|---|
| Multi-Backend Capacity | Admission check-then-allocate serialization (#86); migration/failover destination unconstrained (known debt) | `internal/vpn/capacity_stress_test.go` (`TestHandleIncomingPeerCapacityStress`)<br>`internal/vpn/vpn_ingress_test.go` (`TestIngressAdmissionExactlyOnceConcurrentBurst`)<br>`internal/vpn/ingress_concurrent_legacy_mix_test.go` (`TestIngressCountersWithConcurrentLegacyCreateSession`) |
| Replacement Accounting | Exactly-once counter deltas (#388) | `internal/vpn/ingress_replacement_accounting_test.go` (`TestIngressDifferentBackendReplacementExactlyOnce`, `TestIngressSameBackendReplacementNetOne`, `TestIngressDifferentBackendReplacementRollbackNoPhantom`)<br>`internal/vpn/rekey_replacement_regression_test.go` (`TestRekeyReplacementAcrossBackends`, `TestRekeyKeepsGaugeAtBaseline`) |
| Peer & IP Uniqueness | CIDR allocation & durable lease precedence | `internal/vpn/vpn_ipam_test.go` (`TestGenerateClientConfig_IPAMPersistence`, `TestGenerateClientConfig_ServerRestartIPAMRestoration`, `TestHandleIncomingPeer_IPAMPersistenceFallbackAndCollision`)<br>`internal/vpn/issue338_ipam_collision_test.go` (`TestStartupIPAMCollision_ResolvesDuplicateAndSelfHeals`, `TestStartupIPAMCollision_Scenario1_TwoUsersTwoPeers_OldestWinsOtherQuarantined`, `TestReservePersistedClientIPs_PeerAddressMismatch`)<br>`internal/vpn/issue297_remote_ipam_test.go` (`TestAuthenticatePeerRejectsRemoteServerConnection`) |
| Route Registration & Rollback | Admission-then-register; best-effort reverse rollback | `internal/vpn/vpn_ingress_test.go` (`TestEnsureBackendSessionForIngressRollsBackOnRouteCapacity`)<br>`internal/vpn/faultinjection_test.go` (`TestPartialSessionCreationLeavesNoOrphans`)<br>`internal/vpn/ingress_replacement_accounting_test.go` (`TestIngressDifferentBackendReplacementRollbackNoPhantom`) |
| Reconnect, Failover & Reaper Races | Seamless rekey; failover migration; reaper race resolution | `internal/vpn/vpn_ingress_test.go` (`TestEnsureBackendSessionForIngressReusesLiveSession`)<br>`internal/vpn/vpn_session_reaper_test.go` (`TestSessionReaperHook_ReconnectRace`, `TestSessionReaperHook_ReconcileRace`, `TestSessionReaperHook_ConcurrentDeadlock`)<br>`internal/vpn/faultinjection_test.go` (`TestDisconnectConcurrentWithFailover`)<br>`internal/vpn/loadbalancer/faultinjection_test.go` (`TestFailoverBackendDiesMidMigrationMatrix`) |
| Migration Transaction | Compound migration protocol with rollback; host update rollback | `internal/vpn/rebalance_migration_test.go` (`TestVPNRebalanceLiveMigration`, `TestVPNRebalanceRollbackOnDBFailure`, `TestVPNRebalanceCheckToCommitRace_CompensatingDBRollbackSurvivesCanceledContext`)<br>`internal/vpn/vpn_backend_attachment_test.go` (`TestUpdateBackendServerHost_CanceledContextRollback`, `TestUpdateBackendServerHost_RollbackFailure_ReturnsErrVPNRollbackFailed`, `TestDisableBackend_PersistenceFailurePreservesStateAndDevice`) |
| Restart Durability | Invalidate sessions; reset health; restore devices | `internal/vpn/issue297_restart_test.go` (`TestRestartInvalidatesSessionsBeforeStartingDataPlane`, `TestRestartReservesExistingClientIPBeforeNewConfigAndReconnect`, `TestRestartCleanupFailureDoesNotStartListener`)<br>`internal/vpn/vpn_lifecycle_test.go` (`TestStart_AdminDisabledBackendStaysDetachedWhileEnabledBackendReprobes`, `TestStart_RestoresBackendDevices_DegradesOnAttachFailure`, `TestStart_RequiresFreshProbeBeforeRestoringBackendDevice`, `TestService_StartedAt_LifecycleAndFailure`)<br>`internal/vpn/upstream_durability_test.go` (`TestUpstream_SameDBSamePortSameConfigDurability`) |
| Diagnostics Generations | Generational isolation across restart cycles; whole-vector monotonicity | `internal/vpn/diagnostics_generation_test.go` (`TestDiagGeneration_HistoryPrimingIsGenerationKeyed`, `TestDiagGeneration_LifecycleResetsReprime`, `TestDiagGeneration_OutOfOrderNeverRewindsBaselines`, `TestGenerationWindow_WholeVectorMonotonicity`)<br>`internal/vpn/diagnostics_problems_onset_test.go` (`TestSynthesizeActionableProblems_OnsetSemanticsTable`, `TestActionableProblemOnset_PreservedAcrossPolls`)<br>`internal/vpn/diagnostics_round10_test.go` (`TestDiagGeneration_R1_ProductionStaleSnapshotAfterRestart`) |

### 5.2 Identified Gaps & Follow-Up Recommendations (Phase 4 / Issue #91)

The following coverage gaps represent opportunities for enhanced resilience testing as Phase 4 decomposition proceeds:

1. **Multi-Backend Cascade Failover Under Ingress Burst (Issue #557)**:
   - *Tracking Issue*: Issue #557 (`[P3][Tests] Add multi-backend cascade failover stress suite under sustained ingress load`)
   - *Current Coverage*: `capacity_stress_test.go` verifies 200 concurrent admissions contending on a single backend, and `faultinjection_test.go` verifies `TestDisconnectConcurrentWithFailover`.
   - *Gap*: Concurrent administrative disable or failure of multiple backends while hundreds of incoming client admissions and rekeys arrive simultaneously across remaining backends, including destination capacity overshoot when mass failover transfers sessions without checking `MaxPeersPerBackend`.
   - *Recommendation*: Introduce a multi-backend capacity stress test that disables 50% of available backends mid-run to verify that gauge invariants hold across mass failovers without counter drift and to evaluate destination capacity bounds.
2. **Context Cancellation Across Session Migration Transaction Checkpoints (Issue #558)**:
   - *Tracking Issue*: Issue #558 (`[P3][Tests] Add context cancellation tests across session migration transaction checkpoints`)
   - *Current Coverage*: `rebalance_migration_test.go` (`TestVPNRebalanceLiveMigration`, `TestVPNRebalanceRollbackOnDBFailure`, `TestVPNRebalanceCheckToCommitRace_CompensatingDBRollbackSurvivesCanceledContext`) and `ingress_replacement_accounting_test.go` (`TestIngressDifferentBackendReplacementRollbackNoPhantom`).
   - *Gap*: While compensating database rollback under canceled context is tested in `rebalance_migration_test.go`, verifying that context cancellation at each discrete intermediate checkpoint of `MigrateSession` (DB commit, session manager update, forwarder route redirect) triggers appropriate compensating actions without hanging or leaking lock state lacks dedicated regression coverage.
   - *Recommendation*: Add checkpoint cancellation test suites exercising `MigrateSession` across intermediate transaction boundaries to verify that cooperative timeout contexts abort bounded operations without deadlocks or state corruption.
3. **Concurrent IPAM Lease Exhaustion Racing Re-Hydration (Issue #559)**:
   - *Tracking Issue*: Issue #559 (`[P3][Tests] Add high-concurrency IPAM lease pool exhaustion stress tests`)
   - *Current Coverage*: `issue338_ipam_collision_test.go` comprehensively validates collision resolution, and `ipam_test.go` covers sequential exhaustion.
   - *Gap*: Concurrent client configuration generation racing against `reservePersistedClientIPs` during a service re-initialization window near subnet boundary exhaustion.
   - *Recommendation*: Implement an IPAM boundary stress test validating that exhaustion cleanly rejects requests without leaking lease reservations or corrupting `user_connections`.
4. **Interface-Name Ordering During Asynchronous Backend Deletion (Issue #562)**:
   - *Tracking Issue*: Issue #562 (`[P3][Architecture] Preserve interface-name ordering during asynchronous backend deletion`)
   - *Current Coverage*: `vpn_backend_attachment_test.go` validates sequential enable and disable operations under `s.mu`.
   - *Gap*: Asynchronous database row removal outside `s.mu` racing against rapid backend recreation (`EnableBackend`) reusing interface name `awg-be-{serverID}`, triggering `backend_tunnels.interface_name` UNIQUE constraint violations if recreation executes before asynchronous deletion completes.
   - *Recommendation*: Implement an explicit recreation fence or lifecycle generation transaction to prevent `EnableBackend` from inserting a replacement row while previous generation deletion is pending in the database.

---

## 6. Guidelines for Sub-Service Decomposition (Phase 4 / Issue #91)

When decomposing `Service` into dedicated controllers (e.g. `AdmissionController`, `DeviceManager`, `MigrationCoordinator`, `DiagnosticsCollector`):

1. **Eliminate I/O Technical Debt Under State Locks**: Migrate all database operations (`AuthenticatePeer`, session creation/closure `CreateVPNSession`/`CloseVPNSession`, administrative disable `SetTunnelEnabled`, backend removal `RemoveTunnel`, failover session reads `GetActiveVPNSessions` and persistence `persistFailoverMoves`, runtime configuration `SaveVPNConfig`, session migration `MigrateVPNSessionBackend`, and gauge writes `persistConnectionCount`/`SetConnectionCount`) outside state mutexes by splitting operations into pre-validation, atomic in-memory transitions, and post-transition persistence.
2. **Preserve Single Admission Mutex & Enforce Migration Capacity**: The select-and-reserve capacity decision must remain serialized under a single lock across all backends. Decomposing admission into a sub-service must retain this mutex boundary. In addition, Phase 4 should introduce destination capacity checks and quota handling to `TransferConnectionsIfActive` and `HandleFailover` to eliminate the failover capacity overshoot debt.
3. **Maintain Strict Lock Hierarchy**: Never allow extracted controllers to create circular locking dependencies with `SessionManager`, `tunnel.Pool`, or `DiagnosticsTracker`.
4. **Retain Reverse-Order Rollback**: Extracted admission and migration paths must continue to roll back partial state in strict reverse order of creation, preserving explicit residual state classification.
5. **Isolate I/O from Dataplane Locks**: Network operations and unbound disk/database queries must remain strictly outside dataplane routing and capacity locks.
6. **Strict Separation of Mechanical Extraction from Synchronization Refactoring**: Phase 4 decomposition must strictly separate pure mechanical file-split PRs (preserving existing `Service.mu` boundaries, locking hierarchies, and behavior byte-for-byte) from subsequent synchronization-refactoring PRs. Any future PR that moves database persistence outside locks or introduces asynchronous workers must be treated as a dedicated behavioral change accompanied by targeted concurrency, race detector, fault injection, and lifecycle stress test suites (as tracked in #557, #558, #559, #562).
