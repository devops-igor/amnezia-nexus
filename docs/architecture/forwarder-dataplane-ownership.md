# Dataplane Ownership & Concurrency Contract: Forwarder

## 1. Executive Summary & Purpose

The packet routing engine in `internal/vpn/forwarder/` provides bidirectional packet relay between client WireGuard peer sessions and backend tunnels. It coordinates route indexing, packet buffering, token bucket rate limiting, asynchronous worker pumps, and telemetry accounting.

Prior to decomposing `forwarder.go` (~1,887 lines) into modular same-package units (Issues #517–#520), this document defines the authoritative state ownership, synchronization boundaries, memory management invariants, and goroutine lifecycles. All subsequent refactoring must preserve these behavioral invariants to guarantee zero packet leaks, zero memory corruption, and zero race conditions under concurrent dataplane load.

---

## 2. Forwarder State & Goroutine Inventory

### 2.1 Forwarder Struct Field Inventory

The `Forwarder` struct owns global routing tables, backend queues, synchronization primitives, aggregate telemetry, and lifecycle state.

| Field | Type | Operational Role | Synchronization Mechanism | Mutation Lifecycle |
| :--- | :--- | :--- | :--- | :--- |
| `mu` | `sync.RWMutex` | Primary state lock guarding routing maps, backend devices, and pump state | N/A (Lock Primitive) | Initialized at struct allocation |
| `accountant` | `*TrafficAccountant` | Batched persistence of session/connection byte counters to database | Internal mutex (`TrafficAccountant.mu`) | Set at constructor; started in `Start()`, flushed/stopped in `Stop()` |
| `routesByPeer` | `map[string]*sessionRoute` | Primary route index keyed by peer public key (`peerKey`) | `Forwarder.mu.Lock` (write), `Forwarder.mu.RLock` (read) | Modified on session registration, unregistration, and retirement |
| `routesByIP` | `map[string]*sessionRoute` | Reverse route index keyed by client VIP (`assignedIP`) | `Forwarder.mu.Lock` (write), `Forwarder.mu.RLock` (read) | Modified on session registration, unregistration, and retirement |
| `backendTraffic` | `map[int64]*trafficCounters` | Per-backend tunnel cumulative traffic and rate monitoring | `Forwarder.mu.Lock` (map access), per-counter `trafficCounters.mu` | Entries created in `ensureBackendTrafficLocked`, cleared in `DetachBackendDevice` |
| `backendQueues` | `map[int64]chan []byte` | Egress packet queues toward backend tunnels | `Forwarder.mu.Lock` (map access), Go channel synchronization | Created on route registration or backend attachment; preserved across `DetachBackendDevice` |
| `backendDevices` | `map[int64]PacketDevice` | Attached backend network interfaces / TUN devices | `Forwarder.mu.Lock` (map access) | Attached in `AttachBackendDevice`, removed in `DetachBackendDevice` |
| `backendPumpStops` | `map[int64]chan struct{}` | Per-backend pump termination signaling channels | `Forwarder.mu.Lock` (map access) | Created in `AttachBackendDevice`/`StartPumps`, closed on detach or stop |
| `backendPumpDones` | `map[int64]chan struct{}` | Per-backend pump exit completion notification channels | `Forwarder.mu.Lock` (map access) | Created alongside `backendPumpStops`, closed on pump goroutine exit |
| `bufSize` | `int` | Configured queue capacity for client route packet channels | `Forwarder.mu.Lock` (write), `Forwarder.mu.RLock` (read) | Set at construction; updated via `ReconfigureClientQueueConfig` when idle |
| `backendBufSize` | `int` | Capacity for backend egress queues (default 2048) | Immutable after construction | Set at construction (`DefaultBackendQueueSize`) |
| `maxActiveRoutes` | `int` | Upper bound for concurrently registered active peer routes | `Forwarder.mu.Lock` (write), `Forwarder.mu.RLock` (read) | Set at construction; updated via `ReconfigureClientQueueConfig` |
| `portalSubnet` | `*net.IPNet` | Authorized client CIDR pool used to validate inner source IPs | Immutable after construction | Initialized from CIDR string at constructor |
| `totalRxBytes` | `atomic.Int64` | Cumulative lifetime throughput bytes client to backend | `sync/atomic` operations | Not reset on `Start()`; incremented on successful backend enqueue |
| `totalTxBytes` | `atomic.Int64` | Cumulative lifetime throughput bytes backend to client | `sync/atomic` operations | Not reset on `Start()`; incremented on successful client enqueue |
| `totalRxPackets` | `atomic.Uint64` | Cumulative lifetime throughput packets client to backend | `sync/atomic` operations | Not reset on `Start()`; incremented on successful backend enqueue |
| `totalTxPackets` | `atomic.Uint64` | Cumulative lifetime throughput packets backend to client | `sync/atomic` operations | Not reset on `Start()`; incremented on successful client enqueue |
| `dropsQueueFull` | `atomic.Uint64` | Return packets dropped due to full client route queue | `sync/atomic` operations | Reset on `Start()`; incremented in `RouteBackendToClient` |
| `dropsNoRoute` | `atomic.Uint64` | Return packets dropped due to unmapped VIP or backend mismatch | `sync/atomic` operations | Reset on `Start()`; incremented in `RouteBackendToClient` |
| `dropsPacketTooLarge` | `atomic.Uint64` | Return packets dropped exceeding `MaxClientQueuePacketBytes` | `sync/atomic` operations | Reset on `Start()`; incremented in `RouteBackendToClient` |
| `dropsTotal` | `atomic.Uint64` | Monotonic total of all return-path packet drops | `sync/atomic` operations | Reset on `Start()`; incremented on every return drop event |
| `clientDropsQueueFull` | `atomic.Uint64` | Client packets dropped due to full backend queue | `sync/atomic` operations | Reset on `Start()`; incremented in `RouteClientToBackend` |
| `clientDropsRateLimited`| `atomic.Uint64` | Client packets dropped due to upstream token bucket exhaustion | `sync/atomic` operations | Reset on `Start()`; incremented in `RouteClientToBackend` |
| `clientDropsNoBackend` | `atomic.Uint64` | Client packets dropped because target backend queue is missing | `sync/atomic` operations | Reset on `Start()`; incremented in `RouteClientToBackend` |
| `clientDropsTotal` | `atomic.Uint64` | Monotonic total of all client-to-backend packet drops | `sync/atomic` operations | Reset on `Start()`; incremented on every client drop event |
| `spoofedRebinds` | `atomic.Uint64` | Monotonic count of inner source IPs failing rebind checks | `sync/atomic` operations | Incremented in `routeClientToBackend` on spoof attempt |
| `returnRejectClassifier`| `func(ReturnRejectReason)`| Hook receiving return-path drop classifications | `Forwarder.mu.Lock` (write), `Forwarder.mu.RLock` (snapshot) | Registered via `SetReturnRejectClassifier`; invoked outside locks |
| `writeErrLogUntil` | `atomic.Int64` | Wall-clock Unix timestamp throttling device write error logs | Atomic Load/Store | Updated in `writeClientPacket` on `dev.Write` failure (independent Load/Store) |
| `writeMetricsMu` | `sync.Mutex` | Protects aggregate device write timings and reservoirs | `writeMetricsMu.Lock` | Initialized at struct allocation |
| `writeMetrics` | `DeviceWriteTelemetry` | Aggregate device write latency and stall statistics | `Forwarder.writeMetricsMu` | Updated in `writeClientPacket` and read in `DeviceWriteSnapshot` |
| `writeHistogram` | `writeDurationHistogram` | Histogram binning completed client device write latencies | `Forwarder.writeMetricsMu` | Updated in `writeClientPacket`; exported via `WriteDurationMetrics` |
| `writeLatencies` | `latencyReservoir` | Fixed-size ring buffer for aggregate p50/p95/p99 calculation | `Forwarder.writeMetricsMu` | Updated in `writeClientPacket` |
| `writesInFlight` | `map[*sessionRoute]time.Time`| Active admitted device writes awaiting completion | `Forwarder.writeMetricsMu` | Inserted before `dev.Write`; deleted after write returns |
| `rateTracker` | `*RateTracker` | Current throughput, packet rate, and EWMA tracker | `RateTracker.mu` | Primed on constructor/`Start()`; sampled on `Rates()` |
| `historyRateTracker` | `*RateTracker` | Long-term history throughput tracker | `RateTracker.mu` | Primed on constructor/`Start()`; sampled on `HistoryRates()` |
| `genEpoch` | `atomic.Uint64` | Forwarder lifecycle generation counter | `sync/atomic` operations | Incremented on `Start()`; tags observations and rejects stale samples |
| `backendTrafficGeneration`| `atomic.Uint64` | Generation tag for per-backend traffic history baselines | `sync/atomic` operations | Updated in `Start()` matching `genEpoch` |
| `aggregateQueueOccupancy`| `int` | Sum of packet counts currently queued across all routes | `Forwarder.aggregateQueueMu` | Updated on enqueue, dequeue, capacity change, and route drain |
| `aggregateQueueCapacity` | `int` | Sum of channel buffer capacities across all active routes | `Forwarder.aggregateQueueMu` | Updated on route registration, replacement, and unregistration |
| `queueDwell` | `queueDwellTracker` | High-occupancy dwell duration and threshold tracker | `Forwarder.aggregateQueueMu` | Updated on every queue occupancy transition |
| `aggregateQueueHighWater`| `atomic.Uint64` | Peak aggregate occupancy reached across all client queues | `sync/atomic` CAS | Updated during packet enqueue under `aggregateQueueMu` |
| `aggregateQueueMu` | `sync.Mutex` | Serializes aggregate queue accounting and occupancy updates | `aggregateQueueMu.Lock` | Initialized at struct allocation |
| `running` | `bool` | Lifecycle flag indicating whether forwarder is active | `Forwarder.mu.Lock` (write), `Forwarder.mu.RLock` (read) | Set `true` in `Start()`; set `false` in `Stop()` |
| `stopCh` | `chan struct{}` | Instance stop signal channel allocated at construction | Channel synchronization | Created at constructor; never closed by `Stop()` (subsystems use dedicated stop channels) |
| `pumpsRunning` | `bool` | Indicates whether background pump workers are currently active| `Forwarder.mu.Lock` (write), `Forwarder.mu.RLock` (read) | Set `true` in `StartPumps()`; set `false` in `stopPumpsSignalOnly()` |
| `pumpsStopCh` | `chan struct{}` | Termination signal broadcast to all active pump workers | Channel synchronization | Created in `StartPumps()`; closed in `stopPumpsSignalOnly()` |
| `pumpsWg` | `sync.WaitGroup` | Tracks active pump worker goroutines | `sync.WaitGroup` methods | Incremented on pump spawn; decremented on pump termination |
| `peerRegs` | `map[string]uint64` | Monotonic registration counter per peer key for diagnostics | `Forwarder.mu.Lock` (write), `Forwarder.mu.RLock` (read) | Incremented in `registerSessionLocked` |
| `stopTimeout` | `time.Duration` | Timeout for route retirement write completion during `Stop` | `Forwarder.mu.Lock` (write), `Forwarder.mu.RLock` (read) | Default 5s; overridden via `SetStopTimeoutForTest` |

---

### 2.2 sessionRoute Struct Field Inventory

The `sessionRoute` struct encapsulates per-peer state, downstream packet queues, rate limiters, and write retirement synchronization.

| Field | Type | Operational Role | Synchronization Mechanism | Mutation Lifecycle |
| :--- | :--- | :--- | :--- | :--- |
| `sessionID` | `string` | Unique identifier of the authenticated VPN session | Immutable after route creation | Initialized in `registerSessionLocked` |
| `connectionID` | `string` | Connection instance identifier | Immutable after route creation | Initialized in `registerSessionLocked` |
| `peerKey` | `string` | Public key fingerprint identifying the peer | Immutable after route creation | Initialized in `registerSessionLocked` |
| `assignedIP` | `string` | Virtual IP allocated to the peer | Immutable after route creation | Initialized in `registerSessionLocked` |
| `backendTunnelID` | `int64` | ID of the backend tunnel handling this route's traffic | `Forwarder.mu.Lock` | Set at creation; updated in `UpdateSessionBackend` |
| `returnPath` | `*ReturnPath` | Dedicated return path engine binding (nil for legacy TUN) | Immutable per route generation | Set at creation; changed owner replaces route generation in `BindSessionReturnPath` |
| `clientQueue` | `chan []byte` | Buffered downstream packet channel toward client | Channel operations; protected against close | Created at route creation; never closed |
| `queueReady` | `chan struct{}` | Coalesced notification channel waking the client pump worker | Channel synchronization (cap 1) | Signaled on enqueue; drained on dequeue |
| `queueHighWater` | `atomic.Uint64` | Peak occupancy observed on this specific client queue | `sync/atomic` CAS | Updated on packet enqueue |
| `queueFullDrops` | `atomic.Uint64` | Return packets dropped because `clientQueue` was saturated | `sync/atomic` operations | Incremented in `RouteBackendToClient` |
| `queueOccupancy` | `int` | Cached channel occupancy for reconciliation | `Forwarder.aggregateQueueMu` | Updated during managed enqueue, dequeue, and drain |
| `pressure` | `routePressureWindow` | Windowed recent drop and stall rate evaluator | `routePressureWindow.mu` | Sampled during route diagnostics inspection |
| `writeMu` | `sync.Mutex` | Serializes device write admission with route retirement | `sessionRoute.writeMu` | Acquired during `writeClientPacket` and retirement join |
| `retired` | `atomic.Bool` | Indicates whether route is retired and rejecting new writes | `sync/atomic` operations | Set `true` in `stopRoutePumpLocked` |
| `createdAt` | `time.Time` | Timestamp when route was registered | Immutable after route creation | Initialized in `registerSessionLocked` |
| `traffic` | `trafficCounters` | Cumulative Rx/Tx counters and rate windows for this route | `trafficCounters.mu` and atomics | Incremented on packet admission |
| `writeMetrics` | `DeviceWriteTelemetry` | Per-route device write latency and stall statistics | `Forwarder.writeMetricsMu` | Updated in `writeClientPacket` |
| `writeLatencies` | `routeLatencyReservoir`| Ring buffer of recent write durations for this route | `Forwarder.writeMetricsMu` | Updated in `writeClientPacket` |
| `stopCh` | `chan struct{}` | Termination signal for this route's `pumpClientQueue` worker | Channel synchronization | Created at route registration; closed in `stopRoutePumpLocked` |
| `stopped` | `bool` | Idempotency guard for closing `stopCh` | `Forwarder.mu.Lock` | Set `true` in `stopRoutePumpLocked` |
| `limitDownBps` | `int64` | Downstream bandwidth limit in bytes/sec | `Forwarder.mu.Lock` | Initialized at registration; updated in `SetPeerRateLimit` |
| `limitUpBps` | `int64` | Upstream bandwidth limit in bytes/sec | `Forwarder.mu.Lock` | Initialized at registration; updated in `SetPeerRateLimit` |
| `tbDown` | `*TokenBucket` | Downstream token bucket rate limiter | `TokenBucket.mu` | Created at registration; replaced in `SetPeerRateLimit` |
| `tbUp` | `*TokenBucket` | Upstream token bucket rate limiter | `TokenBucket.mu` | Created at registration; replaced in `SetPeerRateLimit` |
| `pumpStarted` | `bool` | Prevents redundant pump goroutines for this route | `Forwarder.mu.Lock` | Set `true` on pump spawn; cleared on pump exit or route stop |

---

### 2.3 Supporting Dataplane Structs

- **`TokenBucket`**: Mutex-guarded (`tb.mu`) token bucket rate limiter. Tracks `rate`, burst `capacity`, current `tokens`, and `lastUpdate`. `Allow(n)` deducts tokens if available; non-positive rates are treated as nil (unlimited).
- **`ReturnPath`**: Mutex-guarded (`ReturnPath.mu`) lifetime owner for client engine return writes. Owns `closed bool` and `write func(peerKey, assignedIP string, packet []byte) (int, error)`. `Write()` holds `ReturnPath.mu.RLock()` across writer callbacks; `Close()` acquires write `Lock()` and joins in-flight writes.
- **`Retirement`**: Represents a retired route generation undergoing teardown. Carries `route *sessionRoute`. `Wait()` and `WaitContext(ctx)` block until all in-flight device writes admitted under `route.writeMu` finish. Device write quiescence is guaranteed strictly upon **successful** completion of `WaitContext`; on timeout, it returns `ErrRetirementTimeout` and its joining helper goroutine remains blocked on `writeMu` until the write returns.
- **`routePressureWindow`**: Mutex-guarded (`mu`) sliding-window tracker over monotonic route failure counters (`queueFullDrops`, write errors, write stalls). Enforces a 200ms evaluation floor (`routePressureSampleInterval`) to prevent multi-pass telemetry queries from clearing recent incident deltas.
- **`queueDwellTracker`**: Unlocked struct owned strictly by `Forwarder.aggregateQueueMu`. Measures cumulative and consecutive time aggregate queue occupancy dwells above 50% and 80% capacity thresholds.
- **`RateTracker`**: Mutex-guarded (`mu`) generation-aware rate calculator. Owns `GenerationSampler`, computing instant rates, packet rates, drop rates, and 5-minute / 1-hour exponential moving averages (EWMA).
- **`GenerationSampler`**: Thread-safe (`mu`) helper enforcing generation gating, a 200ms sample floor, and whole-vector monotonicity. Rejects observations tagged with stale generations or containing any backward-moving counter.
- **`TrafficAccountant`**: RWMutex-guarded (`mu`) background worker aggregating in-memory delta byte counters across sessions and connections, periodically flushing non-zero deltas to SQL storage.

---

### 2.4 Goroutine Lifecycles & Coordination

```
                  +----------------------------------------------+
                  |               Forwarder.Start()              |
                  |  (Initializes generations & drop baselines)  |
                  +----------------------------------------------+

                  +----------------------------------------------+
                  |             Forwarder.StartPumps()           |
                  |  (Separate caller invocation spawns workers) |
                  +----------------------------------------------+
                               /                    \
                              /                      \
                             v                        v
            +------------------------+      +------------------------+
            |  go pumpBackendQueue() |      |   go pumpClientQueue() |
            +------------------------+      +------------------------+
            | Reads: backendQueues   |      | Reads: clientQueue     |
            | Writes: PacketDevice   |      | Writes: ReturnPath     |
            +------------------------+      +------------------------+
                         |                              |
         (DetachBackendDevice/StopPumps)        (Route Retirement/StopPumps)
                         |                              |
                         v                              v
            +------------------------+      +------------------------+
            |   close(perPumpStopCh) |      |   close(route.stopCh)  |
            |   or close(pumpsStopCh)|      |   or close(pumpsStopCh)|
            +------------------------+      +------------------------+
                         |                              |
                         v                              v
            +------------------------+      +------------------------+
            | close(doneCh)          |      | route.writeMu drained  |
            | pumpsWg.Done()         |      | pumpsWg.Done()         |
            +------------------------+      +------------------------+
```

#### 1. Per-Route Client Pump (`pumpClientQueue`)
- **Spawn Conditions**: Spawned in `registerSessionLocked` (if `f.pumpsRunning` is true) or in `StartPumps` when adopting un-pumped routes. Tracks lifetime via `f.pumpsWg.Add(1)`.
- **Execution Loop**:
  1. Checks termination signals (`stopCh` or `route.stopCh`).
  2. Acquires `f.aggregateQueueMu.Lock()`, reconciles occupancy, and performs a non-blocking read from `route.clientQueue`.
  3. If queue is empty: unlocks `f.aggregateQueueMu` and blocks on `select { case <-stopCh: ... case <-routeStopCh: ... case <-route.queueReady: }`.
  4. If packet is retrieved: unlocks `f.aggregateQueueMu`, acquires `f.mu.RLock()` to resolve the active `packetWriter` (strictly via `routeWriter` wrapping non-nil `ReturnPath`; if `route.returnPath == nil`, dequeued packets have no writer and are discarded), and releases `f.mu.RLock()`.
  5. If writer is non-nil, invokes `writeClientPacket(route, dev, pkt)`.
- **Termination & Cleanup**:
  - Exits when `pumpsStopCh` (global forwarder stop) or `route.stopCh` (route unregistration/retirement) is closed.
  - Calls `defer f.pumpsWg.Done()`.

#### 2. Per-Backend Egress Pump (`pumpBackendQueue`)
- **Spawn Conditions**: Spawned in `AttachBackendDevice` (if `f.pumpsRunning` is true) or in `StartPumps` for each attached backend tunnel device. Tracks lifetime via `f.pumpsWg.Add(1)`.
- **Execution Loop**:
  1. Blocks on `select` reading from `queue` (`chan []byte`), `globalStopCh`, or `perPumpStopCh`.
  2. If packet is received: performs a non-blocking check on stop channels to guarantee prompt termination if signaled while queue was ready.
  3. Writes packet directly to backend interface via `dev.Write(pkt)`.
- **Termination & Cleanup**:
  - Exits when `globalStopCh` or `perPumpStopCh` is closed, or when `queue` is closed.
  - Closes `doneCh` to notify synchronous detach waiters.
  - Calls `defer f.pumpsWg.Done()`.

#### 3. Worker Shutdown Signaling
- **Graceful Forwarder Shutdown (`Stop`)**:
  1. Calls `wait := f.RetireAllRoutes()`. Under `f.mu.Lock()`, every active route is retired via `stopRoutePumpLocked` (closing `route.stopCh`, setting `route.retired = true`), queues are drained via `drainRouteQueueLocked`, and routing tables are cleared.
  2. Runs `wait(ctx)` outside locks with a deadline (default 5s) to join all in-flight device writes. Device write quiescence is guaranteed strictly upon successful completion.
  3. If `wait(ctx)` returns a timeout error (`ErrRetirementTimeout`), `Stop()` enters its timeout recovery path: calls `f.stopPumpsSignalOnly()` (closing `pumpsStopCh` and all `backendPumpStops`), marks `f.running = false` under `f.mu.Lock()`, stops `TrafficAccountant`, and returns the timeout error immediately without blocking on `f.pumpsWg.Wait()`. The background helper goroutines spawned to join `writeMu` remain blocked until the writes finish.
  4. On successful quiescence, calls `StopPumps()`, which invokes `stopPumpsSignalOnly()` and waits on `f.pumpsWg.Wait()`. Note that `StopPumps()` has no timeout mechanism and cannot interrupt a backend device permanently blocked in `dev.Write(pkt)`.
  5. Flushes and terminates `TrafficAccountant`. Sets `f.running = false`.

---

## 3. Packet Buffer Ownership & Memory Lifetime

### 3.1 Packet Traversal: Client to Backend (Upstream)

```
[ Ingress Listener ]
        |
        v Reads plaintext packet from WireGuard / TUN
[ RouteClientToBackend(peerKey, packet) ]
        |
        +---> [ f.mu.RLock() ]
        |       |-- Look up sessionRoute in routesByPeer[peerKey]
        |       |-- Anti-Spoofing Check: packet.srcIP == route.assignedIP
        |       |-- Look up backendQueue in backendQueues[route.backendTunnelID]
        |       \-- Extract route.sessionID, connectionID, tbUp
        |
        +---> [ Upstream Rate Limiting: tbUp.Allow(len(packet)) ]
        |       \-- Saturated: Increment clientDropsRateLimited, return ErrRateLimitExceeded
        |
        +---> [ Packet Slice Allocation: make([]byte, len(packet)) + copy ]
        |       \-- Memory ownership transfers to Forwarder
        |
        +---> [ Enqueue: backendQueue <- pktCopy ]
        |       |-- Success: Record Rx bytes/packets & Accountant Rx
        |       \-- Full: Increment clientDropsQueueFull, return ErrQueueFull
        v
[ pumpBackendQueue ]
        |
        +---> Dequeue pktCopy from backendQueue
        +---> dev.Write(pktCopy)
        \---> Reference released; slice garbage collected
```

1. **Ingress Read**: Network listener reads encrypted payload, decrypts plaintext IP packet into an ingress buffer, and calls `RouteClientToBackend(peerKey, packet)`.
2. **Route Resolution & Anti-Spoofing**: Under `f.mu.RLock()`, the forwarder resolves `sessionRoute` by `peerKey`. The packet's inner IPv4 source IP is validated: if non-zero and not equal to `route.assignedIP`, `spoofedRebinds` is incremented and `ErrSpoofedSourceIP` is returned (packet dropped). The forwarder unconditionally rejects mismatched non-zero inner source IPs; there is no dynamic self-heal rebind path in production routing.
3. **Token Bucket Evaluation**: Evaluates `tbUp.Allow(pktLen)`. If tokens are insufficient, drops are counted and `ErrRateLimitExceeded` is returned.
4. **Buffer Detachment & Allocation**: An independent byte slice is allocated:
   ```go
   pktCopy := make([]byte, len(packet))
   copy(pktCopy, packet)
   ```
   *Invariant*: The enqueued slice is completely decoupled from the caller's stack/arena buffer. There is **NO forwarder-owned `sync.Pool`**: packet slices are independent heap allocations reclaimed by Go garbage collection once channel references are consumed and released.
5. **Backend Enqueue**: A non-blocking send submits `pktCopy` to `backendQueue`:
   - *Success*: Increments `totalRxBytes`, `totalRxPackets`, route/backend traffic counters, and accountant Rx.
   - *Queue Full*: Increments `clientDropsQueueFull` and returns `ErrQueueFull`. `pktCopy` becomes immediately unreachable and is garbage collected.
6. **Backend Transmission**: `pumpBackendQueue` dequeues `pktCopy`, passes it to `dev.Write(pktCopy)`, and releases the slice reference.

---

### 3.2 Packet Traversal: Backend to Client (Downstream / Return Path)

```
[ Backend Network Interface / TUN ]
        |
        v Reads return IP packet
[ RouteBackendToClient(backendTunnelID, packet, destIP) ]
        |
        +---> [ f.mu.RLock() ]
        |       |-- Look up sessionRoute in routesByIP[destIP]
        |       |-- Return-Path Verification: backendTunnelID == route.backendTunnelID
        |       \-- Shape Verification: validReturnDestination(packet, destIP)
        |
        +---> [ Payload Bound Check: len(packet) <= MaxClientQueuePacketBytes (1500) ]
        |       \-- Oversized: Increment dropsPacketTooLarge, return ErrPacketTooLarge
        |
        +---> [ Downstream Rate Limiting: tbDown.Allow(len(packet)) ]
        |       \-- Saturated: Return ErrRateLimitExceeded
        |
        +---> [ Packet Slice Allocation: make([]byte, len(packet)) + copy ]
        |       \-- Independent heap allocation; reclaimed by GC
        |
        +---> [ Re-verify Route & Enqueue under f.mu.RLock() and f.aggregateQueueMu ]
        |       |-- Check routesByIP[destIP] == route (guards against concurrent delete)
        |       |-- Non-blocking enqueue: select { case route.clientQueue <- pktCopy: ... default: ... }
        |       |-- Success: Notify route.queueReady, update high-water mark, record Tx
        |       \-- Saturated: Increment route.queueFullDrops, dropsQueueFull
        v
[ pumpClientQueue ]
        |
        +---> Dequeue under f.aggregateQueueMu; update occupancy
        +---> Resolve writer (routeWriter with ReturnPath; discarded if nil) under f.mu.RLock()
        +---> [ writeClientPacket ]
        |       |-- Acquire route.writeMu
        |       |-- Check !route.retired.Load()
        |       |-- Track in-flight write in f.writesInFlight[route]
        |       |-- dev.Write(pktCopy)
        |       |-- Update writeMetrics, writeLatencies, writeHistogram
        |       \-- Release route.writeMu
        v
[ Client ReturnPath Callback ]
        \-- Slice released; garbage collected
```

1. **Backend Read**: Backend device reads return IP packet and invokes `RouteBackendToClient(backendTunnelID, packet, destIP)`.
2. **Route Resolution & Boundary Checks**: Under `f.mu.RLock()`, resolves `sessionRoute` from `routesByIP[destIP]`. If unmapped, drops are incremented and `ReturnRejectedUnrouted` is reported.
3. **Identity & Shape Fencing**: If route defines a `ReturnPath`:
   - Checks `backendTunnelID == route.backendTunnelID`. Mismatched tunnels reject the packet with `ErrReturnRouteMismatch` and classify `ReturnRejectedMismatch`.
   - Calls `validReturnDestination(packet, destIP)` to verify IPv4 header structure and exact destination IP match. Malformed packets return `ErrReturnRouteMismatch` and classify `ReturnRejectedMalformed`.
4. **Size & Rate Bounds**:
   - Packets exceeding `MaxClientQueuePacketBytes` (1500 bytes) are rejected with `ErrPacketTooLarge`.
   - Checks `tbDown.Allow(pktLen)`. Saturated buckets return `ErrRateLimitExceeded`.
5. **Buffer Allocation & Enqueue**:
   - Allocates `pktCopy := make([]byte, len(packet))` and copies payload (independent heap slice; no forwarder-owned `sync.Pool`).
   - Re-acquires `f.mu.RLock()` and verifies `routesByIP[destIP] == route`.
   - Retaining `f.mu.RLock()`, acquires `f.aggregateQueueMu.Lock()` and attempts non-blocking send (`select { case clientQueue <- pktCopy: ... default: ... }`) to `route.clientQueue`.
   - *Success*: Updates aggregate occupancy, sets `route.queueHighWater` and `f.aggregateQueueHighWater`, posts notification to `route.queueReady`, records Tx statistics, releases `aggregateQueueMu` then `f.mu.RLock()`.
   - *Queue Full*: Releases locks, increments `route.queueFullDrops` and returns `ErrQueueFull`.
   - *Linearization with Retirement*: Because `RetireAllRoutes`, `UnregisterSession`, and `RetireRoutesByReturnPath` acquire `f.mu.Lock()` exclusively, return packet enqueue strictly precedes route retirement/drain, OR if retirement runs first, subsequent return packets find the route missing in `routesByIP` and return `ErrSessionNotRegistered` before any enqueue attempt. Retired queues are never refilled.
6. **Consumer Pump Dequeue**: `pumpClientQueue` wakes, dequeues `pktCopy` under `aggregateQueueMu`, resolves the `packetWriter` strictly via non-nil `ReturnPath` under `f.mu.RLock()` (if `ReturnPath` is nil, dequeued packets have no writer and are discarded), and executes `writeClientPacket`.
7. **Device Write & Retirement Fence**:
   - In `writeClientPacket`, acquires `route.writeMu`.
   - Verifies `!route.retired.Load()`. If retired, the packet is discarded immediately.
   - Records start time in `f.writesInFlight[route]`.
   - Executes `dev.Write(packet)` (which runs `routeWriter.Write` -> `ReturnPath.Write`).
   - Updates latency reservoirs, histograms, stall counters, and deletes in-flight entry.
   - Releases `route.writeMu`. Packet slice becomes eligible for GC.

---

### 3.3 Buffer Sizing & Memory Budget Bounds

```
+------------------------------------------------------------------------+
|          Aggregate Client Queued-Payload Byte Budget (8 GiB)           |
|                       MaxClientQueueMemoryBytes                        |
+------------------------------------------------------------------------+
       |                                                    |
       v (Default Population: 1,000 routes)                 v (Explicit Route Limits)
+-----------------------------------+        +-----------------------------------+
| MaxClientQueuePackets = 5,726 pkts|        | MaxClientQueuePacketsForRoutes(N) |
| DefaultClientQueueSize = 2,048 pkts|        | = MaxMemory / (N * 1500 B)        |
| ~2.8 MB per peer @ 1420 B MTU     |        | Enforces per-route queue limits   |
+-----------------------------------+        +-----------------------------------+
```

- **MTU Bounds**: Target WireGuard VPN MTU is 1420 bytes.
- **Maximum Queued Packet Size**: `MaxClientQueuePacketBytes = 1500` bytes (conservative upper bound per queued packet).
- **Aggregate Client Queued-Payload Byte Budget**: `MaxClientQueueMemoryBytes = 8 << 30` (8 GiB).
  *Important*: The 8 GiB formula is strictly a **queued payload byte budget** (`forwarder.go:329–340`), not an aggregate process memory ceiling. It explicitly excludes Go channel descriptors, GC allocator overhead, route struct metadata, in-flight stack buffers, and backend queues (`backendQueues`).
- **Buffer Pool Lifecycle**: There is **NO forwarder-owned `sync.Pool`**. Packet slices are independent heap allocations (`make([]byte, ...)`) reclaimed by Go garbage collection once channel references are consumed and released.
- **Maximum Supported Active Routes**: `MaxBudgetedActiveRoutes = 8 GiB / 1500 B = 5,726,623` routes. Default active route limit is `MaxSupportedActiveRoutes = 1000`.
- **Queue Sizing Calculation**:
  ```go
  maxPackets := MaxClientQueueMemoryBytes / (activeRoutes * MaxClientQueuePacketBytes)
  ```
  With the default 1,000 routes, the mathematical maximum queue capacity is 5,726 packets. The forwarder caps `DefaultClientQueueSize` at 2,048 packets (~2.8 MB per client) as the default queue capacity, not universal. Explicit configurations via `ReconfigureClientQueueConfig` derive per-route queue capacities bounded by the configured route limit.
- **Queue Memory Isolation**: Client queue sizes (`bufSize`) and backend queue sizes (`backendBufSize` = 2048) are configured independently. Reconfiguring client route queue limits never mutates backend queue allocations.

---

## 4. Route Lifecycle, Identity Protection & Retirement Invariants

### 4.1 Route Lifecycle State Transitions

```
[ New Session ]
       |
       v TryRegisterSessionWithLimit / TryRegisterSessionWithReturnPath
[ ACTIVE ] <-----------------------------------------+
       |                                             |
       +---> Re-register same peerKey                |
       |     \-- Old route generation RETIRED        |
       |                                             | UpdateSessionBackend
       +---> Backend failover / migration -----------+ (Preserves route & queues)
       |
       +---> UnregisterSession / BeginUnregisterSession
       |     \-- stopRoutePumpLocked + drainRouteQueueLocked
       v
[ RETIRED ]
       |
       +---> route.retired = true (Rejects future writes)
       +---> route.stopCh closed (Stops pumpClientQueue)
       +---> clientQueue drained under aggregateQueueMu
       +---> Removed from routesByPeer and routesByIP
       |
       v Retirement.WaitContext(ctx)
[ TERMINATED ] (In-flight writes complete; memory GC'd)
```

#### 1. Registration (`RegisterSession`, `TryRegisterSessionWithLimit`, `TryRegisterSessionWithReturnPath`)
- **Preconditions**: If `ReturnPath` is supplied, it must not be closed (`!path.Closed()`).
- **Admission Budget Gate**: Checks active route count against `maxActiveRoutes`. Re-registration of an existing peer key is always permitted (replacement without population growth). New peers exceeding the limit are rejected with `ErrRouteCapacityExhausted`.
- **Generational Replacement**: If a route already exists for `peerKey`:
  1. Old route is captured in `retirement.route`.
  2. `stopRoutePumpLocked(old)` closes `old.stopCh`, sets `old.retired = true`, and clears `old.pumpStarted`.
  3. `drainRouteQueueLocked(old)` consumes and discards all pending packets in `old.clientQueue` under `aggregateQueueMu.Lock()`.
  4. Deducts old capacity: `changeQueueCapacityLocked(-cap(old.clientQueue))`.
  5. Removes `old.assignedIP` from `routesByIP` if and only if `routesByIP[old.assignedIP] == old`.
- **Installation**: Instantiates new `sessionRoute`, allocates `clientQueue` (capacity `f.bufSize`), sets `routesByPeer[peerKey]` and `routesByIP[assignedIP]`, increments queue capacity, and launches `pumpClientQueue` if pumps are running.
- **Retirement Obligation**: Callers receiving a non-zero `Retirement` must execute `retirement.Wait()` or `retirement.WaitContext(ctx)` after releasing all outer locks (including `Service.mu`) to join in-flight writes.

#### 2. Live Backend Update (`UpdateSessionBackend`)
- Modifies `route.backendTunnelID` under `f.mu.Lock()`.
- Ensures backend queue and traffic structures exist for the new tunnel.
- *Preservation & Failover Delivery Semantics*: Existing `sessionRoute` objects, `clientQueue`, token buckets, session IDs, and pump workers remain entirely untouched. However, `UpdateSessionBackend` does not migrate packets already queued in the upstream backend queue, and in-flight return packets arriving from the old backend tunnel will fail return-path validation (`ErrReturnRouteMismatch`) and be dropped.

#### 3. Unregistration & Teardown (`BeginUnregisterSession`, `RetireAllRoutes`, `RetireRoutesByReturnPath`)
- **Generational Identity Guard**: `BeginUnregisterSession(peerKey, sessionID)` verifies `route.sessionID == sessionID`. A delayed teardown call for an expired session cannot unregister a newer session that replaced it.
- **Reverse Map Protection**: `delete(f.routesByIP, route.assignedIP)` executes only if `routesByIP[route.assignedIP] == route`.
- **Queue Drainage**: Invokes `drainRouteQueueLocked(route)` to prevent orphaned packets from holding memory.
- **Pumps Termination**: Closes `route.stopCh` without closing `route.clientQueue`.

---

### 4.2 Anti-Spoofing & Return Path Identity Protection

1. **Inner Source IP Anti-Spoofing Guard**:
   - In `routeClientToBackend`, the inner packet source IP (`srcIP`) is extracted from the IPv4 header.
   - If `srcIP` is non-zero and does not equal `route.assignedIP`, the packet is dropped, `spoofedRebinds` is atomically incremented, and `ErrSpoofedSourceIP` is returned.
   - The forwarder unconditionally rejects mismatched non-zero inner source IPs (`routeClientToBackend` in `forwarder.go:855–872`). There is no dynamic self-heal rebind path to unassigned subnet addresses in production routing.
2. **Cross-Session Return Path Isolation (`ErrReturnRouteMismatch`)**:
   - In `RouteBackendToClient`, return packets arriving from backend tunnel `B` intended for client VIP `destIP` are verified:
     ```go
     if route.returnPath != nil && backendTunnelID != route.backendTunnelID {
         return ErrReturnRouteMismatch
     }
     ```
   - *Protection*: Guarantees that traffic arriving from an unexpected backend cannot leak into another peer's session during tunnel failover or rebalancing.
3. **Payload Destination Verification (`validReturnDestination`)**:
   - Return packets must have a valid IPv4 header (`version == 4`, `ihl >= 5`, `totalLength <= len(packet)`).
   - The packet header's destination IP must exactly match `route.assignedIP`.

---

### 4.3 Route Retirement & Channel Drain Safety

A critical concurrency pitfall in network dataplanes is the `send on closed channel` panic. The forwarder enforces strict channel lifecycle rules:

1. **The Client Channel Is NEVER Closed**:
   - `route.clientQueue` is created during route allocation and is **never** closed by `UnregisterSession`, `RetireAllRoutes`, or `stopRoutePumpLocked`.
   - *Reason*: Channel non-closure guarantees zero risk of a fatal `send on closed channel` runtime panic across concurrent senders.
2. **Retirement Linearization & Lock-Protected Enqueue**:
   - Return packet enqueue in `RouteBackendToClient` (`forwarder.go:991–1036`) acquires `f.mu.RLock()`, re-validates `routesByIP[destIP] == route`, and retains `f.mu.RLock()` across `f.aggregateQueueMu.Lock()` and the nonblocking channel send (`select { case clientQueue <- pktCopy: ... default: ... }`).
   - Because `RetireAllRoutes`, `UnregisterSession`, and `RetireRoutesByReturnPath` acquire `f.mu.Lock()` exclusively, return packet enqueue strictly precedes route retirement/drain, OR if retirement runs first, subsequent return packets find the route missing in `routesByIP` and return `ErrSessionNotRegistered` before any enqueue attempt.
   - Retired queues are never refilled after being drained.
   - Managed nonblocking channel sends under table locks (`f.mu.RLock()`) are safe and permitted, distinguishing them from blocking channel operations or device I/O.
3. **Termination Signaling via Dedicated Stop Channel**:
   - Goroutine shutdown is signaled exclusively by closing `route.stopCh`.
   - `route.stopped` guards against closing `stopCh` multiple times.
4. **Synchronous Queue Drain**:
   - During retirement, `drainRouteQueueLocked(route)` drains all buffered packets from `route.clientQueue` under `aggregateQueueMu.Lock()`.
5. **Device Write Join Contract (`writeMu`) & Timeout Quiescence**:
   - Active device writes hold `route.writeMu`.
   - Retirement sets `route.retired.Store(true)` and returns a `Retirement` struct.
   - `Retirement.WaitContext(ctx)` (`client_write.go:188–209`) spawns a helper goroutine that acquires and releases `route.writeMu`. Device write quiescence is guaranteed strictly upon **successful** completion of `WaitContext`.
   - When `WaitContext` times out before the admitted write finishes, it returns `ErrRetirementTimeout`. The helper goroutine remains blocked on `route.writeMu` until the underlying write finishes (it is NOT forcefully canceled).

---

## 5. Lock Hierarchy & Synchronization Rules

To guarantee deadlock-free concurrency across high-throughput packet pumps and administrative endpoints, lock acquisition strictly follows two disjoint partial lock graphs:

```
[ Snapshot & Telemetry Path ]                 [ Packet Write Path ]

    Outer Service Locks                       sessionRoute.writeMu
     (e.g. Service.mu)                      (Device write admission)
            |                                          |
            v                                          v
       Forwarder.mu                         Forwarder.writeMetricsMu
   (Routing table lock)                     (Latency & error stats)
            |
            v
 Forwarder.aggregateQueueMu
(Queue occupancy & counters)
            |
            v
 Forwarder.writeMetricsMu
 (Device write telemetry)
```

Additionally, `ReturnPath.mu` synchronizes client return writer callbacks:
- `ReturnPath.Write()` acquires `ReturnPath.mu.RLock()` across writer callbacks.
- `ReturnPath.Close()` acquires `ReturnPath.mu.Lock()` and joins in-flight writes.

### Disjointness & Deadlock Rules:
1. **`Forwarder.mu` and `sessionRoute.writeMu` are strictly disjoint**:
   - Code holding `Forwarder.mu` MUST NEVER acquire `sessionRoute.writeMu` or invoke `Retirement.Wait()` / `route.waitForWriteContext()` (`forwarder.go:189`).
   - Code holding `sessionRoute.writeMu` MUST NEVER acquire `Forwarder.mu`.
   - In `client_write.go:216–231`, `route.writeMu.Lock()` is acquired first and `f.writeMetricsMu.Lock()` is acquired second. Device writes execute kernel/network I/O; holding `Forwarder.mu` across `writeMu` would stall global routing.
2. **Never call `Retirement.Wait()` while holding `Forwarder.mu` or `Service.mu`**:
   - `Retirement.Wait()` blocks waiting for `route.writeMu`. Calling it while holding an outer mutex leads to immediate deadlock.
3. **No blocking I/O under `Forwarder.mu` or `aggregateQueueMu`**:
   - Device writes (`dev.Write`) and blocking channel operations must never execute under table locks.
   - Nonblocking managed channel operations (`select ... default`) are permitted under `f.mu.RLock()` and `aggregateQueueMu.Lock()`.
4. **Classifier callbacks run outside `Forwarder.mu`**:
   - `classifyReturnReject` snapshots `f.returnRejectClassifier` under `f.mu.RLock()` and invokes it after releasing the lock, preventing deadlocks with ingress telemetry counters.

---

## 6. Verified Test Baseline

Every test listed below is verified in the repository (`internal/vpn/forwarder/`) across 82 verified test functions and guards the invariants documented above:

| Test Name | File Location | Guarded Dataplane Invariant |
| :--- | :--- | :--- |
| `TestForwarderBasicRouting` | `forwarder_test.go:57` | Bidirectional packet routing between client and backend |
| `TestForwarderEdgeCasesAndLifecycle` | `forwarder_test.go:125` | Route registration, lookup, unregistration, and query APIs |
| `TestForwarderRateLimitingThrottling` | `forwarder_test.go:201` | Upstream and downstream token bucket rate limiting |
| `TestForwarderPacketPumps` | `forwarder_test.go:272` | Background pump worker packet delivery to devices |
| `TestTokenBucketDirect` | `forwarder_test.go:368` | Direct unit tests of token bucket burst and refill math |
| `TestForwarder_ReattachStopsOldPumpAndDeliversToNewDevice` | `forwarder_test.go:391` | Backend device reattachment stops old pump without leaking |
| `TestForwarderDynamicSourceIPRebindRejected` | `forwarder_test.go:461` | Anti-spoofing rejection of mismatched inner source IP |
| `TestForwarder_StartConcurrentWithBackendLifecycle_Race` | `forwarder_test.go:585` | Race-free concurrent `Start()` and backend attach/detach |
| `TestForwarder_InspectRoutesConcurrentWithUpdateSessionBackend_Race` | `forwarder_test.go:625` | Concurrent `InspectRoutes` and `UpdateSessionBackend` safety |
| `TestDefaultClientQueueSize_Capacity` | `issue151_regression_test.go:9` | Default client queue capacity verification (2048 packets) |
| `TestBackendQueueCapacityIsIndependentFromClientQueueSize` | `issue151_regression_test.go:26` | Memory isolation between client and backend queue sizing |
| `TestDownstreamQueueBurstAbsorption` | `issue151_regression_test.go:47` | Client queue microburst absorption without packet drops |
| `TestDropCounterMetrics_QueueFullAndUnroutable` | `issue151_regression_test.go:104` | Metrics accounting for full queues and unroutable packets |
| `TestCurrentSessionTeardownAfterRepeatedRekeys` | `issue309_teardown_test.go:8` | Session teardown safety after multiple rekey replacements |
| `TestSessionTeardownRejectsMissingIdentity` | `issue309_teardown_test.go:57` | Teardown rejection when session ID does not match |
| `TestQueueFullRecoversAfterConsumerStall` | `issue39_regression_test.go:56` | Recovery of downstream queue after consumer stall clears |
| `TestReregisteredRouteSurvivesLateUnregister` | `issue39_regression_test.go:109` | Late unregister of old session cannot delete replaced route |
| `TestStaleRouteCannotCaptureReturnTraffic` | `issue39_regression_test.go:144` | Expired route cannot hijack return traffic from new session |
| `TestRouteRegisteredBeforeStartPumpsGetsPump` | `issue39_regression_test.go:194` | Routes registered prior to `StartPumps` are safely adopted |
| `TestStalledRouteRecoversAfterStopStartPumps` | `issue39_regression_test.go:224` | Operator recovery via `StopPumps()` and `StartPumps()` |
| `TestRouteQueueStatsExposeOccupancyHighWaterAndDrops` | `queue_observability_test.go:53` | Occupancy, high-water, and drop counters in queue stats |
| `TestForwarderQueueCapacityIsBounded` | `queue_observability_test.go:81` | Verification of bounded queue capacity |
| `TestForwarderQueueHighWaterTracksPeakBeforeConcurrentDrain` | `queue_observability_test.go:94` | High-water mark samples peak occupancy before concurrent drain |
| `TestForwarderRouteReplacementReconcilesQueueOccupancy` | `queue_observability_test.go:111` | Route replacement correctly reconciles aggregate occupancy |
| `TestForwarderRouteReplacementRemovesStaleAssignedIP` | `queue_observability_test.go:136` | Route replacement removes stale assigned IP from reverse map |
| `TestForwarderDirectChannelDrainIsReconciledBeforeNextEnqueue` | `queue_observability_test.go:149` | Direct queue drains reconcile aggregate counters |
| `TestForwarderQueueSizeCanBeReconfiguredBeforeRoutes` | `queue_observability_test.go:172` | Safe queue resizing when no active routes exist |
| `TestForwarderQueueSizeRejectsReconfigurationWithActiveRoutes`| `queue_observability_test.go:187` | Reconfiguration rejected while active sessions exist |
| `TestForwarderDeviceWriteStatsRecordErrorsAndDuration` | `queue_observability_test.go:195` | Device write error and duration telemetry accounting |
| `TestForwarderConcurrentProducerConsumerAccounting` | `queue_observability_test.go:235` | Thread-safe concurrent enqueue, dequeue, and accounting |
| `TestForwarderAggregateHighWaterTracksSimultaneousOccupancy` | `queue_observability_test.go:290` | Aggregate high-water accurately tracks simultaneous load |
| `TestForwarderQueueSaturationRecoveryAndMetrics` | `queue_observability_test.go:313` | Queue saturation recovery and drop metric fidelity |
| `TestForwarderQueueCapacityUsesAggregateMemoryBudget` | `queue_observability_test.go:339` | Aggregate memory budget enforcement (8 GiB ceiling) |
| `TestForwarderRejectsOversizedBackendPacketWithoutQueueing` | `queue_observability_test.go:349` | Drops packets exceeding `MaxClientQueuePacketBytes` |
| `TestForwarderRejectsRegistrationsBeyondActiveRouteLimit` | `queue_observability_test.go:373` | Admission rejection when active route budget is exhausted |
| `TestForwarderSustainedDownstreamStallSaturatesAndRecovers` | `queue_observability_test.go:400` | Downstream stall saturation handling and self-recovery |
| `TestForwarderConfiguredRouteLimitDerivesQueueBudget` | `queue_observability_test.go:459` | Per-route queue capacity derived from configured route limit |
| `TestRouteRetirementDoesNotBlockOtherRoutesOnDeviceWrite` | `queue_observability_test.go:483` | Slow device write on retiring route does not stall other peers |
| `TestRetiredRouteRejectsWriteSelectedBeforeRetirement` | `queue_observability_test.go:547` | Write selected prior to retirement is rejected at admission |
| `TestDeviceTelemetryReportsBlockedWriteBeforeCompletion` | `queue_observability_test.go:589` | Live blocked writes reported in telemetry before finishing |
| `TestClientQueueConfigAllowsSafeLiveRouteLimitChanges` | `queue_observability_test.go:630` | Route limit changes allowed when existing sessions fit |
| `TestRouteBudgetBoundary` | `queue_observability_test.go:656` | Boundary test for route limit allocations |
| `TestPerRouteWriteTelemetrySeparatesDifferentConsumers` | `queue_observability_test.go:680` | Write telemetry isolation across different peer consumers |
| `TestSustainedClientTrafficWithRepeatedStalls` | `queue_observability_test.go:737` | System stability under sustained traffic with repeated stalls |
| `TestManagedQueueDwellPeriodicBursts` | `queue_dwell_test.go:25` | Queue dwell tracking under periodic burst conditions |
| `TestManagedQueueDwellImmediateRecoveryAndTotals` | `queue_dwell_test.go:47` | Dwell recovery and cumulative duration accounting |
| `TestManagedQueueDwellCapacityChanges` | `queue_dwell_test.go:69` | Dwell tracking adaptation to capacity adjustments |
| `TestManagedQueueDwellPumpRecovery` | `queue_dwell_test.go:97` | Dwell tracking reset when consumer pumps clear backpressure |
| `TestInspectRoutesExactPressureThreshold` | `queue_dwell_test.go:115` | Route pressure detection matching exact utilization thresholds|
| `TestManagedQueueDwellLegacyDrainBeforeEnqueue` | `queue_dwell_test.go:138` | Legacy channel drains reconciled before dwell measurement |
| `TestManagedQueueDwellReplacementAndRetirement` | `queue_dwell_test.go:160` | Dwell accounting fidelity during route replacement/retirement |
| `TestRebindHijackBlocked` | `rebind_guard_test.go:34` | Verification that IP rebind hijacking is blocked |
| `TestMismatchedSourceIPRejectedWithoutMutation` | `rebind_guard_test.go:109` | Mismatched source IP rejected without altering route state |
| `TestSpoofedRebindsOutsideSubnet` | `rebind_guard_test.go:173` | Source IP outside `portalSubnet` counted as spoofed rebind |
| `TestReturnPathRoutesOnlyMatchingBackendAndDestination` | `return_path_test.go:26` | Return path validates backend ownership and destination VIP |
| `TestReturnPathBindingRetiresOldWriterAndPreservesReuse` | `return_path_test.go:74` | Binding new ReturnPath replaces route generation and queue; same-owner reuse preserves queues |
| `TestReturnPathClosedAndTUNPressureIsBounded` | `return_path_test.go:130` | Closed ReturnPath rejects writes without unbounded backpressure|
| `TestReturnPathCloseJoinsConcurrentWrites` | `return_path_test.go:181` | ReturnPath `Close()` waits for admitted concurrent writes |
| `TestReturnRetirementClassification` | `return_path_test.go:200` | Return rejection classifier receives correct failure reasons |
| `TestHasSessionRouteWithReturnPathDetectsReverseMapDeletion`| `reverse_map_invariant_test.go:24` | Validates reverse map integrity in route existence checks |
| `TestSquatAttemptRejectedAndCannotCorruptReverseMap` | `reverse_map_invariant_test.go:69` | IP squatting attempts cannot overwrite reverse map entries |
| `TestUnregisterSession_StopsPumpGoroutine` | `teardown_integration_test.go:62`| Unregistering session terminates its pump goroutine |
| `TestUnregisteredSessionRouteRejected` | `teardown_integration_test.go:80`| Unregistered session immediately rejects further packet routing|
| `TestUpdateSessionBackend_MigratesLiveTraffic` | `teardown_integration_test.go:97`| Live traffic seamlessly migrates to updated backend tunnel |
| `TestSessionRouteStopChannelNeverClosedQueue` | `teardown_integration_test.go:136`| Validates `clientQueue` is never closed during route teardown |
| `TestRetireAllRoutes_DrainsQueuesAndJoinsWrites` | `teardown_integration_test.go:150`| `RetireAllRoutes` drains queues and waits for in-flight writes |
| `TestRetireRoutesByReturnPath_SelectiveRetirement` | `teardown_integration_test.go:243`| Selective route retirement matching specific ReturnPath owner |
| `TestForwarder_Stop_FullCleanupAndDrain` | `teardown_integration_test.go:314`| Full forwarder `Stop()` cleans up all routes, queues, and pumps |
| `TestRetireAllRoutes_PermanentlyBlockedWriteTimesOut` | `teardown_integration_test.go:378`| Context timeout terminates wait on permanently hung device |
| `TestForwarder_Stop_PermanentlyBlockedWriteTimesOut` | `teardown_integration_test.go:417`| Forwarder `Stop()` honors timeout on hung device writes |
| `TestTokenBucketSustainedRate` | `tokenbucket_issue94_test.go:21` | Sustained rate limit enforcement over extended windows |
| `TestTokenBucketInitialBurst` | `tokenbucket_issue94_test.go:54` | Initial burst allowance up to bucket capacity |
| `TestTokenBucketCapacityClampedUpToRate` | `tokenbucket_issue94_test.go:87` | Token bucket capacity automatically clamped to at least rate |
| `TestTokenBucketIdleRefill` | `tokenbucket_issue94_test.go:109` | Token replenishment during idle periods |
| `TestTokenBucketCustomCapacity` | `tokenbucket_issue94_test.go:143` | Custom burst capacity configuration semantics |
| `TestTokenBucketConcurrentAllow` | `tokenbucket_issue94_test.go:182` | Thread-safe concurrent `Allow()` invocation under race detector|
| `TestRateTracker_RatesAndEWMA` | `rates_test.go:9` | Throughput rates and EWMA window calculations |
| `TestForwarder_RatesAndPressureAPI` | `rates_test.go:54` | Forwarder `Rates()` and `QueuePressure()` query accuracy |
| `TestForwarder_StartResetsGenerationAndReprimesRates` | `generation_test.go:280` | Forwarder restart bumps generation and re-primes rate baselines |
| `TestGenerationTrafficWindow_WholeVectorMonotonicity` | `traffic_telemetry_test.go:13` | Rejection of non-monotonic counter updates in telemetry windows |
| `TestPumpClientQueueLogsWriteErrors` | `write_error_logging_test.go:44` | Device write errors are logged and rate-throttled to 1/sec |
| `TestBackendQueueFullPacketIsNotCountedAsAdmittedThroughput` | `backend_admission_accounting_test.go:30` | Dropped backend packets excluded from admitted throughput metrics |

---

## 7. Phased Move Sequence for Phase 5 Decomposition

Decomposing `forwarder.go` into same-package modular files must proceed sequentially according to state dependencies. Each phase must leave the full test suite green without altering runtime behavior:

```
[ Issue #516: Architectural Ownership Contract (This Document) ]
                                |
                                v
[ Issue #517: Route Registration, Update & Retirement Lifecycle ]
  - Target: internal/vpn/forwarder/route_lifecycle.go
  - Scope: RegisterSession*, UpdateSessionBackend, UnregisterSession*,
           RetireAllRoutes, retireRoutesMatchingLocked, stopRoutePumpLocked,
           drainRouteQueueLocked
  - Invariants: f.mu lock boundaries, atomic retirement, zero-panic queue drain
                                |
                                v
[ Issue #518: Queues, Memory Budgets & Rate Limiting ]
  - Target: internal/vpn/forwarder/queues.go & rate_limit.go
  - Scope: TokenBucket, ValidateClientRouteLimit, MaxClientQueuePacketsForRoutes,
           ReconfigureClientQueueConfig, reconcileQueueOccupancyLocked,
           aggregateQueueSnapshot, AggregateQueueStats, RouteQueueStats
  - Invariants: aggregateQueueMu synchronization, 8 GiB queued-payload budget
                                |
                                v
[ Issue #519: Ingress and Egress Routing Pumps ]
  - Target: internal/vpn/forwarder/pumps.go
  - Scope: RouteClientToBackend*, RouteBackendToClient, pumpClientQueue,
           pumpBackendQueue, StartPumps, StopPumps, AttachBackendDevice,
           DetachBackendDevice (note: writeClientPacket lives in client_write.go)
  - Invariants: Memory copy isolation, validReturnDestination, route.writeMu join
                                |
                                v
[ Issue #520: Telemetry, Drop Accounting & Lifecycle Epochs ]
  - Target: internal/vpn/forwarder/telemetry.go
  - Scope: DropStats*, ClientDropStats*, PacketStats, Rates, QueuePressure,
           HistoryRates, Start, Stop, IsRunning, ReturnRouteOwner
  - Invariants: Generation epoch advancement, whole-vector monotonicity
```

### Phase Details:

#### 1. Issue #517: Route Lifecycle (`route_lifecycle.go`)
- **Extracted Responsibilities**: Session registration (`RegisterSession`, `RegisterSessionWithLimit`, `BeginRegisterSessionWithLimit`, `TryRegisterSessionWithLimit`, `TryRegisterSessionWithReturnPath`, `registerSessionLocked`), backend migration (`UpdateSessionBackend`), session teardown (`UnregisterSession`, `BeginUnregisterSession`, `beginUnregisterSession`), batch retirement (`RetireAllRoutes`, `RetireRoutesByReturnPath`, `RetireUnmanagedRoutes`, `retireRoutesMatchingLocked`), and route pump stopping/draining (`stopRoutePumpLocked`, `drainRouteQueueLocked`).
- **Critical Invariants**:
  - `Forwarder.mu.Lock` must guard map mutations (`routesByPeer`, `routesByIP`, `peerRegs`).
  - `old.assignedIP` must only be deleted from `routesByIP` if it matches `old`.
  - `clientQueue` is never closed; `drainRouteQueueLocked` drains it under `aggregateQueueMu.Lock()`.
  - Non-blocking retirement returns `Retirement`; caller waits outside `f.mu`.

#### 2. Issue #518: Queues, Memory Budgets & Rate Limiting (`queues.go`, `rate_limit.go`)
- **Extracted Responsibilities**: Rate limiters (`TokenBucket`, `NewTokenBucket`, `Allow`, `SetPeerRateLimit`, `GetPeerRateLimit`), memory budget calculations (`ValidateClientRouteLimit`, `MaxClientQueuePacketsForRoutes`, `ReconfigureClientQueueConfig`, `ReconfigureClientQueueSize`), queue capacity mutations (`changeQueueCapacityLocked`), aggregate occupancy reconciliation (`reconcileQueueOccupancyLocked`, `reconcileBeforeQueueMutationLocked`), and queue statistics (`AggregateQueueStats`, `aggregateQueueSnapshot`, `RouteQueueStats`, `AllRouteQueueStats`).
- **Critical Invariants**:
  - All aggregate queue occupancy mutations require `aggregateQueueMu.Lock()`.
  - Aggregate queued-payload budget of 8 GiB and 1500-byte packet assumption must remain strictly enforced.
  - Channel accessors (`GetClientPacketChannel`, `GetBackendPacketChannel`) remain read-only observation handles.

#### 3. Issue #519: Ingress and Egress Routing Pumps (`pumps.go`)
- **Extracted Responsibilities**: Forwarding path (`RouteClientToBackend`, `RouteClientToBackendWithReturnPath`, `routeClientToBackend`, `RouteBackendToClient`), pump workers (`pumpClientQueue`, `pumpBackendQueue`), device management (`AttachBackendDevice`, `DetachBackendDevice`), pump controllers (`StartPumps`, `StopPumps`, `stopPumpsSignalOnly`), and pump integration with device write admission (`writeClientPacket` in `client_write.go`).
- **Critical Invariants**:
  - Packet slices enqueued to channels must be independent allocations (`copy`).
  - Destination shape and backend ownership must be validated before client delivery (`validReturnDestination`).
  - Device writes must serialize with retirement under `route.writeMu`, never under `f.mu`.
  - Drop classifications must notify `returnRejectClassifier` outside `f.mu`.

#### 4. Issue #520: Telemetry, Drop Accounting & Lifecycle Epochs (`telemetry.go`)
- **Extracted Responsibilities**: Drop counter accessors (`DropStats`, `DropsNoRoute`, `DropsQueueFull`, `DropsPacketTooLarge`, `ClientDropStats`, `ClientDropStatsSinceStartup`, `DropsQueueFullSinceStartup`, `DropsPacketTooLargeSinceStartup`, `RawDropStats`, `RawClientDropStats`, `ResetDropCounters`, `resetDropCounters`, `SeedDropsForTest`, `SpoofedRebinds`), packet totals (`PacketStats`, `GetStats`), rate and pressure methods (`Rates`, `QueuePressure`, `HistoryRates`, `PrimeHistoryRates`), lifecycle state (`Start`, `Stop`, `IsRunning`, `currentGeneration`, `ReturnRouteOwner`, `HasRoutesForReturnPath`).
- **Critical Invariants**:
  - Lifecycle `Start()` must atomically bump `genEpoch` before re-priming rate trackers and clearing drops.
  - Rate updates must capture generation before reading counters to prevent stale observations from mixing generations.
  - History baseline re-priming must run outside `f.mu` to avoid lock inversion with return-path readers.
