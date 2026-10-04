package forwarder

import (
	"sync"
	"sync/atomic"
	"time"
)

// TrafficSnapshot measures traffic at the same boundaries as the aggregate
// forwarder counters: RX after client admission/rate limits; TX after return
// queue acceptance. Available=false means the rate baseline has no interval,
// while Available=true with zero rates is measured idle. Rates are bytes/sec.
type TrafficSnapshot struct {
	RxBytes       int64   `json:"rx_bytes"`
	TxBytes       int64   `json:"tx_bytes"`
	RxPackets     uint64  `json:"rx_packets"`
	TxPackets     uint64  `json:"tx_packets"`
	RxBytesPerSec float64 `json:"rx_bytes_per_sec"`
	TxBytesPerSec float64 `json:"tx_bytes_per_sec"`
	RxPps         float64 `json:"rx_pps"`
	TxPps         float64 `json:"tx_pps"`
	Available     bool    `json:"available"`
	WindowSec     float64 `json:"window_sec"`
}

type trafficCounters struct {
	rxBytes     atomic.Int64
	txBytes     atomic.Int64
	rxPackets   atomic.Uint64
	txPackets   atomic.Uint64
	lastTraffic atomic.Int64
	mu          sync.Mutex
	lastAt      time.Time
	baseline    TrafficSnapshot
	current     TrafficSnapshot

	histLastAt   time.Time
	histBaseline TrafficSnapshot
	histCurrent  TrafficSnapshot
}

func (c *trafficCounters) record(n int64, rx bool) {
	if c == nil {
		return
	}
	if rx {
		c.rxBytes.Add(n)
		c.rxPackets.Add(1)
	} else {
		c.txBytes.Add(n)
		c.txPackets.Add(1)
	}
	now := time.Now().UnixNano()
	for old := c.lastTraffic.Load(); now > old; old = c.lastTraffic.Load() {
		if c.lastTraffic.CompareAndSwap(old, now) {
			break
		}
	}
}

func (c *trafficCounters) snapshot(now time.Time) TrafficSnapshot {
	if c == nil {
		return TrafficSnapshot{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	totals := TrafficSnapshot{RxBytes: c.rxBytes.Load(), TxBytes: c.txBytes.Load(), RxPackets: c.rxPackets.Load(), TxPackets: c.txPackets.Load()}
	if c.lastAt.IsZero() {
		c.lastAt = now
		c.baseline = totals
	}
	elapsed := now.Sub(c.lastAt).Seconds()
	if elapsed >= 0.2 {
		c.current = TrafficSnapshot{
			RxBytesPerSec: float64(totals.RxBytes-c.baseline.RxBytes) / elapsed,
			TxBytesPerSec: float64(totals.TxBytes-c.baseline.TxBytes) / elapsed,
			RxPps:         float64(totals.RxPackets-c.baseline.RxPackets) / elapsed,
			TxPps:         float64(totals.TxPackets-c.baseline.TxPackets) / elapsed,
			Available:     true, WindowSec: elapsed,
		}
		c.lastAt = now
		c.baseline = totals
	}
	totals.RxBytesPerSec, totals.TxBytesPerSec = c.current.RxBytesPerSec, c.current.TxBytesPerSec
	totals.RxPps, totals.TxPps = c.current.RxPps, c.current.TxPps
	totals.Available, totals.WindowSec = c.current.Available, c.current.WindowSec
	return totals
}

func (c *trafficCounters) historySnapshot(now time.Time) TrafficSnapshot {
	if c == nil {
		return TrafficSnapshot{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	totals := TrafficSnapshot{RxBytes: c.rxBytes.Load(), TxBytes: c.txBytes.Load(), RxPackets: c.rxPackets.Load(), TxPackets: c.txPackets.Load()}
	if c.histLastAt.IsZero() {
		c.histLastAt = now
		c.histBaseline = totals
	}
	elapsed := now.Sub(c.histLastAt).Seconds()
	if elapsed >= 0.2 {
		deltaRxBytes := totals.RxBytes - c.histBaseline.RxBytes
		if deltaRxBytes < 0 {
			deltaRxBytes = 0
		}
		deltaTxBytes := totals.TxBytes - c.histBaseline.TxBytes
		if deltaTxBytes < 0 {
			deltaTxBytes = 0
		}
		deltaRxPackets := uint64(0)
		if totals.RxPackets >= c.histBaseline.RxPackets {
			deltaRxPackets = totals.RxPackets - c.histBaseline.RxPackets
		}
		deltaTxPackets := uint64(0)
		if totals.TxPackets >= c.histBaseline.TxPackets {
			deltaTxPackets = totals.TxPackets - c.histBaseline.TxPackets
		}
		c.histCurrent = TrafficSnapshot{
			RxBytesPerSec: float64(deltaRxBytes) / elapsed,
			TxBytesPerSec: float64(deltaTxBytes) / elapsed,
			RxPps:         float64(deltaRxPackets) / elapsed,
			TxPps:         float64(deltaTxPackets) / elapsed,
			Available:     true,
			WindowSec:     elapsed,
		}
		c.histLastAt = now
		c.histBaseline = totals
	}
	totals.RxBytesPerSec, totals.TxBytesPerSec = c.histCurrent.RxBytesPerSec, c.histCurrent.TxBytesPerSec
	totals.RxPps, totals.TxPps = c.histCurrent.RxPps, c.histCurrent.TxPps
	totals.Available, totals.WindowSec = c.histCurrent.Available, c.histCurrent.WindowSec
	return totals
}

func (c *trafficCounters) primeHistory(now time.Time) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.histLastAt.IsZero() {
		c.histLastAt = now
		c.histBaseline = TrafficSnapshot{
			RxBytes:   c.rxBytes.Load(),
			TxBytes:   c.txBytes.Load(),
			RxPackets: c.rxPackets.Load(),
			TxPackets: c.txPackets.Load(),
		}
	}
}

func (c *trafficCounters) lastTrafficAge(now time.Time) int64 {
	at := c.lastTraffic.Load()
	if at == 0 {
		return -1
	} // never observed; zero means traffic within the last second
	age := now.Sub(time.Unix(0, at)) / time.Second
	if age < 0 {
		return 0
	}
	return int64(age)
}

// BackendTrafficSnapshot samples only live registration generations. Attached
// device replacement resets the baseline/counters; detach removes it. No
// registry of former backend IDs accumulates as backends come and go.
func (f *Forwarder) BackendTrafficSnapshot() map[int64]TrafficSnapshot {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := make(map[int64]TrafficSnapshot, len(f.backendTraffic))
	now := time.Now()
	for id, counters := range f.backendTraffic {
		out[id] = counters.snapshot(now)
	}
	return out
}

// BackendTrafficHistorySnapshot samples backend traffic against independent
// history baselines so foreground status polling cannot consume deltas.
func (f *Forwarder) BackendTrafficHistorySnapshot(now time.Time) map[int64]TrafficSnapshot {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := make(map[int64]TrafficSnapshot, len(f.backendTraffic))
	for id, counters := range f.backendTraffic {
		out[id] = counters.historySnapshot(now)
	}
	return out
}

// PrimeBackendTrafficHistory primes independent history baselines for all current backends.
func (f *Forwarder) PrimeBackendTrafficHistory(now time.Time) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	for _, counters := range f.backendTraffic {
		counters.primeHistory(now)
	}
}

func (f *Forwarder) ensureBackendTrafficLocked(id int64) {
	if f.backendTraffic == nil {
		f.backendTraffic = make(map[int64]*trafficCounters)
	}
	if f.backendTraffic[id] == nil {
		f.backendTraffic[id] = &trafficCounters{}
	}
}
