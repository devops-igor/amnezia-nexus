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

// generationTrafficWindow is one generation-aware monotonic window over the
// cumulative per-backend traffic counters (issue #429 review blocker 1):
//   - an observation tagged with an older generation is stale and ignored;
//   - the first observation of a generation (after construction or reset)
//     only primes the baseline;
//   - an observation lower than the accepted baseline reports nothing and
//     leaves the baseline untouched, so activity up to the previously
//     accepted value can never be replayed as a fresh rate;
//   - reset(gen) explicitly starts a new generation, clearing the baseline.
type generationTrafficWindow struct {
	gen       Generation
	primed    bool
	at        time.Time
	rxBytes   uint64
	txBytes   uint64
	rxPackets uint64
	txPackets uint64
	current   TrafficSnapshot
}

// observe applies the generation gate and the monotonic-baseline rule to one
// cumulative observation. accepted reports whether this observation opened a
// new measurement window; current is the previously published window.
func (w *generationTrafficWindow) observe(gen Generation, now time.Time, totals TrafficSnapshot) (current TrafficSnapshot, elapsed float64, accepted bool) {
	rxU := uint64(totals.RxBytes)
	txU := uint64(totals.TxBytes)
	if gen < w.gen {
		return w.current, 0, false
	}
	if gen > w.gen || !w.primed {
		w.gen = gen
		w.primed = true
		w.at = now
		w.rxBytes, w.txBytes = rxU, txU
		w.rxPackets, w.txPackets = totals.RxPackets, totals.TxPackets
		return w.current, 0, false
	}
	elapsed = now.Sub(w.at).Seconds()
	if elapsed < 0.2 {
		return w.current, 0, false
	}
	var (
		dRx, dTx   uint64
		dRxP, dTxP uint64
	)
	if rxU >= w.rxBytes {
		dRx = rxU - w.rxBytes
		w.rxBytes = rxU
	}
	if txU >= w.txBytes {
		dTx = txU - w.txBytes
		w.txBytes = txU
	}
	if totals.RxPackets >= w.rxPackets {
		dRxP = totals.RxPackets - w.rxPackets
		w.rxPackets = totals.RxPackets
	}
	if totals.TxPackets >= w.txPackets {
		dTxP = totals.TxPackets - w.txPackets
		w.txPackets = totals.TxPackets
	}
	w.at = now
	w.current = TrafficSnapshot{
		RxBytesPerSec: float64(dRx) / elapsed,
		TxBytesPerSec: float64(dTx) / elapsed,
		RxPps:         float64(dRxP) / elapsed,
		TxPps:         float64(dTxP) / elapsed,
		Available:     true,
		WindowSec:     elapsed,
	}
	return w.current, elapsed, true
}

// reset starts a new generation: the baseline is cleared so the next
// observation re-primes into it. Older generations are ignored.
func (w *generationTrafficWindow) reset(gen Generation) {
	if gen > w.gen {
		w.gen = gen
	}
	w.primed = false
	w.at = time.Time{}
	w.rxBytes, w.txBytes = 0, 0
	w.rxPackets, w.txPackets = 0, 0
	w.current = TrafficSnapshot{}
}

type trafficCounters struct {
	rxBytes     atomic.Int64
	txBytes     atomic.Int64
	rxPackets   atomic.Uint64
	txPackets   atomic.Uint64
	lastTraffic atomic.Int64
	mu          sync.Mutex
	foreground  generationTrafficWindow
	history     generationTrafficWindow
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
	if current, _, accepted := c.foreground.observe(0, now, totals); accepted {
		c.foreground.current = current
	}
	current := c.foreground.current
	totals.RxBytesPerSec, totals.TxBytesPerSec = current.RxBytesPerSec, current.TxBytesPerSec
	totals.RxPps, totals.TxPps = current.RxPps, current.TxPps
	totals.Available, totals.WindowSec = current.Available, current.WindowSec
	return totals
}

func (c *trafficCounters) historySnapshot(now time.Time, gen Generation) TrafficSnapshot {
	if c == nil {
		return TrafficSnapshot{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	totals := TrafficSnapshot{RxBytes: c.rxBytes.Load(), TxBytes: c.txBytes.Load(), RxPackets: c.rxPackets.Load(), TxPackets: c.txPackets.Load()}
	if current, _, accepted := c.history.observe(gen, now, totals); accepted {
		c.history.current = current
	}
	current := c.history.current
	totals.RxBytesPerSec, totals.TxBytesPerSec = current.RxBytesPerSec, current.TxBytesPerSec
	totals.RxPps, totals.TxPps = current.RxPps, current.TxPps
	totals.Available, totals.WindowSec = current.Available, current.WindowSec
	return totals
}

func (c *trafficCounters) primeHistory(now time.Time, gen Generation) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.history.observe(gen, now, TrafficSnapshot{
		RxBytes:   c.rxBytes.Load(),
		TxBytes:   c.txBytes.Load(),
		RxPackets: c.rxPackets.Load(),
		TxPackets: c.txPackets.Load(),
	})
}

// resetHistoryForGeneration starts a new generation for the history window so
// the next observation re-primes against the restarted component (issue #429
// review blocker 1).
func (c *trafficCounters) resetHistoryForGeneration(gen Generation, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.history.reset(gen)
	c.history.observe(gen, now, TrafficSnapshot{
		RxBytes:   c.rxBytes.Load(),
		TxBytes:   c.txBytes.Load(),
		RxPackets: c.rxPackets.Load(),
		TxPackets: c.txPackets.Load(),
	})
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
	gen := Generation(f.backendTrafficGeneration.Load())
	for id, counters := range f.backendTraffic {
		out[id] = counters.historySnapshot(now, gen)
	}
	return out
}

// PrimeBackendTrafficHistory primes independent history baselines for all current backends.
func (f *Forwarder) PrimeBackendTrafficHistory(now time.Time) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	gen := Generation(f.backendTrafficGeneration.Load())
	for _, counters := range f.backendTraffic {
		counters.primeHistory(now, gen)
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
