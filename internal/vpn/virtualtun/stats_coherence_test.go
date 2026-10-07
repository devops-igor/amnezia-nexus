package virtualtun

import (
	"errors"
	"sync"
	"testing"
)

// Round-5 finding 2: StatsSnapshot.ExternalDrops() used to be computed as a
// REMAINDER between independently loaded atomics.
//
// The same file documented that Stats() is not a coherent snapshot: every
// counter is its own atomic load. So at an internal queue-full drop site, whose
// updates are
//
//	dropCount++ ; dropQueueFull++ ; inQueueFull++ ; inDrops++
//
// a status read landing partway through observes dropCount=1 with every bucket
// still 0, and ExternalDrops() — the remainder — reports 1. An ordinary
// queue-full loss is transiently published as an EXTERNAL drop. The opposite
// interleaving reports 0, so the loss vanishes from DropCategories entirely for
// that sample.
//
// Both are rate-machinery bugs, not display glitches: the reason trackers take
// deltas against a baseline, so a loss that migrates between the external,
// queue-full and directional populations across two samples is read as fresh
// activity.

// newCoherenceProbeDevice builds a device whose queues are one packet deep in
// both directions, so a single packet saturates each and every further
// submission in that direction is a genuine queue-full loss.
func newCoherenceProbeDevice(t *testing.T) *VirtualTUN {
	t.Helper()
	vt, err := New(Config{Name: "coherence-probe", MTU: 1340, InboundCapacity: 1, OutboundCapacity: 1})
	if err != nil {
		t.Fatalf("VirtualTUN construction failed: %v", err)
	}
	t.Cleanup(func() { _ = vt.Close() })
	return vt
}

// assertSnapshotCoherent is the invariant every Stats() sample must satisfy,
// whatever the device was doing concurrently. A snapshot may represent a
// slightly earlier or later instant, but it must never be internally
// inconsistent: no phantom external bucket, and no loss that has left every
// bucket it could be counted in.
func assertSnapshotCoherent(t *testing.T, sample int, s StatsSnapshot) {
	t.Helper()
	internal := s.InboundQueueFullDrops + s.InboundOversizedDrops + s.InboundShutdownDrops +
		s.OutboundQueueFullDrops + s.OutboundShutdownDrops
	if internal != s.Sum() {
		t.Errorf("sample %d: the five direction x reason buckets sum to %d but Sum() is %d; the snapshot mixes two instants",
			sample, internal, s.Sum())
	}
	if s.Sum() != s.InboundDrops+s.OutboundDrops {
		t.Errorf("sample %d: Sum()=%d but inbound(%d)+outbound(%d)=%d",
			sample, s.Sum(), s.InboundDrops, s.OutboundDrops, s.InboundDrops+s.OutboundDrops)
	}
	if got := s.ExternalDrops(); got != s.DropsExternal {
		t.Errorf("sample %d: ExternalDrops()=%d but the snapshot's explicit external counter is %d; the external figure must be RECORDED, not inferred",
			sample, got, s.DropsExternal)
	}
	if s.DropsTotal != s.Sum()+s.ExternalDrops() {
		t.Errorf("sample %d: DropsTotal=%d but Sum()(%d)+external(%d)=%d; a loss is either missing from every bucket or counted twice",
			sample, s.DropsTotal, s.Sum(), s.ExternalDrops(), s.Sum()+s.ExternalDrops())
	}
}

// TestStatsIsCoherentUnderConcurrentDrops is the concurrency coverage the
// finding asks for: drops are driven on several goroutines while Stats() is
// sampled continuously, and every sample must be internally consistent. Run it
// under -race.
//
// The old remainder-inference fails this test in the concurrent case: any
// sample landing between dropCount++ and the bucket increments yields
// ExternalDrops() >= 1 with no external drop ever recorded, or DropsTotal <
// Sum(), i.e. a loss attributed to nothing.
func TestStatsIsCoherentUnderConcurrentDrops(t *testing.T) {
	vt := newCoherenceProbeDevice(t)

	const (
		workers    = 6
		iterations = 500
	)

	var writers, sampler sync.WaitGroup
	stopSampler := make(chan struct{})

	for w := range workers {
		writers.Add(1)
		go func(id int) {
			defer writers.Done()
			for i := range iterations {
				switch (id + i) % 4 {
				case 0: // inbound queue-full candidate
					_ = vt.InjectInbound([]byte("in"))
				case 1: // outbound queue-full candidate
					_, _ = vt.Write([][]byte{[]byte("out")}, 0)
				case 2: // explicitly EXTERNAL, recorded by an outside observer
					vt.RecordDrop()
				case 3: // oversized read: inbound packet into a 1-byte buffer
					if err := vt.InjectInbound(make([]byte, 64)); err == nil {
						_, _ = vt.Read([][]byte{make([]byte, 1)}, []int{1}, 0)
					}
				}
			}
		}(w)
	}

	// Sampler: hammer Stats() for the whole run.
	var lastTotal, lastExternal uint64
	sampler.Add(1)
	go func() {
		defer sampler.Done()
		for {
			select {
			case <-stopSampler:
				return
			default:
			}
			s := vt.Stats()
			assertSnapshotCoherent(t, 0, s)
			// Every counter is monotonic, so a coherent snapshot can never go
			// backwards: a stale read must not masquerade as a drop-rate
			// decrease that later reappears as fresh loss.
			if s.DropsTotal < lastTotal {
				t.Errorf("DropsTotal went backwards across samples: %d < %d", s.DropsTotal, lastTotal)
				return
			}
			if s.ExternalDrops() < lastExternal {
				t.Errorf("ExternalDrops() went backwards across samples: %d < %d", s.ExternalDrops(), lastExternal)
				return
			}
			lastTotal, lastExternal = s.DropsTotal, s.ExternalDrops()
		}
	}()

	writers.Wait()
	close(stopSampler)
	sampler.Wait()

	final := vt.Stats()
	assertSnapshotCoherent(t, -1, final)
	if final.DropsTotal != vt.DroppedPackets() {
		t.Errorf("quiescent DropsTotal=%d but DroppedPackets()=%d", final.DropsTotal, vt.DroppedPackets())
	}
}

// TestNoExternalBucketWithoutRecordDrop is the sharpest form of the finding: a
// device driven ONLY by internal drop sites, sampled throughout, must NEVER
// report a single external drop. The recorded external count is known to be
// exactly 0 for the whole run, so any nonzero external figure in any sample is
// provably invented by the inference.
func TestNoExternalBucketWithoutRecordDrop(t *testing.T) {
	vt := newCoherenceProbeDevice(t)

	const (
		workers    = 4
		iterations = 800
	)

	var writers, sampler sync.WaitGroup
	stopSampler := make(chan struct{})

	for w := range workers {
		writers.Add(1)
		go func(id int) {
			defer writers.Done()
			for i := range iterations {
				if (id+i)%2 == 0 {
					_ = vt.InjectInbound([]byte("in"))
					continue
				}
				_, _ = vt.Write([][]byte{[]byte("out")}, 0)
			}
		}(w)
	}

	sampler.Add(1)
	go func() {
		defer sampler.Done()
		for {
			select {
			case <-stopSampler:
				return
			default:
			}
			s := vt.Stats()
			if s.ExternalDrops() != 0 {
				t.Errorf("internal-only loss published as %d external drops: ExternalDrops() must come from the recording path",
					s.ExternalDrops())
				return
			}
			if s.DropsTotal < s.Sum() {
				t.Errorf("DropsTotal=%d < Sum()=%d: a loss is in the buckets but not in the total", s.DropsTotal, s.Sum())
				return
			}
		}
	}()

	writers.Wait()
	close(stopSampler)
	sampler.Wait()

	final := vt.Stats()
	assertSnapshotCoherent(t, -1, final)
	if final.ExternalDrops() != 0 {
		t.Errorf("quiescent external drops=%d, want 0: no RecordDrop call was ever made", final.ExternalDrops())
	}
}

// TestRecordDropLandsInTheExternalBucket pins the attribution half of the fix
// on a QUIESCENT device, where no interleaving can be blamed: external drops
// must appear under the explicit external counter, and internal drops under
// their own direction x reason buckets, with the two populations disjoint.
func TestRecordDropLandsInTheExternalBucket(t *testing.T) {
	vt := newCoherenceProbeDevice(t)

	// One internal inbound queue-full loss: admit one, refuse one.
	if err := vt.InjectInbound([]byte("in-1")); err != nil {
		t.Fatalf("first inbound packet must be admitted: %v", err)
	}
	if err := vt.InjectInbound([]byte("in-2")); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("second inbound packet onto a 1-deep queue: err=%v, want %v: the internal loss under test would not exist",
			err, ErrQueueFull)
	}
	// One internal outbound queue-full loss: admit one, refuse one.
	if _, err := vt.Write([][]byte{[]byte("out-1")}, 0); err != nil {
		t.Fatalf("outbound write must not error: %v", err)
	}
	if _, err := vt.Write([][]byte{[]byte("out-2")}, 0); err != nil {
		t.Fatalf("outbound queue-full is reported as processed, not an error: %v", err)
	}
	// Four external losses: one at a time and three in a batch.
	vt.RecordDrop()
	vt.RecordDropN(3)

	s := vt.Stats()
	if s.DropsExternal != 4 {
		t.Errorf("external counter=%d, want 4: RecordDrop/RecordDropN must land in the external bucket", s.DropsExternal)
	}
	if s.ExternalDrops() != 4 {
		t.Errorf("ExternalDrops()=%d, want 4", s.ExternalDrops())
	}
	if s.InboundQueueFullDrops != 1 || s.OutboundQueueFullDrops != 1 {
		t.Errorf("internal losses misplaced: inbound_qf=%d outbound_qf=%d, want 1/1",
			s.InboundQueueFullDrops, s.OutboundQueueFullDrops)
	}
	if s.DropsQueueFull != 2 || s.DropsOversized != 0 || s.DropsShutdown != 0 {
		t.Errorf("reason buckets wrong: queue_full=%d oversized=%d shutdown=%d, want 2/0/0",
			s.DropsQueueFull, s.DropsOversized, s.DropsShutdown)
	}
	if s.Sum() != 2 {
		t.Errorf("Sum()=%d, want 2: external drops must stay out of the reason buckets", s.Sum())
	}
	if s.DropsTotal != 6 {
		t.Errorf("DropsTotal=%d, want 6 (2 internal + 4 external)", s.DropsTotal)
	}
	assertSnapshotCoherent(t, -1, s)
}

// TestRecordDropNZeroAndLargeKeepTotalConsistent guards the batch API against a
// partial accounting regression: a zero batch must be a no-op and a large batch
// must land wholly in the external counter.
func TestRecordDropNZeroAndLargeKeepTotalConsistent(t *testing.T) {
	vt := newCoherenceProbeDevice(t)

	before := vt.Stats()
	vt.RecordDropN(0)
	if s := vt.Stats(); s.DropsTotal != before.DropsTotal || s.ExternalDrops() != 0 {
		t.Errorf("RecordDropN(0) changed the accounting: total %d->%d external %d",
			before.DropsTotal, s.DropsTotal, s.ExternalDrops())
	}

	vt.RecordDropN(1_000)
	s := vt.Stats()
	if s.ExternalDrops() != 1_000 || s.DropsTotal != 1_000 || s.Sum() != 0 {
		t.Errorf("RecordDropN(1000): external=%d total=%d sum=%d, want 1000/1000/0",
			s.ExternalDrops(), s.DropsTotal, s.Sum())
	}
	assertSnapshotCoherent(t, -1, s)
}
