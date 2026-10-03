// Package virtualtun provides VirtualTUN, an ownership-neutral in-memory
// implementation of the amneziawg-go tun.Device interface.
//
// VirtualTUN contains no AWG protocol logic. It moves packets between two
// private, bounded FIFO queues and exposes them to two kinds of consumers:
//
//   - The AWG engine consumes packets enqueued by InjectInbound through the
//     tun.Device Read path (device -> engine direction).
//   - A portal consumer drains packets the engine enqueues through its
//     tun.Device Write path via ReceiveOutbound (engine -> consumer
//     direction).
//
// # Packet ownership
//
// Every packet is copied when it enters a queue and when it leaves it: callers
// may reuse their buffers as soon as InjectInbound/Write return, and slices
// returned by ReceiveOutbound belong to the caller.
//
// # Loss and accounting
//
// Queues are bounded and never block the sender: when the destination queue is
// full the packet is dropped and DroppedPackets is incremented. Read drops a
// packet that does not fit the destination buffer (oversized) and reports it
// through the same counter; Close drains both queues and accounts every
// drained packet as a shutdown drop (see Shutdown). RecordDrop lets external
// owners add drops observed outside the device (issue #160 telemetry).
//
// Every internal drop also lands in a per-reason bucket (queue-full,
// oversized, shutdown) and in a direction x reason bucket; Stats reports both
// breakdowns alongside the queue depths. RecordDrop and RecordDropN increment
// the total and the separate external population, so the per-reason and
// directional sums fall short of DropsTotal by exactly
// StatsSnapshot.ExternalDrops(), which is recorded rather than inferred.
//
// DroppedPackets therefore INCLUDES shutdown drops: closing a device with
// packets still queued raises the counter. This is a deliberate semantic
// delta versus the legacy backend, where queued-at-shutdown packets were
// lost uncounted. The vpn.Service aggregation sums the exact per-device
// totals, so its published dropped_packets figures include the same
// shutdown-attributed drops.
//
// # Shutdown
//
// Close has a single linearization point: the moment it acquires the
// lifecycle write lock. A submission (InjectInbound, Write) racing with
// Close either completes its enqueue before that point — and its packet is
// drained and counted as a shutdown drop — or observes the closed state and
// fails with ErrClosed. Once Close returns, no submission can enqueue
// anymore: every accepted packet is accounted exactly once, as either a
// delivered packet or a dropped one.
//
// During Close both queues are actually drained (depths go to zero) and each
// drained packet increments DroppedPackets and the shutdown bucket. After
// Close returns, queue depths are permanently zero and every method rejects
// with an error wrapping ErrClosed. Close is idempotent and never closes the
// packet channels, so a sender can never panic on a closed channel. Blocked
// Read and ReceiveOutbound calls are unblocked and return an error wrapping
// ErrClosed. BatchSize is constant for the lifetime of the device.
package virtualtun

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

const (
	// DefaultInboundCapacity is the default buffer capacity for inbound
	// packets (2048), sized to absorb bursty upload traffic without drops
	// (issue #160). tunnel.DefaultVirtualTUNInboundCapacity re-exports it.
	DefaultInboundCapacity = 2048

	// DefaultOutboundCapacity is the default buffer capacity for outbound
	// packets (1024).
	DefaultOutboundCapacity = 1024

	// DefaultBatchSize is the default number of packets handled per Read
	// call (1), matching the legacy single-packet behavior of the pinned
	// AWG backend path.
	DefaultBatchSize = 1

	// eventsCapacity bounds the tun.Event channel.
	eventsCapacity = 2
)

var (
	// ErrClosed is returned by every method called after Close, and
	// unblocks calls blocked on an empty queue. InjectInbound and Write
	// reject submissions after close with ErrClosed.
	ErrClosed = errors.New("virtualtun: device is closed")

	// ErrInvalidBuffer is returned when Read or Write receive malformed
	// slice arguments (nil bufs, len(sizes) < len(bufs), negative offset,
	// or a destination buffer that cannot receive even one byte at
	// offset). The device never panics on malformed buffers.
	ErrInvalidBuffer = errors.New("virtualtun: invalid buffer arguments")

	// ErrQueueFull is returned by InjectInbound when the inbound queue is
	// full; the packet is dropped and counted before the error is
	// returned.
	ErrQueueFull = errors.New("virtualtun: inbound queue is full")
)

// VirtualTUN is an in-memory tun.Device: a bounded packet queue pair with
// explicit drop accounting and idempotent shutdown. Create one with New.
type VirtualTUN struct {
	inPackets  chan []byte
	outPackets chan []byte
	events     chan tun.Event
	// closed is the shutdown wakeup channel: closed exactly once by
	// Close while holding closeMu, it unblocks readers and receivers.
	// Submissions must not test it directly; they consult t.isClosed()
	// so that the closed check and the enqueue happen atomically with
	// respect to Close (see closeMu).
	closed chan struct{}
	// closeMu guards the lifecycle transition: submissions hold the read
	// lock across their closed-check-plus-enqueue critical section and
	// Close holds the write lock while flipping the state and draining,
	// making Close linearizable with submissions.
	closeMu sync.RWMutex
	// readSuspended is a TEST-ONLY gate on Read. It is false for every
	// production device: nothing outside this package's tests ever sets it,
	// so the production Read path is unchanged.
	//
	// It exists because the upstream engine starts its TUN reader goroutine
	// inside device.NewDevice, and device.Down() only stops the peers and the
	// bind (downLocked), so no upstream API can suspend that reader. A test
	// that needs deterministic INBOUND queue state therefore had no seam.
	readSuspended atomic.Bool
	// resumeRead is closed by ResumeReadsForTest to release every Read
	// blocked on the suspension gate. It is created by SuspendReadsForTest
	// and replaced by the next SuspendReadsForTest, under readMu.
	resumeRead chan struct{}
	// readMu guards resumeRead only.
	readMu sync.Mutex
	mtu    int
	name   string
	// closedFlag is written only by Close under the write lock and read
	// by submissions under the read lock; it exists so submissions can
	// check-and-enqueue atomically without racing on the channel close.
	closedFlag bool
	batchSize  int
	// dropCount is the device-wide drop total behind DroppedPackets: every
	// internal drop plus every RecordDrop/RecordDropN. It is deliberately
	// NOT the source of StatsSnapshot.DropsTotal, which is derived from the
	// per-bucket reads so the snapshot stays coherent.
	dropCount atomic.Uint64
	// externalDrops counts drops recorded through RecordDrop/RecordDropN,
	// i.e. drops an outside owner observed without the device itself
	// classifying them. It is incremented on the RECORDING path (never
	// derived as a remainder), so an internal queue-full or shutdown loss
	// can never be published as an external drop. See Stats.
	externalDrops atomic.Uint64
	inHighWater   atomic.Uint64
	outHighWater  atomic.Uint64
	// Direction x reason drop buckets (issue #424 round 3, finding 1).
	//
	// dropQueueFull/dropOversized/dropShutdown carry only a REASON axis and
	// inDrops/outDrops carry only a DIRECTION axis. Neither can answer "which
	// direction did this queue-full drop happen in", and the two axes together
	// are rank-deficient: outbound oversized never happens (Read is the only
	// oversized site and it drains the inbound queue), yet knowing that does
	// not resolve the four remaining unknowns. These five counters are the
	// cross product of the five internal drop sites and make the attribution
	// exact.
	//
	// There is deliberately no outOversized counter: Read is the only site
	// that drops an oversized packet, and it reads from the inbound queue, so
	// outbound oversized is not a reachable state.
	inQueueFull  atomic.Uint64
	inOversized  atomic.Uint64
	inShutdown   atomic.Uint64
	outQueueFull atomic.Uint64
	outShutdown  atomic.Uint64
	once         sync.Once
}

// Compile-time interface compliance.
var _ tun.Device = (*VirtualTUN)(nil)

// Config configures a VirtualTUN created by New.
type Config struct {
	// Name is the device name reported by Name.
	Name string

	// MTU is the MTU reported by MTU. Zero selects no particular default;
	// callers choose the value that matches their stack.
	MTU int

	// InboundCapacity bounds the queue feeding the engine's Read path.
	// Zero selects DefaultInboundCapacity.
	InboundCapacity int

	// OutboundCapacity bounds the queue drained by ReceiveOutbound.
	// Zero selects DefaultOutboundCapacity.
	OutboundCapacity int

	// BatchSize is the maximum number of packets Read returns per call.
	// Zero selects DefaultBatchSize.
	BatchSize int
}

// New creates a VirtualTUN from cfg. Zero-valued capacity and batch fields
// select the documented defaults; negative values are rejected with an error
// instead of being clamped.
func New(cfg Config) (*VirtualTUN, error) {
	if cfg.MTU < 0 {
		return nil, fmt.Errorf("virtualtun: invalid config: negative MTU %d", cfg.MTU)
	}
	if cfg.InboundCapacity < 0 {
		return nil, fmt.Errorf("virtualtun: invalid config: negative inbound capacity %d", cfg.InboundCapacity)
	}
	if cfg.OutboundCapacity < 0 {
		return nil, fmt.Errorf("virtualtun: invalid config: negative outbound capacity %d", cfg.OutboundCapacity)
	}
	if cfg.BatchSize < 0 {
		return nil, fmt.Errorf("virtualtun: invalid config: negative batch size %d", cfg.BatchSize)
	}

	inbound := cfg.InboundCapacity
	if inbound == 0 {
		inbound = DefaultInboundCapacity
	}
	outbound := cfg.OutboundCapacity
	if outbound == 0 {
		outbound = DefaultOutboundCapacity
	}
	batchSize := cfg.BatchSize
	if batchSize == 0 {
		batchSize = DefaultBatchSize
	}

	return &VirtualTUN{
		inPackets:  make(chan []byte, inbound),
		outPackets: make(chan []byte, outbound),
		events:     make(chan tun.Event, eventsCapacity),
		closed:     make(chan struct{}),
		mtu:        cfg.MTU,
		name:       cfg.Name,
		batchSize:  batchSize,
	}, nil
}

// NewSuspendedForTest creates a device whose reads are ALREADY suspended,
// before any reader goroutine can exist. It is TEST-ONLY and must not be
// called from production code.
//
// This is the only airtight way to freeze the inbound queue for a test whose
// TUN is driven by a reader started inside device.NewDevice (the upstream AWG
// engine). Such a reader spends essentially all its life parked inside Read,
// blocked on <-inPackets, i.e. already past the awaitReadResume check at the
// top of Read: arming the gate afterwards has no effect, and the very next
// InjectInbound is dequeued immediately. Suspending before the goroutine is
// created makes its FIRST Read call block on the gate, so the queue is
// provably never drained.
//
// Production construction is New, which never suspends; the flag is therefore
// false for every device that a production path can build.
func NewSuspendedForTest(cfg Config) (*VirtualTUN, error) {
	vt, err := New(cfg)
	if err != nil {
		return nil, err
	}
	vt.SuspendReadsForTest()
	return vt, nil
}

// ReadsSuspendedForTest reports whether the test-only read gate is armed. It
// exists so a test can assert that the device it was handed really does have
// deterministic inbound queue state, rather than assuming it.
func (t *VirtualTUN) ReadsSuspendedForTest() bool {
	if t == nil {
		return false
	}
	return t.readSuspended.Load()
}

// SuspendReadsForTest makes Read stop dequeuing from the inbound queue so a
// test can build deterministic queue state. It is TEST-ONLY and must not be
// called from production code.
//
// It only takes effect for a Read call that has not yet passed the gate. A
// reader already parked inside Read stays parked and keeps dequeuing, so a
// device whose reader is started by device.NewDevice must be built with
// NewSuspendedForTest instead: there is no way to reach a parked reader.
//
// Motivation: the upstream engine starts its TUN reader goroutine inside
// device.NewDevice and keeps it running for the device's whole life;
// device.Down() only stops the peers and closes the bind (downLocked), so
// there is no upstream API that suspends the reader. Any test that injects
// into the inbound queue and then asserts its occupancy, its peak, or that a
// later Close drains it is otherwise racing that goroutine, which is why such
// tests pass on an idle developer machine and fail on a loaded,
// coverage-instrumented CI runner.
//
// While suspended, a Read blocks without consuming anything: the packets stay
// queued and every drop counter is untouched, exactly as if the reader had not
// run yet. Close still unblocks a suspended Read, so shutdown cannot hang.
func (t *VirtualTUN) SuspendReadsForTest() {
	if t == nil {
		return
	}
	// The gate is armed BEFORE the flag is published, so a Read can never
	// observe readSuspended with no channel to wait on.
	t.readMu.Lock()
	if t.resumeRead == nil {
		t.resumeRead = make(chan struct{})
	}
	t.readMu.Unlock()
	t.readSuspended.Store(true)
}

// ResumeReadsForTest releases every Read blocked by SuspendReadsForTest.
func (t *VirtualTUN) ResumeReadsForTest() {
	if t == nil {
		return
	}
	t.readSuspended.Store(false)
	t.readMu.Lock()
	if t.resumeRead != nil {
		close(t.resumeRead)
		t.resumeRead = nil
	}
	t.readMu.Unlock()
}

// awaitReadResume blocks while reads are suspended. It returns false only when
// the device was closed underneath it, so a suspended Read cannot outlive
// Close and wedge shutdown.
func (t *VirtualTUN) awaitReadResume() bool {
	for t.readSuspended.Load() {
		t.readMu.Lock()
		ch := t.resumeRead
		t.readMu.Unlock()
		if ch == nil {
			// Resume ran between the flag check and the lock. Re-check the flag
			// rather than proceeding on a stale observation.
			continue
		}
		select {
		case <-ch:
		case <-t.closed:
			return false
		}
	}
	return true
}

// isClosed reports whether the device has been closed. Called by submissions
// while holding the closeMu read lock so the observation cannot race with the
// Close transition.
func (t *VirtualTUN) isClosed() bool {
	return t.closedFlag
}

// File implements tun.Device. It always returns nil: the device is in-memory
// and has no file descriptor.
func (t *VirtualTUN) File() *os.File { return nil }

// Read implements tun.Device. It removes packets from the inbound queue into
// bufs, starting each packet at offset within its buffer, and returns the
// number of packets read. At most BatchSize packets (and never more than
// len(bufs)) are returned per call: the first packet blocks until one is
// available or the device is closed, remaining packets are drained only if
// immediately available, so a caller is never made to wait for a full batch.
//
// Buffer handling: len(sizes) must be at least len(bufs); offset must not be
// negative; and every potential destination buffer (the first
// min(len(bufs), BatchSize) entries) must be able to receive at least one
// byte at offset — len(bufs[i]) > offset for each such i. A zero-capacity
// destination (offset == len(bufs[i])) cannot receive a packet and is
// rejected the same way. Violations return an error wrapping ErrInvalidBuffer
// without dequeuing anything: queue state and drop counters are untouched,
// and the device never panics on malformed buffers. A packet larger than
// bufs[i][offset:] is dropped as oversized (drop counter incremented, buffer
// untouched) and Read returns immediately with the packets placed so far; it
// never blocks waiting for a fitting packet.
//
// After Close, Read returns an error wrapping ErrClosed; packets still queued
// are drained and accounted by Close.
func (t *VirtualTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	// Test-only suspension gate. readSuspended is false for every production
	// device, so this is a single atomic load on the production path.
	if !t.awaitReadResume() {
		return 0, ErrClosed
	}
	select {
	case <-t.closed:
		return 0, ErrClosed
	default:
	}
	if len(bufs) == 0 || len(sizes) < len(bufs) || offset < 0 {
		return 0, fmt.Errorf("%w: read: len(bufs) %d, len(sizes) %d, offset %d", ErrInvalidBuffer, len(bufs), len(sizes), offset)
	}

	max := len(bufs)
	if t.batchSize < max {
		max = t.batchSize
	}

	// Validate every potential destination BEFORE dequeuing anything, so
	// a malformed offset cannot consume queue packets or skew drop
	// counters. A buffer with len(bufs[i]) <= offset offers zero or
	// negative receive capacity at offset (offset == len means a
	// zero-capacity destination: cannot hold even one byte).
	for i := 0; i < max; i++ {
		if len(bufs[i]) <= offset {
			return 0, fmt.Errorf("%w: read: bufs[%d] len %d cannot receive at offset %d", ErrInvalidBuffer, i, len(bufs[i]), offset)
		}
	}

	n := 0
	for n < max {
		var pkt []byte
		var ok bool
		if n == 0 {
			// First packet: block until one is available or the
			// device is closed.
			select {
			case pkt, ok = <-t.inPackets:
			case <-t.closed:
				return 0, ErrClosed
			}
		} else {
			// Subsequent packets: take only what is immediately
			// available; never block for a full batch.
			select {
			case pkt, ok = <-t.inPackets:
			case <-t.closed:
				return n, ErrClosed
			default:
				return n, nil
			}
		}
		if !ok {
			// The packet channels are never closed, so this is
			// unreachable today; guarded for safety.
			return n, ErrClosed
		}

		dst := bufs[n][offset:]
		if len(pkt) > len(dst) {
			// Oversized: drop the packet rather than truncate it
			// and return immediately with the packets placed so
			// far. Read never waits for a fitting packet: the
			// caller's next Read re-enters the queue.
			t.dropCount.Add(1)
			t.inOversized.Add(1)
			return n, nil
		}
		copy(dst, pkt)
		sizes[n] = len(pkt)
		n++
	}
	return n, nil
}

// Write implements tun.Device. It copies each packet from bufs[i][offset:]
// into the outbound queue and returns the number of packets processed. The
// pinned AWG engine may pass more buffers than BatchSize reports (its bind
// batches up to IdealBatchSize), so every provided buffer is processed
// regardless of BatchSize.
//
// Buffers shorter than offset are skipped and not counted. The send is
// nonblocking: a full queue drops the packet (drop counter incremented) while
// still counting it as processed, matching the pinned upstream
// processed-count semantics; consumers detect loss through DroppedPackets.
// An empty buffer yields an empty packet, which the engine skips.
//
// After Close, Write returns an error wrapping ErrClosed without touching the
// queue; mid-batch it returns the count processed so far.
func (t *VirtualTUN) Write(bufs [][]byte, offset int) (int, error) {
	select {
	case <-t.closed:
		return 0, ErrClosed
	default:
	}
	if offset < 0 {
		return 0, fmt.Errorf("%w: write: negative offset %d", ErrInvalidBuffer, offset)
	}

	n := 0
	for _, buf := range bufs {
		if len(buf) <= offset {
			continue
		}
		// The read lock makes the closed check and the send a
		// single atomic step relative to Close: either both happen
		// before Close's transition (and Close drains the packet),
		// or isClosed() is true and the submission fails.
		t.closeMu.RLock()
		if t.isClosed() {
			t.closeMu.RUnlock()
			return n, ErrClosed
		}
		pkt := buf[offset:]
		out := make([]byte, len(pkt))
		copy(out, pkt)
		select {
		case t.outPackets <- out:
			depth := uint64(len(t.outPackets))
			for current := t.outHighWater.Load(); depth > current; {
				if t.outHighWater.CompareAndSwap(current, depth) {
					break
				}
				current = t.outHighWater.Load()
			}
			n++
		default:
			// Drop when full to avoid blocking the tun writer.
			t.dropCount.Add(1)
			t.outQueueFull.Add(1)
			n++
		}
		t.closeMu.RUnlock()
	}
	return n, nil
}

// InjectInbound enqueues one packet for delivery to the engine's Read path.
// The packet is copied, so the caller may reuse pkt as soon as the call
// returns. The send is nonblocking: a full inbound queue drops the packet
// (drop counter incremented) and returns ErrQueueFull. After Close it returns
// ErrClosed without enqueuing.
//
// The closed check and the enqueue happen atomically with respect to Close:
// if InjectInbound returns nil, the packet is guaranteed to be either
// delivered to a reader or drained and counted by Close — never silently
// unaccounted.
func (t *VirtualTUN) InjectInbound(pkt []byte) error {
	out := make([]byte, len(pkt))
	copy(out, pkt)
	// Same critical section as Write: check-and-send under the read lock
	// is atomic relative to Close's write-locked transition.
	t.closeMu.RLock()
	defer t.closeMu.RUnlock()
	if t.isClosed() {
		return ErrClosed
	}
	select {
	case t.inPackets <- out:
		depth := uint64(len(t.inPackets))
		for current := t.inHighWater.Load(); depth > current; {
			if t.inHighWater.CompareAndSwap(current, depth) {
				break
			}
			current = t.inHighWater.Load()
		}
		return nil
	default:
		t.dropCount.Add(1)
		t.inQueueFull.Add(1)
		return ErrQueueFull
	}
}

// ReceiveOutbound blocks until one engine-written packet is available and
// returns it; ownership of the returned slice passes to the caller. When the
// device is closed it unblocks and returns ErrClosed. Because Close drains
// the queues before unblocking waiters, ReceiveOutbound never races a packet
// away from shutdown accounting: after Close returns it always fails with
// ErrClosed.
func (t *VirtualTUN) ReceiveOutbound() ([]byte, error) {
	select {
	case pkt, ok := <-t.outPackets:
		if !ok {
			// Unreachable today: the packet channels are never
			// closed; guarded for safety.
			return nil, ErrClosed
		}
		return pkt, nil
	case <-t.closed:
		// Close drains the queues while holding the lifecycle write
		// lock and only then closes the wakeup channel, so no
		// packet can remain here.
		return nil, ErrClosed
	}
}

// Inbound returns a receive-only view of the inbound packet queue, for tests
// and tooling that need to observe the raw queue. Production code should use
// Read or InjectInbound instead.
func (t *VirtualTUN) Inbound() <-chan []byte {
	return t.inPackets
}

// Outbound returns a receive-only view of the outbound packet queue, for
// tests and tooling that need to observe the raw queue. Production code
// should use ReceiveOutbound or Write instead.
func (t *VirtualTUN) Outbound() <-chan []byte {
	return t.outPackets
}

// DroppedPackets returns the total number of packets dropped due to a full
// queue, an oversized destination buffer, or shutdown. RecordDrop and
// RecordDropN increment this total without touching the per-reason buckets;
// Stats reports the reason breakdown. Shutdown drops: every packet drained
// from the queues by Close is added to this total, so closing a device with
// queued packets increases it (a deliberate semantic delta versus the legacy
// backend, where such packets were lost uncounted).
func (t *VirtualTUN) DroppedPackets() uint64 {
	return t.dropCount.Load()
}

// StatsSnapshot is a point-in-time observation of a VirtualTUN's queue
// depths and drop accounting, returned by Stats.
type StatsSnapshot struct {
	// InboundDepth is the number of packets currently queued for the
	// engine's Read path (device -> engine). After Close returns it is
	// permanently zero: Close drains the queue under its linearization
	// point.
	InboundDepth int

	// OutboundDepth is the number of engine-written packets currently
	// queued for ReceiveOutbound (engine -> consumer). After Close
	// returns it is permanently zero: Close drains the queue under its
	// linearization point.
	OutboundDepth int

	InboundCapacity  int
	OutboundCapacity int
	InboundPeak      int
	OutboundPeak     int
	InboundDrops     uint64
	OutboundDrops    uint64

	// The five directional x reason buckets below are the cross product of
	// the internal drop sites (issue #424 round 3, finding 1). Every internal
	// drop increments exactly one of them, alongside dropCount and exactly
	// one of the direction and reason aggregates, so
	//
	//	InboundQueueFullDrops + InboundOversizedDrops + InboundShutdownDrops + OutboundQueueFullDrops + OutboundShutdownDrops
	//
	// equals InboundDrops + OutboundDrops and DropsQueueFull+DropsOversized+
	// DropsShutdown. They are the only way to tell WHICH direction a
	// queue-full or shutdown loss happened in; the aggregates above cannot,
	// because each carries only one axis.
	//
	// There is no outbound oversized bucket: Read is the only oversized drop
	// site and it drains the inbound queue, so the state is unreachable.
	InboundQueueFullDrops  uint64
	InboundOversizedDrops  uint64
	InboundShutdownDrops   uint64
	OutboundQueueFullDrops uint64
	OutboundShutdownDrops  uint64

	// DropsExternal counts drops recorded through RecordDrop/RecordDropN:
	// losses an outside owner observed that the device itself never
	// classified. It is RECORDED on the recording path, never inferred as
	// a remainder between independently loaded counters, so an internal
	// queue-full, oversized or shutdown loss can never appear here.
	//
	// ExternalDrops() returns this field.
	DropsExternal uint64

	// DropsTotal is the total loss across every population: it is always
	// exactly Sum()+DropsExternal. It mirrors DroppedPackets on a
	// quiescent device and includes shutdown drops drained by Close.
	DropsTotal uint64

	// DropsQueueFull counts packets dropped because the destination
	// queue was full (InjectInbound, Write).
	DropsQueueFull uint64

	// DropsOversized counts packets dropped by Read because they did
	// not fit the destination buffer.
	DropsOversized uint64

	// DropsShutdown counts queued packets drained and discarded by
	// Close. Once Close returns, this bucket is final.
	DropsShutdown uint64
}

// Sum returns the internal drop count: the sum of the per-reason buckets,
// which are themselves derived from the five directional x reason buckets so
// the snapshot is internally consistent.
//
// External drops recorded through RecordDrop/RecordDropN are deliberately
// excluded: they carry no reason and no direction, so they live only in
// DropsExternal. DropsTotal is always exactly Sum()+DropsExternal.
func (s StatsSnapshot) Sum() uint64 {
	return s.DropsQueueFull + s.DropsOversized + s.DropsShutdown
}

// ExternalDrops returns the drops recorded through RecordDrop and
// RecordDropN: the drops an external owner observed OUTSIDE the device.
//
// Those drops carry neither a direction nor a reason — the recording API has
// no parameter for either — so they belong to no directional bucket and no
// reason bucket, and every directional x reason sum is short by exactly this
// amount. Callers MUST account for it explicitly rather than summing buckets
// and treating the sum as the total; use it as its own named population
// instead.
//
// The figure is RECORDED, not inferred: it was previously computed as the
// remainder DropsTotal-Sum() between independently loaded atomics, which
// published an ordinary internal queue-full loss as an external drop whenever
// a sample landed between the total increment and the bucket increments, and
// made the loss vanish from the breakdown for the interleaving in the other
// direction. Because the reason trackers take deltas against a baseline, a
// loss that migrates between populations across two samples reads as fresh
// activity.
func (s StatsSnapshot) ExternalDrops() uint64 {
	return s.DropsExternal
}

// Stats returns a snapshot of the queue depths and drop accounting.
//
// Consistency: the snapshot is INTERNALLY COHERENT. Every counter is read
// exactly once into a local, and every aggregate in the returned value —
// the direction totals, the reason totals, Sum, DropsExternal and DropsTotal
// — is DERIVED from those same locals rather than read from its own atomic.
// So the invariants hold for every sample whatever the device was doing
// concurrently:
//
//	Sum() == InboundDrops + OutboundDrops
//	Sum() == InboundQueueFullDrops + InboundOversizedDrops + InboundShutdownDrops
//	       + OutboundQueueFullDrops + OutboundShutdownDrops
//	DropsTotal == Sum() + DropsExternal
//
// A sample may represent a slightly earlier or later instant than any other,
// since the five counters are still five independent atomics, but it can
// never report a loss in one bucket and not in the total, count one loss
// twice, or invent an external drop that was never recorded: the external
// figure comes from the recording path. Every derived value is also
// monotonic, because every input counter is monotonic.
//
// The depths are still separate channel-length reads and are not jointly
// consistent with each other under concurrent traffic. After Close returns
// the snapshot is fully stable: depths are zero and no counter can increase
// except through RecordDrop/RecordDropN. The snapshot is safe to call
// concurrently with all device operations.
func (t *VirtualTUN) Stats() StatsSnapshot {
	inQueueFull := t.inQueueFull.Load()
	inOversized := t.inOversized.Load()
	inShutdown := t.inShutdown.Load()
	outQueueFull := t.outQueueFull.Load()
	outShutdown := t.outShutdown.Load()
	external := t.externalDrops.Load()

	// Reason and direction axes are both derived from the same five
	// directional x reason reads, which is what makes the two axes agree:
	// each internal drop site carries exactly one reason AND exactly one
	// direction, so summing either projection of the same five locals gives
	// the same number.
	inboundDrops := inQueueFull + inOversized + inShutdown
	outboundDrops := outQueueFull + outShutdown
	internalDrops := inboundDrops + outboundDrops

	return StatsSnapshot{
		InboundDepth:     len(t.inPackets),
		OutboundDepth:    len(t.outPackets),
		InboundCapacity:  cap(t.inPackets),
		OutboundCapacity: cap(t.outPackets),
		InboundPeak:      int(t.inHighWater.Load()),  // #nosec G115 -- bounded by inbound queue capacity.
		OutboundPeak:     int(t.outHighWater.Load()), // #nosec G115 -- bounded by outbound queue capacity.
		InboundDrops:     inboundDrops,
		OutboundDrops:    outboundDrops,

		InboundQueueFullDrops:  inQueueFull,
		InboundOversizedDrops:  inOversized,
		InboundShutdownDrops:   inShutdown,
		OutboundQueueFullDrops: outQueueFull,
		OutboundShutdownDrops:  outShutdown,

		DropsExternal: external,
		DropsTotal:    internalDrops + external,

		DropsQueueFull: inQueueFull + outQueueFull,
		DropsOversized: inOversized,
		DropsShutdown:  inShutdown + outShutdown,
	}
}

// RecordDrop increments the dropped packet counter (issue #160 telemetry
// hook) for drops observed outside the device. The loss is recorded in the
// external population as well, so it is published under DropsExternal rather
// than appearing later as a remainder between the total and the reason
// buckets.
func (t *VirtualTUN) RecordDrop() {
	t.RecordDropN(1)
}

// RecordDropN adds n to the dropped packet counter, for external owners that
// observe drops in batches (issue #160 telemetry hook). A zero batch is a
// no-op. The whole batch lands in the external population: batching never
// splits an external drop into a reason or a direction it was not given.
func (t *VirtualTUN) RecordDropN(n uint64) {
	t.dropCount.Add(n)
	t.externalDrops.Add(n)
}

// SendEvent delivers ev to the channel returned by Events. The send never
// blocks; an event beyond the small event buffer is dropped rather than
// stalling the caller.
func (t *VirtualTUN) SendEvent(ev tun.Event) {
	select {
	case t.events <- ev:
	default:
	}
}

// MTU implements tun.Device.
func (t *VirtualTUN) MTU() (int, error) { return t.mtu, nil }

// Name implements tun.Device.
func (t *VirtualTUN) Name() (string, error) { return t.name, nil }

// Events implements tun.Device.
func (t *VirtualTUN) Events() <-chan tun.Event { return t.events }

// Close implements tun.Device. It is idempotent and never closes the packet
// channels, so concurrent senders cannot panic on a closed channel.
//
// Linearization: Close acquires the lifecycle write lock, marks the device
// closed, closes the wakeup channel (unblocking blocked Read and
// ReceiveOutbound calls, which then fail with ErrClosed), and — with no
// concurrent senders possible — drains both queues nonblockingly, counting
// every drained packet as a shutdown drop (DropsShutdown and DroppedPackets).
// The lock acquisition is the linearization point: any submission racing
// with Close either enqueued before it (its packet is drained and accounted)
// or observes the closed state and fails with ErrClosed. Once Close returns,
// both queue depths are zero and remain zero.
func (t *VirtualTUN) Close() error {
	t.once.Do(func() {
		t.closeMu.Lock()
		defer t.closeMu.Unlock()

		t.closedFlag = true
		close(t.closed)

		// All submitters are excluded by the write lock, so this
		// drain sees a quiesced pair of queues: every packet pulled
		// here was accepted before the linearization point and is
		// accounted exactly once as a shutdown drop. Readers and
		// receivers never take closeMu, so a dequeue racing this
		// drain is possible; each packet then resolves to exactly
		// one side (delivered to the consumer, or counted here).
		for {
			select {
			case <-t.inPackets:
				t.dropCount.Add(1)
				t.inShutdown.Add(1)
			default:
			}
			select {
			case <-t.outPackets:
				t.dropCount.Add(1)
				t.outShutdown.Add(1)
			default:
			}
			// Done when both queues are empty; a reader cannot
			// add packets, and submitters are locked out.
			if len(t.inPackets) == 0 && len(t.outPackets) == 0 {
				break
			}
		}
	})
	return nil
}

// BatchSize implements tun.Device. The value is fixed at construction and
// constant for the lifetime of the device. Note that Write still processes
// every buffer it is given: the pinned AWG engine batches more buffers than
// BatchSize reports.
func (t *VirtualTUN) BatchSize() int { return t.batchSize }
