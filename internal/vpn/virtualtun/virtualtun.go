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
// oversized, shutdown); Stats reports the breakdown alongside the queue
// depths. RecordDrop and RecordDropN increment the total only.
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
	mtu     int
	name    string
	// closedFlag is written only by Close under the write lock and read
	// by submissions under the read lock; it exists so submissions can
	// check-and-enqueue atomically without racing on the channel close.
	closedFlag bool
	batchSize  int
	dropCount  atomic.Uint64
	// Per-reason drop buckets. They are separate atomics, incremented
	// alongside dropCount at each internal drop site: the sum of the
	// buckets can transiently lag or lead the total under concurrency
	// (see Stats).
	dropQueueFull atomic.Uint64
	dropOversized atomic.Uint64
	dropShutdown  atomic.Uint64
	once          sync.Once
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
			t.dropOversized.Add(1)
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
			n++
		default:
			// Drop when full to avoid blocking the tun writer.
			t.dropCount.Add(1)
			t.dropQueueFull.Add(1)
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
		return nil
	default:
		t.dropCount.Add(1)
		t.dropQueueFull.Add(1)
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

	// DropsTotal mirrors DroppedPackets: every drop counted by the
	// device plus external drops recorded via RecordDrop/RecordDropN.
	// Includes shutdown drops drained by Close.
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

// Sum returns the sum of the per-reason drop buckets. External drops
// recorded through RecordDrop/RecordDropN are intentionally excluded: they
// have no reason bucket, so Sum equals DropsTotal only when no external
// drops were recorded and no concurrent drop is in flight.
func (s StatsSnapshot) Sum() uint64 {
	return s.DropsQueueFull + s.DropsOversized + s.DropsShutdown
}

// Stats returns a snapshot of the queue depths and drop accounting.
//
// Consistency: each counter is an independent atomic load and each depth a
// separate channel-length read, so the snapshot is not a globally consistent
// point in time. Under concurrent traffic the depths may never be observed
// together, and the per-reason sum (StatsSnapshot.Sum) can transiently lag
// or lead DropsTotal (a goroutine can be between the two Add calls at one
// drop site, and loads of separate atomics are not a single operation).
// DropsTotal is loaded before the buckets, so a single racy snapshot can
// even show a bucket ahead of the total; the underlying counters never
// diverge this way — every counter is individually monotonic and all of
// them converge once traffic stops. After Close returns the snapshot is
// stable: depths are zero, no counter can increase except through
// RecordDrop/RecordDropN. The snapshot is safe to call concurrently with all
// device operations.
func (t *VirtualTUN) Stats() StatsSnapshot {
	return StatsSnapshot{
		InboundDepth:   len(t.inPackets),
		OutboundDepth:  len(t.outPackets),
		DropsTotal:     t.dropCount.Load(),
		DropsQueueFull: t.dropQueueFull.Load(),
		DropsOversized: t.dropOversized.Load(),
		DropsShutdown:  t.dropShutdown.Load(),
	}
}

// RecordDrop increments the dropped packet counter (issue #160 telemetry
// hook) for drops observed outside the device.
func (t *VirtualTUN) RecordDrop() {
	t.dropCount.Add(1)
}

// RecordDropN adds n to the dropped packet counter, for external owners that
// observe drops in batches (issue #160 telemetry hook).
func (t *VirtualTUN) RecordDropN(n uint64) {
	t.dropCount.Add(n)
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
				t.dropShutdown.Add(1)
			default:
			}
			select {
			case <-t.outPackets:
				t.dropCount.Add(1)
				t.dropShutdown.Add(1)
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
