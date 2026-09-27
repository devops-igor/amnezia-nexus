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
// through the same counter; Close discards queued packets and accounts them
// too. RecordDrop lets external owners add drops observed outside the device
// (issue #160 telemetry).
//
// # Shutdown
//
// Close is idempotent and never closes the packet channels, so a sender can
// never panic on a closed channel. Blocked Read and ReceiveOutbound calls are
// unblocked and return an error wrapping ErrClosed; submissions after close
// are rejected with ErrClosed. BatchSize is constant for the lifetime of the
// device.
//
// # Defaults
//
// New applies DefaultInboundCapacity (2048), DefaultOutboundCapacity (1024)
// and DefaultBatchSize (1) when the corresponding Config field is zero.
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
	// slice arguments (nil bufs, len(sizes) < len(bufs), negative offset).
	// The device never panics on malformed buffers.
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
	closed     chan struct{}
	mtu        int
	name       string
	batchSize  int
	dropCount  atomic.Uint64
	once       sync.Once
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
// negative; violations return an error wrapping ErrInvalidBuffer and the
// device never panics. A packet larger than bufs[i][offset:] is dropped as
// oversized (drop counter incremented, buffer untouched) and Read returns
// immediately with the packets placed so far; it never blocks waiting for a
// fitting packet.
//
// After Close, Read returns an error wrapping ErrClosed; packets still queued
// are discarded and accounted by Close.
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
		pkt := buf[offset:]
		out := make([]byte, len(pkt))
		copy(out, pkt)
		select {
		case t.outPackets <- out:
			n++
		case <-t.closed:
			return n, ErrClosed
		default:
			// Drop when full to avoid blocking the tun writer.
			t.dropCount.Add(1)
			n++
		}
	}
	return n, nil
}

// InjectInbound enqueues one packet for delivery to the engine's Read path.
// The packet is copied, so the caller may reuse pkt as soon as the call
// returns. The send is nonblocking: a full inbound queue drops the packet
// (drop counter incremented) and returns ErrQueueFull. After Close it returns
// ErrClosed without enqueuing.
func (t *VirtualTUN) InjectInbound(pkt []byte) error {
	select {
	case <-t.closed:
		return ErrClosed
	default:
	}
	out := make([]byte, len(pkt))
	copy(out, pkt)
	select {
	case t.inPackets <- out:
		return nil
	default:
		t.dropCount.Add(1)
		return ErrQueueFull
	}
}

// ReceiveOutbound blocks until one engine-written packet is available and
// returns it; ownership of the returned slice passes to the caller. When the
// device is closed it unblocks and returns ErrClosed. A packet already queued
// when Close races with the close may still be delivered.
func (t *VirtualTUN) ReceiveOutbound() ([]byte, error) {
	select {
	case <-t.closed:
		// Deterministic fast path: once Close has completed, never
		// deliver; queued packets were accounted as discarded.
		return nil, ErrClosed
	default:
	}
	select {
	case pkt, ok := <-t.outPackets:
		if !ok {
			// Unreachable today: the packet channels are never
			// closed; guarded for safety.
			return nil, ErrClosed
		}
		return pkt, nil
	case <-t.closed:
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
// queue, an oversized destination buffer, or shutdown.
func (t *VirtualTUN) DroppedPackets() uint64 {
	return t.dropCount.Load()
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
// channels, so concurrent senders cannot panic on a closed channel. Blocked
// Read and ReceiveOutbound calls unblock with ErrClosed. Packets still queued
// in either direction are discarded and accounted: the drop counter is
// increased by the number of packets queued at close (a snapshot taken after
// close; a packet delivered by a reader racing with Close may be counted as
// well).
func (t *VirtualTUN) Close() error {
	t.once.Do(func() {
		close(t.closed)
		// Discard queued packets with accounting. Channels are never
		// closed, so a sender racing with Close can still enqueue;
		// submissions after Close are rejected, so at most a
		// bounded number of in-flight packets can be missed by
		// this snapshot.
		if discarded := len(t.inPackets) + len(t.outPackets); discarded > 0 {
			t.dropCount.Add(uint64(discarded))
		}
	})
	return nil
}

// BatchSize implements tun.Device. The value is fixed at construction and
// constant for the lifetime of the device. Note that Write still processes
// every buffer it is given: the pinned AWG engine batches more buffers than
// BatchSize reports.
func (t *VirtualTUN) BatchSize() int { return t.batchSize }
