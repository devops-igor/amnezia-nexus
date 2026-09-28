package virtualtun

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

func mustNew(t *testing.T, cfg Config) *VirtualTUN {
	t.Helper()
	vt, err := New(cfg)
	if err != nil {
		t.Fatalf("New(%+v): %v", cfg, err)
	}
	t.Cleanup(func() { _ = vt.Close() })
	return vt
}

// TestNew_Validation covers config validation: errors, never silent clamping.
func TestNew_Validation(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{"negative MTU", Config{MTU: -1}},
		{"negative inbound capacity", Config{InboundCapacity: -5}},
		{"negative outbound capacity", Config{OutboundCapacity: -5}},
		{"negative batch size", Config{BatchSize: -1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vt, err := New(tt.cfg)
			if err == nil {
				_ = vt.Close()
				t.Fatal("expected error, got nil")
			}
		})
	}

	t.Run("zero config selects defaults", func(t *testing.T) {
		vt := mustNew(t, Config{})
		if got := cap(vt.inPackets); got != DefaultInboundCapacity {
			t.Errorf("inbound capacity = %d, want %d", got, DefaultInboundCapacity)
		}
		if got := cap(vt.outPackets); got != DefaultOutboundCapacity {
			t.Errorf("outbound capacity = %d, want %d", got, DefaultOutboundCapacity)
		}
		if got := vt.BatchSize(); got != DefaultBatchSize {
			t.Errorf("BatchSize = %d, want %d", got, DefaultBatchSize)
		}
	})

	t.Run("explicit values preserved", func(t *testing.T) {
		vt := mustNew(t, Config{Name: "x", MTU: 1340, InboundCapacity: 8, OutboundCapacity: 4, BatchSize: 3})
		name, err := vt.Name()
		if err != nil || name != "x" {
			t.Errorf("Name = %q, %v", name, err)
		}
		mtu, err := vt.MTU()
		if err != nil || mtu != 1340 {
			t.Errorf("MTU = %d, %v", mtu, err)
		}
		if got := cap(vt.inPackets); got != 8 {
			t.Errorf("inbound capacity = %d, want 8", got)
		}
		if got := cap(vt.outPackets); got != 4 {
			t.Errorf("outbound capacity = %d, want 4", got)
		}
	})
}

// TestRead_PacketPreservation checks exact bytes across offsets and boundaries.
func TestRead_PacketPreservation(t *testing.T) {
	tests := []struct {
		name   string
		pktLen int
		bufCap int
		offset int
	}{
		{"zero offset", 20, 64, 0},
		{"ethernet-style offset 14", 20, 64, 14},
		{"packet exactly fills capacity", 50, 64, 14},
		{"single-byte packet", 1, 8, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vt := mustNew(t, Config{BatchSize: 1})
			pkt := make([]byte, tt.pktLen)
			for i := range pkt {
				pkt[i] = byte(i + 1)
			}
			if err := vt.InjectInbound(pkt); err != nil {
				t.Fatalf("InjectInbound: %v", err)
			}
			// Poison the buffer to catch wrong copy regions.
			buf := make([]byte, tt.bufCap)
			for i := range buf {
				buf[i] = 0xAA
			}
			bufs := [][]byte{buf}
			sizes := []int{0}
			n, err := vt.Read(bufs, sizes, tt.offset)
			if err != nil {
				t.Fatalf("Read: %v", err)
			}
			if n != 1 {
				t.Fatalf("n = %d, want 1", n)
			}
			if sizes[0] != tt.pktLen {
				t.Errorf("sizes[0] = %d, want %d", sizes[0], tt.pktLen)
			}
			if !bytes.Equal(buf[tt.offset:tt.offset+tt.pktLen], pkt) {
				t.Errorf("packet corrupted at offset %d", tt.offset)
			}
			for i, b := range buf[:tt.offset] {
				if b != 0xAA {
					t.Errorf("prefix byte %d modified: %#x", i, b)
				}
			}
			for i, b := range buf[tt.offset+tt.pktLen:] {
				if b != 0xAA {
					t.Errorf("suffix byte %d modified: %#x", i, b)
				}
			}
		})
	}
}

// TestRead_OversizedDropped verifies the no-silent-truncation contract.
func TestRead_OversizedDropped(t *testing.T) {
	vt := mustNew(t, Config{BatchSize: 1})

	big := bytes.Repeat([]byte{0x42}, 100)
	if err := vt.InjectInbound(big); err != nil {
		t.Fatalf("InjectInbound: %v", err)
	}
	buf := bytes.Repeat([]byte{0xAA}, 64) // capacity 64 < 100
	sizes := []int{7}                     // pre-set: must stay untouched on drop
	n, err := vt.Read([][]byte{buf}, sizes, 0)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if n != 0 {
		t.Errorf("n = %d, want 0", n)
	}
	if sizes[0] != 7 {
		t.Errorf("sizes[0] = %d, want untouched (7): nothing was placed", sizes[0])
	}
	if !bytes.Equal(buf, bytes.Repeat([]byte{0xAA}, 64)) {
		t.Error("oversized drop modified the destination buffer")
	}
	if got := vt.DroppedPackets(); got != 1 {
		t.Errorf("DroppedPackets = %d, want 1", got)
	}

	// The drop must not consume the loop: the next (fitting) packet is
	// delivered and no packet before it is reordered.
	small := []byte{1, 2, 3}
	if err := vt.InjectInbound(small); err != nil {
		t.Fatalf("InjectInbound: %v", err)
	}
	sizes[0] = 0
	n, err = vt.Read([][]byte{buf}, sizes, 0)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if n != 1 || sizes[0] != 3 || !bytes.Equal(buf[:3], small) {
		t.Errorf("subsequent packet lost or corrupted: n=%d sizes=%d buf=%v", n, sizes[0], buf[:3])
	}
}

// TestRead_MalformedBuffers: malformed arguments return errors, never panic.
func TestRead_MalformedBuffers(t *testing.T) {
	vt := mustNew(t, Config{})
	_ = vt.InjectInbound([]byte{1})

	tests := []struct {
		name   string
		bufs   [][]byte
		sizes  []int
		offset int
		want   error
	}{
		{"zero bufs", nil, []int{0}, 0, ErrInvalidBuffer},
		{"nil sizes", [][]byte{make([]byte, 8)}, nil, 0, ErrInvalidBuffer},
		{"sizes shorter than bufs", [][]byte{make([]byte, 8)}, nil, 0, ErrInvalidBuffer},
		{"negative offset", [][]byte{make([]byte, 8)}, []int{0}, -1, ErrInvalidBuffer},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Read panicked: %v", r)
				}
			}()
			n, err := vt.Read(tt.bufs, tt.sizes, tt.offset)
			if !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
			if n != 0 {
				t.Errorf("n = %d, want 0", n)
			}
		})
	}
}

// TestWrite_MalformedArguments covers Write-side argument validation.
func TestWrite_MalformedArguments(t *testing.T) {
	vt := mustNew(t, Config{})
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Write panicked: %v", r)
		}
	}()

	n, err := vt.Write(nil, -1)
	if !errors.Is(err, ErrInvalidBuffer) || n != 0 {
		t.Errorf("Write(nil, -1) = (%d, %v), want (0, %v)", n, err, ErrInvalidBuffer)
	}

	// nil bufs with valid offset is a zero-size batch: no-op success.
	n, err = vt.Write(nil, 0)
	if err != nil || n != 0 {
		t.Errorf("Write(nil, 0) = (%d, %v), want (0, nil)", n, err)
	}

	// Buffers shorter than offset are skipped, not counted.
	buf := make([]byte, 4)
	n, err = vt.Write([][]byte{buf}, 16)
	if err != nil || n != 0 {
		t.Errorf("short-buffer Write = (%d, %v), want (0, nil)", n, err)
	}
	if got := vt.DroppedPackets(); got != 0 {
		t.Errorf("DroppedPackets = %d, want 0", got)
	}
}

// TestWrite_BufferIsolation: caller may reuse its buffer after Write returns.
func TestWrite_BufferIsolation(t *testing.T) {
	vt := mustNew(t, Config{})
	pkt := bytes.Repeat([]byte{0x5A}, 32)
	orig := make([]byte, len(pkt))
	copy(orig, pkt)

	if _, err := vt.Write([][]byte{pkt}, 0); err != nil {
		t.Fatalf("Write: %v", err)
	}
	for i := range pkt {
		pkt[i] = 0x00 // simulate caller buffer pool reuse
	}

	got, err := vt.ReceiveOutbound()
	if err != nil {
		t.Fatalf("ReceiveOutbound: %v", err)
	}
	if !bytes.Equal(got, orig) {
		t.Errorf("packet corrupted after caller buffer reuse: got %x, want %x", got, orig)
	}
}

// TestWrite_ShortBufferAtOffset: offset content is preserved exactly.
func TestWrite_ShortBufferAtOffset(t *testing.T) {
	vt := mustNew(t, Config{})
	buf := make([]byte, 20+10)
	for i := 0; i < 20; i++ {
		buf[i] = 0xFF // header region before offset must not leak
	}
	for i := 0; i < 10; i++ {
		buf[20+i] = byte(i)
	}
	n, err := vt.Write([][]byte{buf}, 20)
	if err != nil || n != 1 {
		t.Fatalf("Write = (%d, %v), want (1, nil)", n, err)
	}
	got, err := vt.ReceiveOutbound()
	if err != nil {
		t.Fatalf("ReceiveOutbound: %v", err)
	}
	want := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	if !bytes.Equal(got, want) {
		t.Errorf("got %x, want %x", got, want)
	}
}

// TestRead_CallerBufferReuse: data is copied out; the queue slot may be reused.
func TestRead_CallerBufferReuse(t *testing.T) {
	vt := mustNew(t, Config{})
	pkt := []byte{9, 8, 7}
	if err := vt.InjectInbound(pkt); err != nil {
		t.Fatalf("InjectInbound: %v", err)
	}
	for i := range pkt {
		pkt[i] = 0
	}

	buf := make([]byte, 16)
	sizes := []int{0}
	if _, err := vt.Read([][]byte{buf}, sizes, 0); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if sizes[0] != 3 || !bytes.Equal(buf[:3], []byte{9, 8, 7}) {
		t.Errorf("read corrupted: sizes=%d buf=%v", sizes[0], buf[:3])
	}
}

// TestBatchSize_Contract covers the documented batching behavior.
func TestBatchSize_Contract(t *testing.T) {
	vt := mustNew(t, Config{BatchSize: 4, InboundCapacity: 16})
	if got := vt.BatchSize(); got != 4 {
		t.Fatalf("BatchSize = %d, want 4", got)
	}
	// First packet blocks until available; the rest are drained
	// non-blocking up to BatchSize.
	for i := 0; i < 4; i++ {
		if err := vt.InjectInbound([]byte{byte(i)}); err != nil {
			t.Fatalf("InjectInbound: %v", err)
		}
	}
	bufs := [][]byte{make([]byte, 8), make([]byte, 8), make([]byte, 8), make([]byte, 8)}
	sizes := []int{0, 0, 0, 0}
	n, err := vt.Read(bufs, sizes, 0)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if n != 4 {
		t.Fatalf("n = %d, want 4", n)
	}
	for i := range sizes {
		if sizes[i] != 1 {
			t.Errorf("sizes[%d] = %d, want 1", i, sizes[i])
		}
	}

	// Batch capped by len(bufs) when smaller than BatchSize.
	if err := vt.InjectInbound([]byte{0}); err != nil {
		t.Fatalf("InjectInbound: %v", err)
	}
	n, err = vt.Read([][]byte{make([]byte, 8)}, []int{0}, 0)
	if err != nil || n != 1 {
		t.Errorf("capped read = (%d, %v), want (1, nil)", n, err)
	}

	// Blocked-first-packet Read unblocks on close with ErrClosed.
	vt2, err := New(Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	errCh := make(chan error, 1)
	go func() {
		_, err := vt2.Read([][]byte{make([]byte, 8)}, []int{0}, 0)
		errCh <- err
	}()
	if err := vt2.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-errCh:
		if !errors.Is(err, ErrClosed) {
			t.Errorf("blocked Read after close = %v, want ErrClosed", err)
		}
	case <-timeout(t):
		t.Fatal("blocked Read was not unblocked by Close")
	}
}

// TestRead_BlockedUnblocksOnClose covers close-while-blocked for Read.
func TestRead_BlockedUnblocksOnClose(t *testing.T) {
	vt, err := New(Config{BatchSize: 1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := vt.Read([][]byte{make([]byte, 16)}, []int{0}, 0)
		done <- err
	}()
	// Give the reader a moment to block, then close.
	if err := vt.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrClosed) {
			t.Errorf("Read after close = %v, want ErrClosed", err)
		}
	case <-timeout(t):
		t.Fatal("Read blocked forever after Close")
	}
}

// TestReceiveOutbound_BlockedUnblocksOnClose covers close-while-blocked for
// the queue-draining consumer path.
func TestReceiveOutbound_BlockedUnblocksOnClose(t *testing.T) {
	vt, err := New(Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := vt.ReceiveOutbound()
		done <- err
	}()
	if err := vt.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrClosed) {
			t.Errorf("ReceiveOutbound after close = %v, want ErrClosed", err)
		}
	case <-timeout(t):
		t.Fatal("ReceiveOutbound blocked forever after Close")
	}
}

// TestClose_RejectsNewSubmissions: after close, submissions are rejected.
func TestClose_RejectsNewSubmissions(t *testing.T) {
	vt := mustNew(t, Config{})
	if err := vt.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := vt.InjectInbound([]byte{1}); !errors.Is(err, ErrClosed) {
		t.Errorf("InjectInbound after close = %v, want ErrClosed", err)
	}
	if _, err := vt.Write([][]byte{make([]byte, 4, 8)}, 0); !errors.Is(err, ErrClosed) {
		t.Errorf("Write after close = %v, want ErrClosed", err)
	}
	if _, err := vt.ReceiveOutbound(); !errors.Is(err, ErrClosed) {
		t.Errorf("ReceiveOutbound after close = %v, want ErrClosed", err)
	}
	if _, err := vt.Read([][]byte{make([]byte, 4)}, []int{0}, 0); !errors.Is(err, ErrClosed) {
		t.Errorf("Read after close = %v, want ErrClosed", err)
	}
	if got := vt.DroppedPackets(); got != 0 {
		// No packets were queued at close, and rejected submissions must
		// not count as drops.
		t.Errorf("DroppedPackets = %d, want 0", got)
	}
}

// TestClose_AccountsQueuedPackets: queued packets discarded at close are
// counted.
func TestClose_AccountsQueuedPackets(t *testing.T) {
	vt, err := New(Config{InboundCapacity: 8, OutboundCapacity: 8})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := vt.InjectInbound([]byte{1, 2, 3}); err != nil {
		t.Fatalf("InjectInbound: %v", err)
	}
	if _, err := vt.Write([][]byte{bytes.Repeat([]byte{7}, 10)}, 0); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := vt.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := vt.DroppedPackets(); got != 2 {
		t.Errorf("DroppedPackets = %d, want 2 (1 inbound + 1 outbound queued at close)", got)
	}
	// Queued packets are actually gone.
	if _, err := vt.ReceiveOutbound(); !errors.Is(err, ErrClosed) {
		t.Errorf("ReceiveOutbound after close = %v, want ErrClosed", err)
	}
}

// TestClose_Idempotent: repeated create/close cycles are safe.
func TestClose_Idempotent(t *testing.T) {
	for cycle := 0; cycle < 50; cycle++ {
		vt, err := New(Config{Name: fmt.Sprintf("cycle-%d", cycle), MTU: 1500, InboundCapacity: 4, OutboundCapacity: 4})
		if err != nil {
			t.Fatalf("cycle %d: New: %v", cycle, err)
		}
		if err := vt.InjectInbound([]byte{1}); err != nil {
			t.Fatalf("cycle %d: InjectInbound: %v", cycle, err)
		}
		for i := 0; i < 2; i++ {
			if err := vt.Close(); err != nil {
				t.Fatalf("cycle %d: Close #%d: %v", cycle, i, err)
			}
		}
		// Ensure no send-on-closed-channel panic is possible after close.
		if err := vt.InjectInbound([]byte{2}); !errors.Is(err, ErrClosed) {
			t.Fatalf("cycle %d: submission after close = %v, want ErrClosed", cycle, err)
		}
	}
}

// TestConcurrentInjectReadClose hammers inject/read/receive/close from many
// goroutines under -race; the only hard assertions are no panic, no
// send-on-closed panic, and monotonic drop accounting.
func TestConcurrentInjectReadClose(t *testing.T) {
	for iter := 0; iter < 10; iter++ {
		vt, err := New(Config{InboundCapacity: 32, OutboundCapacity: 32, BatchSize: 2})
		if err != nil {
			t.Fatalf("New: %v", err)
		}

		var wg sync.WaitGroup
		stop := make(chan struct{})

		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				_ = vt.InjectInbound([]byte{byte(i)})
			}
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 64)
			bufs := [][]byte{buf, make([]byte, 64)}
			sizes := []int{0, 0}
			for {
				select {
				case <-stop:
					return
				default:
				}
				_, _ = vt.Read(bufs, sizes, 0)
			}
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, err := vt.ReceiveOutbound(); err != nil {
					return
				}
			}
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 3; i++ {
				_, _ = vt.Write([][]byte{bytes.Repeat([]byte{0x11}, 20)}, 0)
			}
		}()

		// Close from a fourth goroutine while everything runs.
		closeDone := make(chan struct{})
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = vt.Close()
			close(closeDone)
		}()
		// Readers/writers must observe closure shortly after.
		go func() {
			<-closeDone
			close(stop)
		}()
		wg.Wait()

		// Stats must stay sane under concurrent drops: depths never
		// exceed queue capacity and the drop total never goes backwards.
		s := vt.Stats()
		if s.InboundDepth > cap(vt.inPackets) || s.OutboundDepth > cap(vt.outPackets) {
			t.Errorf("iteration %d: Stats depths exceed queue capacity: %+v", iter, s)
		}
		if s2 := vt.Stats(); s2.DropsTotal < s.DropsTotal {
			t.Errorf("iteration %d: DropsTotal went backwards: %d < %d", iter, s2.DropsTotal, s.DropsTotal)
		}

		if got := vt.DroppedPackets(); got == 0 {
			// At close both queues held packets or drops happened on
			// the way; zero would mean the queues were empty AND no
			// overflow occurred in this iteration. Possible but
			// vanishingly rare; do not fail on it, just note it.
			t.Logf("iteration %d: no drops recorded (queues drained empty before close)", iter)
		}
	}
}

// TestTunDeviceSatisfied documents interface compliance in an assertion.
func TestTunDeviceSatisfied(t *testing.T) {
	var _ tun.Device = (*VirtualTUN)(nil)
	vt := mustNew(t, Config{})
	if vt.File() != nil {
		t.Error("File() must be nil for an in-memory device")
	}
	if len(vt.Events()) != 0 {
		t.Error("Events channel should start empty")
	}
}

// timeout fails the test if the operation does not complete in time.
func timeout(t *testing.T) <-chan time.Time {
	t.Helper()
	return time.After(2 * time.Second)
}

// TestRecordDropHooks covers the telemetry hooks.
func TestRecordDropHooks(t *testing.T) {
	vt := mustNew(t, Config{})
	vt.RecordDrop()
	vt.RecordDropN(41)
	if got := vt.DroppedPackets(); got != 42 {
		t.Errorf("DroppedPackets = %d, want 42", got)
	}
}

// TestStats_QueueDepths covers depth reporting on both queue directions.
func TestStats_QueueDepths(t *testing.T) {
	vt := mustNew(t, Config{InboundCapacity: 4, OutboundCapacity: 4, BatchSize: 2})

	s := vt.Stats()
	if s.InboundDepth != 0 || s.OutboundDepth != 0 {
		t.Fatalf("fresh device depths = (%d, %d), want (0, 0)", s.InboundDepth, s.OutboundDepth)
	}
	if s.DropsTotal != 0 || s.Sum() != 0 {
		t.Fatalf("fresh device drops = total %d, buckets %d, want 0", s.DropsTotal, s.Sum())
	}

	for i := 0; i < 2; i++ {
		if err := vt.InjectInbound([]byte{byte(i)}); err != nil {
			t.Fatalf("InjectInbound: %v", err)
		}
	}
	if _, err := vt.Write([][]byte{bytes.Repeat([]byte{7}, 4)}, 0); err != nil {
		t.Fatalf("Write: %v", err)
	}

	s = vt.Stats()
	if s.InboundDepth != 2 {
		t.Errorf("InboundDepth = %d, want 2", s.InboundDepth)
	}
	if s.OutboundDepth != 1 {
		t.Errorf("OutboundDepth = %d, want 1", s.OutboundDepth)
	}

	// Draining the outbound queue is observable through Stats.
	if _, err := vt.ReceiveOutbound(); err != nil {
		t.Fatalf("ReceiveOutbound: %v", err)
	}
	if s = vt.Stats(); s.OutboundDepth != 0 {
		t.Errorf("OutboundDepth after drain = %d, want 0", s.OutboundDepth)
	}

	// Reading the inbound queue through the tun.Device path too.
	bufs := [][]byte{make([]byte, 8), make([]byte, 8)}
	sizes := []int{0, 0}
	if n, err := vt.Read(bufs, sizes, 0); err != nil || n != 2 {
		t.Fatalf("Read = (%d, %v), want (2, nil)", n, err)
	}
	if s = vt.Stats(); s.InboundDepth != 0 {
		t.Errorf("InboundDepth after Read = %d, want 0", s.InboundDepth)
	}
}

// TestStats_PerReasonAccounting walks the three internal drop sites: one
// device accumulates one drop of each reason; subtests build on each other
// (running counters), matching the accounting model.
func TestStats_PerReasonAccounting(t *testing.T) {
	vt := mustNew(t, Config{InboundCapacity: 2, OutboundCapacity: 1})

	t.Run("queue-full on InjectInbound", func(t *testing.T) {
		// Fill the inbound queue with 2-byte packets (they will be
		// made oversized by the 1-byte read buffer in the next
		// subtest), then force one queue-full drop.
		for i := 0; i < 2; i++ {
			if err := vt.InjectInbound([]byte{byte(i), byte(i)}); err != nil {
				t.Fatalf("InjectInbound #%d: %v", i, err)
			}
		}
		if err := vt.InjectInbound([]byte{0xFF}); !errors.Is(err, ErrQueueFull) {
			t.Fatalf("overflow InjectInbound = %v, want ErrQueueFull", err)
		}
		s := vt.Stats()
		if s.DropsQueueFull != 1 || s.DropsOversized != 0 || s.DropsShutdown != 0 {
			t.Errorf("buckets = (qf %d, ov %d, sd %d), want (1, 0, 0)", s.DropsQueueFull, s.DropsOversized, s.DropsShutdown)
		}
		if s.DropsTotal != 1 || s.Sum() != s.DropsTotal {
			t.Errorf("total %d, sum %d, want both 1", s.DropsTotal, s.Sum())
		}
	})

	t.Run("oversized on Read", func(t *testing.T) {
		// The queued 2-byte packets do not fit a 1-byte buffer: each
		// Read drops the head packet as oversized and returns
		// immediately, so two calls drain both via the oversized path.
		sizes := []int{0}
		for i := 0; i < 2; i++ {
			if n, err := vt.Read([][]byte{make([]byte, 1)}, sizes, 0); err != nil || n != 0 {
				t.Fatalf("oversized Read #%d = (%d, %v), want (0, nil)", i+1, n, err)
			}
		}
		s := vt.Stats()
		if s.DropsOversized != 2 {
			t.Errorf("DropsOversized = %d, want 2 (both queued packets exceed the 1-byte buffer)", s.DropsOversized)
		}
		if s.DropsQueueFull != 1 || s.DropsShutdown != 0 {
			t.Errorf("buckets = (qf %d, sd %d), want (1, 0)", s.DropsQueueFull, s.DropsShutdown)
		}
		if s.DropsTotal != 3 || s.Sum() != s.DropsTotal {
			t.Errorf("total %d, sum %d, want both 3", s.DropsTotal, s.Sum())
		}
	})

	t.Run("queue-full on Write", func(t *testing.T) {
		// Fill the single outbound slot, then overflow it once. The
		// dropped packet still counts as processed (session 1
		// processed-count semantics).
		if _, err := vt.Write([][]byte{bytes.Repeat([]byte{7}, 4)}, 0); err != nil {
			t.Fatalf("Write: %v", err)
		}
		n, err := vt.Write([][]byte{bytes.Repeat([]byte{7}, 4)}, 0)
		if err != nil || n != 1 {
			t.Fatalf("overflow Write = (%d, %v), want (1, nil)", n, err)
		}
		s := vt.Stats()
		if s.DropsQueueFull != 2 {
			t.Errorf("DropsQueueFull = %d, want 2 (1 InjectInbound + 1 Write)", s.DropsQueueFull)
		}
		if s.DropsOversized != 2 || s.DropsShutdown != 0 {
			t.Errorf("buckets = (ov %d, sd %d), want (2, 0)", s.DropsOversized, s.DropsShutdown)
		}
		if s.DropsTotal != 4 || s.Sum() != s.DropsTotal {
			t.Errorf("total %d, sum %d, want both 4", s.DropsTotal, s.Sum())
		}
	})

	t.Run("shutdown on Close", func(t *testing.T) {
		// The outbound queue holds 1 packet; the inbound queue is empty
		// (both its packets were consumed as oversized drops).
		if err := vt.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		s := vt.Stats()
		if s.DropsShutdown != 1 {
			t.Errorf("DropsShutdown = %d, want 1 (outbound packet queued at close)", s.DropsShutdown)
		}
		if s.DropsQueueFull != 2 || s.DropsOversized != 2 {
			t.Errorf("buckets = (qf %d, ov %d), want (2, 2)", s.DropsQueueFull, s.DropsOversized)
		}
		if s.DropsTotal != 5 || s.Sum() != s.DropsTotal {
			t.Errorf("total %d, sum %d, want both 5", s.DropsTotal, s.Sum())
		}
	})
}

// TestStats_ExternalDropsNotAttributed: RecordDrop/RecordDropN increment the
// total only, never a reason bucket.
func TestStats_ExternalDropsNotAttributed(t *testing.T) {
	vt := mustNew(t, Config{})
	vt.RecordDrop()
	vt.RecordDropN(9)

	s := vt.Stats()
	if s.DropsTotal != 10 {
		t.Errorf("DropsTotal = %d, want 10", s.DropsTotal)
	}
	if s.Sum() != 0 {
		t.Errorf("per-reason sum = %d, want 0 (external drops have no bucket)", s.Sum())
	}
	if s.DropsQueueFull != 0 || s.DropsOversized != 0 || s.DropsShutdown != 0 {
		t.Errorf("buckets = (qf %d, ov %d, sd %d), want all 0", s.DropsQueueFull, s.DropsOversized, s.DropsShutdown)
	}
}

// TestStats_SnapshotIsIndependent: the returned snapshot is a value copy;
// later drops do not mutate an already-returned snapshot.
func TestStats_SnapshotIsIndependent(t *testing.T) {
	vt := mustNew(t, Config{InboundCapacity: 1})
	if err := vt.InjectInbound([]byte{1}); err != nil {
		t.Fatalf("InjectInbound: %v", err)
	}

	before := vt.Stats()
	if err := vt.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	after := vt.Stats()

	if before.DropsShutdown != 0 || before.DropsTotal != 0 {
		t.Errorf("snapshot taken before Close changed: shutdown=%d total=%d, want 0/0", before.DropsShutdown, before.DropsTotal)
	}
	if after.DropsShutdown != 1 || after.DropsTotal != 1 {
		t.Errorf("post-Close stats = shutdown %d total %d, want 1/1", after.DropsShutdown, after.DropsTotal)
	}
	if before.InboundDepth != 1 {
		t.Errorf("pre-Close InboundDepth = %d, want 1", before.InboundDepth)
	}
}

// TestRead_OffsetBeyondCapacity: a destination that cannot receive even one
// byte at offset (offset >= len(bufs[i])) is malformed for every potential
// destination in the batch. Read must reject with ErrInvalidBuffer BEFORE
// dequeuing anything: queue state and drop counters stay untouched (review
// finding 1; the offset > len(buf) case used to panic).
func TestRead_OffsetBeyondCapacity(t *testing.T) {
	tests := []struct {
		name    string
		batch   int
		bufLens []int
		offset  int
	}{
		{"offset equals buffer length", 1, []int{8}, 8},
		{"offset exceeds buffer length", 1, []int{8}, 9},
		{"zero-length buffer at offset zero", 1, []int{0}, 0},
		{"later buffer shorter than offset", 4, []int{16, 16, 4, 16}, 8},
		{"later buffer zero-length", 2, []int{16, 0}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vt := mustNew(t, Config{BatchSize: tt.batch, InboundCapacity: 8})
			if err := vt.InjectInbound([]byte{1, 2, 3}); err != nil {
				t.Fatalf("InjectInbound: %v", err)
			}
			before := vt.Stats()
			if before.InboundDepth != 1 || before.DropsTotal != 0 {
				t.Fatalf("pre-Read stats = %+v, want depth 1, drops 0", before)
			}

			bufs := make([][]byte, len(tt.bufLens))
			for i, n := range tt.bufLens {
				bufs[i] = make([]byte, n)
			}
			sizes := make([]int, len(tt.bufLens))
			for i := range sizes {
				sizes[i] = 7 // sentinel: must stay untouched on rejection
			}

			n, err := vt.Read(bufs, sizes, tt.offset)
			if !errors.Is(err, ErrInvalidBuffer) {
				t.Errorf("err = %v, want %v", err, ErrInvalidBuffer)
			}
			if n != 0 {
				t.Errorf("n = %d, want 0", n)
			}
			for i := range sizes {
				if sizes[i] != 7 {
					t.Errorf("sizes[%d] = %d, want untouched sentinel 7", i, sizes[i])
				}
			}

			// The rejected call consumed no packet and counted no drop.
			after := vt.Stats()
			if after != before {
				t.Errorf("stats changed by rejected Read: before %+v, after %+v", before, after)
			}

			// The queue is intact: a valid call still delivers the packet.
			n, err = vt.Read([][]byte{make([]byte, 16)}, []int{0}, 0)
			if err != nil || n != 1 {
				t.Errorf("recovery Read = (%d, %v), want (1, nil)", n, err)
			}
		})
	}
}

// TestClose_InFlightSubmissionAccounted deterministically constructs the
// review-finding interleave: a submission is inside its critical section
// (closed check passed, enqueue not done) while Close runs to completion.
// The invariant requires the packet to be drained and shutdown-accounted —
// an accepted-but-unaccounted packet is the bug. Gate = the lifecycle read
// lock the submission holds; deterministic, no hammering.
func TestClose_InFlightSubmissionAccounted(t *testing.T) {
	vt, err := New(Config{InboundCapacity: 4, OutboundCapacity: 4})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = vt.Close() })

	// Hold the submission critical section open (as InjectInbound/Write do
	// between their closed check and their enqueue).
	vt.closeMu.RLock()

	closeDone := make(chan struct{})
	go func() {
		_ = vt.Close()
		close(closeDone)
	}()

	// Close must block behind the in-flight submission, not complete.
	select {
	case <-closeDone:
		vt.closeMu.RUnlock()
		t.Fatal("Close completed while a submission critical section was in flight: linearization point broken")
	case <-time.After(100 * time.Millisecond):
	}

	// Complete the submission: the closed check passes (Close has not run),
	// the packet enqueues, the lock releases. This is the "passed the check,
	// got descheduled, enqueued after close" packet from the review finding.
	vt.inPackets <- []byte{9}
	vt.closeMu.RUnlock()

	select {
	case <-closeDone:
	case <-timeout(t):
		t.Fatal("Close deadlocked behind a submission critical section")
	}

	s := vt.Stats()
	if s.InboundDepth != 0 || s.OutboundDepth != 0 {
		t.Errorf("post-Close depths = (%d, %d), want (0, 0)", s.InboundDepth, s.OutboundDepth)
	}
	if s.DropsShutdown != 1 || s.DropsTotal != 1 {
		t.Errorf("post-Close drops = shutdown %d total %d, want 1/1 (accepted-but-unaccounted or double-counted)", s.DropsShutdown, s.DropsTotal)
	}
}

// TestClose_RacingSubmissionEitherClosedOrAccounted drives real submissions
// (InjectInbound, Write) through a gate held before their enqueue step, runs
// Close to completion behind the gate, then releases it. The submission must
// resolve to exactly one of two outcomes — ErrClosed with nothing enqueued,
// or success with the packet drained and shutdown-accounted. No third
// outcome.
func TestClose_RacingSubmissionEitherClosedOrAccounted(t *testing.T) {
	tests := []struct {
		name   string
		submit func(*VirtualTUN) error
	}{
		{"InjectInbound", func(vt *VirtualTUN) error { return vt.InjectInbound([]byte{9}) }},
		{"Write", func(vt *VirtualTUN) error {
			_, err := vt.Write([][]byte{bytes.Repeat([]byte{9}, 8)}, 0)
			return err
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vt, err := New(Config{InboundCapacity: 4, OutboundCapacity: 4})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			t.Cleanup(func() { _ = vt.Close() })

			// Gate: hold the lifecycle read lock so the submission
			// cannot pass its closed check plus enqueue while the gate
			// is closed.
			vt.closeMu.RLock()
			res := make(chan error, 1)
			go func() { res <- tt.submit(vt) }()

			// Run Close to completion while the gate is held: it must
			// block behind the gated submission.
			closeDone := make(chan struct{})
			go func() {
				_ = vt.Close()
				close(closeDone)
			}()
			select {
			case <-closeDone:
				vt.closeMu.RUnlock()
				t.Fatal("Close completed behind a gated submission")
			case <-time.After(100 * time.Millisecond):
			}

			// Release the gate. Whichever wins the lock, the invariant
			// must hold.
			vt.closeMu.RUnlock()

			select {
			case <-closeDone:
			case <-timeout(t):
				t.Fatal("Close deadlocked behind the gated submission")
			}
			var subErr error
			select {
			case subErr = <-res:
			case <-timeout(t):
				t.Fatal("submission never resolved")
			}

			s := vt.Stats()
			switch {
			case subErr == nil:
				// Accepted: must be covered by shutdown accounting.
				if s.DropsShutdown != 1 || s.DropsTotal != 1 {
					t.Errorf("accepted submission but drops = shutdown %d total %d, want 1/1 (unaccounted packet)", s.DropsShutdown, s.DropsTotal)
				}
			case errors.Is(subErr, ErrClosed):
				// Rejected: nothing enqueued, nothing counted.
				if s.DropsShutdown != 0 || s.DropsTotal != 0 {
					t.Errorf("rejected submission but drops = shutdown %d total %d, want 0/0", s.DropsShutdown, s.DropsTotal)
				}
			default:
				t.Fatalf("third outcome: %v", subErr)
			}
			if s.InboundDepth != 0 || s.OutboundDepth != 0 {
				t.Errorf("post-Close depths = (%d, %d), want (0, 0)", s.InboundDepth, s.OutboundDepth)
			}
		})
	}
}

// TestStats_AfterClose asserts the documented post-Close semantics exactly:
// both depths are zero, every queued packet is in the shutdown bucket (and
// only there), the snapshot is stable, and rejected post-close calls do not
// perturb it.
func TestStats_AfterClose(t *testing.T) {
	vt, err := New(Config{InboundCapacity: 4, OutboundCapacity: 4})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := vt.InjectInbound([]byte{byte(i)}); err != nil {
			t.Fatalf("InjectInbound #%d: %v", i, err)
		}
	}
	if _, err := vt.Write([][]byte{bytes.Repeat([]byte{7}, 4)}, 0); err != nil {
		t.Fatalf("Write: %v", err)
	}
	// Consume one inbound packet so exactly one inbound + one outbound
	// remain queued at close.
	if n, err := vt.Read([][]byte{make([]byte, 16)}, []int{0}, 0); err != nil || n != 1 {
		t.Fatalf("Read = (%d, %v), want (1, nil)", n, err)
	}

	if err := vt.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	post := vt.Stats()
	if post.InboundDepth != 0 || post.OutboundDepth != 0 {
		t.Errorf("post-Close depths = (%d, %d), want (0, 0)", post.InboundDepth, post.OutboundDepth)
	}
	if post.DropsShutdown != 2 {
		t.Errorf("DropsShutdown = %d, want 2 (1 inbound + 1 outbound drained)", post.DropsShutdown)
	}
	if post.DropsTotal != 2 || post.Sum() != 2 {
		t.Errorf("DropsTotal = %d, Sum = %d, want 2/2", post.DropsTotal, post.Sum())
	}
	if post.DropsQueueFull != 0 || post.DropsOversized != 0 {
		t.Errorf("other buckets = (qf %d, ov %d), want (0, 0)", post.DropsQueueFull, post.DropsOversized)
	}

	// The snapshot is stable after close: nothing can change it except
	// explicit external telemetry hooks.
	if post2 := vt.Stats(); post2 != post {
		t.Errorf("post-Close snapshot drifted: %+v vs %+v", post2, post)
	}

	// Rejected post-close calls must not perturb the accounting.
	if err := vt.InjectInbound([]byte{1}); !errors.Is(err, ErrClosed) {
		t.Errorf("InjectInbound after close = %v, want ErrClosed", err)
	}
	if _, err := vt.Write([][]byte{make([]byte, 4)}, 0); !errors.Is(err, ErrClosed) {
		t.Errorf("Write after close = %v, want ErrClosed", err)
	}
	if _, err := vt.Read([][]byte{make([]byte, 4)}, []int{0}, 0); !errors.Is(err, ErrClosed) {
		t.Errorf("Read after close = %v, want ErrClosed", err)
	}
	if _, err := vt.ReceiveOutbound(); !errors.Is(err, ErrClosed) {
		t.Errorf("ReceiveOutbound after close = %v, want ErrClosed", err)
	}
	if post3 := vt.Stats(); post3 != post {
		t.Errorf("post-Close snapshot perturbed by rejected calls: %+v vs %+v", post3, post)
	}
}
