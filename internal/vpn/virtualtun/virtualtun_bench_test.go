package virtualtun

// Benchmarks for the VirtualTUN packet paths (issue #385 session 2). They
// mirror the intent of tunnel's BenchmarkVirtualTUNRead/Write (issue #93
// baseline): the per-packet channel hop and copy costs of the in-memory
// device, hermetic — no AWG engine, no network. Config mirrors tunnel's
// benchVirtualTUN (MTU 1340); VirtualTUN does not enforce MTU, so 1420B
// packets measure the same paths regardless.
//
// Run: go test -bench=. -benchmem -run=^$ ./internal/vpn/virtualtun/

import (
	"fmt"
	"testing"
)

// benchPacket builds a synthetic packet of the given size.
func benchPacket(size int) []byte {
	pkt := make([]byte, size)
	pkt[0] = 0x40
	return pkt
}

// BenchmarkInjectReadRoundTrip measures the device→engine path:
// InjectInbound (make+copy into the inbound queue) immediately followed by
// Read (channel hop + copy into the caller's buffer), one packet per
// iteration. Mirrors tunnel.BenchmarkVirtualTUNRead.
func BenchmarkInjectReadRoundTrip(b *testing.B) {
	for _, size := range []int{64, 512, 1420} {
		b.Run(fmt.Sprintf("packet_%dB", size), func(b *testing.B) {
			vt, err := New(Config{Name: "bench-vtun", MTU: 1340})
			if err != nil {
				b.Fatalf("New: %v", err)
			}
			b.Cleanup(func() { _ = vt.Close() })

			pkt := benchPacket(size)
			bufs := [][]byte{make([]byte, 2048)}
			sizes := []int{0}
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				if err := vt.InjectInbound(pkt); err != nil {
					b.Fatalf("InjectInbound: %v", err)
				}
				if n, err := vt.Read(bufs, sizes, 0); err != nil || n != 1 {
					b.Fatalf("Read = (%d, %v), want (1, nil)", n, err)
				}
			}
		})
	}
}

// BenchmarkWriteReceiveRoundTrip measures the engine→consumer path: Write
// (make+copy out of the caller's buffer into the outbound queue) immediately
// followed by ReceiveOutbound (channel hop, ownership transfer to the
// caller). Mirrors tunnel.BenchmarkVirtualTUNWrite.
func BenchmarkWriteReceiveRoundTrip(b *testing.B) {
	for _, size := range []int{64, 512, 1420} {
		b.Run(fmt.Sprintf("packet_%dB", size), func(b *testing.B) {
			vt, err := New(Config{Name: "bench-vtun", MTU: 1340})
			if err != nil {
				b.Fatalf("New: %v", err)
			}
			b.Cleanup(func() { _ = vt.Close() })

			buf := make([]byte, size+16) // offset 16 like a real tun consumer
			buf[16] = 0x40
			bufs := [][]byte{buf}
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				if _, err := vt.Write(bufs, 16); err != nil {
					b.Fatalf("Write: %v", err)
				}
				if _, err := vt.ReceiveOutbound(); err != nil {
					b.Fatalf("ReceiveOutbound: %v", err)
				}
			}
		})
	}
}

// BenchmarkReadBatched measures the batched drain path on a BatchSize=128
// device (the pinned engine's IdealBatchSize): one Read call per iteration
// returns up to 128 packets. The inbound queue is prefilled to capacity and a
// feeder goroutine keeps topping it up, so Read measures the drain, not queue
// starvation. ns/op is per batched Read call; MB/s assumes a full batch of
// 128 packets (the queue starts full; a partially drained batch is possible
// only if the feeder is descheduled mid-drain).
func BenchmarkReadBatched(b *testing.B) {
	for _, size := range []int{64, 512, 1420} {
		b.Run(fmt.Sprintf("batch128_packet_%dB", size), func(b *testing.B) {
			const batch = 128
			vt, err := New(Config{Name: "bench-vtun", MTU: 1340, BatchSize: batch})
			if err != nil {
				b.Fatalf("New: %v", err)
			}
			b.Cleanup(func() { _ = vt.Close() })

			// Prefill the queue so the first Reads never starve.
			pkt := benchPacket(size)
			for err := vt.InjectInbound(pkt); err == nil; err = vt.InjectInbound(pkt) {
			}

			// Keep the queue topped up for the whole run.
			stop := make(chan struct{})
			go func() {
				for {
					select {
					case <-stop:
						return
					default:
					}
					_ = vt.InjectInbound(pkt) // nonblocking; a full queue just idles the feeder
				}
			}()
			b.Cleanup(func() { close(stop) })

			bufs := make([][]byte, batch)
			for i := range bufs {
				bufs[i] = make([]byte, 2048)
			}
			sizes := make([]int, batch)
			b.SetBytes(int64(batch * size))
			b.ReportAllocs()
			for b.Loop() {
				n, err := vt.Read(bufs, sizes, 0)
				if err != nil {
					b.Fatalf("Read: %v", err)
				}
				if n == 0 {
					b.Fatal("Read returned 0 packets (feeder starved)")
				}
			}
		})
	}
}
