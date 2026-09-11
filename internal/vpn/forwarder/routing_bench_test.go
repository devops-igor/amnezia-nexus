package forwarder

// Issue #93: hermetic packet-path benchmarks — BASELINE ONLY, no
// optimization. These measure the per-packet allocation cost of the real
// routing path in both directions (RouteClientToBackend /
// RouteBackendToClient, each makes one pktCopy per packet) with synthetic
// packets and sessions, no network and no real tunnels.
//
// Run: go test -bench=. -benchmem -run=^$ ./internal/vpn/forwarder/
//
// The forwarder's queue channels are drained in the benchmark loop so the
// non-blocking sends never hit ErrQueueFull; we do NOT start pumps so the
// measurement isolates the routing/copy path itself. The per-peer token
// buckets are left nil (unlimited) — rate limiting is measured separately
// by BenchmarkTokenBucketAllow.

import (
	"fmt"
	"net"
	"testing"
)

// benchPeerKey / benchAssignedIP build deterministic per-iteration identities.
func benchPeerKey(i int) string    { return fmt.Sprintf("bench-peer-%d", i) }
func benchAssignedIP(i int) string { return fmt.Sprintf("10.9.0.%d", 2+i%254) }
func benchSessionID(i, gen int) string {
	return fmt.Sprintf("bench-sess-%d-%d", i, gen)
}

// newBenchForwarder registers nPeers synthetic sessions (no pumps, unlimited
// rate) toward backendID. Run func (`b.Run` body, executed once) is invoked
// with the ready forwarder.
func setupBenchForwarder(b *testing.B, nPeers int, backendID int64) *Forwarder {
	b.Helper()
	f := NewForwarder(nil, "10.9.0.0/24")
	for i := 0; i < nPeers; i++ {
		f.RegisterSession(
			benchSessionID(i, 0),
			fmt.Sprintf("conn-%d", i),
			benchPeerKey(i),
			benchAssignedIP(i),
			backendID,
		)
	}
	return f
}

// syntheticPacket builds a valid-looking IPv4 packet of the given size so
// RouteClientToBackend parses its inner source IP without error paths.
func syntheticPacket(size int, srcIP string) []byte {
	pkt := make([]byte, size)
	if size >= 20 {
		pkt[0] = 0x40 // IPv4
		ip := net.ParseIP(srcIP)
		if ip4 := ip.To4(); ip4 != nil {
			copy(pkt[12:16], ip4)
		}
	}
	return pkt
}

// drainChannelNonBlocking empties ch to keep sends non-blocking; a queue
// that stays near-empty measures routing cost, not backpressure.
func drainChannel(ch <-chan []byte) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

func BenchmarkRouteClientToBackend(b *testing.B) {
	const backendID = 1
	const peerIndex = 0 // single peer: fixed route lookup cost
	sizes := []int{64, 512, 1420}
	for _, size := range sizes {
		b.Run(fmt.Sprintf("packet_%dB", size), func(b *testing.B) {
			f := setupBenchForwarder(b, 1, backendID)
			pkt := syntheticPacket(size, benchAssignedIP(peerIndex))
			ch := f.backendQueues[backendID]
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := f.RouteClientToBackend(benchPeerKey(peerIndex), pkt); err != nil {
					b.Fatalf("RouteClientToBackend: %v", err)
				}
				drainChannel(ch) // keep queue non-full without extra goroutine
			}
		})
	}
}

func BenchmarkRouteBackendToClient(b *testing.B) {
	const backendID = 1
	const peerIndex = 0
	sizes := []int{64, 512, 1420}
	for _, size := range sizes {
		b.Run(fmt.Sprintf("packet_%dB", size), func(b *testing.B) {
			f := setupBenchForwarder(b, 1, backendID)
			pkt := syntheticPacket(size, "203.0.113.7")
			peerKey := benchPeerKey(peerIndex)
			ch, ok := f.GetClientPacketChannel(peerKey)
			if !ok {
				b.Fatal("client channel missing")
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := f.RouteBackendToClient(backendID, pkt, benchAssignedIP(peerIndex)); err != nil {
					b.Fatalf("RouteBackendToClient: %v", err)
				}
				drainChannel(ch)
			}
		})
	}
}

// BenchmarkTokenBucketAllow measures the cost of the per-packet rate-limit
// check itself (mutex + time math) — the other fixed per-packet cost on the
// throttled path. The rate is high enough that the benchmark's sustained
// consumption stays within refill.
func BenchmarkTokenBucketAllow(b *testing.B) {
	// 64 GiB/s sustained: drains ~14 GB per second of benchmark window at
	// ~50 ns/op ≈ 28 GB/s of consumption — comfortably inside refill, so no
	// rejection fires and the measurement isolates the mutex+time cost.
	tb := NewTokenBucket(64<<30, 64<<30)
	pkt := make([]byte, 1420)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !tb.Allow(int64(len(pkt))) {
			b.Fatal("unexpected rate-limit rejection in benchmark")
		}
	}
}
