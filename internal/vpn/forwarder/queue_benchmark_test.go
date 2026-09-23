package forwarder

import (
	"fmt"
	"testing"
)

// Benchmark the enqueue hot path at increasing route populations. Draining
// the compatibility channel keeps queue saturation out of the measurement.
func BenchmarkBackendToClientManyRoutes(b *testing.B) {
	for _, routes := range []int{1, 100, 1000} {
		b.Run(fmt.Sprintf("routes=%d", routes), func(b *testing.B) {
			f := NewForwarder(nil, "10.100.0.0/16", 32)
			ips := make([]string, routes)
			queues := make([]<-chan []byte, routes)
			for i := range routes {
				peer := fmt.Sprintf("peer-%d", i)
				ips[i] = fmt.Sprintf("10.100.%d.%d", i/254, i%254+1)
				f.RegisterSession("session", "connection", peer, ips[i], 1)
				queues[i], _ = f.GetClientPacketChannel(peer)
			}
			packet := make([]byte, 1420)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				n := i % routes
				if err := f.RouteBackendToClient(1, packet, ips[n]); err != nil {
					b.Fatal(err)
				}
				<-queues[n]
			}
		})
	}
}
