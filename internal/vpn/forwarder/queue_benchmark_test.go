package forwarder

import (
	"fmt"
	"testing"
)

type benchmarkClientDevice struct{ completed chan struct{} }

func (d *benchmarkClientDevice) Read([]byte) (int, error) { return 0, nil }
func (d *benchmarkClientDevice) Close() error             { return nil }
func (d *benchmarkClientDevice) Write(packet []byte) (int, error) {
	d.completed <- struct{}{}
	return len(packet), nil
}

// BenchmarkHealthyClientPacketDevice includes managed dequeue, write admission,
// PacketDevice.Write and write telemetry. It measures a synthetic healthy sink,
// not encryption or network capacity. The review target is 500 Mbps (62.5 MB/s).
func BenchmarkHealthyClientPacketDevice(b *testing.B) {
	const batch = 128
	f := NewForwarder(nil, "10.100.0.0/16", batch)
	dev := &benchmarkClientDevice{completed: make(chan struct{}, batch)}
	f.RegisterSession("session", "connection", "peer", "10.100.0.10", 1)
	f.AttachPeerDevice("peer", dev)
	f.StartPumps(b.Context())
	defer f.StopPumps()
	packet := make([]byte, 1420)
	b.SetBytes(int64(len(packet)))
	b.ReportAllocs()
	b.ResetTimer()
	for sent := 0; sent < b.N; {
		n := min(batch, b.N-sent)
		for range n {
			if err := f.RouteBackendToClient(1, packet, "10.100.0.10"); err != nil {
				b.Fatal(err)
			}
		}
		for range n {
			<-dev.completed
		}
		sent += n
	}
	b.StopTimer()
	mbps := float64(b.N) * float64(len(packet)) * 8 / b.Elapsed().Seconds() / 1e6
	b.ReportMetric(mbps, "Mbps")
	if full, noRoute, total := f.DropStats(); full != 0 || noRoute != 0 || total != 0 {
		b.Fatal("healthy traffic dropped packets")
	}
}

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
