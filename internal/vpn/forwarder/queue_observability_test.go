package forwarder

import (
	"errors"
	"testing"
	"time"
)

func TestRouteQueueStatsExposeOccupancyHighWaterAndDrops(t *testing.T) {
	f := NewForwarder(nil, "10.100.0.0/16", 2)
	f.RegisterSession("session-1", "connection-1", "peer-1", "10.100.0.10", 1)

	if err := f.RouteBackendToClient(1, []byte("one"), "10.100.0.10"); err != nil {
		t.Fatalf("first route: %v", err)
	}
	if err := f.RouteBackendToClient(1, []byte("two"), "10.100.0.10"); err != nil {
		t.Fatalf("second route: %v", err)
	}
	if err := f.RouteBackendToClient(1, []byte("three"), "10.100.0.10"); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("third route error = %v, want ErrQueueFull", err)
	}

	stats, ok := f.RouteQueueStats("peer-1")
	if !ok {
		t.Fatal("RouteQueueStats did not find registered peer")
	}
	if stats.Occupancy != 2 || stats.Capacity != 2 || stats.HighWater != 2 || stats.QueueFullDrops != 1 {
		t.Fatalf("unexpected queue stats: %+v", stats)
	}

	all := f.AllRouteQueueStats()
	if all["peer-1"] != stats {
		t.Fatalf("AllRouteQueueStats mismatch: %+v", all)
	}
}

func TestForwarderQueueCapacityIsBounded(t *testing.T) {
	f := NewForwarder(nil, "10.100.0.0/16", MaxClientQueuePackets+1)
	f.RegisterSession("session-1", "connection-1", "peer-1", "10.100.0.10", 1)

	ch, ok := f.GetClientPacketChannel("peer-1")
	if !ok {
		t.Fatal("client queue missing")
	}
	if cap(ch) != MaxClientQueuePackets {
		t.Fatalf("queue capacity = %d, want bounded %d", cap(ch), MaxClientQueuePackets)
	}
}

func TestForwarderQueueHighWaterTracksPeakBeforeConcurrentDrain(t *testing.T) {
	f := NewForwarder(nil, "10.100.0.0/16", 1)
	f.RegisterSession("session-1", "connection-1", "peer-1", "10.100.0.10", 1)

	if err := f.RouteBackendToClient(1, []byte("packet"), "10.100.0.10"); err != nil {
		t.Fatalf("route packet: %v", err)
	}

	stats, ok := f.RouteQueueStats("peer-1")
	if !ok {
		t.Fatal("RouteQueueStats did not find registered peer")
	}
	if stats.HighWater != 1 {
		t.Fatalf("high-water = %d, want 1", stats.HighWater)
	}
}

func TestForwarderRouteReplacementReconcilesQueueOccupancy(t *testing.T) {
	f := NewForwarder(nil, "10.100.0.0/16", 2)
	f.RegisterSession("session-1", "connection-1", "peer-1", "10.100.0.10", 1)
	if err := f.RouteBackendToClient(1, []byte("one"), "10.100.0.10"); err != nil {
		t.Fatalf("route packet: %v", err)
	}
	occupancy, _, _ := f.AggregateQueueStats()
	if occupancy != 1 {
		t.Fatalf("initial aggregate occupancy = %d, want 1", occupancy)
	}

	f.RegisterSession("session-2", "connection-2", "peer-1", "10.100.0.10", 1)
	occupancy, _, _ = f.AggregateQueueStats()
	if occupancy != 0 {
		t.Fatalf("replacement aggregate occupancy = %d, want 0", occupancy)
	}
	stats, ok := f.RouteQueueStats("peer-1")
	if !ok {
		t.Fatal("replacement route missing")
	}
	if stats.Occupancy != 0 || stats.HighWater != 0 {
		t.Fatalf("replacement route stats = %+v, want empty queue", stats)
	}
}

func TestForwarderRouteReplacementRemovesStaleAssignedIP(t *testing.T) {
	f := NewForwarder(nil, "10.100.0.0/16", 2)
	f.RegisterSession("session-1", "connection-1", "peer-1", "10.100.0.10", 1)
	f.RegisterSession("session-2", "connection-2", "peer-1", "10.100.0.11", 1)

	if err := f.RouteBackendToClient(1, []byte("stale"), "10.100.0.10"); !errors.Is(err, ErrSessionNotRegistered) {
		t.Fatalf("stale IP route error = %v, want ErrSessionNotRegistered", err)
	}
	if err := f.RouteBackendToClient(1, []byte("current"), "10.100.0.11"); err != nil {
		t.Fatalf("current IP route: %v", err)
	}
}

func TestForwarderDirectChannelDrainIsReconciledBeforeNextEnqueue(t *testing.T) {
	f := NewForwarder(nil, "10.100.0.0/16", 2)
	f.RegisterSession("session-1", "connection-1", "peer-1", "10.100.0.10", 1)
	if err := f.RouteBackendToClient(1, []byte("one"), "10.100.0.10"); err != nil {
		t.Fatalf("first route: %v", err)
	}
	queue, ok := f.GetClientPacketChannel("peer-1")
	if !ok {
		t.Fatal("GetClientPacketChannel did not find registered peer")
	}
	<-queue
	if err := f.RouteBackendToClient(1, []byte("two"), "10.100.0.10"); err != nil {
		t.Fatalf("second route: %v", err)
	}
	stats, ok := f.RouteQueueStats("peer-1")
	if !ok {
		t.Fatal("RouteQueueStats did not find registered peer")
	}
	if stats.Occupancy != 1 || stats.HighWater != 1 {
		t.Fatalf("direct drain was not reconciled: %+v", stats)
	}
}

func TestForwarderQueueSizeCanBeReconfiguredBeforeRoutes(t *testing.T) {
	f := NewForwarder(nil, "10.100.0.0/16", 2)
	if err := f.ReconfigureClientQueueSize(4); err != nil {
		t.Fatalf("reconfigure queue size: %v", err)
	}
	f.RegisterSession("session-1", "connection-1", "peer-1", "10.100.0.10", 1)
	ch, ok := f.GetClientPacketChannel("peer-1")
	if !ok {
		t.Fatal("client queue missing")
	}
	if cap(ch) != 4 {
		t.Fatalf("queue capacity = %d, want 4", cap(ch))
	}
}

func TestForwarderQueueSizeRejectsReconfigurationWithActiveRoutes(t *testing.T) {
	f := NewForwarder(nil, "10.100.0.0/16", 2)
	f.RegisterSession("session-1", "connection-1", "peer-1", "10.100.0.10", 1)
	if err := f.ReconfigureClientQueueSize(4); err == nil {
		t.Fatal("reconfigure with active route unexpectedly succeeded")
	}
}

func TestForwarderDeviceWriteStatsRecordErrorsAndDuration(t *testing.T) {
	f := NewForwarder(nil, "10.100.0.0/16", 4)
	dev := &errDevice{err: errors.New("device stalled")}
	f.AttachPeerDevice("peer-1", dev)
	f.RegisterSession("session-1", "connection-1", "peer-1", "10.100.0.10", 1)
	f.StartPumps(t.Context())
	defer f.StopPumps()

	if err := f.RouteBackendToClient(1, []byte("packet"), "10.100.0.10"); err != nil {
		t.Fatalf("route packet: %v", err)
	}
	deadline := time.Now().Add(time.Second)
	for dev.writeCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if dev.writeCount() == 0 {
		t.Fatal("client pump did not attempt device write")
	}

	errorsCount, total, max := f.DeviceWriteStats()
	if errorsCount != 1 {
		t.Fatalf("device write errors = %d, want 1", errorsCount)
	}
	if total <= 0 || max <= 0 {
		t.Fatalf("device write duration not recorded: total=%s max=%s", total, max)
	}
	deadline = time.Now().Add(time.Second)
	for {
		occupancy, _, _ := f.AggregateQueueStats()
		if occupancy == 0 || time.Now().After(deadline) {
			if occupancy != 0 {
				t.Fatalf("aggregate queue occupancy = %d after pump drain, want 0", occupancy)
			}
			break
		}
		time.Sleep(time.Millisecond)
	}
}
