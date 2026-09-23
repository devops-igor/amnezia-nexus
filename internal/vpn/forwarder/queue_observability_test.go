package forwarder

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type blockingWriteDevice struct {
	mu       sync.Mutex
	started  int
	released chan struct{}
	startedC chan struct{}
}

func newBlockingWriteDevice() *blockingWriteDevice {
	return &blockingWriteDevice{
		released: make(chan struct{}),
		startedC: make(chan struct{}, 16),
	}
}

func (d *blockingWriteDevice) Read(p []byte) (int, error) { return 0, nil }
func (d *blockingWriteDevice) Close() error               { return nil }
func (d *blockingWriteDevice) Write(p []byte) (int, error) {
	d.mu.Lock()
	d.started++
	d.mu.Unlock()
	select {
	case d.startedC <- struct{}{}:
	default:
	}
	<-d.released
	return len(p), nil
}
func (d *blockingWriteDevice) release() {
	select {
	case <-d.released:
	default:
		close(d.released)
	}
}
func (d *blockingWriteDevice) writeCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.started
}

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
	errorsCount, total, max := f.DeviceWriteStats()
	for errorsCount == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
		errorsCount, total, max = f.DeviceWriteStats()
	}
	if dev.writeCount() == 0 {
		t.Fatal("client pump did not attempt device write")
	}

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

func TestForwarderConcurrentProducerConsumerAccounting(t *testing.T) {
	f := NewForwarder(nil, "10.100.0.0/16", 16)
	f.RegisterSession("session-1", "connection-1", "peer-1", "10.100.0.10", 1)
	queue, ok := f.GetClientPacketChannel("peer-1")
	if !ok {
		t.Fatal("client queue missing")
	}

	const producers = 8
	const packetsPerProducer = 200
	var accepted, dropped atomic.Int64
	var wg sync.WaitGroup
	wg.Add(producers)
	for i := 0; i < producers; i++ {
		go func() {
			defer wg.Done()
			for n := 0; n < packetsPerProducer; n++ {
				if err := f.RouteBackendToClient(1, []byte("packet"), "10.100.0.10"); err == nil {
					accepted.Add(1)
				} else if errors.Is(err, ErrQueueFull) {
					dropped.Add(1)
				} else {
					t.Errorf("unexpected producer error: %v", err)
				}
			}
		}()
	}
	for {
		select {
		case <-queue:
		default:
			if accepted.Load()+dropped.Load() == producers*packetsPerProducer {
				wg.Wait()
				for len(queue) > 0 {
					<-queue
				}
				goto drained
			}
			time.Sleep(time.Microsecond)
		}
	}

drained:
	if accepted.Load()+dropped.Load() != producers*packetsPerProducer {
		t.Fatalf("producer accounting accepted=%d dropped=%d", accepted.Load(), dropped.Load())
	}
	occupancy, _, highWater := f.AggregateQueueStats()
	if occupancy != len(queue) {
		t.Fatalf("aggregate occupancy=%d, channel length=%d", occupancy, len(queue))
	}
	if highWater > cap(queue) || highWater == 0 {
		t.Fatalf("aggregate high-water=%d, capacity=%d", highWater, cap(queue))
	}
}

func TestForwarderAggregateHighWaterTracksSimultaneousOccupancy(t *testing.T) {
	f := NewForwarder(nil, "10.100.0.0/16", 2)
	f.RegisterSession("session-1", "connection-1", "peer-1", "10.100.0.10", 1)
	f.RegisterSession("session-2", "connection-2", "peer-2", "10.100.0.11", 1)
	for _, ip := range []string{"10.100.0.10", "10.100.0.10", "10.100.0.11", "10.100.0.11"} {
		if err := f.RouteBackendToClient(1, []byte("packet"), ip); err != nil {
			t.Fatalf("enqueue %s: %v", ip, err)
		}
	}
	q1, _ := f.GetClientPacketChannel("peer-1")
	q2, _ := f.GetClientPacketChannel("peer-2")
	for len(q1) > 0 {
		<-q1
	}
	for len(q2) > 0 {
		<-q2
	}
	_, _, highWater := f.AggregateQueueStats()
	if highWater != 4 {
		t.Fatalf("aggregate high-water=%d, want simultaneous occupancy 4", highWater)
	}
}

func TestForwarderQueueSaturationRecoveryAndMetrics(t *testing.T) {
	f := NewForwarder(nil, "10.100.0.0/16", 2)
	f.RegisterSession("session-1", "connection-1", "peer-1", "10.100.0.10", 1)
	for i := 0; i < 2; i++ {
		if err := f.RouteBackendToClient(1, []byte("packet"), "10.100.0.10"); err != nil {
			t.Fatalf("saturation enqueue %d: %v", i, err)
		}
	}
	if err := f.RouteBackendToClient(1, []byte("drop"), "10.100.0.10"); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("saturation error=%v, want ErrQueueFull", err)
	}
	q, _ := f.GetClientPacketChannel("peer-1")
	<-q
	if err := f.RouteBackendToClient(1, []byte("recovered"), "10.100.0.10"); err != nil {
		t.Fatalf("enqueue after recovery: %v", err)
	}
	stats, _ := f.RouteQueueStats("peer-1")
	if stats.Occupancy != 2 || stats.HighWater != 2 || stats.QueueFullDrops != 1 {
		t.Fatalf("recovery metrics=%+v", stats)
	}
	occupancy, capacity, highWater := f.AggregateQueueStats()
	if occupancy != 2 || capacity != 2 || highWater != 2 {
		t.Fatalf("aggregate metrics occupancy=%d capacity=%d high-water=%d", occupancy, capacity, highWater)
	}
}

func TestForwarderQueueCapacityUsesAggregateMemoryBudget(t *testing.T) {
	want := MaxClientQueueMemoryBytes / (MaxSupportedActiveRoutes * MaxClientQueuePacketBytes)
	if MaxClientQueuePackets != want {
		t.Fatalf("MaxClientQueuePackets=%d, want budget-derived %d", MaxClientQueuePackets, want)
	}
	if MaxClientQueuePackets <= 0 {
		t.Fatal("budget-derived queue capacity must be positive")
	}
}

func TestForwarderRejectsOversizedBackendPacketWithoutQueueing(t *testing.T) {
	f := NewForwarder(nil, "10.100.0.0/16", 2)
	f.RegisterSession("session-1", "connection-1", "peer-1", "10.100.0.10", 1)
	queue, ok := f.GetClientPacketChannel("peer-1")
	if !ok {
		t.Fatal("client queue missing")
	}

	packet := make([]byte, MaxClientQueuePacketBytes+1)
	packet[0] = 0x5a
	if err := f.RouteBackendToClient(1, packet, "10.100.0.10"); !errors.Is(err, ErrPacketTooLarge) {
		t.Fatalf("oversized packet error=%v, want ErrPacketTooLarge", err)
	}
	if len(queue) != 0 {
		t.Fatalf("oversized packet was queued: len=%d", len(queue))
	}
	if full, noRoute, total := f.DropStats(); full != 0 || noRoute != 0 || total != 1 || f.DropsPacketTooLarge() != 1 {
		t.Fatalf("oversized drop metrics: full=%d no-route=%d total=%d oversized=%d", full, noRoute, total, f.DropsPacketTooLarge())
	}
	if _, tx, _ := f.GetStats(); tx != 0 {
		t.Fatalf("oversized packet changed tx stats: %d", tx)
	}
}

func TestForwarderRejectsRegistrationsBeyondActiveRouteLimit(t *testing.T) {
	f := NewForwarder(nil, "10.100.0.0/16", 1)
	for i := 0; i < MaxSupportedActiveRoutes; i++ {
		f.RegisterSession("session", "connection", fmt.Sprintf("peer-%d", i), fmt.Sprintf("10.101.%d.%d", i/254, i%254+1), 1)
	}

	peer := fmt.Sprintf("peer-%d", MaxSupportedActiveRoutes)
	ip := "10.200.0.1"
	f.RegisterSession("rejected-session", "rejected-connection", peer, ip, 1)
	if _, ok := f.GetClientPacketChannel(peer); ok {
		t.Fatal("registration beyond MaxSupportedActiveRoutes created a route")
	}
	if _, _, active := f.GetStats(); active != MaxSupportedActiveRoutes {
		t.Fatalf("active routes=%d, want %d", active, MaxSupportedActiveRoutes)
	}

	f.RegisterSession("replacement", "replacement-connection", "peer-0", "10.200.0.2", 1)
	if _, ok := f.GetClientPacketChannel("peer-0"); !ok {
		t.Fatal("existing route replacement was incorrectly rejected")
	}
	f.UnregisterSession("peer-1")
	f.RegisterSession("accepted-after-unregister", "connection", peer, ip, 1)
	if _, ok := f.GetClientPacketChannel(peer); !ok {
		t.Fatal("route was not accepted after an active route was unregistered")
	}
}

func TestForwarderSustainedDownstreamStallSaturatesAndRecovers(t *testing.T) {
	f := NewForwarder(nil, "10.100.0.0/16", 4)
	dev := newBlockingWriteDevice()
	f.AttachPeerDevice("peer-1", dev)
	f.RegisterSession("session-1", "connection-1", "peer-1", "10.100.0.10", 1)
	f.StartPumps(t.Context())
	defer f.StopPumps()
	defer dev.release()

	pkt := []byte("packet")
	if err := f.RouteBackendToClient(1, pkt, "10.100.0.10"); err != nil {
		t.Fatalf("first enqueue: %v", err)
	}
	select {
	case <-dev.startedC:
	case <-time.After(time.Second):
		t.Fatal("client device write did not start")
	}

	// The in-flight write has already left the queue. All four buffered slots
	// remain available while the device is stalled.
	for i := 0; i < 4; i++ {
		if err := f.RouteBackendToClient(1, pkt, "10.100.0.10"); err != nil {
			t.Fatalf("queued packet %d: %v", i, err)
		}
	}
	if err := f.RouteBackendToClient(1, pkt, "10.100.0.10"); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("stalled queue error=%v, want ErrQueueFull", err)
	}

	stats, ok := f.RouteQueueStats("peer-1")
	if !ok {
		t.Fatal("route stats missing")
	}
	if stats.Occupancy != 4 || stats.HighWater != 4 || stats.QueueFullDrops != 1 {
		t.Fatalf("stalled queue stats=%+v, want occupancy/high-water=4 and one drop", stats)
	}

	dev.release()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		occupancy, _, _ := f.AggregateQueueStats()
		if occupancy == 0 && dev.writeCount() >= 5 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	occupancy, _, highWater := f.AggregateQueueStats()
	if occupancy != 0 {
		t.Fatalf("queue did not recover: occupancy=%d", occupancy)
	}
	if highWater != 4 {
		t.Fatalf("high-water changed during recovery: %d", highWater)
	}
	if dev.writeCount() != 5 {
		t.Fatalf("device writes=%d, want 5 accepted packets", dev.writeCount())
	}
}

func TestForwarderConfiguredRouteLimitDerivesQueueBudget(t *testing.T) {
	const routes = 100
	want := MaxClientQueuePacketsForRoutes(routes)
	f := NewForwarderWithLimits(nil, "10.100.0.0/16", want+1, routes)
	f.RegisterSession("session-1", "connection-1", "peer-1", "10.100.0.10", 1)
	queue, ok := f.GetClientPacketChannel("peer-1")
	if !ok {
		t.Fatal("client queue missing")
	}
	if cap(queue) != want {
		t.Fatalf("queue capacity=%d, want budget-derived %d for %d routes", cap(queue), want, routes)
	}
	for i := 0; i < routes-1; i++ {
		f.RegisterSession(fmt.Sprintf("session-%d", i+2), "connection", fmt.Sprintf("peer-%d", i+2), fmt.Sprintf("10.102.%d.%d", i/254, i%254+1), 1)
	}
	f.RegisterSession("excess", "connection", fmt.Sprintf("peer-%d", routes+1), "10.200.0.1", 1)
	if _, ok := f.GetClientPacketChannel(fmt.Sprintf("peer-%d", routes+1)); ok {
		t.Fatal("route beyond configured maximum unexpectedly registered")
	}
}

func TestRouteRetirementDoesNotBlockOtherRoutesOnDeviceWrite(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(fmt.Sprintf("replace=%t", replace), func(t *testing.T) {
			f := NewForwarder(nil, "10.100.0.0/16", 2)
			dev := newBlockingWriteDevice()
			f.AttachPeerDevice("peer", dev)
			f.RegisterSession("session", "connection", "peer", "10.100.0.10", 1)
			f.StartPumps(t.Context())
			defer f.StopPumps()
			defer dev.release()
			if err := f.RouteBackendToClient(1, []byte("packet"), "10.100.0.10"); err != nil {
				t.Fatal(err)
			}
			select {
			case <-dev.startedC:
			case <-time.After(time.Second):
				t.Fatal("write did not start")
			}
			retired := make(chan struct{})
			go func() {
				if replace {
					f.RegisterSession("replacement", "connection", "peer", "10.100.0.11", 1)
				} else {
					f.UnregisterSession("peer")
				}
				f.RegisterSession("other", "connection", "other", "10.100.0.12", 1)
				close(retired)
			}()
			select {
			case <-retired:
			case <-time.After(time.Second):
				t.Fatal("stalled write blocked route retirement or unrelated registration")
			}
			if _, ok := f.RouteQueueStats("other"); !ok {
				t.Fatal("unrelated route missing")
			}
		})
	}
}

type pacedQueueDevice struct {
	permits chan struct{}
	started chan struct{}
	written chan struct{}
}

func (d *pacedQueueDevice) Read([]byte) (int, error) { return 0, nil }
func (d *pacedQueueDevice) Close() error             { return nil }
func (d *pacedQueueDevice) Write(packet []byte) (int, error) {
	d.started <- struct{}{}
	<-d.permits
	time.Sleep(100 * time.Microsecond)
	d.written <- struct{}{}
	return len(packet), nil
}

func TestSustainedClientTrafficWithRepeatedStalls(t *testing.T) {
	const capacity = 32
	f := NewForwarder(nil, "10.100.0.0/16", capacity)
	dev := &pacedQueueDevice{
		permits: make(chan struct{}, capacity+1),
		started: make(chan struct{}, capacity+1),
		written: make(chan struct{}, capacity+1),
	}
	f.AttachPeerDevice("peer", dev)
	f.RegisterSession("session", "connection", "peer", "10.100.0.10", 1)
	f.StartPumps(t.Context())
	defer f.StopPumps()
	defer close(dev.permits)
	packet := make([]byte, 1420)
	wait := func(ch <-chan struct{}, count int) {
		t.Helper()
		timeout := time.NewTimer(3 * time.Second)
		defer timeout.Stop()
		for i := 0; i < count; i++ {
			select {
			case <-ch:
			case <-timeout.C:
				t.Fatalf("device stalled after %d/%d events", i, count)
			}
		}
	}
	enqueue := func() {
		t.Helper()
		if err := f.RouteBackendToClient(1, packet, "10.100.0.10"); err != nil {
			t.Fatalf("unexpected overflow during healthy traffic: %v", err)
		}
	}
	release := func(count int) {
		for i := 0; i < count; i++ {
			dev.permits <- struct{}{}
		}
		wait(dev.written, count)
	}
	var accepted, drops int64
	for cycle := 0; cycle < 3; cycle++ {
		// Sustained healthy bursts before each stall and after recovery. The
		// consumer adds latency to every MTU-sized packet; pacing stays below
		// its service rate so any queue overflow here is unexplained loss.
		for burst := 0; burst < 20; burst++ {
			for i := 0; i < capacity/2; i++ {
				enqueue()
				accepted++
			}
			release(capacity / 2)
			wait(dev.started, capacity/2)
		}
		enqueue()
		accepted++
		wait(dev.started, 1)
		for i := 0; i < capacity; i++ {
			enqueue()
			accepted++
		}
		for i := 0; i < capacity; i++ {
			if err := f.RouteBackendToClient(1, packet, "10.100.0.10"); !errors.Is(err, ErrQueueFull) {
				t.Fatalf("stalled queue returned %v", err)
			}
			drops++
		}
		stats, _ := f.RouteQueueStats("peer")
		if stats.Occupancy != capacity || stats.HighWater != capacity || stats.QueueFullDrops != uint64(drops) {
			t.Fatalf("stall metrics: %+v, drops=%d", stats, drops)
		}
		release(capacity + 1)
		wait(dev.started, capacity)
		if occupancy, _, peak := f.AggregateQueueStats(); occupancy != 0 || peak != capacity {
			t.Fatalf("recovery occupancy=%d peak=%d", occupancy, peak)
		}
	}
	f.StopPumps() // all write metrics must be published before inspecting them
	if _, tx, _ := f.GetStats(); tx != accepted*int64(len(packet)) {
		t.Fatalf("accepted byte accounting=%d, want %d", tx, accepted*int64(len(packet)))
	}
	if full, noRoute, total := f.DropStats(); full != uint64(drops) || noRoute != 0 || total != uint64(drops) {
		t.Fatalf("drop accounting: full=%d no-route=%d total=%d, want %d queue drops", full, noRoute, total, drops)
	}
	if errors, total, max := f.DeviceWriteStats(); errors != 0 || total <= 0 || max <= 0 {
		t.Fatalf("write metrics: errors=%d total=%s max=%s", errors, total, max)
	}
}
