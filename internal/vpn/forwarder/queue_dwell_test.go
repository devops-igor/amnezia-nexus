package forwarder

import (
	"fmt"
	"testing"
	"testing/synctest"
	"time"
)

func enqueueDwellPackets(t *testing.T, f *Forwarder, n int) {
	t.Helper()
	for range n {
		if err := f.RouteBackendToClient(1, returnPacketFor("192.0.2.1"), "192.0.2.1"); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
	}
}

func drainDwellQueue(f *Forwarder, peer string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.drainRouteQueueLocked(f.routesByPeer[peer])
}

func TestManagedQueueDwellPeriodicBursts(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := NewForwarder(nil, "", 1000)
		f.RegisterSession("session", "connection", "peer", "192.0.2.1", 1)
		f.QueuePressure()
		for i := 1; i <= 4; i++ {
			time.Sleep(10*time.Second - 25*time.Millisecond)
			enqueueDwellPackets(t, f, 810)
			got := f.QueuePressure()
			if got.ConsecutiveAbove80Sec != 0 {
				t.Fatalf("burst %d falsely reports sustained pressure: %ds", i, got.ConsecutiveAbove80Sec)
			}
			time.Sleep(25 * time.Millisecond)
			drainDwellQueue(f, "peer")
		}
		got := f.QueuePressure()
		if got.SecondsAbove80Pct != 0 || got.ConsecutiveAbove80Sec != 0 {
			t.Fatalf("four 25ms bursts became sustained pressure: %+v", got)
		}
	})
}

func TestManagedQueueDwellImmediateRecoveryAndTotals(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := NewForwarder(nil, "", 1000)
		f.RegisterSession("session", "connection", "peer", "192.0.2.1", 1)
		enqueueDwellPackets(t, f, 900)
		f.QueuePressure()
		time.Sleep(40 * time.Second)
		if got := f.QueuePressure(); got.ConsecutiveAbove80Sec != 40 {
			t.Fatalf("real sustained pressure missing: %+v", got)
		}
		time.Sleep(10 * time.Millisecond)
		drainDwellQueue(f, "peer")
		got := f.QueuePressure()
		if got.Occupancy != 0 || got.ConsecutiveAbove80Sec != 0 || got.ConsecutiveAbove50Sec != 0 {
			t.Fatalf("recovery must bypass rate throttle: %+v", got)
		}
		if got.SecondsAbove80Pct != 40 || got.SecondsAbove50Pct != 40 {
			t.Fatalf("measured dwell must survive the drain: %+v", got)
		}
	})
}

func TestManagedQueueDwellCapacityChanges(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := NewForwarder(nil, "", 1000)
		f.RegisterSession("session", "connection", "peer", "192.0.2.1", 1)
		enqueueDwellPackets(t, f, 810)
		f.QueuePressure()
		time.Sleep(30 * time.Second)
		if got := f.QueuePressure(); got.ConsecutiveAbove80Sec != 30 {
			t.Fatalf("sustained occupancy not measured: %+v", got)
		}
		f.RegisterSession("other-session", "other-connection", "other", "192.0.2.2", 1)
		got := f.QueuePressure()
		if got.Capacity != 2000 || got.ConsecutiveAbove80Sec != 0 || got.ConsecutiveAbove50Sec != 0 {
			t.Fatalf("added empty capacity must end saturation immediately: %+v", got)
		}
		f.UnregisterSession("other")
		time.Sleep(3 * time.Second)
		if got := f.QueuePressure(); got.ConsecutiveAbove80Sec != 3 {
			t.Fatalf("removed capacity must start a new run: %+v", got)
		}
		f.UnregisterSession("peer")
		got = f.QueuePressure()
		if got.Capacity != 0 || got.Occupancy != 0 || got.ConsecutiveAbove80Sec != 0 {
			t.Fatalf("last-route removal must clear pressure: %+v", got)
		}
	})
}

func TestManagedQueueDwellPumpRecovery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := NewForwarder(nil, "", 1000)
		f.RegisterSession("session", "connection", "peer", "192.0.2.1", 1)
		enqueueDwellPackets(t, f, 810)
		f.QueuePressure()
		time.Sleep(40 * time.Second)
		f.QueuePressure()
		f.StartPumps(t.Context())
		defer f.StopPumps()
		synctest.Wait()
		got := f.QueuePressure()
		if got.Occupancy != 0 || got.ConsecutiveAbove80Sec != 0 {
			t.Fatalf("managed pump drain must immediately clear pressure: %+v", got)
		}
	})
}

func TestInspectRoutesExactPressureThreshold(t *testing.T) {
	for _, tc := range []struct {
		capacity, occupancy int
		pressure            bool
	}{
		{1, 0, false}, {1, 1, true}, {2, 1, false}, {5, 3, false}, {5, 4, true},
		{10, 7, false}, {10, 8, true}, {2048, 1638, false}, {2048, 1639, true},
	} {
		t.Run(fmt.Sprintf("%d_of_%d", tc.occupancy, tc.capacity), func(t *testing.T) {
			f := NewForwarder(nil, "", tc.capacity)
			f.RegisterSession("session", "connection", "peer", "192.0.2.1", 1)
			enqueueDwellPackets(t, f, tc.occupancy)
			routes := f.InspectRoutes()
			if len(routes) != 1 || routes[0].HasPressure != tc.pressure {
				t.Fatalf("pressure for %d/%d: %+v; want %v", tc.occupancy, tc.capacity, routes, tc.pressure)
			}
			if got := len(ProblemRoutesFromSnapshot(routes, 50)); (got > 0) != tc.pressure {
				t.Fatalf("problem routes=%d; want pressure=%v", got, tc.pressure)
			}
		})
	}
}

func TestManagedQueueDwellLegacyDrainBeforeEnqueue(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := NewForwarder(nil, "", 1000)
		f.RegisterSession("session", "connection", "peer", "192.0.2.1", 1)
		enqueueDwellPackets(t, f, 900)
		f.QueuePressure()
		time.Sleep(10 * time.Second)
		channel, ok := f.GetClientPacketChannel("peer")
		if !ok {
			t.Fatal("client queue missing")
		}
		for range 900 {
			<-channel
		}
		enqueueDwellPackets(t, f, 1)
		got := f.QueuePressure()
		if got.ConsecutiveAbove80Sec != 0 || got.SecondsAbove80Pct != 0 || got.Occupancy != 1 {
			t.Fatalf("unknown legacy drain time must not invent exact dwell: %+v", got)
		}
	})
}

func TestManagedQueueDwellReplacementAndRetirement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := NewForwarder(nil, "", 1000)
		f.RegisterSession("session", "connection", "peer", "192.0.2.1", 1)
		enqueueDwellPackets(t, f, 810)
		f.QueuePressure()
		time.Sleep(30 * time.Second)
		f.QueuePressure()
		f.RegisterSession("replacement", "connection", "peer", "192.0.2.1", 1)
		got := f.QueuePressure()
		if got.Occupancy != 0 || got.Capacity != 1000 || got.ConsecutiveAbove80Sec != 0 || got.SecondsAbove80Pct != 30 {
			t.Fatalf("route replacement must end the run and preserve measured history: %+v", got)
		}
		enqueueDwellPackets(t, f, 810)
		time.Sleep(5 * time.Second)
		wait := f.RetireAllRoutes()
		if err := wait(t.Context()); err != nil {
			t.Fatal(err)
		}
		got = f.QueuePressure()
		if got.Capacity != 0 || got.Occupancy != 0 || got.ConsecutiveAbove80Sec != 0 || got.SecondsAbove80Pct != 35 {
			t.Fatalf("route retirement lost dwell or retained pressure: %+v", got)
		}
		if err := f.ReconfigureClientQueueSize(10); err != nil {
			t.Fatal(err)
		}
		f.RegisterSession("new", "connection", "peer", "192.0.2.1", 1)
		enqueueDwellPackets(t, f, 8)
		time.Sleep(3 * time.Second)
		got = f.QueuePressure()
		if got.Capacity != 10 || got.ConsecutiveAbove80Sec != 3 {
			t.Fatalf("new queue size must start a fresh measured run: %+v", got)
		}
	})
}
