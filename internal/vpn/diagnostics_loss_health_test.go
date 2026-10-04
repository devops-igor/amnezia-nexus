package vpn

import (
	"testing"
	"time"
)

func TestReturnQueueLossHasOneCurrentHealthExplanation(t *testing.T) {
	svc, fwd, engine, _, _ := newSingleOwnerFixture(t)
	fwd.RegisterSessionWithReturnPath("s", "c", "peer", "192.0.2.1", 1, engine.returnPath)
	svc.populateOperationalDiagnostics(&Status{})
	packet := returnPacket("192.0.2.1")
	for range 10 {
		if err := fwd.RouteBackendToClient(1, packet, "192.0.2.1"); err != nil {
			t.Fatal(err)
		}
	}
	if err := fwd.RouteBackendToClient(1, packet, "192.0.2.1"); err == nil {
		t.Fatal("overflow did not refuse packet")
	}
	queue, _ := fwd.GetClientPacketChannel("peer")
	for range 10 {
		<-queue
	}
	time.Sleep(250 * time.Millisecond)
	status := Status{ForwarderAvailable: true, EngineRunning: true}
	svc.populateOperationalDiagnostics(&status)
	if status.DropCategories.ReturnQueueFull != 1 || status.DropCategories.TotalDrops != 1 {
		t.Fatalf("fixture lost conservation: %+v", status.DropCategories)
	}
	var count int
	for _, condition := range status.HealthAssessment.Conditions {
		if condition.Category == "drops" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("one real return queue refusal generated %d loss explanations: %+v", count, status.HealthAssessment.Conditions)
	}
}

func TestUnattributedRetirementDoesNotInventLossRate(t *testing.T) {
	dev := &noStatsDevice{}
	dev.dropped.Add(9)
	svc := &Service{backendDevices: map[int64]BackendDevice{1: dev}}
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	before := svc.collectDropCategories()
	svc.sampleDropRates(at, &before, 0)
	svc.mu.Lock()
	svc.retiredBackendDeviceDrops.addInto(snapshotBackendDeviceDrops(dev))
	delete(svc.backendDevices, 1)
	svc.mu.Unlock()
	after := svc.collectDropCategories()
	svc.sampleDropRates(at.Add(time.Second), &after, 0)
	if before.TotalDrops != 9 || after.TotalDrops != 9 {
		t.Fatal("retirement changed total")
	}
	for reason, rate := range after.ReasonRates {
		if rate != 0 {
			t.Errorf("no new packet was lost but %s rate=%v", reason, rate)
		}
	}
}
