package vpn

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

type statusBlockedDevice struct {
	started chan struct{}
	release chan struct{}
}

func (d *statusBlockedDevice) Read([]byte) (int, error) { return 0, nil }
func (d *statusBlockedDevice) Close() error             { return nil }
func (d *statusBlockedDevice) Write(packet []byte) (int, error) {
	select {
	case d.started <- struct{}{}:
	default:
	}
	<-d.release
	return len(packet), nil
}

func TestStatusExposesLiveAndCompletedDeviceWriteTelemetry(t *testing.T) {
	svc, err := NewVPNService(setupTestDB(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	dev := &statusBlockedDevice{started: make(chan struct{}, 1), release: make(chan struct{})}
	svc.forwarder.AttachPeerDevice("peer", dev)
	svc.forwarder.RegisterSession("session", "connection", "peer", "10.100.0.10", 1)
	svc.forwarder.StartPumps(t.Context())
	defer svc.forwarder.StopPumps()
	defer func() {
		select {
		case <-dev.release:
		default:
			close(dev.release)
		}
	}()
	if err := svc.forwarder.RouteBackendToClient(1, []byte("packet"), "10.100.0.10"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-dev.started:
	case <-time.After(time.Second):
		t.Fatal("write did not start")
	}
	time.Sleep(forwarder.DeviceWriteStallThreshold)
	status, err := svc.GetStatus(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	var metrics map[string]float64
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	metrics = make(map[string]float64)
	for _, key := range []string{
		"forwarder_device_write_count", "forwarder_device_writes_in_flight",
		"forwarder_device_write_oldest_in_flight_ms", "forwarder_device_write_max_duration_ms",
		"forwarder_device_write_stalls", "forwarder_device_write_stall_threshold_ms",
	} {
		var value float64
		if err := json.Unmarshal(fields[key], &value); err != nil {
			t.Fatalf("missing/invalid status field %s: %v", key, err)
		}
		metrics[key] = value
	}
	if metrics["forwarder_device_write_count"] != 1 || metrics["forwarder_device_writes_in_flight"] != 1 || metrics["forwarder_device_write_stalls"] != 1 {
		t.Fatalf("missing blocked write telemetry: %v", metrics)
	}
	if metrics["forwarder_device_write_oldest_in_flight_ms"] < metrics["forwarder_device_write_stall_threshold_ms"] || metrics["forwarder_device_write_max_duration_ms"] != 0 {
		t.Fatalf("live/completed durations conflated: %v", metrics)
	}
	close(dev.release)
	svc.forwarder.UnregisterSession("peer")
	status, err = svc.GetStatus(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if status.ForwarderDeviceWritesInFlight != 0 || status.ForwarderDeviceWriteOldestMS != 0 || status.ForwarderDeviceWriteStalls != 1 || status.ForwarderDeviceWriteMaxMS < forwarder.DeviceWriteStallThreshold.Milliseconds() {
		t.Fatalf("completed write telemetry incorrect: %+v", status)
	}
}

func TestUpdateConfigChangesPeerLimitWithLiveQueues(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	svc.forwarder.RegisterSession("session", "connection", "peer", "10.100.0.10", 1)
	queue, _ := svc.forwarder.GetClientPacketChannel("peer")
	for _, limit := range []int{2000, 1} {
		cfg, err := svc.GetConfig(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		cfg.MaxTotalPeers = limit
		if err := svc.UpdateConfig(t.Context(), cfg); err != nil {
			t.Fatalf("live limit=%d update failed: %v", limit, err)
		}
		stored, err := db.GetVPNConfig(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if stored.MaxTotalPeers != limit || stored.ClientQueueSize != cap(queue) {
			t.Fatalf("persisted queue configuration diverged: %+v", stored)
		}
		if current, _ := svc.forwarder.GetClientPacketChannel("peer"); current != queue {
			t.Fatal("limit change replaced live queue")
		}
	}
	svc.forwarder.RegisterSession("second", "connection", "peer2", "10.100.0.11", 1)
	if _, ok := svc.forwarder.GetClientPacketChannel("peer2"); ok {
		t.Fatal("lowered route limit was not applied to runtime")
	}
	cfg, err := svc.GetConfig(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	cfg.MaxTotalPeers = 2
	if err := svc.UpdateConfig(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	svc.forwarder.RegisterSession("second", "connection", "peer2", "10.100.0.11", 1)
	if _, ok := svc.forwarder.GetClientPacketChannel("peer2"); !ok {
		t.Fatal("raised route limit was not applied to runtime")
	}
	// Reducing below the live population must preserve persistence/runtime.
	cfg, err = svc.GetConfig(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	cfg.MaxTotalPeers = 1
	if err := svc.UpdateConfig(t.Context(), cfg); err == nil {
		t.Fatal("limit below live population was accepted")
	}
	stored, err := db.GetVPNConfig(t.Context())
	if err != nil || stored.MaxTotalPeers != 2 {
		t.Fatalf("failed update changed stored capacity: %+v, %v", stored, err)
	}
}
