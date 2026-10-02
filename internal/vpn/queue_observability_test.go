package vpn

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/ingress"
)

type statusBlockedDevice struct {
	started chan struct{}
	release chan struct{}
}

func returnPacket(destination string) []byte {
	p := make([]byte, 28)
	p[0] = 0x45
	p[9] = 17
	binary.BigEndian.PutUint16(p[2:4], 28)
	ip := netip.MustParseAddr(destination).As4()
	copy(p[16:20], ip[:])
	return p
}

func TestServiceRetirementReleasesGlobalLockDuringBlockedWrite(t *testing.T) {
	for _, action := range []string{"disconnect-session", "disconnect-user", "release", "reap", "replace"} {
		t.Run(action, func(t *testing.T) {
			db := setupTestDB(t)
			svc, _, _, userID, peer := setupTestVPNService(t, db)
			// Keep the status probe local: external public-IP detection can take
			// longer than this test's two-second lock-contention deadline.
			svc.cfg.PublicEndpoint = "198.51.100.1"
			if err := svc.pool.SyncFromDB(t.Context()); err != nil {
				t.Fatal(err)
			}
			otherUser, err := db.CreateUser(t.Context(), &models.User{Username: "bob", Enabled: true})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.CreateConnection(t.Context(), &models.UserConnection{UserID: otherUser, ServerID: 0, Protocol: "awg", ClientID: "bob-peer", Name: "bob"}); err != nil {
				t.Fatal(err)
			}
			sess, _, err := svc.HandleIncomingPeerForTest(t.Context(), peer)
			if err != nil {
				t.Fatal(err)
			}
			oldQueue, _ := svc.forwarder.GetClientPacketChannel(peer)
			_, conn, err := svc.auth.AuthenticatePeer(t.Context(), peer)
			if err != nil {
				t.Fatal(err)
			}
			dev := &statusBlockedDevice{started: make(chan struct{}, 1), release: make(chan struct{})}
			path := forwarder.NewReturnPath(func(_, _ string, p []byte) (int, error) { return dev.Write(p) })
			if _, err := svc.forwarder.BindSessionReturnPath(sess.ID, conn.ID, peer, sess.AssignedIP, sess.BackendTunnelID, path); err != nil {
				t.Fatal(err)
			}
			svc.forwarder.StartPumps(t.Context())
			defer svc.forwarder.StopPumps()
			defer func() {
				select {
				case <-dev.release:
				default:
					close(dev.release)
				}
			}()
			if err := svc.forwarder.RouteBackendToClient(sess.BackendTunnelID, returnPacket(sess.AssignedIP), sess.AssignedIP); err != nil {
				t.Fatal(err)
			}
			if action == "replace" {
				// Make the old assignment unusable so this is a real route
				// replacement. Healthy rekeys now keep the existing route.
				backend, err := svc.pool.GetTunnelByID(sess.BackendTunnelID)
				if err != nil {
					t.Fatal(err)
				}
				if err := svc.pool.SetTunnelStatus(t.Context(), backend.ServerID, "degraded", 0); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case <-dev.started:
			case <-time.After(time.Second):
				t.Fatal("write did not start")
			}
			done := make(chan error, 1)
			go func() {
				var err error
				switch action {
				case "disconnect-session":
					err = svc.DisconnectSession(t.Context(), sess.ID)
				case "disconnect-user":
					err = svc.DisconnectUser(t.Context(), userID)
				case "release":
					err = svc.ReleaseClient(t.Context(), peer)
				case "reap":
					err = svc.sessionMgr.CloseSession(t.Context(), sess.ID, "idle_timeout")
					svc.reapSession(t.Context(), sess)
				case "replace":
					_, _, err = svc.HandleIncomingPeerForTest(t.Context(), peer)
				}
				done <- err
			}()
			deadline := time.Now().Add(2 * time.Second)
			for {
				current, ok := svc.forwarder.GetClientPacketChannel(peer)
				if !ok || current != oldQueue {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("old route never retired")
				}
				time.Sleep(time.Millisecond)
			}
			statusDone := make(chan error, 1)
			go func() {
				status, err := svc.GetStatus(t.Context())
				if err == nil && status.ForwarderDeviceWritesInFlight != 1 {
					err = fmt.Errorf("retired write missing from status: %+v", status)
				}
				statusDone <- err
			}()
			select {
			case err := <-statusDone:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("retirement held Service.mu and blocked GetStatus")
			}
			otherDone := make(chan error, 1)
			go func() {
				_, _, err := svc.HandleIncomingPeerForTest(t.Context(), "bob-peer")
				otherDone <- err
			}()
			select {
			case err := <-otherDone:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("retirement blocked unrelated handshake")
			}
			select {
			case err := <-done:
				t.Fatalf("retirement returned before admitted write completed: %v", err)
			default:
			}
			close(dev.release)
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("retirement failed to complete after release")
			}
		})
	}
}

func TestRejectImpossiblePeerBudgetBeforePersisting(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	before, err := db.GetVPNConfig(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := svc.GetConfig(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	cfg.MaxTotalPeers = forwarder.MaxBudgetedActiveRoutes + 1
	if err := svc.UpdateConfig(t.Context(), cfg); err == nil {
		t.Fatal("impossible budget accepted")
	}
	after, err := db.GetVPNConfig(t.Context())
	if err != nil || after.MaxTotalPeers != before.MaxTotalPeers {
		t.Fatalf("rejection changed persistence: %+v, %v", after, err)
	}
	if _, err := NewVPNService(db, cfg); err == nil {
		t.Fatal("startup accepted impossible budget")
	}
	if err := db.SaveVPNConfig(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := NewVPNService(db, nil); err == nil {
		t.Fatal("startup accepted impossible persisted budget")
	}
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
	path := forwarder.NewReturnPath(func(_, _ string, p []byte) (int, error) { return dev.Write(p) })
	svc.forwarder.RegisterSessionWithReturnPath("session", "connection", "peer", "10.100.0.10", 1, path)
	svc.forwarder.StartPumps(t.Context())
	defer svc.forwarder.StopPumps()
	defer func() {
		select {
		case <-dev.release:
		default:
			close(dev.release)
		}
	}()
	if err := svc.forwarder.RouteBackendToClient(1, returnPacket("10.100.0.10"), "10.100.0.10"); err != nil {
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
	// The per-route map is keyed by ingress.PeerKeyFingerprint, the opaque
	// collision-resistant identifier (issue #424 round 6, finding 2). It is
	// NOT a truncated key prefix: two peers sharing 8 leading characters would
	// collapse into one entry and a route would silently disappear from the
	// payload. The REDACTED display form travels in the value's
	// peer_key_display field, where a human reads it.
	fingerprint := ingress.PeerKeyFingerprint("peer")
	route, ok := status.ForwarderRouteQueues[fingerprint]
	if !ok {
		t.Fatalf("status omitted per-route stalled write: %+v", status.ForwarderRouteQueues)
	}
	if route.WritesInFlight != 1 || route.WriteStalls != 1 || route.OldestWriteMS < forwarder.DeviceWriteStallThreshold.Milliseconds() {
		t.Fatalf("status omitted per-route stalled write: %+v", route)
	}
	if route.PeerKeyDisplay != ingress.RedactKey("peer") {
		t.Fatalf("route display key = %q, want the redacted display form %q",
			route.PeerKeyDisplay, ingress.RedactKey("peer"))
	}
	if strings.Contains(fingerprint, "peer") {
		t.Fatalf("fingerprint %q leaked the raw peer key", fingerprint)
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
