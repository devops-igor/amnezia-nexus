package vpn

import (
	"context"
	"errors"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
	"testing"
	"time"
)

func lifecycleTestService(t *testing.T) (*Service, int64, *models.BackendTunnel) {
	t.Helper()
	ctx := context.Background()
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	id, err := db.CreateServer(ctx, &models.Server{Name: "ops-probe", Host: "192.0.2.10",
		Protocols: map[string]any{"awg": map[string]any{"installed": true, "port": 51820, "public_key": "old-probe-key"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.EnableBackend(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := svc.SetTunnelStatus(ctx, id, models.TunnelStatusActive, 1); err != nil {
		t.Fatal(err)
	}
	tun, err := svc.GetTunnel(id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.DisableBackend(context.Background(), id) })
	return svc, id, tun
}

func TestBackendCandidateFailurePreservesWorkingDevice(t *testing.T) {
	for _, kind := range []string{"public-key", "host"} {
		t.Run(kind, func(t *testing.T) {
			svc, id, tun := lifecycleTestService(t)
			raw := svc.GetBackendDeviceForTest(tun.ID)
			old := &testBackendDevice{AWGClientDevice: raw.(*tunnel.AWGClientDevice), inPacketsCh: make(chan []byte, 1)}
			svc.SetBackendDeviceForTest(tun.ID, old)
			svc.forwarder.AttachBackendDevice(tun.ID, old)
			svc.forwarder.RegisterSession("candidate-session", "candidate-connection", "candidate-peer", "192.0.2.100", tun.ID)
			svc.forwarder.StartPumps(context.Background())
			t.Cleanup(svc.forwarder.StopPumps)
			if old == nil || old.IsClosed() {
				t.Fatal("fixture must have old live device")
			}
			if _, err := old.Write(make([]byte, 20)); err != nil {
				t.Fatal("fixture old device must admit plaintext")
			}
			<-old.inPacketsCh
			if err := svc.db.UpdateServerProtocols(context.Background(), id, map[string]any{"awg": map[string]any{
				"installed": true, "port": 51820, "public_key": tun.PublicKey, "awg_params": map[string]any{"h1": "invalid-header"}}}); err != nil {
				t.Fatal(err)
			}
			var err error
			if kind == "public-key" {
				err = svc.UpdateBackendServerPublicKey(context.Background(), id, "new-probe-key")
			} else {
				err = svc.UpdateBackendServerHost(context.Background(), id, "192.0.2.11")
			}
			if err == nil {
				t.Fatal("fixture must force actual device constructor failure")
			}
			if errors.Is(err, ErrVPNRollbackFailed) {
				t.Fatal("proof requires ordinary reported compensation")
			}
			after, e := svc.GetTunnel(id)
			if e != nil {
				t.Fatal(e)
			}
			row, e := svc.db.GetBackendTunnel(context.Background(), tun.ID)
			if e != nil {
				t.Fatal(e)
			}
			if after.PublicKey != tun.PublicKey || after.Endpoint != tun.Endpoint || row.PublicKey != tun.PublicKey || row.Endpoint != tun.Endpoint {
				t.Fatal("fixture must restore OLD pool and durable identity")
			}
			if !after.Enabled || old.IsClosed() || svc.GetBackendDeviceForTest(tun.ID) != old {
				t.Fatal("failed candidate must preserve attached OLD device")
			}
			if _, err := old.Write(make([]byte, 20)); err != nil {
				t.Fatal("OLD device no longer usable after failed candidate", err)
			}
			<-old.inPacketsCh
			if err := svc.forwarder.RouteClientToBackend("candidate-peer", []byte("post-failure-packet")); err != nil {
				t.Fatal(err)
			}
			select {
			case <-old.inPacketsCh:
			case <-time.After(time.Second):
				t.Fatal("forwarder no longer delivers through OLD after candidate failure")
			}
			if svc.retiredBackendDeviceDrops.Total() != 0 {
				t.Fatal("failed candidate retired OLD loss ownership")
			}

		})
	}
}

func TestBackendQuarantineRetryPersistsAcrossReload(t *testing.T) {
	svc, id, tun := lifecycleTestService(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := svc.DisableBackend(ctx, id); err == nil {
		t.Fatal("expected canceled durable disable failure")
	}
	inMem, err := svc.GetTunnel(id)
	if err != nil {
		t.Fatal(err)
	}
	row, err := svc.db.GetBackendTunnel(context.Background(), tun.ID)
	if err != nil {
		t.Fatal(err)
	}
	if inMem.Enabled || !row.Enabled {
		t.Fatal("fixture must enter memory-only quarantine")
	}
	if err := svc.DisableBackend(context.Background(), id); err != nil {
		t.Fatal("expected false-success retry")
	}
	row, err = svc.db.GetBackendTunnel(context.Background(), tun.ID)
	if err != nil {
		t.Fatal(err)
	}
	if row.Enabled {
		t.Fatal("retry must persist quarantine")
	}
	restart := tunnel.NewPool(svc.db)
	if err := restart.SyncFromDB(context.Background()); err != nil {
		t.Fatal(err)
	}
	reloaded, err := restart.GetTunnel(id)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Enabled {
		t.Fatal("fresh pool must reload quarantine")
	}

}

func TestBackendCandidateSuccessRetiresOldLossExactlyOnce(t *testing.T) {
	svc, id, tun := lifecycleTestService(t)
	raw := svc.GetBackendDeviceForTest(tun.ID).(*tunnel.AWGClientDevice)
	old := &testBackendDevice{AWGClientDevice: raw}
	old.dropCount.Store(7)
	svc.SetBackendDeviceForTest(tun.ID, old)
	svc.forwarder.AttachBackendDevice(tun.ID, old)
	if err := svc.UpdateBackendServerPublicKey(context.Background(), id, "candidate-success-key"); err != nil {
		t.Fatal(err)
	}
	candidate := svc.GetBackendDeviceForTest(tun.ID)
	if !old.IsClosed() || candidate == old || candidate == nil || candidate.IsClosed() {
		t.Fatal("successful candidate must replace OLD and close it")
	}
	if svc.retiredBackendDeviceDrops.ClientExternal != 7 {
		t.Fatal("OLD external ownership not transferred exactly once")
	}
	if err := svc.UpdateBackendServerPublicKey(context.Background(), id, "candidate-success-key"); err != nil {
		t.Fatal(err)
	}
	if svc.GetBackendDeviceForTest(tun.ID) != candidate || svc.retiredBackendDeviceDrops.ClientExternal != 7 {
		t.Fatal("idempotent success replaced candidate or retired OLD twice")
	}
	if _, err := candidate.Write(make([]byte, 20)); err != nil {
		t.Fatal("successful candidate unusable", err)
	}
}
