package vpn

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

func TestAuditNativeReadinessBlocksServiceReaders(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	sid, _, _ := createTestServerAndKey(t, db, "audit-native-lock", "198.51.100.1")
	raw, err := json.Marshal(models.NaiveProxyParams{Username: "audit-user", Password: "audit-password", Domain: "naive.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	tun, err := svc.pool.AddTunnelWithConfig(ctx, sid, "198.51.100.1:443", "", tunnel.BackendTunnelOptions{Protocol: models.ProtocolNaive, ProtocolParams: raw})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "naive")
	marker := filepath.Join(dir, "entered")
	script := "#!/usr/bin/python3\nimport json,socket,sys,time\nfrom urllib.parse import urlparse\nc=json.load(open(sys.argv[1]));open('" + marker + "','w').close();time.sleep(0.5);u=urlparse(c['listen']);s=socket.socket();s.bind((u.hostname,u.port));s.listen();time.sleep(30)\n"
	if err := os.WriteFile(bin, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NAIVE_BIN_PATH", bin)
	t.Setenv("NAIVE_DISABLE_DOWNLOAD", "0")
	finished := make(chan error, 1)
	go func() { finished <- svc.finishEnableBackend(ctx, svc.pool, tun, nil, sid, 0) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("native process not reached")
		}
		time.Sleep(5 * time.Millisecond)
	}
	reader := make(chan struct{})
	go func() {
		svc.mu.RLock()
		_ = svc.adminDisableEpoch
		svc.mu.RUnlock()
		close(reader)
	}()
	blocked := false
	select {
	case <-reader:
	case <-time.After(150 * time.Millisecond):
		blocked = true
	}
	err = <-finished
	<-reader
	if dev := svc.backendDevices[tun.ID]; dev != nil {
		defer dev.Close()
	}
	t.Logf("unrelated Service.mu reader blocked during native startup=%v activationError=%v", blocked, err)
	if blocked {
		t.Fatal("native readiness executes under service-wide state lock")
	}
}

func TestAuditHostSyncRejectsStalePreparedCredential(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	sid, _, _ := createTestServerAndKey(t, db, "audit-host-sync-race", "198.51.100.1")

	cred1, err := json.Marshal(models.NaiveProxyParams{Username: "user1", Password: "pwd1", Domain: "naive1.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	cred2, err := json.Marshal(models.NaiveProxyParams{Username: "user2", Password: "pwd2", Domain: "naive2.example.com"})
	if err != nil {
		t.Fatal(err)
	}

	tun, err := svc.pool.AddTunnelWithConfig(ctx, sid, "198.51.100.1:443", "", tunnel.BackendTunnelOptions{
		Protocol:       models.ProtocolNaive,
		ProtocolParams: cred1,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = svc.pool.SetTunnelStatus(ctx, sid, TunnelStatusActive, 0)

	// 1. Direct test: candidate prepared with cred1, but pool rotated to cred2
	prepMap, candCloser, err := svc.prepareNaiveCandidateForTunnel(ctx, tun)
	if err != nil {
		t.Fatalf("prepare candidate failed: %v", err)
	}
	defer func() {
		if candCloser != nil {
			_ = candCloser.Close()
		}
	}()

	candDev := prepMap["candidate_device"].(BackendDevice)
	if candDev.IsClosed() {
		t.Fatal("expected candidate device to be open initially")
	}

	// Concurrent credential rotation commits cred2 to pool
	_, err = svc.pool.AddTunnelWithConfig(ctx, sid, "198.51.100.1:443", "", tunnel.BackendTunnelOptions{
		Protocol:       models.ProtocolNaive,
		ProtocolParams: cred2,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Host synchronization attempts to attach under Service.mu
	svc.mu.Lock()
	syncErr := svc.syncBackendForwarderOnHostUpdateLocked(ctx, sid, tun.ID, nil, prepMap)
	svc.mu.Unlock()

	if !errors.Is(syncErr, ErrStaleCandidate) {
		t.Fatalf("expected ErrStaleCandidate, got: %v", syncErr)
	}
	if !candDev.IsClosed() {
		t.Fatal("expected stale candidate device to be closed immediately on rejection")
	}

	svc.mu.RLock()
	attachedDev := svc.backendDevices[tun.ID]
	svc.mu.RUnlock()
	if attachedDev != nil {
		t.Fatal("expected no device to be attached after stale candidate rejection")
	}

	// 2. Lifecycle re-preparation during UpdateBackendServerHost
	cred3, err := json.Marshal(models.NaiveProxyParams{Username: "user3", Password: "pwd3", Domain: "naive3.example.com"})
	if err != nil {
		t.Fatal(err)
	}

	rotationExecuted := false
	svc.SetUpdateBackendServerHostPreLockHook(func() {
		if !rotationExecuted {
			rotationExecuted = true
			_, rotErr := svc.pool.AddTunnelWithConfig(ctx, sid, "198.51.100.2:443", "", tunnel.BackendTunnelOptions{
				Protocol:       models.ProtocolNaive,
				ProtocolParams: cred3,
			})
			if rotErr != nil {
				t.Errorf("rotation in hook failed: %v", rotErr)
			}
		}
	})

	updateErr := svc.UpdateBackendServerHost(ctx, sid, "198.51.100.2")
	if updateErr != nil {
		t.Fatalf("UpdateBackendServerHost failed: %v", updateErr)
	}
	if !rotationExecuted {
		t.Fatal("expected rotation hook to execute")
	}

	svc.mu.RLock()
	liveDev := svc.backendDevices[tun.ID]
	svc.mu.RUnlock()
	if liveDev == nil || liveDev.IsClosed() {
		t.Fatal("expected new candidate device to be prepared and attached for rotated credentials")
	}
	defer liveDev.Close()

	currTun, err := svc.pool.GetTunnel(sid)
	if err != nil {
		t.Fatal(err)
	}
	if !models.EqualJSON(currTun.ProtocolParams, cred3) {
		t.Errorf("expected pool tunnel to have cred3, got: %s", string(currTun.ProtocolParams))
	}
}

func TestHostSyncRejectsStaleEndpointWithUnchangedCredentials(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	sid, _, _ := createTestServerAndKey(t, db, "audit-endpoint-sync-race", "198.51.100.1")

	cred, err := json.Marshal(models.NaiveProxyParams{Username: "user1", Password: "pwd1", Domain: "naive1.example.com"})
	if err != nil {
		t.Fatal(err)
	}

	tun, err := svc.pool.AddTunnelWithConfig(ctx, sid, "198.51.100.1:443", "", tunnel.BackendTunnelOptions{
		Protocol:       models.ProtocolNaive,
		ProtocolParams: cred,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = svc.pool.SetTunnelStatus(ctx, sid, TunnelStatusActive, 0)

	// 1. Direct test: candidate prepared for 198.51.100.1:443, but pool endpoint concurrently changed to 198.51.100.2:443 with unchanged credentials
	prepMap, candCloser, err := svc.prepareNaiveCandidateForTunnel(ctx, tun)
	if err != nil {
		t.Fatalf("prepare candidate failed: %v", err)
	}
	defer func() {
		if candCloser != nil {
			_ = candCloser.Close()
		}
	}()

	candDev := prepMap["candidate_device"].(BackendDevice)
	if candDev.IsClosed() {
		t.Fatal("expected candidate device to be open initially")
	}

	// Concurrent endpoint change with unchanged credentials
	if err := svc.pool.SetTunnelEndpoint(ctx, tun.ID, "198.51.100.2:443"); err != nil {
		t.Fatal(err)
	}

	// Host synchronization attempts to attach under Service.mu
	svc.mu.Lock()
	syncErr := svc.syncBackendForwarderOnHostUpdateLocked(ctx, sid, tun.ID, nil, prepMap)
	svc.mu.Unlock()

	if !errors.Is(syncErr, ErrStaleCandidate) {
		t.Fatalf("expected ErrStaleCandidate on endpoint change with unchanged credentials, got: %v", syncErr)
	}
	if !candDev.IsClosed() {
		t.Fatal("expected stale candidate device to be closed immediately on rejection")
	}

	svc.mu.RLock()
	attachedDev := svc.backendDevices[tun.ID]
	svc.mu.RUnlock()
	if attachedDev != nil {
		t.Fatal("expected no device to be attached after stale candidate rejection")
	}

	// 2. Lifecycle re-preparation during UpdateBackendServerHost when endpoint changes in hook
	endpointChangedInHook := false
	svc.SetUpdateBackendServerHostPreLockHook(func() {
		if !endpointChangedInHook {
			endpointChangedInHook = true
			if epErr := svc.pool.SetTunnelEndpoint(ctx, tun.ID, "198.51.100.3:443"); epErr != nil {
				t.Errorf("endpoint update in hook failed: %v", epErr)
			}
		}
	})

	updateErr := svc.UpdateBackendServerHost(ctx, sid, "198.51.100.3")
	if updateErr != nil {
		t.Fatalf("UpdateBackendServerHost failed: %v", updateErr)
	}
	if !endpointChangedInHook {
		t.Fatal("expected pre-lock hook to execute")
	}

	svc.mu.RLock()
	liveDev := svc.backendDevices[tun.ID]
	liveEndpoint := svc.backendDeviceEndpoints[tun.ID]
	svc.mu.RUnlock()

	if liveDev == nil || liveDev.IsClosed() {
		t.Fatal("expected new candidate device to be prepared and attached for new endpoint")
	}
	defer liveDev.Close()

	if liveEndpoint != "198.51.100.3:443" {
		t.Errorf("expected attached device endpoint to be 198.51.100.3:443, got: %s", liveEndpoint)
	}
}
