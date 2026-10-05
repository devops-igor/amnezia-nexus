package vpn

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/clientawg"
)

func newDiagnosticsLifecycleService(t *testing.T, name, host, publicKey string) (*Service, int64) {
	t.Helper()
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	serverID, err := db.CreateServer(t.Context(), &models.Server{
		Name: name, Host: host,
		Protocols: map[string]any{"awg": map[string]any{
			"installed": true, "port": 51820, "public_key": publicKey,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	svc.SetAWGStatusProvider(&mockAWGManagerWithClientAdder{})
	return svc, serverID
}

func TestDiagnosticsConcurrentBackendLifecycle(t *testing.T) {
	svc, serverID := newDiagnosticsLifecycleService(t, "diagnostics-lifecycle", "192.0.2.20", "diagnostics-key")
	if err := svc.EnableBackend(t.Context(), serverID); err != nil {
		t.Fatal(err)
	}
	svc.mu.Lock()
	svc.rollingHistory = NewRollingHistory()
	svc.cfg.PublicEndpoint = "nexus.invalid:51820"
	svc.mu.Unlock()
	t.Cleanup(func() { _ = svc.DisableBackend(context.Background(), serverID) })
	tun, err := svc.GetTunnel(serverID)
	if err != nil {
		t.Fatal(err)
	}
	first := svc.GetBackendDeviceForTest(tun.ID)
	if first == nil || first.IsClosed() {
		t.Fatal("real initial AWG device missing")
	}

	start, stop := make(chan struct{}), make(chan struct{})
	errors := make(chan error, 2)
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		<-start
		for {
			svc.sampleRollingHistory()
			if _, err := svc.GetStatus(t.Context()); err != nil {
				errors <- err
				return
			}
			select {
			case <-stop:
				return
			default:
			}
		}
	}()
	go func() {
		defer workers.Done()
		defer close(stop)
		<-start
		for i := range 12 {
			if err := svc.DisableBackend(t.Context(), serverID); err != nil {
				errors <- err
				return
			}
			if err := svc.EnableBackend(t.Context(), serverID); err != nil {
				errors <- err
				return
			}
			host := fmt.Sprintf("192.0.2.%d", 21+i%2)
			if err := svc.UpdateBackendServerHost(t.Context(), serverID, host); err != nil {
				errors <- err
				return
			}
		}
	}()
	close(start)
	workers.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
	last := svc.GetBackendDeviceForTest(tun.ID)
	if last == nil || last == first || last.IsClosed() || !first.IsClosed() {
		t.Fatal("test did not execute real retirement, re-enable and replacement")
	}
	if len(svc.rollingHistory.Snapshot().Window15m) == 0 {
		t.Fatal("no history observation executed")
	}
}

func TestDiagnosticsCapturedRetirementCountsOnce(t *testing.T) {
	svc, serverID, dev := retireDirectionFixture(t)
	produceReturnQueueFullDrops(t, dev, 3)
	captured := svc.captureDiagnosticsInputs()
	if err := svc.DisableBackend(t.Context(), serverID); err != nil {
		t.Fatal(err)
	}
	// A detached reference still exposes its final synchronized counters.
	old := captured.collectDropCategories()
	current := svc.collectDropCategories()
	for _, d := range []DropCategoryBreakdown{old, current} {
		if d.ReturnBackendDeviceQueueFull != 3 || d.ReturnTotalDrops != 3 || d.TotalDrops != 3 {
			t.Fatalf("retirement lost or counted the captured device twice: %+v", d)
		}
		assertDisjointDropReasons(t, d)
	}
}

func TestDiagnosticsSlowHandshakeDoesNotHoldServiceLock(t *testing.T) {
	for _, background := range []bool{false, true} {
		t.Run(fmt.Sprintf("history=%v", background), func(t *testing.T) {
			svc, _, dev := newTestHistoryService(t)
			entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var once sync.Once
			dev.lastHandshakeFn = func() time.Time {
				once.Do(func() { close(entered) })
				<-release
				return time.Time{}
			}
			go func() {
				defer close(done)
				if background {
					svc.sampleRollingHistory()
				} else {
					_, _ = svc.GetStatus(t.Context())
				}
			}()
			select {
			case <-entered:
			case <-time.After(2 * time.Second):
				close(release)
				t.Fatal("handshake callback not reached")
			}
			unlocked := svc.mu.TryLock()
			if unlocked {
				svc.mu.Unlock()
			}
			close(release)
			<-done
			if !unlocked {
				t.Fatal("slow device callback held Service.mu")
			}
		})
	}
}

func TestGetStatusCohortSurvivesConcurrentAdministrativeDisconnect(t *testing.T) {
	svc, _, _ := newTestHistoryService(t)
	svc.cfg.PublicEndpoint = ""
	original := externalIPDetector
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	externalIPDetector = func(context.Context) string {
		once.Do(func() { close(entered) })
		<-release
		return "203.0.113.5"
	}
	t.Cleanup(func() { externalIPDetector = original })
	for _, name := range []string{"VPN_PUBLIC_ENDPOINT", "PUBLIC_ENDPOINT", "PUBLIC_IP"} {
		t.Setenv(name, "")
	}
	result := make(chan *Status, 1)
	go func() { status, _ := svc.GetStatus(t.Context()); result <- status }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("status assembly did not reach endpoint callback")
	}
	sessions := svc.sessionMgr.ListActiveSessionsSnapshot()
	if len(sessions) != 1 {
		close(release)
		t.Fatal("fixture requires one real session")
	}
	err := svc.DisconnectSession(t.Context(), sessions[0].ID)
	close(release)
	status := <-result
	if err != nil {
		t.Fatal(err)
	}
	if status == nil || !status.RoutingConsistency.IsConsistent ||
		status.RoutingConsistency.ActiveSessionsCount != 1 ||
		status.RoutingConsistency.ActiveRoutesCount != 1 || status.ConnectedSessions != 1 {
		t.Fatalf("valid admin mutation fabricated an inconsistent cohort: %+v", status)
	}
	next, err := svc.GetStatus(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !next.RoutingConsistency.IsConsistent || next.ConnectedSessions != 0 || next.RoutingConsistency.ActiveRoutesCount != 0 {
		t.Fatalf("next response did not observe completed disconnect: %+v", next.RoutingConsistency)
	}
}

type orphanDiagnosticPortal struct{ present bool }

func (p *orphanDiagnosticPortal) Status() (clientawg.Status, error) {
	if !p.present {
		return clientawg.Status{}, nil
	}
	return clientawg.Status{Peers: []clientawg.PeerStatus{{
		PublicKey: "orphan-diagnostic-peer", AllowedIP: netip.MustParsePrefix("192.0.2.80/32"),
	}}}, nil
}
func (*orphanDiagnosticPortal) AddPeer(clientawg.Peer) error { return nil }
func (p *orphanDiagnosticPortal) RemovePeer(string) error    { p.present = false; return nil }

func TestGetStatusDoesNotInvertPeerReconciliationLockOrder(t *testing.T) {
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	engine, err := svc.NewIngressEngine(t.Context(), "diagnostic-lock-order", nil)
	if err != nil {
		t.Fatal(err)
	}
	engine.peerSync.portal = &orphanDiagnosticPortal{present: true}
	entered, release := make(chan struct{}), make(chan struct{})
	skipRevoke := false
	engine.peerSync.revokeSession = func(ctx context.Context, key string) error {
		close(entered)
		<-release
		if skipRevoke {
			return nil
		} // let defective implementations fail without leaking workers
		return svc.RevokeUpstreamPeerSession(ctx, key)
	}
	svc.ingressEngine, svc.running, engine.running = engine, true, true
	svc.cfg.PublicEndpoint = "nexus.invalid:51820"
	reconcileDone, statusDone := make(chan error, 1), make(chan error, 1)
	go func() { reconcileDone <- engine.peerSync.reconcileNow(t.Context()) }()
	<-entered // real reconciliation owns peerSynchronizer.mu
	go func() { _, err := svc.GetStatus(t.Context()); statusDone <- err }()
	deadline := time.Now().Add(2 * time.Second)
	parked := false
	for time.Now().Before(deadline) {
		stack := make([]byte, 1<<18)
		n := runtime.Stack(stack, true)
		if bytes.Contains(stack[:n], []byte("(*peerSynchronizer).Status")) {
			parked = true
			break
		}
		runtime.Gosched()
	}
	free := svc.mu.TryLock()
	if free {
		svc.mu.Unlock()
	} else {
		skipRevoke = true
	}
	close(release)
	for _, done := range []chan error{reconcileDone, statusDone} {
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("status/reconcile lock cycle")
		}
	}
	if !parked {
		t.Fatal("status never parked on the real peer synchronizer")
	}
	if !free {
		t.Fatal("status held Service.mu while waiting for peerSynchronizer.mu")
	}
}

func TestDiagnosticsConcurrentEngineRetirement(t *testing.T) {
	svc, _, engine, _, _ := newSingleOwnerFixture(t)
	svc.running, svc.rollingHistory = true, NewRollingHistory()
	_ = engine.Router().HandlePacket([]byte{1})
	start, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		<-start
		for range 100 {
			svc.sampleRollingHistory()
		}
	}()
	close(start)
	if err := svc.Stop(); err != nil {
		t.Fatal(err)
	}
	<-done
	d := svc.collectDropCategories()
	if d.ClientMalformed != 1 || d.TotalDrops != 1 {
		t.Fatalf("engine retirement changed loss: %+v", d)
	}
}
