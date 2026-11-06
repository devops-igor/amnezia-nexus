package orchestrator

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

type mockCanaryUpdater struct {
	db              *database.DB
	mu              sync.Mutex
	tunnels         map[int64]*models.BackendTunnel
	canaryErr       error
	canaryCalls     int
	hasCanary       bool
	onCanarySuccess func(tunnelID int64)
	updates         []string
}

func newMockCanaryUpdater(db *database.DB, tunnels ...*models.BackendTunnel) *mockCanaryUpdater {
	m := &mockCanaryUpdater{
		db:        db,
		tunnels:   make(map[int64]*models.BackendTunnel),
		hasCanary: true,
	}
	for _, t := range tunnels {
		cp := *t
		m.tunnels[t.ServerID] = &cp
	}
	return m
}

func (m *mockCanaryUpdater) GetTunnel(serverID int64) (*models.BackendTunnel, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tunnels[serverID]
	if !ok {
		return nil, errors.New("tunnel not found")
	}
	cp := *t
	return &cp, nil
}

func (m *mockCanaryUpdater) SetTunnelStatus(ctx context.Context, serverID int64, status string, latencyMS int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.updates = append(m.updates, status)
	if t, ok := m.tunnels[serverID]; ok {
		t.Status = status
		t.LatencyMS = latencyMS
		if m.db != nil {
			_ = m.db.UpdateBackendTunnelStatus(ctx, t.ID, status, latencyMS)
		}
	}
	return nil
}

func (m *mockCanaryUpdater) SetTunnelStatusWithVersion(ctx context.Context, serverID, expectedTunnelID, expectedVersion int64, status string, latencyMS int64) error {
	return m.SetTunnelStatus(ctx, serverID, status, latencyMS)
}

func (m *mockCanaryUpdater) SetCanarySuccessCallback(cb func(tunnelID int64)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onCanarySuccess = cb
}

func (m *mockCanaryUpdater) ProbeCanary(ctx context.Context, tunnel *models.BackendTunnel) error {
	m.mu.Lock()
	m.canaryCalls++
	err := m.canaryErr
	cb := m.onCanarySuccess
	m.mu.Unlock()
	if err == nil && cb != nil && tunnel != nil {
		cb(tunnel.ID)
	}
	return err
}

func (m *mockCanaryUpdater) HasCanaryProber(tunnel *models.BackendTunnel) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.hasCanary
}

func TestOrchestrator_HandshakeBlocked_PreservesSessionsUnderOuterFailure(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	_ = db.SaveVPNConfig(ctx, &models.VPNConfig{HealthThresholdMS: 500})

	s1, _ := db.CreateServer(ctx, &models.Server{Name: "Server 1", Host: "10.0.0.1"})
	s2, _ := db.CreateServer(ctx, &models.Server{Name: "Server 2", Host: "10.0.0.2"})

	t1, _ := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      s1,
		InterfaceName: "awg0",
		PublicKey:     "pub1",
		Endpoint:      "10.0.0.1:51820",
		Status:        models.TunnelStatusHandshakeBlocked,
		Enabled:       true,
	})
	t2, _ := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      s2,
		InterfaceName: "awg1",
		PublicKey:     "pub2",
		Endpoint:      "10.0.0.2:51820",
		Status:        models.TunnelStatusActive,
		Enabled:       true,
	})

	uID, _ := db.CreateUser(ctx, &models.User{Username: "alice", Role: models.RoleUser})
	sessID := "session-alice-1"
	_ = db.CreateVPNSession(ctx, &models.VPNSession{
		ID:              sessID,
		UserID:          uID,
		BackendTunnelID: t1,
		PeerPublicKey:   "peer-alice-pub",
		AssignedIP:      "10.100.1.10",
		Status:          "connected",
	})

	tun1, _ := db.GetBackendTunnel(ctx, t1)
	tun2, _ := db.GetBackendTunnel(ctx, t2)
	updater := newMockCanaryUpdater(db, tun1, tun2)

	// Outer probe for t1 fails (simulating DPI handshake drop); t2 succeeds
	orch := New(db, nil, WithProbeFunc(func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		if strings.Contains(endpoint, "10.0.0.1") {
			return 0, errors.New("DPI handshake drop")
		}
		return 25 * time.Millisecond, nil
	}), WithTunnelStatusUpdater(updater))

	// Run health checks across failure threshold
	for i := 0; i < orch.ProbeFailureThreshold(); i++ {
		if err := orch.CheckBackendTunnelHealth(ctx); err != nil {
			t.Fatalf("CheckBackendTunnelHealth failed: %v", err)
		}
	}

	// Verify t1 is preserved in handshake_blocked and NOT degraded
	res1, err := db.GetBackendTunnel(ctx, t1)
	if err != nil {
		t.Fatal(err)
	}
	if res1.Status != models.TunnelStatusHandshakeBlocked {
		t.Fatalf("expected status %s, got %s", models.TunnelStatusHandshakeBlocked, res1.Status)
	}

	// Verify session on t1 was NOT migrated
	sess, err := db.GetVPNSessionByID(ctx, sessID)
	if err != nil {
		t.Fatal(err)
	}
	if sess.BackendTunnelID != t1 {
		t.Fatalf("expected session to stay on tunnel %d, but was migrated to %d", t1, sess.BackendTunnelID)
	}
}

func TestOrchestrator_HandshakeBlocked_RecoveryRequiresInnerCanary(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	_ = db.SaveVPNConfig(ctx, &models.VPNConfig{HealthThresholdMS: 500})

	s1, _ := db.CreateServer(ctx, &models.Server{Name: "Server 1", Host: "10.0.0.1"})
	t1, _ := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      s1,
		InterfaceName: "awg0",
		PublicKey:     "pub1",
		Endpoint:      "10.0.0.1:51820",
		Status:        models.TunnelStatusHandshakeBlocked,
		Enabled:       true,
	})

	tun1, _ := db.GetBackendTunnel(ctx, t1)
	updater := newMockCanaryUpdater(db, tun1)

	// Outer probe succeeds
	orch := New(db, nil, WithProbeFunc(func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 20 * time.Millisecond, nil
	}), WithTunnelStatusUpdater(updater))

	// Case 1: Outer probe succeeds, but inner canary probe fails -> must transition to degraded (BLOCKER 1: data-plane failure)
	updater.canaryErr = errors.New("inner data plane blackhole")
	if err := orch.CheckBackendTunnelHealth(ctx); err != nil {
		t.Fatalf("CheckBackendTunnelHealth failed: %v", err)
	}

	res1, _ := db.GetBackendTunnel(ctx, t1)
	if res1.Status != models.TunnelStatusDegraded {
		t.Fatalf("tunnel MUST transition to degraded when canary fails, got %s", res1.Status)
	}
	if updater.canaryCalls == 0 {
		t.Fatal("expected canary probe to be called during recovery check")
	}

	// Case 2: BOTH outer probe and inner canary probe succeed!
	updater.canaryErr = nil
	if err := orch.CheckBackendTunnelHealth(ctx); err != nil {
		t.Fatalf("CheckBackendTunnelHealth failed: %v", err)
	}

	resRecovered, _ := db.GetBackendTunnel(ctx, t1)
	if resRecovered.Status != models.TunnelStatusActive {
		t.Fatalf("tunnel MUST recover to active when both succeed, got %s", resRecovered.Status)
	}
}

func TestOrchestrator_HandshakeBlocked_BothProbesFail_Degrades(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	_ = db.SaveVPNConfig(ctx, &models.VPNConfig{HealthThresholdMS: 500})

	s1, _ := db.CreateServer(ctx, &models.Server{Name: "Server 1", Host: "10.0.0.1"})
	t1, _ := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      s1,
		InterfaceName: "awg0",
		PublicKey:     "pub1",
		Endpoint:      "10.0.0.1:51820",
		Status:        models.TunnelStatusHandshakeBlocked,
		Enabled:       true,
	})

	tun1, _ := db.GetBackendTunnel(ctx, t1)
	updater := newMockCanaryUpdater(db, tun1)
	updater.canaryErr = errors.New("canary data plane failed")

	orch := New(db, nil, WithProbeFunc(func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 0, errors.New("outer network failure")
	}), WithTunnelStatusUpdater(updater))

	for i := 0; i < orch.ProbeFailureThreshold(); i++ {
		if err := orch.CheckBackendTunnelHealth(ctx); err != nil {
			t.Fatalf("CheckBackendTunnelHealth failed: %v", err)
		}
	}

	res, _ := db.GetBackendTunnel(ctx, t1)
	if res.Status != models.TunnelStatusDegraded {
		t.Fatalf("expected status degraded when both probes fail, got %s", res.Status)
	}
}

func TestOrchestrator_Rework8_PromotionToActiveRejectedWhenInnerCanaryFails(t *testing.T) {
	cases := []struct {
		name          string
		initialStatus string
	}{
		{name: "from connecting", initialStatus: models.TunnelStatusConnecting},
		{name: "from degraded", initialStatus: models.TunnelStatusDegraded},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, cleanup := setupTestDB(t)
			defer cleanup()
			ctx := context.Background()

			_ = db.SaveVPNConfig(ctx, &models.VPNConfig{HealthThresholdMS: 500})

			s1, _ := db.CreateServer(ctx, &models.Server{Name: "Server-" + tc.name, Host: "10.0.0.1"})
			t1, _ := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
				ServerID:      s1,
				InterfaceName: "awg0",
				PublicKey:     "pub1",
				Endpoint:      "10.0.0.1:51820",
				Status:        tc.initialStatus,
				Enabled:       true,
			})

			tun1, _ := db.GetBackendTunnel(ctx, t1)
			updater := newMockCanaryUpdater(db, tun1)

			// Outer probe succeeds (20ms latency)
			orch := New(db, nil, WithProbeFunc(func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
				return 20 * time.Millisecond, nil
			}), WithTunnelStatusUpdater(updater))

			// Inner canary probe fails!
			updater.canaryErr = errors.New("inner data plane blackhole")
			if err := orch.CheckBackendTunnelHealth(ctx); err != nil {
				t.Fatalf("CheckBackendTunnelHealth failed: %v", err)
			}

			// Must NOT be active! Must transition to/stay degraded (BLOCKER 1: inner failure is data-plane failure)
			res, _ := db.GetBackendTunnel(ctx, t1)
			if res.Status == models.TunnelStatusActive {
				t.Fatalf("tunnel MUST NOT be promoted to active when canary fails, got %s", res.Status)
			}
			if res.Status != models.TunnelStatusDegraded {
				t.Fatalf("expected status degraded, got %s", res.Status)
			}
		})
	}
}

func TestOrchestrator_Rework8_InitialOuterFailure_TransitionsToHandshakeBlocked_PreservesConnectedClient(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	_ = db.SaveVPNConfig(ctx, &models.VPNConfig{HealthThresholdMS: 500})

	s1, _ := db.CreateServer(ctx, &models.Server{Name: "Server 1", Host: "10.0.0.1"})
	t1, _ := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:          s1,
		InterfaceName:     "awg0",
		PublicKey:         "pub1",
		Endpoint:          "10.0.0.1:51820",
		Status:            models.TunnelStatusActive,
		Enabled:           true,
		ActiveConnections: 1,
	})

	uID, _ := db.CreateUser(ctx, &models.User{Username: "bob", Role: models.RoleUser})
	sessID := "session-bob-1"
	_ = db.CreateVPNSession(ctx, &models.VPNSession{
		ID:              sessID,
		UserID:          uID,
		BackendTunnelID: t1,
		PeerPublicKey:   "peer-bob-pub",
		AssignedIP:      "10.100.1.20",
		Status:          "connected",
	})

	tun1, _ := db.GetBackendTunnel(ctx, t1)
	updater := newMockCanaryUpdater(db, tun1)

	// Outer probe fails on cycle 1 (< threshold 3); inner canary succeeds
	orch := New(db, nil, WithProbeFunc(func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 0, errors.New("initial DPI outer handshake packet drop")
	}), WithTunnelStatusUpdater(updater))

	// Run single health check (failures=1 < threshold=3)
	if err := orch.CheckBackendTunnelHealth(ctx); err != nil {
		t.Fatalf("CheckBackendTunnelHealth failed: %v", err)
	}

	// Verify tunnel transitioned to handshake_blocked (not active, not degraded)
	res1, _ := db.GetBackendTunnel(ctx, t1)
	if res1.Status != models.TunnelStatusHandshakeBlocked {
		t.Fatalf("expected status %s during initial outer failure with active sessions, got %s", models.TunnelStatusHandshakeBlocked, res1.Status)
	}

	// Verify session on t1 was NOT migrated
	sess, err := db.GetVPNSessionByID(ctx, sessID)
	if err != nil {
		t.Fatal(err)
	}
	if sess.BackendTunnelID != t1 {
		t.Fatalf("expected session to remain on tunnel %d, but migrated to %d", t1, sess.BackendTunnelID)
	}
}

func TestOrchestrator_Rework14_ScheduledBootstrapRequiresInnerProof(t *testing.T) {
	cases := []struct {
		name           string
		initialStatus  string
		hasCanary      bool
		canaryErr      error
		expectedStatus string
	}{
		{
			name:           "connecting without canary prober remains connecting",
			initialStatus:  models.TunnelStatusConnecting,
			hasCanary:      false,
			canaryErr:      nil,
			expectedStatus: models.TunnelStatusConnecting,
		},
		{
			name:           "degraded with ErrNoActiveDevice does not promote to active",
			initialStatus:  models.TunnelStatusDegraded,
			hasCanary:      true,
			canaryErr:      tunnel.ErrNoActiveDevice,
			expectedStatus: models.TunnelStatusDegraded,
		},
		{
			name:           "handshake_blocked without canary prober remains blocked",
			initialStatus:  models.TunnelStatusHandshakeBlocked,
			hasCanary:      false,
			canaryErr:      nil,
			expectedStatus: models.TunnelStatusHandshakeBlocked,
		},
		{
			name:           "handshake_blocked with ErrNoActiveDevice degrades",
			initialStatus:  models.TunnelStatusHandshakeBlocked,
			hasCanary:      true,
			canaryErr:      tunnel.ErrNoActiveDevice,
			expectedStatus: models.TunnelStatusDegraded,
		},
		{
			name:           "connecting with true canary failure transitions to degraded",
			initialStatus:  models.TunnelStatusConnecting,
			hasCanary:      true,
			canaryErr:      errors.New("inner canary drop"),
			expectedStatus: models.TunnelStatusDegraded,
		},
		{
			name:           "connecting with attached good canary promotes to active",
			initialStatus:  models.TunnelStatusConnecting,
			hasCanary:      true,
			canaryErr:      nil,
			expectedStatus: models.TunnelStatusActive,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, cleanup := setupTestDB(t)
			defer cleanup()
			ctx := context.Background()

			_ = db.SaveVPNConfig(ctx, &models.VPNConfig{HealthThresholdMS: 500})

			s1, _ := db.CreateServer(ctx, &models.Server{Name: "Server-" + tc.name, Host: "10.0.0.1"})
			t1, _ := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
				ServerID:      s1,
				InterfaceName: "awg0",
				PublicKey:     "pub1",
				Endpoint:      "10.0.0.1:51820",
				Status:        tc.initialStatus,
				Enabled:       true,
			})

			tun1, _ := db.GetBackendTunnel(ctx, t1)
			updater := newMockCanaryUpdater(db, tun1)
			updater.hasCanary = tc.hasCanary
			updater.canaryErr = tc.canaryErr

			orch := New(db, nil, WithProbeFunc(func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
				return 20 * time.Millisecond, nil
			}), WithTunnelStatusUpdater(updater))

			if err := orch.CheckBackendTunnelHealth(ctx); err != nil {
				t.Fatalf("CheckBackendTunnelHealth failed: %v", err)
			}

			res, _ := db.GetBackendTunnel(ctx, t1)
			if res.Status != tc.expectedStatus {
				t.Fatalf("expected status %s, got %s", tc.expectedStatus, res.Status)
			}
		})
	}
}
