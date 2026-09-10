package vpn

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-web-ui-go/internal/models"
)

type mockAWGRoutingRemediator struct {
	mu           sync.Mutex
	status       map[string]any
	statusErr    error
	remediated   []remediationCall
	remediateErr error
	onRemediate  func(server *models.Server, subnet string)
}

type remediationCall struct {
	ServerID int64
	Subnet   string
}

func (m *mockAWGRoutingRemediator) GetServerStatus(ctx context.Context, server *models.Server) (map[string]any, error) {
	return m.status, m.statusErr
}

func (m *mockAWGRoutingRemediator) EnsureBackendRoutingAndNAT(ctx context.Context, server *models.Server, subnet string) error {
	m.mu.Lock()
	m.remediated = append(m.remediated, remediationCall{
		ServerID: server.ID,
		Subnet:   subnet,
	})
	onRem := m.onRemediate
	err := m.remediateErr
	m.mu.Unlock()

	if onRem != nil {
		onRem(server, subnet)
	}
	return err
}

func TestService_GetPortalSubnet(t *testing.T) {
	t.Run("nil config returns default subnet", func(t *testing.T) {
		svc := &Service{}
		if got := svc.getPortalSubnet(); got != "10.100.0.0/16" {
			t.Errorf("expected 10.100.0.0/16, got %s", got)
		}
	})

	t.Run("empty SubnetCIDR returns default subnet", func(t *testing.T) {
		svc := &Service{cfg: &models.VPNConfig{SubnetCIDR: ""}}
		if got := svc.getPortalSubnet(); got != "10.100.0.0/16" {
			t.Errorf("expected 10.100.0.0/16, got %s", got)
		}
	})

	t.Run("configured SubnetCIDR is returned", func(t *testing.T) {
		svc := &Service{cfg: &models.VPNConfig{SubnetCIDR: "10.250.0.0/16"}}
		if got := svc.getPortalSubnet(); got != "10.250.0.0/16" {
			t.Errorf("expected 10.250.0.0/16, got %s", got)
		}
	})
}

func TestService_EnableBackend_RemediatesRoutingAndNAT(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	svc.cfg.SubnetCIDR = "10.180.0.0/16"

	ctx := context.Background()
	srvID, err := db.CreateServer(ctx, &models.Server{
		Name: "awg-routing-server",
		Host: "198.51.100.40",
		Protocols: map[string]any{
			"awg": map[string]any{
				"installed":  true,
				"port":       51820,
				"public_key": "server-endpoint-pubkey",
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	mockRem := &mockAWGRoutingRemediator{}
	svc.SetAWGStatusProvider(mockRem)

	if err := svc.EnableBackend(ctx, srvID); err != nil {
		t.Fatalf("EnableBackend failed: %v", err)
	}

	mockRem.mu.Lock()
	defer mockRem.mu.Unlock()
	if len(mockRem.remediated) == 0 {
		t.Fatal("expected EnsureBackendRoutingAndNAT to be called on EnableBackend")
	}
	call := mockRem.remediated[0]
	if call.ServerID != srvID {
		t.Errorf("expected server ID %d, got %d", srvID, call.ServerID)
	}
	if call.Subnet != "10.180.0.0/16" {
		t.Errorf("expected subnet 10.180.0.0/16, got %s", call.Subnet)
	}
}

func TestService_EnableBackend_SafeOnRemediationFailure(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	ctx := context.Background()
	srvID, err := db.CreateServer(ctx, &models.Server{
		Name: "awg-routing-fail-server",
		Host: "198.51.100.41",
		Protocols: map[string]any{
			"awg": map[string]any{
				"installed":  true,
				"port":       51820,
				"public_key": "server-endpoint-pubkey",
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	// When remediation fails with temporary SSH error, EnableBackend should log warning and not crash/fail
	mockRem := &mockAWGRoutingRemediator{
		remediateErr: errors.New("ssh connection refused"),
	}
	svc.SetAWGStatusProvider(mockRem)

	if err := svc.EnableBackend(ctx, srvID); err != nil {
		t.Fatalf("EnableBackend should not fail when remediation has SSH error, got: %v", err)
	}
}

func TestService_AttachBackendForwarder_TriggersRemediation(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	svc.cfg.SubnetCIDR = "10.190.0.0/16"

	ctx := context.Background()
	srvID, err := db.CreateServer(ctx, &models.Server{
		Name: "awg-attach-server",
		Host: "198.51.100.42",
		Protocols: map[string]any{
			"awg": map[string]any{
				"installed":  true,
				"port":       51820,
				"public_key": "server-endpoint-pubkey",
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	done := make(chan struct{}, 1)
	mockRem := &mockAWGRoutingRemediator{
		onRemediate: func(server *models.Server, subnet string) {
			select {
			case done <- struct{}{}:
			default:
			}
		},
	}
	svc.SetAWGStatusProvider(mockRem)

	tun := &models.BackendTunnel{
		ID:         100,
		ServerID:   srvID,
		Endpoint:   "198.51.100.42:51820",
		PublicKey:  "server-endpoint-pubkey",
		PrivateKey: "cGFzc3dvcmRmb3J0ZXN0aW5ncHVycG9zZXMxMjM0NQ==",
	}

	if err := svc.attachBackendForwarder(tun, nil); err != nil {
		t.Fatalf("attachBackendForwarder failed: %v", err)
	}

	select {
	case <-done:
		// Succeeded in background
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for background routing remediation")
	}

	mockRem.mu.Lock()
	defer mockRem.mu.Unlock()
	if len(mockRem.remediated) == 0 {
		t.Fatal("expected remediation call")
	}
	if mockRem.remediated[0].ServerID != srvID {
		t.Errorf("expected server ID %d, got %d", srvID, mockRem.remediated[0].ServerID)
	}
	if mockRem.remediated[0].Subnet != "10.190.0.0/16" {
		t.Errorf("expected subnet 10.190.0.0/16, got %s", mockRem.remediated[0].Subnet)
	}
}

func TestService_AttachBackendForwarder_RetriesUntilAWGProviderSet(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	svc.cfg.SubnetCIDR = "10.191.0.0/16"

	ctx := context.Background()
	srvID, err := db.CreateServer(ctx, &models.Server{
		Name: "awg-retry-server",
		Host: "198.51.100.43",
		Protocols: map[string]any{
			"awg": map[string]any{
				"installed":  true,
				"port":       51820,
				"public_key": "server-endpoint-pubkey",
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	done := make(chan struct{}, 1)
	mockRem := &mockAWGRoutingRemediator{
		onRemediate: func(server *models.Server, subnet string) {
			select {
			case done <- struct{}{}:
			default:
			}
		},
	}

	tun := &models.BackendTunnel{
		ID:         101,
		ServerID:   srvID,
		Endpoint:   "198.51.100.43:51820",
		PublicKey:  "server-endpoint-pubkey",
		PrivateKey: "cGFzc3dvcmRmb3J0ZXN0aW5ncHVycG9zZXMxMjM0NQ==",
	}

	// Attach forwarder BEFORE setting AWGStatusProvider (simulating startup race)
	if err := svc.attachBackendForwarder(tun, nil); err != nil {
		t.Fatalf("attachBackendForwarder failed: %v", err)
	}

	// Short sleep then set provider during the retry window
	time.Sleep(300 * time.Millisecond)
	svc.SetAWGStatusProvider(mockRem)

	select {
	case <-done:
		// Succeeded via retry
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for background routing remediation after provider set")
	}

	mockRem.mu.Lock()
	defer mockRem.mu.Unlock()
	if len(mockRem.remediated) == 0 {
		t.Fatal("expected remediation call after provider set")
	}
	if mockRem.remediated[0].ServerID != srvID {
		t.Errorf("expected server ID %d, got %d", srvID, mockRem.remediated[0].ServerID)
	}
	if mockRem.remediated[0].Subnet != "10.191.0.0/16" {
		t.Errorf("expected subnet 10.191.0.0/16, got %s", mockRem.remediated[0].Subnet)
	}
}

func TestService_RemediateBackendRouting_EdgeCases(t *testing.T) {
	ctx := context.Background()

	t.Run("nil db returns error", func(t *testing.T) {
		svc := &Service{}
		err := svc.remediateBackendRouting(ctx, 1)
		if err == nil || !strings.Contains(err.Error(), "database not available") {
			t.Errorf("expected database not available error, got: %v", err)
		}
	})

	t.Run("nil awgProvider returns error", func(t *testing.T) {
		db := setupTestDB(t)
		svc := &Service{db: db}
		err := svc.remediateBackendRouting(ctx, 1)
		if err == nil || !strings.Contains(err.Error(), "awg provider not available") {
			t.Errorf("expected awg provider not available error, got: %v", err)
		}
	})

	t.Run("provider does not implement RoutingRemediator is a no-op", func(t *testing.T) {
		db := setupTestDB(t)
		svc := &Service{db: db, awgProvider: &mockAWGStatusProvider{}}
		err := svc.remediateBackendRouting(ctx, 1)
		if err != nil {
			t.Errorf("expected nil error for non-remediator provider, got: %v", err)
		}
	})

	t.Run("server not found returns error", func(t *testing.T) {
		db := setupTestDB(t)
		svc := &Service{
			db:          db,
			awgProvider: &mockAWGRoutingRemediator{},
		}
		err := svc.remediateBackendRouting(ctx, 999999)
		if err == nil || !strings.Contains(err.Error(), "not found") {
			t.Errorf("expected not found error, got: %v", err)
		}
	})
}
