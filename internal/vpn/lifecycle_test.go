package vpn

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-web-ui-go/internal/models"
	"github.com/devops-igor/amnezia-web-ui-go/internal/vpn/endpoint"
)

// TestTunUnavailableManagementMode proves the production wiring contract:
// when the service requires a real TUN device (RequireTunDevice) and the host
// has none, Start fails with an error chain wrapping endpoint.ErrTunUnavailable
// and the subsystem reports a data-plane-down status (listener not running)
// instead of half-starting.
func TestTunUnavailableManagementMode(t *testing.T) {
	if _, statErr := os.Stat(endpoint.TunDevicePath); statErr == nil {
		t.Skip("TUN device available on this host: management-mode degradation cannot be exercised")
	}

	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	svc.RequireTunDevice()

	ctx := context.Background()
	startErr := svc.Start(ctx)
	if !errors.Is(startErr, endpoint.ErrTunUnavailable) {
		t.Fatalf("expected endpoint.ErrTunUnavailable from Start, got: %v", startErr)
	}
	if svc.IsRunning() {
		t.Error("service must not report running after a TUN-unavailable Start")
	}

	status, statErr := svc.GetStatus(ctx)
	if statErr != nil {
		t.Fatalf("GetStatus failed: %v", statErr)
	}
	if status.ListenerRunning {
		t.Error("listener_running must be false in management-only mode")
	}
}

// TestEnableBackendWithoutAWGProtocol proves EnableBackend loads the server's
// AWG credentials and refuses to enable a server without the AWG protocol
// installed.
func TestEnableBackendWithoutAWGProtocol(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	ctx := context.Background()
	srvID, err := db.CreateServer(ctx, &models.Server{
		Name:      "no-awg-host",
		Host:      "198.51.100.10",
		Protocols: map[string]any{},
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	enableErr := svc.EnableBackend(ctx, srvID)
	if enableErr == nil {
		t.Fatal("expected error enabling backend without AWG protocol")
	}
	if !strings.Contains(enableErr.Error(), "AWG") {
		t.Errorf("expected AWG-related error, got: %v", enableErr)
	}
}
