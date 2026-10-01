package vpn

import (
	"context"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

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
