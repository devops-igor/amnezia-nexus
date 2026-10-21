package orchestrator

import (
	"context"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestNextMimicryProfile_RotationOrder(t *testing.T) {
	tests := []struct {
		name    string
		current models.AWGMimicryProfile
		want    models.AWGMimicryProfile
	}{
		{name: "auto_rotates_to_dns", current: models.AWGMimicryAuto, want: models.AWGMimicryDNS},
		{name: "empty_rotates_to_dns", current: "", want: models.AWGMimicryDNS},
		{name: "sip_rotates_to_dns", current: models.AWGMimicrySIP, want: models.AWGMimicryDNS},
		{name: "dns_rotates_to_quic", current: models.AWGMimicryDNS, want: models.AWGMimicryQUIC},
		{name: "quic_rotates_to_tls", current: models.AWGMimicryQUIC, want: models.AWGMimicryTLS},
		{name: "tls_rotates_to_sip", current: models.AWGMimicryTLS, want: models.AWGMimicrySIP},
		{name: "unknown_rotates_to_dns", current: "unknown", want: models.AWGMimicryDNS},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NextMimicryProfile(tt.current)
			if got != tt.want {
				t.Errorf("NextMimicryProfile(%q) = %q, want %q", tt.current, got, tt.want)
			}
		})
	}
}

func TestNextMimicryProfile_FullCycle(t *testing.T) {
	// Verify continuous cycle starting from Auto advances to DNS and cycles indefinitely:
	// auto -> dns -> quic -> tls -> sip -> dns ...
	cycle := []models.AWGMimicryProfile{
		models.AWGMimicryAuto,
		models.AWGMimicryDNS,
		models.AWGMimicryQUIC,
		models.AWGMimicryTLS,
		models.AWGMimicrySIP,
		models.AWGMimicryDNS,
	}

	curr := cycle[0]
	for i := 1; i < len(cycle); i++ {
		next := NextMimicryProfile(curr)
		if next != cycle[i] {
			t.Fatalf("step %d from %q: expected %q, got %q", i, curr, cycle[i], next)
		}
		curr = next
	}
}

func TestCheckAutoTrialHandshakes_ConsecutiveRotations_DoNotFilterOut(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	sID, err := db.CreateServer(ctx, &models.Server{
		Name:    "AWG Server",
		Host:    "10.0.0.1",
		SSHPort: 22,
		Protocols: map[string]any{
			"awg": map[string]any{"port": 55424},
		},
	})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	uID, err := db.CreateUser(ctx, &models.User{
		Username: "autotrial_consecutive_user",
		Role:     models.RoleUser,
		Enabled:  true,
	})
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	connID, err := db.CreateConnection(ctx, &models.UserConnection{
		UserID:     uID,
		ServerID:   sID,
		Protocol:   "awg",
		ClientID:   "cid-consecutive",
		Name:       "auto_vpn_consecutive",
		AWGMimicry: models.AWGMimicryAuto,
		CreatedAt:  time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("failed to create connection: %v", err)
	}

	reg := newMockOrchRegistry()
	awgMgr := newMockOrchProtocolManager("awg")

	// The remote server's clientsTable tracks the active mimicry profile.
	// An auto connection initially runs with SIP, so initial mimicry on remote is "auto" (or "sip").
	// RotateMimicry simulates the lockstep rotation:
	// auto/sip -> dns -> quic -> tls -> sip
	remoteMimicry := "auto"
	awgMgr.clients = []map[string]any{
		{
			"clientId": "cid-consecutive",
			"userData": map[string]any{
				"latestHandshake": "never",
			},
		},
	}
	awgMgr.rotateFunc = func(ctx context.Context, server *models.Server, clientID string) (string, error) {
		switch remoteMimicry {
		case "auto", "sip":
			remoteMimicry = "dns"
		case "dns":
			remoteMimicry = "quic"
		case "quic":
			remoteMimicry = "tls"
		case "tls":
			remoteMimicry = "sip"
		default:
			remoteMimicry = "dns"
		}
		return remoteMimicry, nil
	}
	reg.Register(awgMgr)

	orch := New(db, reg)

	// First run: stalled connection should rotate to dns while keeping "auto" in DB
	if err := orch.CheckAutoTrialHandshakes(ctx); err != nil {
		t.Fatalf("first CheckAutoTrialHandshakes failed: %v", err)
	}

	if len(awgMgr.rotatedProfiles) != 1 || awgMgr.rotatedProfiles[0] != "dns" {
		t.Fatalf("expected first rotation to advance to dns, got %v", awgMgr.rotatedProfiles)
	}

	uc1, err := db.GetConnection(ctx, connID)
	if err != nil {
		t.Fatalf("failed to get connection after first run: %v", err)
	}
	if uc1.AWGMimicry != models.AWGMimicryAuto {
		t.Fatalf("expected awg_mimicry in DB to remain %q after first rotation, got %q", models.AWGMimicryAuto, uc1.AWGMimicry)
	}

	// Second run: connection must NOT be filtered out because DB still has "auto".
	// It should rotate again, advancing to quic.
	if err := orch.CheckAutoTrialHandshakes(ctx); err != nil {
		t.Fatalf("second CheckAutoTrialHandshakes failed: %v", err)
	}

	if len(awgMgr.rotatedProfiles) != 2 || awgMgr.rotatedProfiles[1] != "quic" {
		t.Fatalf("expected second rotation to advance to quic, got %v", awgMgr.rotatedProfiles)
	}

	uc2, err := db.GetConnection(ctx, connID)
	if err != nil {
		t.Fatalf("failed to get connection after second run: %v", err)
	}
	if uc2.AWGMimicry != models.AWGMimicryAuto {
		t.Fatalf("expected awg_mimicry in DB to remain %q after second rotation, got %q", models.AWGMimicryAuto, uc2.AWGMimicry)
	}
}
