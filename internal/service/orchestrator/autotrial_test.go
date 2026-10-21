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
		{name: "dns_rotates_to_sip", current: models.AWGMimicryDNS, want: models.AWGMimicrySIP},
		{name: "quic_rotates_to_sip", current: models.AWGMimicryQUIC, want: models.AWGMimicrySIP},
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
	// Verify continuous cycle starting from Auto advances to DNS and cycles strictly between SIP and DNS:
	// auto -> dns -> sip -> dns -> sip ...
	cycle := []models.AWGMimicryProfile{
		models.AWGMimicryAuto,
		models.AWGMimicryDNS,
		models.AWGMimicrySIP,
		models.AWGMimicryDNS,
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
	// An active auto client that had established a handshake but subsequently stalled (> 180s).
	// Initial mimicry on remote is "sip" (or "auto").
	// RotateMimicry simulates the lockstep rotation cycling strictly between SIP and DNS:
	// auto/sip -> dns -> sip -> dns
	remoteMimicry := "sip"
	awgMgr.clients = []map[string]any{
		{
			"clientId": "cid-consecutive",
			"userData": map[string]any{
				"latestHandshake": "5 minutes ago",
			},
		},
	}
	awgMgr.rotateFunc = func(ctx context.Context, server *models.Server, clientID string) (string, error) {
		switch remoteMimicry {
		case "auto", "sip":
			remoteMimicry = "dns"
		case "dns":
			remoteMimicry = "sip"
		default:
			remoteMimicry = "dns"
		}
		// Also update the mock clientsTable with rotated profile and timestamp like real RotateMimicry
		awgMgr.clients[0]["userData"].(map[string]any)["awg_mimicry"] = remoteMimicry
		awgMgr.clients[0]["userData"].(map[string]any)["rotated_at"] = time.Now().UTC().Format(time.RFC3339)
		return remoteMimicry, nil
	}
	reg.Register(awgMgr)

	orch := New(db, reg)

	// Step (a): Stalled client with no prior rotation rotates auto -> dns
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

	// Step (b): Second background run immediately afterwards (within cooldown) skips rotation and retains dns
	if err := orch.CheckAutoTrialHandshakes(ctx); err != nil {
		t.Fatalf("second CheckAutoTrialHandshakes failed: %v", err)
	}

	if len(awgMgr.rotatedProfiles) != 1 {
		t.Fatalf("expected rotation to be skipped within cooldown, but rotated %d times: %v", len(awgMgr.rotatedProfiles), awgMgr.rotatedProfiles)
	}
	if remoteMimicry != "dns" {
		t.Fatalf("expected remote mimicry to retain dns, got %q", remoteMimicry)
	}

	uc2, err := db.GetConnection(ctx, connID)
	if err != nil {
		t.Fatalf("failed to get connection after second run: %v", err)
	}
	if uc2.AWGMimicry != models.AWGMimicryAuto {
		t.Fatalf("expected awg_mimicry in DB to remain %q after second run, got %q", models.AWGMimicryAuto, uc2.AWGMimicry)
	}

	// Step (c): Background run after cooldown expiry advances to sip (never QUIC/TLS)
	// Simulate cooldown expiry by advancing rotated_at past DefaultAutoTrialCooldown
	expiredTime := time.Now().Add(-(DefaultAutoTrialCooldown + time.Hour)).UTC().Format(time.RFC3339)
	awgMgr.clients[0]["userData"].(map[string]any)["rotated_at"] = expiredTime

	if err := orch.CheckAutoTrialHandshakes(ctx); err != nil {
		t.Fatalf("third CheckAutoTrialHandshakes failed: %v", err)
	}

	if len(awgMgr.rotatedProfiles) != 2 || awgMgr.rotatedProfiles[1] != "sip" {
		t.Fatalf("expected rotation to advance to sip after cooldown expiry, got %v", awgMgr.rotatedProfiles)
	}
	if remoteMimicry != "sip" {
		t.Fatalf("expected remote mimicry to advance to sip, got %q", remoteMimicry)
	}

	uc3, err := db.GetConnection(ctx, connID)
	if err != nil {
		t.Fatalf("failed to get connection after third run: %v", err)
	}
	if uc3.AWGMimicry != models.AWGMimicryAuto {
		t.Fatalf("expected awg_mimicry in DB to remain %q after third run, got %q", models.AWGMimicryAuto, uc3.AWGMimicry)
	}
}

func TestCheckAutoTrialHandshakes_DormantClient_DoesNotRotateFromSIP(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	sID, err := db.CreateServer(ctx, &models.Server{
		Name:    "AWG Server Dormant",
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
		Username: "dormant_user",
		Role:     models.RoleUser,
		Enabled:  true,
	})
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	dormantCases := []struct {
		name      string
		cid       string
		handshake any
	}{
		{name: "handshake_never", cid: "cid-dormant-never", handshake: "never"},
		{name: "handshake_none", cid: "cid-dormant-none", handshake: "(none)"},
		{name: "handshake_empty", cid: "cid-dormant-empty", handshake: ""},
		{name: "handshake_zero", cid: "cid-dormant-zero", handshake: int64(0)},
		{name: "handshake_nil", cid: "cid-dormant-nil", handshake: nil},
		{name: "handshake_unreported", cid: "cid-dormant-unreported", handshake: "omit"},
	}

	var connIDs []string
	var remoteClients []map[string]any

	for _, dc := range dormantCases {
		connID, err := db.CreateConnection(ctx, &models.UserConnection{
			UserID:     uID,
			ServerID:   sID,
			Protocol:   "awg",
			ClientID:   dc.cid,
			Name:       "auto_vpn_" + dc.cid,
			AWGMimicry: models.AWGMimicryAuto,
			CreatedAt:  time.Now().UTC(),
		})
		if err != nil {
			t.Fatalf("failed to create connection for %s: %v", dc.cid, err)
		}
		connIDs = append(connIDs, connID)

		if dc.handshake != "omit" {
			userData := map[string]any{
				"awg_mimicry": "sip",
			}
			if dc.handshake != nil {
				userData["latestHandshake"] = dc.handshake
			}
			remoteClients = append(remoteClients, map[string]any{
				"clientId": dc.cid,
				"userData": userData,
			})
		}
	}

	reg := newMockOrchRegistry()
	awgMgr := newMockOrchProtocolManager("awg")
	awgMgr.clients = remoteClients
	reg.Register(awgMgr)

	orch := New(db, reg)

	// Execute CheckAutoTrialHandshakes across multiple background runs (simulating cron ticks over several days)
	for run := 1; run <= 5; run++ {
		if err := orch.CheckAutoTrialHandshakes(ctx); err != nil {
			t.Fatalf("run %d failed: %v", run, err)
		}
	}

	// Verify that NO dormant client was ever rotated
	if len(awgMgr.rotated) != 0 || len(awgMgr.rotatedProfiles) != 0 {
		t.Fatalf("expected 0 rotations for dormant clients, but got rotated=%v, profiles=%v", awgMgr.rotated, awgMgr.rotatedProfiles)
	}

	// Verify all DB connections maintain auto mimicry, preserving default SIP configuration
	for _, cid := range connIDs {
		uc, err := db.GetConnection(ctx, cid)
		if err != nil {
			t.Fatalf("failed to get connection %s: %v", cid, err)
		}
		if uc.AWGMimicry != models.AWGMimicryAuto {
			t.Fatalf("expected connection %s AWGMimicry to remain auto, got %q", cid, uc.AWGMimicry)
		}
	}
}

func TestExtractClientStatus_RotatedAt(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	nowStr := now.Format(time.RFC3339)

	clients := []map[string]any{
		{
			"clientId": "c1",
			"userData": map[string]any{
				"latestHandshake": "never",
				"rotated_at":      nowStr,
			},
		},
		{
			"clientId": "c2",
			"userData": map[string]any{
				"latestHandshake": "never",
				"rotated_at":      "invalid-time",
			},
		},
		{
			"clientId": "c3",
			"userData": map[string]any{
				"latestHandshake": "never",
			},
		},
	}

	_, _, rotatedTimes := extractClientStatus(clients)
	if len(rotatedTimes) != 1 {
		t.Fatalf("expected 1 parsed rotation time, got %d", len(rotatedTimes))
	}
	if !rotatedTimes["c1"].Equal(now) {
		t.Fatalf("expected c1 rotated time %v, got %v", now, rotatedTimes["c1"])
	}
	if _, ok := rotatedTimes["c2"]; ok {
		t.Fatalf("expected c2 invalid rotated time not to be parsed")
	}
	if _, ok := rotatedTimes["c3"]; ok {
		t.Fatalf("expected c3 without rotated time not to be in map")
	}
}
