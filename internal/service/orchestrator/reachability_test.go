package orchestrator

import (
	"context"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestOrchestrator_DataPlaneI1Protocol(t *testing.T) {
	ctx := context.Background()

	t.Run("returns sip by default when db is nil", func(t *testing.T) {
		orch := &Orchestrator{}
		if got := orch.dataPlaneI1Protocol(ctx); got != "sip" {
			t.Errorf("expected default 'sip', got %q", got)
		}
	})

	t.Run("returns sip by default when vpn_config is unset", func(t *testing.T) {
		db, cleanup := setupTestDB(t)
		defer cleanup()

		orch := New(db, nil)
		if got := orch.dataPlaneI1Protocol(ctx); got != "sip" {
			t.Errorf("expected default 'sip', got %q", got)
		}
	})

	t.Run("returns configured dns protocol", func(t *testing.T) {
		db, cleanup := setupTestDB(t)
		defer cleanup()

		if err := db.SaveVPNConfig(ctx, &models.VPNConfig{
			VPNDataPlaneI1Protocol: "dns",
		}); err != nil {
			t.Fatalf("SaveVPNConfig failed: %v", err)
		}

		orch := New(db, nil)
		if got := orch.dataPlaneI1Protocol(ctx); got != "dns" {
			t.Errorf("expected 'dns', got %q", got)
		}
	})

	t.Run("returns configured sip protocol", func(t *testing.T) {
		db, cleanup := setupTestDB(t)
		defer cleanup()

		if err := db.SaveVPNConfig(ctx, &models.VPNConfig{
			VPNDataPlaneI1Protocol: "sip",
		}); err != nil {
			t.Fatalf("SaveVPNConfig failed: %v", err)
		}

		orch := New(db, nil)
		if got := orch.dataPlaneI1Protocol(ctx); got != "sip" {
			t.Errorf("expected 'sip', got %q", got)
		}
	})
}

func TestOrchestrator_ProbeAWGHealth_ProtocolAlignment(t *testing.T) {
	ctx := context.Background()

	t.Run("probeAWGHealth executes with sip by default", func(t *testing.T) {
		db, cleanup := setupTestDB(t)
		defer cleanup()

		orch := New(db, nil)
		server := &models.Server{
			ID:   1,
			Host: "127.0.0.1",
		}

		// Probing against a closed UDP port: PerformAWGHandshake completes and returns profile
		reachRes, autoTrials, ok := orch.probeAWGHealth(
			ctx,
			server,
			"127.0.0.1",
			54321,
			"BSX9ZtdoVp6sTwS+ziidJqp/aBjHrp1+xSOzc3+Z36Y=",
			"",
			"",
			"",
			nil,
		)
		if ok {
			t.Errorf("expected ok=false for unreachable mock port")
		}
		if reachRes == nil {
			t.Fatalf("expected non-nil reachRes")
		}
		if profile, exists := reachRes["profile"]; !exists || profile != "sip" {
			t.Errorf("expected primary reachability probe profile 'sip', got %v", profile)
		}
		if autoTrials == nil {
			t.Errorf("expected non-nil autoTrials map")
		}
	})

	t.Run("probeAWGHealth executes with dns when configured in vpn_config", func(t *testing.T) {
		db, cleanup := setupTestDB(t)
		defer cleanup()

		if err := db.SaveVPNConfig(ctx, &models.VPNConfig{
			VPNDataPlaneI1Protocol: "dns",
		}); err != nil {
			t.Fatalf("SaveVPNConfig failed: %v", err)
		}

		orch := New(db, nil)
		server := &models.Server{
			ID:   2,
			Host: "127.0.0.1",
		}

		reachRes, _, _ := orch.probeAWGHealth(
			ctx,
			server,
			"127.0.0.1",
			54322,
			"BSX9ZtdoVp6sTwS+ziidJqp/aBjHrp1+xSOzc3+Z36Y=",
			"",
			"",
			"",
			nil,
		)
		if reachRes == nil {
			t.Fatalf("expected non-nil reachRes")
		}
		if profile, exists := reachRes["profile"]; !exists || profile != "dns" {
			t.Errorf("expected primary reachability probe profile 'dns', got %v", profile)
		}
	})
}
