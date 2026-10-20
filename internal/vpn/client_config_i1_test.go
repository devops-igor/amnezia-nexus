package vpn

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestPortalI1ProtocolSwitchAndGenerationFailure(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	cfg, err := svc.GetConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cfg.VPNDataPlaneI1Protocol = "dns"
	if err := svc.UpdateConfig(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	loaded, err := db.GetVPNConfig(ctx)
	if err != nil || loaded.VPNDataPlaneI1Protocol != "dns" {
		t.Fatalf("DNS setting not persisted: %+v, %v", loaded, err)
	}
	userID, err := db.CreateUser(ctx, &models.User{Username: "dns-i1-user", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	config, _, err := svc.GenerateClientConfig(ctx, userID)
	if err != nil {
		t.Fatal(err)
	}
	if i1 := parseDirectiveString(t, config, "I1"); !strings.HasPrefix(i1, "<r 2><b 0x") {
		t.Fatalf("expected DNS I1, got %q", i1)
	}
	config2, _, err := svc.GenerateClientConfig(ctx, userID)
	if err != nil || config2 != config {
		t.Fatalf("DNS refetch not stable: %v", err)
	}
	cfg.VPNDataPlaneI1Protocol = "sip"
	if err := svc.UpdateConfig(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	config3, _, err := svc.GenerateClientConfig(ctx, userID)
	if err != nil || config3 != config {
		t.Fatalf("existing connection changed after protocol switch: %v", err)
	}
	cfg.VPNDataPlaneI1Protocol = "quic"
	if err := svc.UpdateConfig(ctx, cfg); err == nil {
		t.Fatal("unsupported protocol accepted")
	}
	if err := db.SaveVPNConfig(ctx, cfg); err == nil {
		t.Fatal("unsupported protocol persisted")
	}
	if _, err := NewVPNService(nil, cfg); err == nil {
		t.Fatal("NewVPNService with nil DB and invalid I1 protocol should return error")
	}
	svcNoDB, err := NewVPNService(nil, nil)
	if err != nil {
		t.Fatalf("NewVPNService(nil, nil): %v", err)
	}
	cfgNoDB, err := svcNoDB.GetConfig(ctx)
	if err != nil {
		t.Fatalf("svcNoDB.GetConfig: %v", err)
	}
	cfgNoDB.VPNDataPlaneI1Protocol = "quic"
	if err := svcNoDB.UpdateConfig(ctx, cfgNoDB); err == nil || !strings.Contains(err.Error(), "invalid vpn_data_plane_i1_protocol") {
		t.Fatalf("UpdateConfig on DB-less service with invalid protocol should return invalid protocol error, got %v", err)
	}
	otherID, err := db.CreateUser(ctx, &models.User{Username: "cancelled-i1-user", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err := svc.GenerateClientConfig(cancelled, otherID); err == nil {
		t.Fatal("cancelled generation succeeded")
	}
	if _, err := resolvePortalI1(ctx, cfg, map[string]any{}); err == nil || !strings.Contains(err.Error(), "invalid vpn_data_plane_i1_protocol") {
		t.Fatalf("invalid protocol not rejected by resolvePortalI1: %v", err)
	}
	cfg.VPNDataPlaneI1Protocol = "sip"
	if _, err := resolvePortalI1(cancelled, cfg, map[string]any{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if _, err := resolvePortalI1(ctx, cfg, map[string]any{"portal_i1": ""}); err == nil {
		t.Fatal("empty persisted I1 accepted")
	}
	if _, err := resolvePortalI1(ctx, cfg, map[string]any{"portal_i1": 42}); err == nil {
		t.Fatal("invalid persisted I1 accepted")
	}
}

func TestVPNService_DBLessI1ProtocolValidation(t *testing.T) {
	badCfg := &models.VPNConfig{VPNDataPlaneI1Protocol: "quic"}
	if _, err := NewVPNService(nil, badCfg); err == nil || !strings.Contains(err.Error(), "invalid vpn_data_plane_i1_protocol") {
		t.Fatalf("NewVPNService(nil, invalid) must return invalid protocol error, got %v", err)
	}
	svc, err := NewVPNService(nil, nil)
	if err != nil {
		t.Fatalf("NewVPNService(nil, nil) failed: %v", err)
	}
	cfg, err := svc.GetConfig(context.Background())
	if err != nil {
		t.Fatalf("svc.GetConfig: %v", err)
	}
	cfg.VPNDataPlaneI1Protocol = "quic"
	if err := svc.UpdateConfig(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "invalid vpn_data_plane_i1_protocol") {
		t.Fatalf("UpdateConfig on DB-less service with invalid protocol must return invalid protocol error, got %v", err)
	}
}

func TestGenerateClientConfig_ConcurrentFirstFetch_Explicit(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	const rounds = 5
	const concurrency = 4
	for r := 0; r < rounds; r++ {
		uID, err := db.CreateUser(ctx, &models.User{Username: fmt.Sprintf("race-exp-user-%d", r), Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		conn := &models.UserConnection{UserID: uID, ServerID: 0, Protocol: "awg", Name: "race-exp-conn"}
		connID, err := db.CreateConnection(ctx, conn)
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		out := make([]string, concurrency)
		errs := make([]error, concurrency)
		start := make(chan struct{})
		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				cfg, _, err := svc.GenerateClientConfigForConnection(ctx, uID, connID)
				errs[i] = err
				if err == nil {
					out[i] = parseDirectiveString(t, cfg, "I1")
				}
			}(i)
		}
		close(start)
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				t.Fatalf("round %d goroutine %d failed: %v", r, i, err)
			}
		}
		persisted, err := db.GetConnection(ctx, connID)
		if err != nil {
			t.Fatal(err)
		}
		persistedI1, _ := persisted.ClientParams["portal_i1"].(string)
		if persistedI1 == "" {
			t.Fatalf("round %d: persisted portal_i1 is empty", r)
		}
		for i, v := range out {
			if v != persistedI1 {
				t.Fatalf("round %d: goroutine %d got I1 %q, want persisted %q", r, i, v, persistedI1)
			}
		}
	}
}

func TestGenerateClientConfig_ConcurrentFirstFetch_Implicit(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	const rounds = 5
	const concurrency = 4
	for r := 0; r < rounds; r++ {
		uID, err := db.CreateUser(ctx, &models.User{Username: fmt.Sprintf("race-imp-user-%d", r), Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		connID, err := db.CreateConnection(ctx, &models.UserConnection{UserID: uID, Protocol: "awg", Name: "impl-awg"})
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		out := make([]string, concurrency)
		errs := make([]error, concurrency)
		start := make(chan struct{})
		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				cfg, _, err := svc.GenerateClientConfig(ctx, uID)
				errs[i] = err
				if err == nil {
					out[i] = parseDirectiveString(t, cfg, "I1")
				}
			}(i)
		}
		close(start)
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				t.Fatalf("round %d goroutine %d failed: %v", r, i, err)
			}
		}
		persisted, err := db.GetConnection(ctx, connID)
		if err != nil {
			t.Fatal(err)
		}
		persistedI1, _ := persisted.ClientParams["portal_i1"].(string)
		if persistedI1 == "" {
			t.Fatalf("round %d: persisted portal_i1 is empty", r)
		}
		for i, v := range out {
			if v != persistedI1 {
				t.Fatalf("round %d: goroutine %d got I1 %q, want persisted %q", r, i, v, persistedI1)
			}
		}
	}
}

func TestGenerateClientConfig_ConcurrentFirstFetch_LegacyRow(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	const rounds = 5
	const concurrency = 4
	for r := 0; r < rounds; r++ {
		uID, err := db.CreateUser(ctx, &models.User{Username: fmt.Sprintf("race-leg-user-%d", r), Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		connID, err := db.CreateConnection(ctx, &models.UserConnection{UserID: uID, Protocol: "awg", Name: "legacy-conn"})
		if err != nil {
			t.Fatal(err)
		}
		// Generate config once to simulate initial issuance
		if _, _, err := svc.GenerateClientConfigForConnection(ctx, uID, connID); err != nil {
			t.Fatal(err)
		}
		// Strip portal_i1 to simulate a legacy pre-A1 row
		c, err := db.GetConnection(ctx, connID)
		if err != nil {
			t.Fatal(err)
		}
		delete(c.ClientParams, "portal_i1")
		if ok, err := db.UpdateConnection(ctx, connID, map[string]any{"client_params": c.ClientParams}); err != nil || !ok {
			t.Fatalf("failed to strip portal_i1: %v", err)
		}

		var wg sync.WaitGroup
		out := make([]string, concurrency)
		errs := make([]error, concurrency)
		start := make(chan struct{})
		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				cfg, _, err := svc.GenerateClientConfigForConnection(ctx, uID, connID)
				errs[i] = err
				if err == nil {
					out[i] = parseDirectiveString(t, cfg, "I1")
				}
			}(i)
		}
		close(start)
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				t.Fatalf("round %d goroutine %d failed: %v", r, i, err)
			}
		}
		persisted, err := db.GetConnection(ctx, connID)
		if err != nil {
			t.Fatal(err)
		}
		persistedI1, _ := persisted.ClientParams["portal_i1"].(string)
		if persistedI1 == "" {
			t.Fatalf("round %d: persisted portal_i1 is empty", r)
		}
		for i, v := range out {
			if v != persistedI1 {
				t.Fatalf("round %d: goroutine %d got I1 %q, want persisted %q", r, i, v, persistedI1)
			}
		}
	}
}
