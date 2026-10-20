package vpn

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
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

	// Empty generator result test: empty i1 from generator returns server error
	func() {
		restoreGen := setGenerateMimicryPacketsForTest(func(ctx context.Context, mimicry string, domain string, sshClient ssh.SSHClient) (map[string]string, error) {
			return map[string]string{"i1": ""}, nil
		})
		defer restoreGen()
		if _, err := resolvePortalI1(ctx, cfg, map[string]any{}); err == nil || !strings.Contains(err.Error(), "empty generator result") {
			t.Fatalf("expected empty generator result error, got %v", err)
		}
	}()

	// Injected generator failure test: verify generator error cause is preserved,
	// and GenerateClientConfig leaves no partial row or IP allocation (M14 kill oracle).
	func() {
		restoreGen := setGenerateMimicryPacketsForTest(func(ctx context.Context, mimicry string, domain string, sshClient ssh.SSHClient) (map[string]string, error) {
			return nil, fmt.Errorf("injected generator failure: %w", context.DeadlineExceeded)
		})
		defer restoreGen()

		if _, err := resolvePortalI1(ctx, cfg, map[string]any{}); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("generator cause lost in resolvePortalI1: %v", err)
		}
		genFailUID, err := db.CreateUser(ctx, &models.User{Username: "generator-fail-user", Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		allocBefore := svc.ipam.AllocatedCount()
		if cfgStr, _, err := svc.GenerateClientConfig(ctx, genFailUID); !errors.Is(err, context.DeadlineExceeded) || cfgStr != "" {
			t.Fatalf("render did not propagate generator cause: cfg=%q, err=%v", cfgStr, err)
		}
		conns, err := db.GetConnectionsByUserID(ctx, genFailUID)
		if err != nil {
			t.Fatal(err)
		}
		if len(conns) != 0 || svc.ipam.AllocatedCount() != allocBefore {
			t.Fatalf("failed generation persisted partial row or lease: rows=%d, ipam=%d (was %d)", len(conns), svc.ipam.AllocatedCount(), allocBefore)
		}
	}()
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

func TestGenerateClientConfig_ConcurrentFirstFetch_WinnerKeyIntegrity(t *testing.T) {
	t.Run("awgConn nil with concurrent winner returns error and preserves winner keys", func(t *testing.T) {
		db := setupTestDB(t)
		ctx := context.Background()
		svc, err := NewVPNService(db, nil)
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := svc.GetConfig(ctx)
		if err != nil {
			t.Fatal(err)
		}
		portalPub := svc.portalPubKey

		uID, err := db.CreateUser(ctx, &models.User{Username: "race-nil-user", Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		user, err := db.GetUser(ctx, uID)
		if err != nil {
			t.Fatal(err)
		}

		winnerConn := &models.UserConnection{
			UserID:   uID,
			ServerID: 0,
			Protocol: "awg",
			Name:     "race-nil-user-awg",
			ClientID: "winner-client-pubkey",
			ClientParams: map[string]any{
				"portal_i1":          "<r 2><b 0x01020304>",
				"client_private_key": "winner-client-privkey",
			},
		}
		winnerConnID, err := db.CreateConnection(ctx, winnerConn)
		if err != nil {
			t.Fatal(err)
		}

		// Simulate request where awgConn was nil before the concurrent winner committed
		_, _, err = svc.renderClientConfigForConnection(ctx, db, cfg, portalPub, user, nil, false)
		if err == nil {
			t.Fatal("expected error when awgConn is nil and connection was created concurrently, got nil")
		}
		if !errors.Is(err, ErrConnectionCreatedConcurrently) && !strings.Contains(err.Error(), "concurrently") {
			t.Fatalf("expected concurrent creation error, got %v", err)
		}

		persisted, err := db.GetConnection(ctx, winnerConnID)
		if err != nil {
			t.Fatal(err)
		}
		if persisted.ClientID != "winner-client-pubkey" {
			t.Fatalf("winner clientID overwritten: got %q, want %q", persisted.ClientID, "winner-client-pubkey")
		}
		if persisted.ClientParams["client_private_key"] != "winner-client-privkey" {
			t.Fatalf("winner client_private_key overwritten: got %v", persisted.ClientParams["client_private_key"])
		}
		if persisted.ClientParams["portal_i1"] != "<r 2><b 0x01020304>" {
			t.Fatalf("winner portal_i1 overwritten: got %v", persisted.ClientParams["portal_i1"])
		}
	})

	t.Run("existing awgConn with refreshed I1 reuses I1 and retains awgConn", func(t *testing.T) {
		db := setupTestDB(t)
		ctx := context.Background()
		svc, err := NewVPNService(db, nil)
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := svc.GetConfig(ctx)
		if err != nil {
			t.Fatal(err)
		}
		portalPub := svc.portalPubKey

		uID, err := db.CreateUser(ctx, &models.User{Username: "existing-conn-user", Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		user, err := db.GetUser(ctx, uID)
		if err != nil {
			t.Fatal(err)
		}

		conn := &models.UserConnection{
			UserID:   uID,
			ServerID: 0,
			Protocol: "awg",
			Name:     "existing-conn-user-awg",
			ClientID: "existing-client-pubkey",
			ClientParams: map[string]any{
				"portal_i1":          "<r 2><b 0xfeedbeef>",
				"client_private_key": "existing-client-privkey",
			},
		}
		connID, err := db.CreateConnection(ctx, conn)
		if err != nil {
			t.Fatal(err)
		}

		callerConn := &models.UserConnection{
			ID:       connID,
			UserID:   uID,
			ServerID: 0,
			Protocol: "awg",
			Name:     "existing-conn-user-awg",
			ClientID: "existing-client-pubkey",
			ClientParams: map[string]any{
				"client_private_key": "existing-client-privkey",
			},
		}

		renderedCfg, _, err := svc.renderClientConfigForConnection(ctx, db, cfg, portalPub, user, callerConn, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		i1 := parseDirectiveString(t, renderedCfg, "I1")
		if i1 != "<r 2><b 0xfeedbeef>" {
			t.Fatalf("expected refreshed I1 %q, got %q", "<r 2><b 0xfeedbeef>", i1)
		}

		persisted, err := db.GetConnection(ctx, connID)
		if err != nil {
			t.Fatal(err)
		}
		if persisted.ClientID != "existing-client-pubkey" {
			t.Fatalf("clientID changed: got %q, want %q", persisted.ClientID, "existing-client-pubkey")
		}
		if persisted.ClientParams["client_private_key"] != "existing-client-privkey" {
			t.Fatalf("client_private_key changed: got %v", persisted.ClientParams["client_private_key"])
		}
	})

	t.Run("concurrent GenerateClientConfig from scratch preserves winner keys", func(t *testing.T) {
		db := setupTestDB(t)
		ctx := context.Background()
		svc, err := NewVPNService(db, nil)
		if err != nil {
			t.Fatal(err)
		}
		uID, err := db.CreateUser(ctx, &models.User{Username: "scratch-user", Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		const concurrency = 4
		var wg sync.WaitGroup
		errs := make([]error, concurrency)
		cfgs := make([]string, concurrency)
		start := make(chan struct{})
		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				cfgStr, _, err := svc.GenerateClientConfig(ctx, uID)
				errs[i] = err
				cfgs[i] = cfgStr
			}(i)
		}
		close(start)
		wg.Wait()

		var successCount int
		for _, err := range errs {
			if err == nil {
				successCount++
			} else if !errors.Is(err, ErrConnectionCreatedConcurrently) && !strings.Contains(err.Error(), "concurrently") {
				t.Fatalf("unexpected error from concurrent fetch: %v", err)
			}
		}
		if successCount < 1 {
			t.Fatalf("expected at least 1 success, got %d", successCount)
		}

		conns, err := db.GetConnectionsByUserID(ctx, uID)
		if err != nil || len(conns) == 0 {
			t.Fatalf("expected connection created, got conns=%+v err=%v", conns, err)
		}
		for i, err := range errs {
			if err == nil {
				clientPub := ExtractClientPublicKeyFromConfig(cfgs[i])
				if clientPub != "" && clientPub != conns[0].ClientID {
					t.Fatalf("winner client config pubkey %q does not match persisted %q", clientPub, conns[0].ClientID)
				}
			}
		}
	})
}

func TestGenerateClientConfig_UserErrorClassification(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Missing user returns ErrUserNotFound
	_, _, err = svc.GenerateClientConfig(ctx, "non-existent-user-id")
	if !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound for missing user, got %v", err)
	}

	// 2. Database error does NOT return ErrUserNotFound
	if _, err := db.ExecContext(ctx, "DROP TABLE users"); err != nil {
		t.Fatal(err)
	}
	_, _, err = svc.GenerateClientConfig(ctx, "any-user-id")
	if err == nil {
		t.Fatal("expected error with dropped users table")
	}
	if errors.Is(err, ErrUserNotFound) {
		t.Fatalf("database error must not be classified as ErrUserNotFound: %v", err)
	}
}
