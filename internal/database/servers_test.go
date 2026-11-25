package database

import (
	"context"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/security"
)

func TestServersEmptyAndNotFound(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()

	allServers, err := db.GetAllServers(ctx)
	if err != nil || len(allServers) != 0 {
		t.Fatalf("GetAllServers empty DB = (%v, %v), want ([], nil)", allServers, err)
	}

	c, err := db.CountServers(ctx)
	if err != nil || c != 0 {
		t.Errorf("CountServers on empty DB = %d, err = %v, want 0, nil", c, err)
	}

	nonExistent, err := db.GetServer(ctx, 9999)
	if err != nil || nonExistent != nil {
		t.Errorf("GetServer(9999) = (%v, %v), want (nil, nil)", nonExistent, err)
	}

	nonExistentAlias, err := db.GetServerByID(ctx, 9999)
	if err != nil || nonExistentAlias != nil {
		t.Errorf("GetServerByID(9999) = (%v, %v), want (nil, nil)", nonExistentAlias, err)
	}

	exists, err := db.ServerExists(ctx, 9999)
	if err != nil || exists {
		t.Errorf("ServerExists(9999) = (%v, %v), want (false, nil)", exists, err)
	}
}

func TestServersCreateAndGet(t *testing.T) {
	db, secretKey := setupTestDB(t)
	ctx := context.Background()

	encP, _ := security.EncryptCredential("PreEncryptedPass", secretKey)
	encK, _ := security.EncryptCredential("PreEncryptedKey", secretKey)

	testCases := []struct {
		name      string
		server    *models.Server
		wantID    int64
		checkPass string
		checkKey  string
	}{
		{
			name: "Server with Plaintext Pass and Key",
			server: &models.Server{
				Name:      "Server One",
				Host:      "10.0.0.1",
				SSHUser:   "root",
				SSHPort:   22,
				SSHPass:   "MySecretPass1",
				SSHKey:    "MySecretKey1",
				Protocols: map[string]any{"awg": map[string]any{"port": 51820}},
				CreatedAt: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
			},
			wantID:    1,
			checkPass: "MySecretPass1",
			checkKey:  "MySecretKey1",
		},
		{
			name: "Server with Zero CreatedAt and Null Protocols",
			server: &models.Server{
				Name:    "Server Two",
				Host:    "10.0.0.2",
				SSHUser: "admin",
				SSHPort: 2222,
			},
			wantID:    2,
			checkPass: "",
			checkKey:  "",
		},
		{
			name: "Server with Pre-encrypted Fernet Credentials",
			server: &models.Server{
				Name:      "Server Three",
				Host:      "10.0.0.3",
				SSHUser:   "ubuntu",
				SSHPort:   2200,
				SSHPass:   encP,
				SSHKey:    encK,
				Protocols: map[string]any{"telemt": map[string]any{"port": 443}},
			},
			wantID:    3,
			checkPass: "PreEncryptedPass",
			checkKey:  "PreEncryptedKey",
		},
		{
			name: "Server with Predefined Explicit ID",
			server: &models.Server{
				ID:        100,
				Name:      "Server 100",
				Host:      "10.0.0.100",
				SSHUser:   "root",
				SSHPort:   22,
				SSHPass:   "ExplicitIDPass",
				Protocols: map[string]any{"openvpn": map[string]any{"port": 1194}},
			},
			wantID:    100,
			checkPass: "ExplicitIDPass",
			checkKey:  "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			id, err := db.CreateServer(ctx, tc.server)
			if err != nil {
				t.Fatalf("CreateServer failed: %v", err)
			}
			s, err := db.GetServerByID(ctx, id)
			if err != nil || s == nil {
				t.Fatalf("GetServerByID(%d) failed: %v", id, err)
			}
			if s.SSHPass != tc.checkPass || s.SSHKey != tc.checkKey {
				t.Errorf("Credentials mismatch: got (%q, %q), want (%q, %q)", s.SSHPass, s.SSHKey, tc.checkPass, tc.checkKey)
			}
		})
	}
}

func TestServersReachabilityAndStatus(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()

	s1ID, _ := db.CreateServer(ctx, &models.Server{Name: "S1", Host: "10.0.0.1"})
	s2ID, _ := db.CreateServer(ctx, &models.Server{Name: "S2", Host: "10.0.0.2"})

	_ = db.UpdateServerReachability(ctx, s1ID, models.ReachabilityOnline)
	_ = db.UpdateServerReachabilityExtended(ctx, s2ID, models.ReachabilityOffline, map[string]any{"ping_ms": 150})

	st1, err := db.GetServerStatus(ctx, s1ID)
	if err != nil || st1 != models.ReachabilityOnline {
		t.Errorf("GetServerStatus(s1) = %s, want %s", st1, models.ReachabilityOnline)
	}

	st2, err := db.GetServerStatus(ctx, s2ID)
	if err != nil || st2 != models.ReachabilityOffline {
		t.Errorf("GetServerStatus(s2) = %s, want %s", st2, models.ReachabilityOffline)
	}

	stUnknown, err := db.GetServerStatus(ctx, 999)
	if err != nil || stUnknown != models.ReachabilityUnknown {
		t.Errorf("GetServerStatus(999) = %s, want %s", stUnknown, models.ReachabilityUnknown)
	}

	all, err := db.GetAllServers(ctx)
	if err != nil || len(all) != 2 {
		t.Fatalf("GetAllServers expected 2, got %d, err=%v", len(all), err)
	}
}

func TestServersUpdateAndCredentials(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()

	sID, _ := db.CreateServer(ctx, &models.Server{Name: "Server S", Host: "10.0.0.1"})

	if err := db.UpdateServerStats(ctx, sID, map[string]any{"awg": map[string]any{"port": 51821}}); err != nil {
		t.Fatalf("UpdateServerStats failed: %v", err)
	}

	if err := db.UpdateServerSSHStatus(ctx, sID, "online"); err != nil {
		t.Fatalf("UpdateServerSSHStatus failed: %v", err)
	}

	if err := db.UpdateServerCredentials(ctx, sID, "NewSSHPass!", "NewSSHKey!"); err != nil {
		t.Fatalf("UpdateServerCredentials failed: %v", err)
	}
	updatedCreds, _ := db.GetServer(ctx, sID)
	if updatedCreds.SSHPass != "NewSSHPass!" || updatedCreds.SSHKey != "NewSSHKey!" {
		t.Errorf("UpdateServerCredentials failed: pass=%q, key=%q", updatedCreds.SSHPass, updatedCreds.SSHKey)
	}

	err := db.UpdateServer(ctx, sID, map[string]any{
		"name":        "Updated Server",
		"host":        "10.0.0.22",
		"ssh_user":    "admin_final",
		"ssh_port":    2223,
		"password":    "UpdatedPass",
		"private_key": "UpdatedKey",
		"protocols":   map[string]any{"ss": map[string]any{"port": 8388}},
	})
	if err != nil {
		t.Fatalf("UpdateServer failed: %v", err)
	}

	if err := db.UpdateServer(ctx, sID, map[string]any{}); err != nil {
		t.Errorf("UpdateServer empty map failed: %v", err)
	}

	if err := db.UpdateServer(ctx, sID, map[string]any{"invalid_col": "value"}); err == nil {
		t.Errorf("UpdateServer with invalid column should return error")
	}
}

func TestServersDeleteAndCascade(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()

	sID, _ := db.CreateServer(ctx, &models.Server{Name: "Cascade Server", Host: "10.0.0.1"})
	uID, _ := db.CreateUser(ctx, &models.User{Username: "server_cascade_user"})
	_, _ = db.CreateConnection(ctx, &models.UserConnection{UserID: uID, ServerID: sID, Protocol: "awg"})
	_ = db.SaveKnownHost(ctx, sID, "SHA256:test_fingerprint_server1")
	_, _ = db.CreateBackendTunnel(ctx, &models.BackendTunnel{ServerID: sID, InterfaceName: "awg-test"})

	deleted, err := db.DeleteServer(ctx, sID)
	if err != nil || !deleted {
		t.Fatalf("DeleteServer failed: %v", err)
	}

	sCheck, _ := db.GetServer(ctx, sID)
	if sCheck != nil {
		t.Errorf("server was not deleted")
	}
	conns, _ := db.GetConnectionsByServerID(ctx, sID)
	if len(conns) != 0 {
		t.Errorf("connections not cascaded: %d", len(conns))
	}

	deletedFalse, err := db.DeleteServer(ctx, 9999)
	if err != nil || deletedFalse {
		t.Errorf("DeleteServer(9999) = (%v, %v), want (false, nil)", deletedFalse, err)
	}
}

func TestServersEdgeCases(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()

	sID, _ := db.CreateServer(ctx, &models.Server{Name: "Edge Server", Host: "10.0.0.1"})

	if err := db.UpdateServerProtocols(ctx, sID, nil); err != nil {
		t.Fatalf("UpdateServerProtocols(nil) failed: %v", err)
	}

	_, _ = db.sqlDB.ExecContext(ctx, "INSERT INTO servers (id, name, host, ssh_user, protocols) VALUES (888, 'Bad JSON Server', '10.0.0.88', 'root', 'invalid-json{')")
	badJSONSrv, err := db.GetServer(ctx, 888)
	if err != nil || badJSONSrv == nil || len(badJSONSrv.Protocols) != 0 {
		t.Fatalf("GetServer with bad JSON failed: %+v, err=%v", badJSONSrv, err)
	}

	badProto := map[string]any{"bad": make(chan int)}
	if _, err := db.CreateServer(ctx, &models.Server{Name: "Bad Proto Server", Host: "1.1.1.1", Protocols: badProto}); err == nil {
		t.Errorf("expected error creating server with unmarshalable protocol")
	}
	if err := db.UpdateServer(ctx, sID, map[string]any{"protocols": badProto}); err == nil {
		t.Errorf("expected error updating server with unmarshalable protocol")
	}
	if err := db.UpdateServerProtocols(ctx, sID, badProto); err == nil {
		t.Errorf("expected error in UpdateServerProtocols with unmarshalable protocol")
	}
}

// The provider-absence observation is a durable column, and clearing it must
// really clear it: a server the provider lists again carries no observation, which
// is a different fact from "absent since the beginning of time".
func TestServersProviderAbsenceRoundTrip(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()

	id, err := db.CreateServer(ctx, &models.Server{Name: "Provider server", Host: "198.51.100.9"})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	created, err := db.GetServer(ctx, id)
	if err != nil || created == nil {
		t.Fatalf("GetServer(%d) failed: %v", id, err)
	}
	if created.ProviderAbsent() {
		t.Fatalf("a newly registered server was already marked provider-absent: %q", created.ProviderAbsentAt)
	}

	observed := time.Date(2026, 11, 24, 9, 30, 0, 0, time.UTC)
	if err := db.SetServerProviderAbsence(ctx, id, observed, "acct-north"); err != nil {
		t.Fatalf("SetServerProviderAbsence failed: %v", err)
	}
	marked, err := db.GetServer(ctx, id)
	if err != nil || marked == nil {
		t.Fatalf("GetServer(%d) after recording absence failed: %v", id, err)
	}
	if !marked.ProviderAbsent() {
		t.Fatal("the recorded absence did not reach the row")
	}
	if got, want := marked.ProviderAbsentAt, observed.Format(time.RFC3339); got != want {
		t.Fatalf("recorded observation = %q, want %q", got, want)
	}
	// The account the listing was read from is stored with the observation, so a later
	// key change is visible rather than silent.
	if got := marked.ProviderAbsentAccountID; got != "acct-north" {
		t.Fatalf("recorded observing account = %q, want acct-north", got)
	}

	all, err := db.GetAllServers(ctx)
	if err != nil || len(all) != 1 {
		t.Fatalf("GetAllServers = %d rows, err=%v", len(all), err)
	}
	if !all[0].ProviderAbsent() || all[0].ProviderAbsentAccountID != "acct-north" {
		t.Fatal("GetAllServers did not read the recorded absence and its account")
	}

	if err := db.SetServerProviderAbsence(ctx, id, time.Time{}, ""); err != nil {
		t.Fatalf("clearing the absence failed: %v", err)
	}
	cleared, err := db.GetServer(ctx, id)
	if err != nil || cleared == nil {
		t.Fatalf("GetServer(%d) after clearing failed: %v", id, err)
	}
	if cleared.ProviderAbsent() {
		t.Fatalf("a cleared observation still reads as absent: %q", cleared.ProviderAbsentAt)
	}
	if cleared.ProviderAbsentAccountID != "" {
		t.Fatalf("clearing left the observing account behind: %q", cleared.ProviderAbsentAccountID)
	}
	// The rest of the row is untouched by both writes.
	if cleared.Name != "Provider server" || cleared.Host != "198.51.100.9" {
		t.Fatalf("recording provider absence changed the server row: %+v", cleared)
	}
}

// The narrow provider-absence read the background prober and the deploy path use.
// A missing row must not read as "provider-confirmed absent": nothing is known
// about it, and a caller must not turn that into a refusal.
func TestServersIsProviderAbsent(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()

	id, err := db.CreateServer(ctx, &models.Server{Name: "Provider server", Host: "198.51.100.44"})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	if absent, err := db.IsServerProviderAbsent(ctx, id); err != nil || absent {
		t.Fatalf("IsServerProviderAbsent(%d) = (%v, %v), want (false, nil)", id, absent, err)
	}

	if err := db.SetServerProviderAbsence(ctx, id, time.Now().UTC(), ""); err != nil {
		t.Fatalf("SetServerProviderAbsence failed: %v", err)
	}
	if absent, err := db.IsServerProviderAbsent(ctx, id); err != nil || !absent {
		t.Fatalf("IsServerProviderAbsent(%d) after recording = (%v, %v), want (true, nil)", id, absent, err)
	}

	if err := db.SetServerProviderAbsence(ctx, id, time.Time{}, ""); err != nil {
		t.Fatalf("clearing the absence failed: %v", err)
	}
	if absent, err := db.IsServerProviderAbsent(ctx, id); err != nil || absent {
		t.Fatalf("IsServerProviderAbsent(%d) after clearing = (%v, %v), want (false, nil)", id, absent, err)
	}

	missing, err := db.IsServerProviderAbsent(ctx, 424242)
	if err != nil || missing {
		t.Fatalf("IsServerProviderAbsent on a missing row = (%v, %v), want (false, nil)", missing, err)
	}
}
