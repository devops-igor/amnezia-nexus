package ingress

import (
	"context"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// Peer keys with distinct 8-character prefixes so RedactKey output is
// distinguishable per peer in error-message assertions.
const (
	testPeer1 = "aaaaaaaa-1-peer-key"
	testPeer2 = "bbbbbbbb-2-peer-key"
	testPeer3 = "cccccccc-3-peer-key"
	testPeer4 = "dddddddd-4-peer-key"
)

// newTestDB opens a fresh migrated SQLite database for one test.
func newTestDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.Open(filepath.Join(t.TempDir(), "panel.db"), "ingress-test-secret")
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// seedPortalClient inserts one portal user plus one portal AWG connection
// whose client_id is the peer public key, returning (connectionID, userID).
// An empty assignedIP seeds a connection with no durable lease.
func seedPortalClient(t *testing.T, db *database.DB, username, peerKey, assignedIP string) (string, string) {
	t.Helper()
	ctx := context.Background()
	user := &models.User{Username: username, Role: "user", Enabled: true}
	if _, err := db.CreateUser(ctx, user); err != nil {
		t.Fatalf("create user %s: %v", username, err)
	}
	params := map[string]any{}
	if assignedIP != "" {
		params["assigned_ip"] = assignedIP
	}
	conn := &models.UserConnection{
		UserID:       user.ID,
		ServerID:     0,
		Protocol:     "awg",
		ClientID:     peerKey,
		ClientParams: params,
		Name:         username + "-conn",
	}
	id, err := db.CreateConnection(ctx, conn)
	if err != nil {
		t.Fatalf("create connection for %s: %v", username, err)
	}
	return id, user.ID
}

// assertErrorRedactsKeys verifies an error names every conflicting peer in
// redacted form only, never the full peer public key.
func assertErrorRedactsKeys(t *testing.T, err error, keys ...string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error")
	}
	msg := err.Error()
	for _, key := range keys {
		redacted := RedactKey(key)
		if !strings.Contains(msg, redacted) {
			t.Errorf("error %q does not name the conflicting peer (redacted %q)", msg, redacted)
		}
		if strings.Contains(msg, key) {
			t.Errorf("error %q leaks the unredacted peer public key", msg)
		}
	}
}

func TestLoadResolverFromDurableState(t *testing.T) {
	db := newTestDB(t)
	seedPortalClient(t, db, "alice", testPeer1, "10.40.0.2")
	seedPortalClient(t, db, "bob", testPeer2, "10.40.0.3")

	r, err := LoadResolver(t.Context(), db)
	if err != nil {
		t.Fatalf("LoadResolver: %v", err)
	}
	if r.Len() != 2 {
		t.Fatalf("resolver holds %d entries, want 2", r.Len())
	}
	owner, ok := r.Lookup(netip.MustParseAddr("10.40.0.2"))
	if !ok {
		t.Fatal("10.40.0.2 not resolved")
	}
	if owner.PeerPublicKey != testPeer1 {
		t.Fatalf("owner = %s, want %s", RedactKey(owner.PeerPublicKey), RedactKey(testPeer1))
	}
	if owner.UserID == "" || owner.ConnectionID == "" {
		t.Fatalf("ownership record missing connection/user identity: %+v", owner)
	}
	if !owner.IP.Is4() || owner.IP != netip.MustParseAddr("10.40.0.2") {
		t.Fatalf("ownership IP = %v, want 4-byte 10.40.0.2", owner.IP)
	}

	ip, ok := r.LookupByPeer(testPeer2)
	if !ok || ip != netip.MustParseAddr("10.40.0.3") {
		t.Fatalf("LookupByPeer = %v, %v; want 10.40.0.3, true", ip, ok)
	}

	if _, ok := r.Lookup(netip.MustParseAddr("10.40.0.99")); ok {
		t.Fatal("unassigned address resolved")
	}
	if _, ok := r.Lookup(netip.IPv6Loopback()); ok {
		t.Fatal("IPv6 address resolved")
	}
	if _, ok := r.Lookup(netip.Addr{}); ok {
		t.Fatal("zero address resolved")
	}
}

func TestLoadResolverSkipsUnassignedAndNonPortal(t *testing.T) {
	db := newTestDB(t)
	seedPortalClient(t, db, "alice", testPeer1, "10.40.0.2")
	seedPortalClient(t, db, "bob", testPeer2, "10.40.0.3")
	// A portal connection with no durable lease is skipped.
	seedPortalClient(t, db, "leaseless", testPeer3, "")

	r, err := LoadResolver(t.Context(), db)
	if err != nil {
		t.Fatalf("LoadResolver: %v", err)
	}
	if r.Len() != 2 {
		t.Fatalf("resolver holds %d entries, want 2 (leaseless row skipped)", r.Len())
	}

	// Non-portal rows (server != 0) never come back from the accessor the
	// resolver is built on; verify that property at the source.
	_, remoteUser := seedPortalClient(t, db, "remoteholder", testPeer4, "10.40.0.200")
	remote := &models.UserConnection{
		UserID:       remoteUser,
		ServerID:     7,
		Protocol:     "awg",
		ClientID:     testPeer4,
		ClientParams: map[string]any{"assigned_ip": "10.40.0.201"},
		Name:         "remote-conn",
	}
	if _, err := db.CreateConnection(context.Background(), remote); err != nil {
		t.Fatalf("create remote connection: %v", err)
	}
	assignments, err := db.GetVPNClientIPAssignments(context.Background())
	if err != nil {
		t.Fatalf("GetVPNClientIPAssignments: %v", err)
	}
	for _, a := range assignments {
		if a.AssignedIP == "10.40.0.201" {
			t.Fatalf("accessor returned a non-portal assignment: %+v", a)
		}
	}
}

func TestLoadResolverFailsClosedOnDuplicateIP(t *testing.T) {
	db := newTestDB(t)
	seedPortalClient(t, db, "alice", testPeer1, "10.40.0.2")
	// A second connection, different peer, same durable IP.
	seedPortalClient(t, db, "mallory", testPeer2, "10.40.0.2")

	r, err := LoadResolver(t.Context(), db)
	if err == nil {
		t.Fatalf("LoadResolver accepted conflicting durable state: %+v", r)
	}
	assertErrorRedactsKeys(t, err, testPeer1, testPeer2)
	if !strings.Contains(err.Error(), "10.40.0.2") {
		t.Fatalf("conflict error does not name the conflicting IP: %v", err)
	}
}

func TestLoadResolverFailsClosedOnDuplicatePeer(t *testing.T) {
	db := newTestDB(t)
	seedPortalClient(t, db, "alice", testPeer1, "10.40.0.2")
	// The same peer key on a second connection owning a different IP.
	seedPortalClient(t, db, "alice-alias", testPeer1, "10.40.0.3")

	if _, err := LoadResolver(t.Context(), db); err == nil {
		t.Fatal("LoadResolver accepted one peer owning two durable IPs")
	} else {
		assertErrorRedactsKeys(t, err, testPeer1)
	}
}

func TestLoadResolverRejectsCollisionAcrossTables(t *testing.T) {
	db := newTestDB(t)
	seedPortalClient(t, db, "alice", testPeer1, "10.40.0.2")

	// The accessor's JOIN is key-based, so one lease surfaces exactly one
	// row even when a lingering vpn_sessions entry exists; a true durable
	// conflict needs a second connection claiming the same assigned_ip.
	// (Legacy in-session collisions are reconciled upstream by
	// reservePersistedClientIPs, not here.) The loader must fail closed
	// when that durable conflict exists.
	seedPortalClient(t, db, "mallory", testPeer2, "10.40.0.2")

	r, err := LoadResolver(t.Context(), db)
	if err == nil {
		t.Fatalf("LoadResolver accepted a durable IP collision: %+v", r)
	}
	assertErrorRedactsKeys(t, err, testPeer1, testPeer2)
	if !strings.Contains(err.Error(), "10.40.0.2") {
		t.Fatalf("conflict error does not name the conflicting IP: %v", err)
	}
}

func TestUpdateAndRemove(t *testing.T) {
	r := NewResolver()

	if err := r.Update(PeerOwnership{PeerPublicKey: testPeer1, ConnectionID: "c1", UserID: "u1", IP: netip.MustParseAddr("10.40.0.5")}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if r.Len() != 1 {
		t.Fatalf("Len = %d, want 1", r.Len())
	}

	// Idempotent re-assertion of unchanged ownership succeeds: a #391 re-sync
	// of an unchanged lease must not fail.
	if err := r.Update(PeerOwnership{PeerPublicKey: testPeer1, ConnectionID: "c1", UserID: "u1", IP: netip.MustParseAddr("10.40.0.5")}); err != nil {
		t.Fatalf("idempotent Update: %v", err)
	}

	// Same peer, different IP: rejected.
	err := r.Update(PeerOwnership{PeerPublicKey: testPeer1, IP: netip.MustParseAddr("10.40.0.6")})
	assertErrorRedactsKeys(t, err, testPeer1)

	// Same IP, different peer: rejected.
	err = r.Update(PeerOwnership{PeerPublicKey: testPeer2, IP: netip.MustParseAddr("10.40.0.5")})
	assertErrorRedactsKeys(t, err, testPeer1, testPeer2)

	// Non-IPv4, zero address, and empty peer key: rejected.
	if err := r.Update(PeerOwnership{PeerPublicKey: testPeer2, IP: netip.IPv6Loopback()}); err == nil {
		t.Fatal("Update accepted an IPv6 assignment")
	}
	if err := r.Update(PeerOwnership{PeerPublicKey: testPeer2, IP: netip.Addr{}}); err == nil {
		t.Fatal("Update accepted a zero address")
	}
	if err := r.Update(PeerOwnership{IP: netip.MustParseAddr("10.40.0.7")}); err == nil {
		t.Fatal("Update accepted an empty peer key")
	}

	// Remove drops both index entries.
	ip, ok := r.Remove(testPeer1)
	if !ok || ip != netip.MustParseAddr("10.40.0.5") {
		t.Fatalf("Remove = %v, %v; want 10.40.0.5, true", ip, ok)
	}
	if r.Len() != 0 {
		t.Fatalf("Len after Remove = %d, want 0", r.Len())
	}
	if _, ok := r.Remove(testPeer1); ok {
		t.Fatal("Remove of an unknown peer reported success")
	}

	// The freed IP can be reassigned to a different peer.
	if err := r.Update(PeerOwnership{PeerPublicKey: testPeer2, IP: netip.MustParseAddr("10.40.0.5")}); err != nil {
		t.Fatalf("Update after Remove: %v", err)
	}
}

func TestReloadSwapsAtomicallyAndLeavesOldStateOnError(t *testing.T) {
	db := newTestDB(t)
	seedPortalClient(t, db, "alice", testPeer1, "10.40.0.2")
	r, err := LoadResolver(t.Context(), db)
	if err != nil {
		t.Fatalf("LoadResolver: %v", err)
	}

	// Reload observes new durable state (a new lease appeared).
	seedPortalClient(t, db, "bob", testPeer2, "10.40.0.3")
	if err := r.Reload(t.Context(), db); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if r.Len() != 2 {
		t.Fatalf("Len after Reload = %d, want 2", r.Len())
	}

	// A conflicting durable write makes Reload fail closed and preserve the
	// previous contents.
	seedPortalClient(t, db, "mallory", testPeer3, "10.40.0.2")
	if err := r.Reload(t.Context(), db); err == nil {
		t.Fatal("Reload accepted conflicting durable state")
	}
	if r.Len() != 2 {
		t.Fatalf("Len after failed Reload = %d, want 2 (previous contents preserved)", r.Len())
	}
	if _, ok := r.Lookup(netip.MustParseAddr("10.40.0.3")); !ok {
		t.Fatal("failed Reload discarded the previous contents")
	}
}

func TestResolverConcurrentAccess(t *testing.T) {
	r := NewResolver()
	const workers = 8
	const iterations = 200

	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			ip := netip.AddrFrom4([4]byte{10, 40, 1, byte(worker + 1)})
			// One distinct peer per worker: the resolver's one-peer-one-IP
			// invariant would rightly reject several workers sharing a key.
			owner := PeerOwnership{PeerPublicKey: fmt.Sprintf("wwwwwwww-%02d-peer", worker), ConnectionID: "c", UserID: "u", IP: ip}
			for range iterations {
				if err := r.Update(owner); err != nil {
					t.Errorf("Update: %v", err)
					return
				}
				if _, ok := r.Lookup(ip); !ok {
					t.Error("Lookup missed a freshly updated entry")
					return
				}
				r.Len()
				r.LookupByPeer(owner.PeerPublicKey)
			}
		}(w)
	}
	// A churner exercising the miss path concurrently with readers/writers.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range iterations {
			r.Remove("does-not-exist")
		}
	}()
	wg.Wait()

	if r.Len() != workers {
		t.Fatalf("Len = %d, want %d", r.Len(), workers)
	}
}
