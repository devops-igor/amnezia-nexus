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

	r, stats, err := LoadResolver(t.Context(), db)
	if err != nil {
		t.Fatalf("LoadResolver: %v", err)
	}
	if stats.Loaded != 2 {
		t.Fatalf("Loaded = %d, want 2", stats.Loaded)
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

	r, stats, err := LoadResolver(t.Context(), db)
	if err != nil {
		t.Fatalf("LoadResolver: %v", err)
	}
	if r.Len() != 2 {
		t.Fatalf("resolver holds %d entries, want 2 (leaseless row skipped)", r.Len())
	}
	// Leaseless connections never reach the loader: the accessor itself
	// drops rows with no assigned IP, so every skip counter stays zero.
	if *stats != (LoadStats{Loaded: 2}) {
		t.Fatalf("load stats = %+v, want only Loaded=2", stats)
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

// TestLoadResolverSkipsSessionOnlyLegacyLeases pins review finding 5: a
// connection whose IP exists only in vpn_sessions (NeedsMigration=true,
// the legacy fallback before restart cleanup migrates it into
// client_params) is runtime residue, not durable ownership. The loader
// must skip it, count it, and never authorize its IP on the data path.
func TestLoadResolverSkipsSessionOnlyLegacyLeases(t *testing.T) {
	db := newTestDB(t)
	seedPortalClient(t, db, "alice", testPeer1, "10.40.0.2")
	legacyIP := "10.40.0.77"

	// A legacy row: portal connection with NO durable assigned_ip but a
	// live vpn_sessions lease, exactly what GetVPNClientIPAssignments
	// reports as NeedsMigration=true.
	ctx := context.Background()
	serverID, err := db.CreateServer(ctx, &models.Server{Name: "Server 8", Host: "192.0.2.10"})
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	tunnelID, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      serverID,
		InterfaceName: "awg0",
		PublicKey:     "tunnel-pub",
		Endpoint:      "192.0.2.10:51820",
	})
	if err != nil {
		t.Fatalf("create backend tunnel: %v", err)
	}
	user := &models.User{Username: "legacy-user", Role: "user", Enabled: true}
	if _, err := db.CreateUser(ctx, user); err != nil {
		t.Fatalf("create legacy user: %v", err)
	}
	if _, err := db.CreateConnection(ctx, &models.UserConnection{
		UserID:       user.ID,
		ServerID:     0,
		Protocol:     "awg",
		ClientID:     testPeer3,
		ClientParams: map[string]any{},
		Name:         "legacy-conn",
	}); err != nil {
		t.Fatalf("create legacy connection: %v", err)
	}
	if err := db.CreateVPNSession(ctx, &models.VPNSession{
		ID:              "sess-legacy",
		UserID:          user.ID,
		BackendTunnelID: tunnelID,
		PeerPublicKey:   testPeer3,
		AssignedIP:      legacyIP,
		Status:          "connected",
	}); err != nil {
		t.Fatalf("create legacy vpn session: %v", err)
	}

	// Precondition: the accessor really reports this row as session-only.
	assignments, err := db.GetVPNClientIPAssignments(ctx)
	if err != nil {
		t.Fatalf("GetVPNClientIPAssignments: %v", err)
	}
	found := false
	for _, a := range assignments {
		if a.PeerKey == testPeer3 {
			found = true
			if !a.NeedsMigration || a.AssignedIP != legacyIP {
				t.Fatalf("expected a NeedsMigration row with IP %s, got %+v", legacyIP, a)
			}
		}
	}
	if !found {
		t.Fatal("accessor did not return the legacy session-only row")
	}

	r, stats, err := LoadResolver(t.Context(), db)
	if err != nil {
		t.Fatalf("LoadResolver: %v", err)
	}
	if r.Len() != 1 {
		t.Fatalf("resolver holds %d entries, want 1 (legacy row excluded)", r.Len())
	}
	if owner, ok := r.Lookup(netip.MustParseAddr(legacyIP)); ok {
		t.Fatalf("session-only legacy lease %s authorized as ownership: %+v", legacyIP, owner)
	}
	if owner, ok := r.LookupByPeer(testPeer3); ok {
		t.Fatalf("legacy peer gained ownership: %v", owner)
	}
	if stats.SkippedNeedsMigration != 1 || stats.Loaded != 1 {
		t.Fatalf("load stats = %+v, want Loaded=1 SkippedNeedsMigration=1", stats)
	}
}

func TestLoadResolverFailsClosedOnDuplicateIP(t *testing.T) {
	db := newTestDB(t)
	seedPortalClient(t, db, "alice", testPeer1, "10.40.0.2")
	// A second connection, different peer, same durable IP.
	seedPortalClient(t, db, "mallory", testPeer2, "10.40.0.2")

	r, _, err := LoadResolver(t.Context(), db)
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

	if _, _, err := LoadResolver(t.Context(), db); err == nil {
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

	r, _, err := LoadResolver(t.Context(), db)
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

	// Same peer, different IP: replacement — the lease moved. The old IP
	// becomes unmapped, the new one resolves, and no other peer is touched.
	if err := r.Update(PeerOwnership{PeerPublicKey: testPeer1, ConnectionID: "c1", UserID: "u1", IP: netip.MustParseAddr("10.40.0.6")}); err != nil {
		t.Fatalf("replacement Update: %v", err)
	}
	if r.Len() != 1 {
		t.Fatalf("Len after replacement = %d, want 1 (old mapping dropped)", r.Len())
	}
	if _, ok := r.Lookup(netip.MustParseAddr("10.40.0.5")); ok {
		t.Fatal("replaced-away IP still resolves")
	}
	if ip, ok := r.LookupByPeer(testPeer1); !ok || ip != netip.MustParseAddr("10.40.0.6") {
		t.Fatalf("LookupByPeer after replacement = %v, %v; want 10.40.0.6, true", ip, ok)
	}

	// Same IP, different peer: rejected — replacement never repossesses
	// another peer's address.
	err := r.Update(PeerOwnership{PeerPublicKey: testPeer2, IP: netip.MustParseAddr("10.40.0.6")})
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

	// Remove drops both index entries (the peer's current IP after the
	// replacement above).
	ip, ok := r.Remove(testPeer1)
	if !ok || ip != netip.MustParseAddr("10.40.0.6") {
		t.Fatalf("Remove = %v, %v; want 10.40.0.6, true", ip, ok)
	}
	if r.Len() != 0 {
		t.Fatalf("Len after Remove = %d, want 0", r.Len())
	}
	if _, ok := r.Remove(testPeer1); ok {
		t.Fatal("Remove of an unknown peer reported success")
	}

	// The freed IP can be reassigned to a different peer.
	if err := r.Update(PeerOwnership{PeerPublicKey: testPeer2, IP: netip.MustParseAddr("10.40.0.6")}); err != nil {
		t.Fatalf("Update after Remove: %v", err)
	}
}

// TestUpdateReplacesPeerIPAtomically pins finding 7's replacement contract:
// a peer's lease move swaps both maps atomically, other peers are untouched,
// and replacing onto an IP another peer owns stays a fail-closed conflict.
func TestUpdateReplacesPeerIPAtomically(t *testing.T) {
	r := NewResolver()
	ownership := func(peer, conn string, ip netip.Addr) PeerOwnership {
		return PeerOwnership{PeerPublicKey: peer, ConnectionID: conn, UserID: "u1", IP: ip}
	}
	oldIP := netip.MustParseAddr("10.40.0.5")
	newIP := netip.MustParseAddr("10.40.0.6")
	otherIP := netip.MustParseAddr("10.40.0.7")

	if err := r.Update(ownership(testPeer1, "c1", oldIP)); err != nil {
		t.Fatalf("seed peer1: %v", err)
	}
	if err := r.Update(ownership(testPeer2, "c2", otherIP)); err != nil {
		t.Fatalf("seed peer2: %v", err)
	}

	// The lease moves: same peer, new IP, updated connection identity.
	if err := r.Update(ownership(testPeer1, "c1-new", newIP)); err != nil {
		t.Fatalf("replacement Update: %v", err)
	}

	if _, ok := r.Lookup(oldIP); ok {
		t.Fatal("old IP still resolves after replacement")
	}
	owner, ok := r.Lookup(newIP)
	if !ok {
		t.Fatal("new IP does not resolve after replacement")
	}
	if owner.PeerPublicKey != testPeer1 || owner.ConnectionID != "c1-new" {
		t.Fatalf("new IP owner = %+v, want peer1/c1-new", owner)
	}
	if ip, ok := r.LookupByPeer(testPeer1); !ok || ip != newIP {
		t.Fatalf("LookupByPeer(peer1) = %v, %v; want %v, true", ip, ok, newIP)
	}

	// Other peers are unaffected.
	if owner, ok := r.Lookup(otherIP); !ok || owner.PeerPublicKey != testPeer2 {
		t.Fatalf("other peer's ownership disturbed: %+v, %v", owner, ok)
	}
	if r.Len() != 2 {
		t.Fatalf("Len = %d, want 2", r.Len())
	}

	// Replacement onto someone else's IP remains a conflict, and the
	// failed Update leaves both mappings untouched.
	err := r.Update(ownership(testPeer3, "c3", otherIP))
	assertErrorRedactsKeys(t, err, testPeer2, testPeer3)
	if _, ok := r.LookupByPeer(testPeer3); ok {
		t.Fatal("failed replacement still registered the new peer")
	}
	if ip, ok := r.LookupByPeer(testPeer2); !ok || ip != otherIP {
		t.Fatalf("failed replacement disturbed the existing owner: %v, %v", ip, ok)
	}

	// A peer may move back to a previously-replaced-away IP once it is
	// free again (no stale mapping blocks it).
	if err := r.Update(ownership(testPeer3, "c3", oldIP)); err != nil {
		t.Fatalf("claiming the freed IP: %v", err)
	}
	if owner, ok := r.Lookup(oldIP); !ok || owner.PeerPublicKey != testPeer3 {
		t.Fatalf("freed IP owner = %+v, %v; want peer3", owner, ok)
	}
}

// TestUpdateReplacementConcurrentReaders proves a lease move is atomic for
// concurrent lookups: readers observe either the old or the new mapping,
// never a mixture, and the old IP never resolves to a peer that moved away.
func TestUpdateReplacementConcurrentReaders(t *testing.T) {
	r := NewResolver()
	oldIP := netip.AddrFrom4([4]byte{10, 40, 0, 5})
	newIP := netip.AddrFrom4([4]byte{10, 40, 0, 6})
	if err := r.Update(PeerOwnership{PeerPublicKey: testPeer1, ConnectionID: "c1", UserID: "u1", IP: oldIP}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	const readers = 4
	const iterations = 500
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range iterations {
			if err := r.Update(PeerOwnership{PeerPublicKey: testPeer1, ConnectionID: "c1", UserID: "u1", IP: newIP}); err != nil {
				t.Errorf("Update(new): %v", err)
				return
			}
			if err := r.Update(PeerOwnership{PeerPublicKey: testPeer1, ConnectionID: "c1", UserID: "u1", IP: oldIP}); err != nil {
				t.Errorf("Update(old): %v", err)
				return
			}
		}
	}()
	for range readers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range iterations {
				owner, ok := r.Lookup(oldIP)
				if ok && owner.PeerPublicKey != testPeer1 {
					t.Errorf("old IP resolved to a foreign owner: %+v", owner)
					return
				}
				if owner, ok := r.Lookup(newIP); ok && owner.PeerPublicKey != testPeer1 {
					t.Errorf("new IP resolved to a foreign owner: %+v", owner)
					return
				}
				if ip, ok := r.LookupByPeer(testPeer1); ok && ip != oldIP && ip != newIP {
					t.Errorf("peer resolved to an unknown IP %v", ip)
					return
				}
				r.Len()
			}
		}()
	}
	wg.Wait()

	if r.Len() != 1 {
		t.Fatalf("Len = %d, want 1", r.Len())
	}
	if ip, ok := r.LookupByPeer(testPeer1); !ok || (ip != oldIP && ip != newIP) {
		t.Fatalf("final state = %v, %v; want old or new IP", ip, ok)
	}
}

func TestReloadSwapsAtomicallyAndLeavesOldStateOnError(t *testing.T) {
	db := newTestDB(t)
	seedPortalClient(t, db, "alice", testPeer1, "10.40.0.2")
	r, _, err := LoadResolver(t.Context(), db)
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
