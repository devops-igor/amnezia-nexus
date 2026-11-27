package database

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

// allocationReleaseCapture collects structured records so a test can assert that
// an operator-visible report was actually emitted (not merely that a helper
// exists).
type allocationReleaseCapture struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *allocationReleaseCapture) Enabled(context.Context, slog.Level) bool { return true }

func (h *allocationReleaseCapture) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r.Clone())
	return nil
}

func (h *allocationReleaseCapture) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h *allocationReleaseCapture) WithGroup(string) slog.Handler { return h }

// find returns the first captured record whose message contains substr, together
// with its attributes rendered as strings.
func (h *allocationReleaseCapture) find(substr string) (slog.Record, map[string]string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, rec := range h.records {
		if !strings.Contains(rec.Message, substr) {
			continue
		}
		attrs := make(map[string]string, rec.NumAttrs())
		rec.Attrs(func(a slog.Attr) bool {
			attrs[a.Key] = a.Value.String()
			return true
		})
		return rec, attrs, true
	}
	return slog.Record{}, nil, false
}

// count returns how many captured records have a message containing substr.
func (h *allocationReleaseCapture) count(substr string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, rec := range h.records {
		if strings.Contains(rec.Message, substr) {
			n++
		}
	}
	return n
}

// messages renders the captured record messages for a failure report.
func (h *allocationReleaseCapture) messages() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.records) == 0 {
		return "(none)"
	}
	msgs := make([]string, 0, len(h.records))
	for _, rec := range h.records {
		msgs = append(msgs, rec.Level.String()+": "+rec.Message)
	}
	return strings.Join(msgs, " | ")
}

// TestAWGIPAllocations_RefusesMismatchedIdentityPair is the persistence-boundary
// regression for the allocator identity split: AddClient refuses an explicit
// client_id that names a different client than the public key, and both storage
// entry points must enforce the same rule instead of storing the pair under one
// identity while dropping the other. A refused call must name both identities and
// leave every existing row untouched.
func TestAWGIPAllocations_RefusesMismatchedIdentityPair(t *testing.T) {
	db, cleanup := setupTestDBForAllocations(t)
	defer cleanup()

	ctx := context.Background()
	const (
		serverID   = int64(1)
		explicitID = "portal-user-1"
		publicKey  = "pubkey-of-portal-user-1"
		subnetAddr = "10.66.66.0"
		subnetCIDR = 24
		gatewayIP  = "10.66.66.1"
	)

	// Allocation must refuse before inserting anything.
	_, err := db.AllocateAWGClientIP(ctx, serverID, explicitID, publicKey, nil, subnetAddr, subnetCIDR, gatewayIP)
	if err == nil {
		t.Fatalf("mismatched allocation was accepted; want a refusal naming both identities")
	}
	if !strings.Contains(err.Error(), explicitID) || !strings.Contains(err.Error(), publicKey) {
		t.Fatalf("allocation refusal did not name both identities: %v", err)
	}
	assertAllocationRowCount(t, db, serverID, 0)

	// Adoption must refuse before inserting anything, whether or not an IP is
	// supplied.
	for _, ip := range []string{"10.66.66.9", ""} {
		adopted, adoptErr := db.AdoptAWGClientIPLease(ctx, serverID, explicitID, publicKey, ip)
		if adoptErr == nil {
			t.Fatalf("mismatched adoption (ip=%q) was accepted; want a refusal", ip)
		}
		if adopted {
			t.Fatalf("mismatched adoption (ip=%q) reported success alongside its error", ip)
		}
		if !strings.Contains(adoptErr.Error(), explicitID) || !strings.Contains(adoptErr.Error(), publicKey) {
			t.Fatalf("adoption refusal (ip=%q) did not name both identities: %v", ip, adoptErr)
		}
	}
	assertAllocationRowCount(t, db, serverID, 0)

	// Adoption over an existing lease must refuse without superseding or
	// re-assigning the row.
	const heldIP = "10.66.66.7"
	seedAllocationRow(t, db, serverID, publicKey, heldIP)
	if adopted, adoptErr := db.AdoptAWGClientIPLease(ctx, serverID, explicitID, publicKey, heldIP); adoptErr == nil || adopted {
		t.Fatalf("mismatched adoption of an existing lease = (%v, %v), want an error", adopted, adoptErr)
	}
	if owner := allocationOwner(t, db, serverID, heldIP); owner != publicKey {
		t.Fatalf("existing lease mutated by refused adoption: owner=%q want %q", owner, publicKey)
	}
	assertAllocationRowCount(t, db, serverID, 1)
}

// TestAWGIPAllocations_AcceptsMatchingAndKeyOnlyPairs is the positive control for
// the identity rule: a matching pair and a key-only call both remain valid
// allocations, so the refusal above rejects only genuinely conflicting input.
func TestAWGIPAllocations_AcceptsMatchingAndKeyOnlyPairs(t *testing.T) {
	db, cleanup := setupTestDBForAllocations(t)
	defer cleanup()

	ctx := context.Background()
	const (
		serverID   = int64(1)
		subnetAddr = "10.66.66.0"
		subnetCIDR = 24
		gatewayIP  = "10.66.66.1"
	)

	matchIP, err := db.AllocateAWGClientIP(ctx, serverID, "match-key", "match-key", nil, subnetAddr, subnetCIDR, gatewayIP)
	if err != nil {
		t.Fatalf("matching-pair allocation failed: %v", err)
	}
	if owner := allocationOwner(t, db, serverID, matchIP); owner != "match-key" {
		t.Fatalf("matching-pair row owner = %q, want %q", owner, "match-key")
	}

	keyOnlyIP, err := db.AllocateAWGClientIP(ctx, serverID, "", "key-only", nil, subnetAddr, subnetCIDR, gatewayIP)
	if err != nil {
		t.Fatalf("key-only allocation failed: %v", err)
	}
	if owner := allocationOwner(t, db, serverID, keyOnlyIP); owner != "key-only" {
		t.Fatalf("key-only row owner = %q, want %q", owner, "key-only")
	}

	if ok, err := db.AdoptAWGClientIPLease(ctx, serverID, "adopt-match", "adopt-match", "10.66.66.40"); err != nil || !ok {
		t.Fatalf("matching-pair adoption = (%v, %v), want (true, nil)", ok, err)
	}
	if ok, err := db.AdoptAWGClientIPLease(ctx, serverID, "", "adopt-key-only", "10.66.66.41"); err != nil || !ok {
		t.Fatalf("key-only adoption = (%v, %v), want (true, nil)", ok, err)
	}
}

// TestAWGIPAllocations_ReleaseThroughNonAuthoritativeIdentity_ReportsNoMatch is
// the regression for the allocator identity split: a row stored under the public
// key (awg.AllocationKey) is released through the explicit client_id, which
// matches no row. That release used to return silently, leaving the address
// reserved with no trace. It must now be reported at ERROR, naming the address
// and the surviving owner, and the row must survive it.
func TestAWGIPAllocations_ReleaseThroughNonAuthoritativeIdentity_ReportsNoMatch(t *testing.T) {
	db, cleanup := setupTestDBForAllocations(t)
	defer cleanup()

	ctx := context.Background()
	const (
		serverID   = int64(1)
		explicitID = "portal-user-1"
		publicKey  = "pubkey-of-portal-user-1"
		ip         = "10.66.66.20"
	)

	// Seed the row under the canonical (public key) identity, exactly as a valid
	// allocation stores it.
	seedAllocationRow(t, db, serverID, publicKey, ip)

	capture := &allocationReleaseCapture{}
	previous := slog.Default()
	slog.SetDefault(slog.New(capture))
	defer slog.SetDefault(previous)

	// Release through the OTHER identity. The predicate still requires an exact
	// identity match, so nothing is deleted -- and the caller must be told.
	if err := db.ReleaseAWGClientIP(ctx, serverID, explicitID, ip); err != nil {
		t.Fatalf("release through the explicit identity returned an error: %v", err)
	}

	rec, attrs, reported := capture.find("AWG IP release matched no allocation row")
	if !reported {
		t.Fatalf("release that matched no row was silent; captured records: %s", capture.messages())
	}
	if rec.Level < slog.LevelError {
		t.Fatalf("genuine mismatch reported at %s, want at least ERROR so LOG_LEVEL=ERROR keeps it", rec.Level)
	}
	if attrs["ip"] != ip || attrs["client_id"] != explicitID || attrs["owner_id"] != publicKey {
		t.Fatalf("no-match report named the wrong target: %v", attrs)
	}

	// The address is still reserved for its real owner: reporting the miss must
	// not free (or hide the existence of) the lease.
	if owner := allocationOwner(t, db, serverID, ip); owner != publicKey {
		t.Fatalf("lease owner after the mismatched release = %q, want %q", owner, publicKey)
	}

	// Control: the authoritative identity does release it, and a release that
	// matches a row adds no further miss report.
	if err := db.ReleaseAWGClientIP(ctx, serverID, publicKey, ip); err != nil {
		t.Fatalf("release through the authoritative identity failed: %v", err)
	}
	if owner := allocationOwner(t, db, serverID, ip); owner != "" {
		t.Fatalf("lease %s still held by %q after the authoritative release", ip, owner)
	}
	if got := capture.count("AWG IP release matched no allocation row"); got != 1 {
		t.Fatalf("expected exactly 1 no-match report (from the mismatched release), got %d", got)
	}
}

// TestAWGIPAllocations_ReleaseMissVisibleAtErrorLevel exercises the real text
// handler the panel installs for LOG_LEVEL=ERROR. A genuine miss -- the address is
// still held under another identity -- must be visible in that configuration,
// while a matching release emits nothing and an intentional repeat release stays
// an idempotent nil.
func TestAWGIPAllocations_ReleaseMissVisibleAtErrorLevel(t *testing.T) {
	db, cleanup := setupTestDBForAllocations(t)
	defer cleanup()

	ctx := context.Background()
	const (
		serverID = int64(1)
		ownerKey = "owner-pubkey"
		wrongKey = "other-identity"
		ip       = "10.66.66.30"
	)

	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelError})))
	defer slog.SetDefault(previous)

	// Control: a matching release removes the row and emits nothing.
	seedAllocationRow(t, db, serverID, ownerKey, ip)
	if err := db.ReleaseAWGClientIP(ctx, serverID, ownerKey, ip); err != nil {
		t.Fatalf("matching release failed: %v", err)
	}
	if out := buf.String(); out != "" {
		t.Fatalf("matching release emitted output at ERROR: %q", out)
	}

	// Genuine miss: seed the lease again under its owner, then release through a
	// different identity. At ERROR-only this must still be visible.
	seedAllocationRow(t, db, serverID, ownerKey, ip)
	if err := db.ReleaseAWGClientIP(ctx, serverID, wrongKey, ip); err != nil {
		t.Fatalf("mismatched release returned an error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "level=ERROR") || !strings.Contains(out, "still held by another identity") {
		t.Fatalf("genuine miss was not visible at ERROR; output: %q", out)
	}
	if !strings.Contains(out, ownerKey) || !strings.Contains(out, ip) {
		t.Fatalf("genuine-miss report did not name the address and surviving owner; output: %q", out)
	}
	if owner := allocationOwner(t, db, serverID, ip); owner != ownerKey {
		t.Fatalf("lease owner after the mismatched release = %q, want %q", owner, ownerKey)
	}

	// Intentional repeat: release the (now orphaned) row through its real owner,
	// then release again. The repeat must stay nil and must not become an ERROR.
	if err := db.ReleaseAWGClientIP(ctx, serverID, ownerKey, ip); err != nil {
		t.Fatalf("release through the authoritative identity failed: %v", err)
	}
	buf.Reset()
	if err := db.ReleaseAWGClientIP(ctx, serverID, ownerKey, ip); err != nil {
		t.Fatalf("repeat release returned an error: %v", err)
	}
	if out := buf.String(); out != "" {
		t.Fatalf("intentional repeat release emitted output at ERROR: %q", out)
	}
}

// TestAWGIPAllocations_ReleasePredicateVariants pins the three release
// predicates against their own lease so a matching release is never reported as
// a miss, and a release with nothing to look up stays a documented no-op.
func TestAWGIPAllocations_ReleasePredicateVariants(t *testing.T) {
	db, cleanup := setupTestDBForAllocations(t)
	defer cleanup()

	ctx := context.Background()
	const serverID = int64(1)
	rows := []struct{ clientID, ip string }{
		{clientID: "client-a", ip: "10.66.66.2"},
		{clientID: "client-b", ip: "10.66.66.3"},
		{clientID: "client-c", ip: "10.66.66.4"},
	}
	for _, row := range rows {
		seedAllocationRow(t, db, serverID, row.clientID, row.ip)
	}

	capture := &allocationReleaseCapture{}
	previous := slog.Default()
	slog.SetDefault(slog.New(capture))
	defer slog.SetDefault(previous)

	// Nothing to look up: a no-op, not a miss.
	if err := db.ReleaseAWGClientIP(ctx, serverID, "", ""); err != nil {
		t.Fatalf("empty release returned an error: %v", err)
	}
	// IP only, and identity only, each release their own row.
	if err := db.ReleaseAWGClientIP(ctx, serverID, "", rows[1].ip); err != nil {
		t.Fatalf("release by IP failed: %v", err)
	}
	if err := db.ReleaseAWGClientIP(ctx, serverID, rows[2].clientID, ""); err != nil {
		t.Fatalf("release by identity failed: %v", err)
	}

	if owner := allocationOwner(t, db, serverID, rows[0].ip); owner != rows[0].clientID {
		t.Fatalf("untouched lease %s owner = %q, want %q", rows[0].ip, owner, rows[0].clientID)
	}
	for _, row := range rows[1:] {
		if owner := allocationOwner(t, db, serverID, row.ip); owner != "" {
			t.Fatalf("released lease %s still held by %q", row.ip, owner)
		}
	}
	if got := capture.count("AWG IP release matched no allocation row"); got != 0 {
		t.Fatalf("matching releases were reported as misses %d time(s): %s", got, capture.messages())
	}
}

// seedAllocationRow inserts an allocated lease directly, bypassing the allocator,
// so a release scenario can start from a row it did not have to allocate.
func seedAllocationRow(t *testing.T, db *DB, serverID int64, clientID, ip string) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := db.SQLDB().ExecContext(context.Background(),
		"INSERT INTO awg_ip_allocations (server_id, client_id, ip, status, created_at, updated_at) VALUES (?, ?, ?, 'allocated', ?, ?)",
		serverID, clientID, ip, now, now,
	); err != nil {
		t.Fatalf("failed to seed allocation %s/%s: %v", clientID, ip, err)
	}
}

// assertAllocationRowCount asserts how many allocation rows exist for a server,
// independent of identity.
func assertAllocationRowCount(t *testing.T, db *DB, serverID int64, want int) {
	t.Helper()
	var got int
	if err := db.SQLDB().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM awg_ip_allocations WHERE server_id = ?", serverID,
	).Scan(&got); err != nil {
		t.Fatalf("failed to count allocation rows: %v", err)
	}
	if got != want {
		t.Fatalf("allocation rows for server %d = %d, want %d", serverID, got, want)
	}
}

// allocationOwner returns the client_id holding ip on serverID, or "" when no
// allocated row exists.
func allocationOwner(t *testing.T, db *DB, serverID int64, ip string) string {
	t.Helper()
	var owner string
	err := db.SQLDB().QueryRowContext(context.Background(),
		"SELECT client_id FROM awg_ip_allocations WHERE server_id = ? AND ip = ? AND status = 'allocated'",
		serverID, ip,
	).Scan(&owner)
	if errors.Is(err, sql.ErrNoRows) {
		return ""
	}
	if err != nil {
		t.Fatalf("failed to read allocation owner for %s: %v", ip, err)
	}
	return owner
}
