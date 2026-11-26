package database

import (
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

// TestAWGIPAllocations_ReleaseThroughNonAuthoritativeIdentity_ReportsNoMatch is
// the regression for the allocator identity split: an allocation made with both
// an explicit client_id and a public key is stored under the public key
// (awg.AllocationKey), so a release made through the explicit client_id matches
// no row. That release used to return silently, leaving the address reserved
// with no trace. It must now be reported, and the row must survive it.
func TestAWGIPAllocations_ReleaseThroughNonAuthoritativeIdentity_ReportsNoMatch(t *testing.T) {
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

	ip, err := db.AllocateAWGClientIP(ctx, serverID, explicitID, publicKey, nil, subnetAddr, subnetCIDR, gatewayIP)
	if err != nil {
		t.Fatalf("allocate failed: %v", err)
	}

	// The stored identity is the public key: that is what every existing row and
	// every release call site resolves to.
	var storedID string
	if err := db.SQLDB().QueryRowContext(ctx,
		"SELECT client_id FROM awg_ip_allocations WHERE server_id = ? AND ip = ? AND status = 'allocated'",
		serverID, ip,
	).Scan(&storedID); err != nil {
		t.Fatalf("allocated row not found: %v", err)
	}
	if storedID != publicKey {
		t.Fatalf("allocation stored identity %q, want the public key %q", storedID, publicKey)
	}

	capture := &allocationReleaseCapture{}
	previous := slog.Default()
	slog.SetDefault(slog.New(capture))
	defer slog.SetDefault(previous)

	// Release through the OTHER identity. The predicate still requires an exact
	// identity match, so nothing is deleted -- and the caller must be told.
	if err := db.ReleaseAWGClientIP(ctx, serverID, explicitID, ip); err != nil {
		t.Fatalf("release through the explicit identity returned an error: %v", err)
	}

	_, attrs, reported := capture.find("AWG IP release matched no allocation row")
	if !reported {
		t.Fatalf("release that matched no row was silent; captured records: %s", capture.messages())
	}
	if attrs["ip"] != ip || attrs["client_id"] != explicitID {
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
	now := time.Now().UTC().Format(time.RFC3339)
	for _, row := range rows {
		if _, err := db.SQLDB().ExecContext(ctx,
			"INSERT INTO awg_ip_allocations (server_id, client_id, ip, status, created_at, updated_at) VALUES (?, ?, ?, 'allocated', ?, ?)",
			serverID, row.clientID, row.ip, now, now,
		); err != nil {
			t.Fatalf("failed to seed allocation %s/%s: %v", row.clientID, row.ip, err)
		}
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
