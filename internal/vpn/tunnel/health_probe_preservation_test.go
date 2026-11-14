package tunnel

import (
	"context"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// TestHealthProber_HasEstablishedSessions pins the predicate both blocked-backend
// decisions depend on: it must read the probe snapshots and, when neither carries
// the counter, the live pool row. A conservative false for a session-carrying
// backend would let the native writer drop protection.
func TestHealthProber_HasEstablishedSessions(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)
	pool := NewPool(db)

	sID, err := db.CreateServer(ctx, &models.Server{Name: "Established-Server", Host: "192.0.2.91"})
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	tun, err := pool.AddTunnel(ctx, sID, "192.0.2.91:51820", "pubkey-established-1")
	if err != nil {
		t.Fatalf("add tunnel: %v", err)
	}
	if err := pool.SetTunnelStatus(ctx, sID, models.TunnelStatusHandshakeBlocked, 25); err != nil {
		t.Fatalf("set blocked status: %v", err)
	}
	hp := NewHealthProber(pool, db, DefaultHealthConfig())

	// Settle the pool row the way ingress admission does: one live session.
	pool.IncrementConnections(sID)
	live, err := pool.GetTunnel(sID)
	if err != nil {
		t.Fatalf("read tunnel: %v", err)
	}
	if live.ActiveConnections != 1 {
		t.Fatalf("precondition: pool reports %d connections, want 1", live.ActiveConnections)
	}

	noSessions := &models.BackendTunnel{ID: tun.ID, ServerID: sID, ActiveConnections: 0}
	withSessions := &models.BackendTunnel{ID: tun.ID, ServerID: sID, ActiveConnections: 2}

	cases := []struct {
		name        string
		snapshot    *models.BackendTunnel
		probeTarget *models.BackendTunnel
		want        bool
	}{
		{"live pool row alone carries the session", nil, noSessions, true},
		{"snapshot carries the session", withSessions, noSessions, true},
		{"probe target carries the session", noSessions, withSessions, true},
		{"both snapshots report none but the pool does", noSessions, noSessions, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hp.hasEstablishedSessions(tc.snapshot, tc.probeTarget); got != tc.want {
				t.Errorf("hasEstablishedSessions() = %t, want %t", got, tc.want)
			}
		})
	}

	// With no live session anywhere, the predicate must be false; otherwise the
	// preservation status would be held for a backend nothing is using.
	pool.DecrementConnections(sID)
	drained, err := pool.GetTunnel(sID)
	if err != nil {
		t.Fatalf("re-read tunnel: %v", err)
	}
	if drained.ActiveConnections != 0 {
		t.Fatalf("precondition: pool reports %d connections after drain, want 0", drained.ActiveConnections)
	}
	if hp.hasEstablishedSessions(noSessions, noSessions) {
		t.Error("hasEstablishedSessions() = true with no session anywhere, want false")
	}

	// A prober without a pool still answers from the snapshots it was given.
	noPool := NewHealthProber(nil, db, DefaultHealthConfig())
	if noPool.hasEstablishedSessions(noSessions, noSessions) {
		t.Error("pool-less prober invented a session")
	}
	if !noPool.hasEstablishedSessions(withSessions, noSessions) {
		t.Error("pool-less prober ignored the snapshot session")
	}
}
