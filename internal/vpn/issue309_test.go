package vpn

import (
	"context"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

func TestIdleReaperRemovesCurrentRouteAfterRepeatedRekeys(t *testing.T) {
	ctx := context.Background()
	svc, _, _, userID, peer := setupTestVPNService(t, setupTestDB(t))
	defer func() { _ = svc.Stop() }()
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	tunnels := svc.pool.GetActiveTunnels()
	if len(tunnels) == 0 {
		t.Fatal("no active tunnels")
	}
	tunnelID := tunnels[0].ID
	const ip = "10.100.0.88"

	var currentID string
	for gen := uint64(1); gen <= 4; gen++ {
		sess, err := svc.sessionMgr.CreateSession(ctx, userID, peer, ip, tunnelID, "conn", gen)
		if err != nil {
			t.Fatal(err)
		}
		currentID = sess.ID
		svc.forwarder.RegisterSession(sess.ID, "conn", peer, ip, tunnelID)
	}
	if got := svc.forwarder.RouteSessionID(peer); got != currentID {
		t.Fatalf("active route = %q, want %q", got, currentID)
	}

	svc.sessionMgr.SetSessionLastSeen(peer, time.Now().UTC().Add(-10*time.Minute))
	timedOut, err := svc.endpoint.SweepTimedOutSessions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(timedOut) != 1 || timedOut[0].ID != currentID {
		t.Fatalf("timed out sessions = %+v, want %s", timedOut, currentID)
	}
	if got := svc.forwarder.RouteSessionID(peer); got != "" {
		t.Fatalf("reaped session still has forwarder route %s", got)
	}
	if _, ok := svc.forwarder.GetClientPacketChannel(peer); ok {
		t.Fatal("reaped session still has client packet channel")
	}
	if err := svc.forwarder.RouteBackendToClient(tunnelID, nil, ip); err != forwarder.ErrSessionNotRegistered {
		t.Fatalf("return traffic after reap = %v, want ErrSessionNotRegistered", err)
	}
}
