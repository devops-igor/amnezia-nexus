package reconciliation

// The periodic protocol reconciler is a dial path of its own: every remote audit it
// performs reads the backend over SSH (container status, the clients table for
// legacy adoption, the live peer list for zombie cleanup). A server the provider's
// inventory no longer lists must not be dialled by any of those phases, while a
// listed server is still audited in the same pass.

import (
	"context"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestReconciliation_SkipsProviderAbsentServerRemoteAudits(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	protocols := map[string]any{"awg": map[string]any{"port": 55424}}
	absentID, err := db.CreateServer(ctx, &models.Server{
		Name: "Provider absent", Host: "198.51.100.70", SSHPort: 22, Protocols: protocols,
	})
	if err != nil {
		t.Fatalf("failed to seed the absent server: %v", err)
	}
	liveID, err := db.CreateServer(ctx, &models.Server{
		Name: "Still listed", Host: "198.51.100.71", SSHPort: 22, Protocols: protocols,
	})
	if err != nil {
		t.Fatalf("failed to seed the listed server: %v", err)
	}
	if err := db.SetServerProviderAbsence(ctx, absentID, time.Now().UTC()); err != nil {
		t.Fatalf("failed to record the provider absence: %v", err)
	}

	// container_exists=true keeps this a pure read: no protocol is judged stale,
	// so the only thing under test is whether the backend was contacted.
	awgMgr := &mockStatusProtocolManager{proto: "awg", containerExists: true}
	reg := newMockRegistry()
	reg.Register(awgMgr)

	r := New(db, reg)

	// The startup pass (status + zombie peers + legacy adoption).
	if err := r.CleanupStaleProtocols(ctx); err != nil {
		t.Fatalf("CleanupStaleProtocols failed: %v", err)
	}
	// The periodic pass.
	if err := r.CleanupZombiePeers(ctx); err != nil {
		t.Fatalf("CleanupZombiePeers failed: %v", err)
	}

	awgMgr.mu.Lock()
	statusQueries := append([]int64(nil), awgMgr.statusQueries...)
	clientQueries := append([]int64(nil), awgMgr.clientQueries...)
	awgMgr.mu.Unlock()

	requireNoQuery := func(kind string, ids []int64) {
		t.Helper()
		for _, id := range ids {
			if id == absentID {
				t.Fatalf("%s dialled the absent server (server %d); no remote audit may contact it", kind, id)
			}
		}
	}
	requireQuery := func(kind string, ids []int64) {
		t.Helper()
		for _, id := range ids {
			if id == liveID {
				return
			}
		}
		t.Fatalf("%s never contacted the listed server, so the pass did not run: %v", kind, ids)
	}

	requireNoQuery("the protocol status check", statusQueries)
	requireNoQuery("the clients read", clientQueries)
	requireQuery("the protocol status check", statusQueries)
	requireQuery("the clients read", clientQueries)
}
