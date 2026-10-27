package naive

import (
	"context"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/manager"
	"github.com/devops-igor/amnezia-nexus/internal/manager/awg"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/service/reconciliation"
)

// reloadGateSSH blocks "caddy reload" until released, simulating the reload window.
type reloadGateSSH struct {
	*mockNaiveSSHClient
	entered chan struct{}
	release chan struct{}
}

func (g *reloadGateSSH) RunSudoCommand(ctx context.Context, cmd string) (string, string, int, error) {
	if strings.Contains(cmd, "caddy reload") {
		close(g.entered)
		<-g.release
	}
	return g.mockNaiveSSHClient.RunSudoCommand(ctx, cmd)
}

// removeRecorder records RemoveClient calls instead of forwarding them.
type removeRecorder struct {
	*NaiveManager
	mu      sync.Mutex
	removed []string
}

func (r *removeRecorder) RemoveClient(_ context.Context, _ *models.Server, clientID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.removed = append(r.removed, clientID)
	return nil
}

type singleResolver struct{ mgr manager.ProtocolManager }

func (s singleResolver) Get(string) (manager.ProtocolManager, bool) { return s.mgr, true }

func seedCaddyfile(mock *mockNaiveSSHClient) {
	mock.files[NaiveCaddyfilePath] = []byte(RenderCaddyfile(443, "naive.example.com", nil))
}

func TestNaiveManager_AddClientEmitsCreationDate(t *testing.T) {
	mock := newMockNaiveSSHClient()
	seedCaddyfile(mock)
	mgr := NewNaiveManagerWithServerLocks(&mockNaivePool{client: mock}, awg.NewServerLockRegistry())
	server := &models.Server{ID: 71, Host: "198.51.100.71", SSHPort: 22}
	ctx := context.Background()

	added, err := mgr.AddClient(ctx, server, map[string]any{"name": "grace"})
	if err != nil {
		t.Fatalf("AddClient: %v", err)
	}
	for _, key := range []string{"creationDate", "created_at"} {
		if ts, err := time.Parse(time.RFC3339, added[key].(string)); err != nil || time.Since(ts) > time.Minute {
			t.Errorf("AddClient %s = %v, want recent RFC3339 (err=%v)", key, added[key], err)
		}
	}

	clients, err := mgr.GetClients(ctx, server)
	if err != nil || len(clients) != 1 {
		t.Fatalf("GetClients = %v, %v; want 1 client", clients, err)
	}
	if clients[0]["creationDate"] != added["creationDate"] {
		t.Errorf("GetClients creationDate = %v, want %v", clients[0]["creationDate"], added["creationDate"])
	}

	// Entries past the 5-minute window stop emitting creationDate and are pruned after 10 minutes.
	id := added["client_id"].(string)
	mgr.recordClientCreation(id, time.Now().Add(-6*time.Minute))
	if clients, _ = mgr.GetClients(ctx, server); clients[0]["creationDate"] != nil {
		t.Errorf("expected no creationDate after 6 minutes, got %v", clients[0]["creationDate"])
	}
	mgr.recordClientCreation(id, time.Now().Add(-11*time.Minute))
	_, _ = mgr.GetClients(ctx, server)
	if _, ok := mgr.recentClients[id]; ok {
		t.Errorf("expected entry older than 10 minutes to be pruned")
	}
}

// TestNaiveManager_ReconcilerSparesClientDuringReload reproduces R12-H1: reconciliation running
// while AddClient waits on the Caddy reload must not remove the just-created credential.
func TestNaiveManager_ReconcilerSparesClientDuringReload(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "grace_*.db")
	if err != nil {
		t.Fatalf("temp db: %v", err)
	}
	_ = f.Close()
	db, err := database.New(f.Name(), "test-secret-key")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()
	mock := newMockNaiveSSHClient()
	seedCaddyfile(mock)
	gate := &reloadGateSSH{mockNaiveSSHClient: mock, entered: make(chan struct{}), release: make(chan struct{})}
	mgr := NewNaiveManagerWithServerLocks(&mockNaivePool{client: gate}, awg.NewServerLockRegistry())

	sID, err := db.CreateServer(ctx, &models.Server{
		Name: "S", Host: "198.51.100.72", SSHPort: 22, Protocols: map[string]any{mgr.Protocol(): map[string]any{"port": 443}},
	})
	if err != nil {
		t.Fatalf("CreateServer: %v", err)
	}
	// Legacy adoption already completed, so untracked remote peers are treated as zombies.
	if err := db.SetSetting(ctx, "legacy_peers_adopted:"+strconv.FormatInt(sID, 10)+":"+models.NormalizeProtocol(mgr.Protocol()), true); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}

	addDone := make(chan map[string]any, 1)
	go func() {
		res, err := mgr.AddClient(ctx, &models.Server{ID: sID, Host: "198.51.100.72", SSHPort: 22}, map[string]any{"name": "inflight"})
		if err != nil {
			t.Errorf("AddClient: %v", err)
		}
		addDone <- res
	}()

	<-gate.entered // Caddyfile uploaded, reload in flight, no DB rows yet

	rec := &removeRecorder{NaiveManager: mgr}
	if err := reconciliation.New(db, singleResolver{rec}).CleanupZombiePeers(ctx); err != nil {
		t.Fatalf("CleanupZombiePeers: %v", err)
	}

	close(gate.release)
	added := <-addDone

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.removed) != 0 {
		t.Fatalf("reconciler removed in-flight client(s) %v", rec.removed)
	}
	if !strings.Contains(string(mock.files[NaiveCaddyfilePath]), added["client_id"].(string)) {
		t.Errorf("created client missing from remote Caddyfile")
	}
}
