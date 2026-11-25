package orchestrator

// Every background job that dials a server must honour the provider-absent state,
// not only the reachability loop.
//
// One test per path, each measuring the dialling itself (a probe callback, or a
// protocol-manager call that opens an SSH session) rather than reading a log, and
// each running a live server beside the absent one in the same pass so the
// suppression is distinguishable from a job that did nothing at all.

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// recordingProtocolManager counts the GetClients calls a job makes per server,
// which is the SSH session a traffic or auto-trial pass would open. It lives here
// rather than in the shared mock so the large existing test file does not grow.
type recordingProtocolManager struct {
	*mockOrchProtocolManager
	mu      sync.Mutex
	queries []int64
}

func newRecordingProtocolManager(proto string) *recordingProtocolManager {
	return &recordingProtocolManager{mockOrchProtocolManager: newMockOrchProtocolManager(proto)}
}

func (m *recordingProtocolManager) GetClients(ctx context.Context, server *models.Server) ([]map[string]any, error) {
	m.mu.Lock()
	if server != nil {
		m.queries = append(m.queries, server.ID)
	}
	m.mu.Unlock()
	return m.mockOrchProtocolManager.GetClients(ctx, server)
}

func (m *recordingProtocolManager) clientQueries() []int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]int64(nil), m.queries...)
}

// TestOrchestrator_CheckBackendTunnelHealth_SkipsProviderAbsentServer covers the
// scheduled backend health pass: the AWG handshake probe must not run for a tunnel
// whose server the provider's inventory has confirmed absent, while a tunnel on a
// listed server is probed exactly as before.
func TestOrchestrator_CheckBackendTunnelHealth_SkipsProviderAbsentServer(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	absentServerID, err := db.CreateServer(ctx, &models.Server{Name: "Provider absent", Host: "198.51.100.20", SSHPort: 22})
	if err != nil {
		t.Fatalf("failed to seed the absent server: %v", err)
	}
	liveServerID, err := db.CreateServer(ctx, &models.Server{Name: "Still listed", Host: "198.51.100.21", SSHPort: 22})
	if err != nil {
		t.Fatalf("failed to seed the listed server: %v", err)
	}

	absentTunnelID, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      absentServerID,
		InterfaceName: "awg-absent",
		PublicKey:     "pub-absent",
		PrivateKey:    "priv-absent",
		Endpoint:      "198.51.100.20:55424",
		Enabled:       true,
		Status:        models.TunnelStatusActive,
	})
	if err != nil {
		t.Fatalf("failed to seed the absent server's tunnel: %v", err)
	}
	liveTunnelID, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      liveServerID,
		InterfaceName: "awg-live",
		PublicKey:     "pub-live",
		PrivateKey:    "priv-live",
		Endpoint:      "198.51.100.21:55424",
		Enabled:       true,
		Status:        models.TunnelStatusActive,
	})
	if err != nil {
		t.Fatalf("failed to seed the listed server's tunnel: %v", err)
	}

	// The observation is recorded, never inferred from the tunnel's own fields.
	if err := db.SetServerProviderAbsence(ctx, absentServerID, time.Now().UTC(), ""); err != nil {
		t.Fatalf("failed to record the provider absence: %v", err)
	}

	var probes int32
	var probedEndpoints []string
	probe := func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		atomic.AddInt32(&probes, 1)
		probedEndpoints = append(probedEndpoints, endpoint)
		return 12 * time.Millisecond, nil
	}

	orch := New(db, nil, WithProbeFunc(probe))
	if err := orch.CheckBackendTunnelHealth(ctx); err != nil {
		t.Fatalf("CheckBackendTunnelHealth failed: %v", err)
	}

	if got := atomic.LoadInt32(&probes); got != 1 {
		t.Fatalf("expected exactly one backend handshake probe (the listed server), got %d", got)
	}
	if len(probedEndpoints) != 1 || probedEndpoints[0] != "198.51.100.21:55424" {
		t.Fatalf("the probe did not target only the listed server: %v", probedEndpoints)
	}

	// The absent tunnel's health was not measured and therefore not rewritten.
	absentTunnel, err := db.GetBackendTunnel(ctx, absentTunnelID)
	if err != nil || absentTunnel == nil {
		t.Fatalf("failed to read the absent server's tunnel back: %v", err)
	}
	if absentTunnel.Status != models.TunnelStatusActive {
		t.Fatalf("a refused probe rewrote the absent tunnel's status to %q", absentTunnel.Status)
	}
	liveTunnel, err := db.GetBackendTunnel(ctx, liveTunnelID)
	if err != nil || liveTunnel == nil {
		t.Fatalf("failed to read the listed server's tunnel back: %v", err)
	}
	if liveTunnel.LatencyMS != 12 {
		t.Fatalf("the listed server's tunnel was not updated from its probe: latency=%d", liveTunnel.LatencyMS)
	}
}

// TestOrchestrator_SyncTraffic_SkipsProviderAbsentServer covers the scheduled
// traffic sync: it opens an SSH session per protocol per server, so an absent
// server must not be queried at all while a listed one still is.
func TestOrchestrator_SyncTraffic_SkipsProviderAbsentServer(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	awgProtocols := map[string]any{"awg": map[string]any{"port": 55424}}

	absentServerID, err := db.CreateServer(ctx, &models.Server{
		Name: "Provider absent", Host: "198.51.100.30", SSHPort: 22, Protocols: awgProtocols,
	})
	if err != nil {
		t.Fatalf("failed to seed the absent server: %v", err)
	}
	liveServerID, err := db.CreateServer(ctx, &models.Server{
		Name: "Still listed", Host: "198.51.100.31", SSHPort: 22, Protocols: awgProtocols,
	})
	if err != nil {
		t.Fatalf("failed to seed the listed server: %v", err)
	}

	userID, err := db.CreateUser(ctx, &models.User{Username: "traffic_absence_user", Role: models.RoleUser, Enabled: true})
	if err != nil {
		t.Fatalf("failed to seed the user: %v", err)
	}
	for _, srv := range []struct {
		id     int64
		client string
	}{{absentServerID, "cid-absent"}, {liveServerID, "cid-live"}} {
		if _, err := db.CreateConnection(ctx, &models.UserConnection{
			UserID:    userID,
			ServerID:  srv.id,
			Protocol:  "awg",
			ClientID:  srv.client,
			Name:      "auto_vpn_" + srv.client,
			CreatedAt: time.Now().UTC(),
		}); err != nil {
			t.Fatalf("failed to seed the connection for server %d: %v", srv.id, err)
		}
	}

	if err := db.SetServerProviderAbsence(ctx, absentServerID, time.Now().UTC(), ""); err != nil {
		t.Fatalf("failed to record the provider absence: %v", err)
	}

	awgMgr := newRecordingProtocolManager("awg")
	awgMgr.clients = []map[string]any{{
		"clientId": "cid-live",
		"userData": map[string]any{"dataReceivedBytes": 1024, "dataSentBytes": 2048},
	}}
	reg := newMockOrchRegistry()
	reg.Register(awgMgr)

	orch := New(db, reg)
	if err := orch.SyncTraffic(ctx); err != nil {
		t.Fatalf("SyncTraffic failed: %v", err)
	}

	queried := map[int64]int{}
	for _, id := range awgMgr.clientQueries() {
		queried[id]++
	}
	if queried[absentServerID] != 0 {
		t.Fatalf("the absent server was queried %d time(s); no session may be opened to it", queried[absentServerID])
	}
	if queried[liveServerID] != 1 {
		t.Fatalf("the listed server was queried %d time(s), want 1", queried[liveServerID])
	}
}

// TestOrchestrator_CheckAutoTrialHandshakes_SkipsProviderAbsentServer covers the
// scheduled auto-trial pass: it reads the backend's clients over SSH and rotates
// mimicry, so an absent server must not be read or rotated while a listed one is.
func TestOrchestrator_CheckAutoTrialHandshakes_SkipsProviderAbsentServer(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	absentServerID, err := db.CreateServer(ctx, &models.Server{
		Name: "Provider absent", Host: "198.51.100.40", SSHPort: 22,
		Protocols: map[string]any{"awg": map[string]any{"port": 55424}},
	})
	if err != nil {
		t.Fatalf("failed to seed the absent server: %v", err)
	}
	liveServerID, err := db.CreateServer(ctx, &models.Server{
		Name: "Still listed", Host: "198.51.100.41", SSHPort: 22,
		Protocols: map[string]any{"awg": map[string]any{"port": 55424}},
	})
	if err != nil {
		t.Fatalf("failed to seed the listed server: %v", err)
	}

	userID, err := db.CreateUser(ctx, &models.User{Username: "autotrial_absence_user", Role: models.RoleUser, Enabled: true})
	if err != nil {
		t.Fatalf("failed to seed the user: %v", err)
	}
	for _, srv := range []struct {
		id     int64
		client string
	}{{absentServerID, "cid-absent"}, {liveServerID, "cid-live"}} {
		if _, err := db.CreateConnection(ctx, &models.UserConnection{
			UserID:     userID,
			ServerID:   srv.id,
			Protocol:   "awg",
			ClientID:   srv.client,
			Name:       "autotrial_" + srv.client,
			AWGMimicry: models.AWGMimicryAuto,
			CreatedAt:  time.Now().UTC(),
		}); err != nil {
			t.Fatalf("failed to seed the connection for server %d: %v", srv.id, err)
		}
	}

	if err := db.SetServerProviderAbsence(ctx, absentServerID, time.Now().UTC(), ""); err != nil {
		t.Fatalf("failed to record the provider absence: %v", err)
	}

	awgMgr := newRecordingProtocolManager("awg")
	// Both clients have stalled handshakes, so both would be rotated if the pass
	// dialled them.
	awgMgr.clients = []map[string]any{
		{"clientId": "cid-absent", "userData": map[string]any{"latestHandshake": "5 minutes ago"}},
		{"clientId": "cid-live", "userData": map[string]any{"latestHandshake": "5 minutes ago"}},
	}
	reg := newMockOrchRegistry()
	reg.Register(awgMgr)

	orch := New(db, reg)
	if err := orch.CheckAutoTrialHandshakes(ctx); err != nil {
		t.Fatalf("CheckAutoTrialHandshakes failed: %v", err)
	}

	for _, id := range awgMgr.clientQueries() {
		if id == absentServerID {
			t.Fatal("the absent server's clients were read over SSH; it must not be dialled")
		}
	}
	rotated := map[string]bool{}
	for _, client := range awgMgr.rotated {
		rotated[client] = true
	}
	if rotated["cid-absent"] {
		t.Fatal("the absent server's connection was rotated through a host the provider no longer lists")
	}
	if !rotated["cid-live"] {
		t.Fatal("the listed server's stalled connection was not rotated, so the pass did not run")
	}
}
