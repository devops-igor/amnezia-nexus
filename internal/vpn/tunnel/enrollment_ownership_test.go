package tunnel

// Enrollment generation ownership (issue #794 group B).
//
// A deploy-created replacement must stay quarantined until ITS OWN qualification
// commits, whatever order the retired generation's runtime release, the deploy add
// and the caller's own enrollment marking arrive in. The release runs after the pool
// lock is dropped, so these tests pause it there, put the real deploy add (the path
// Service.EnableBackendWithConfig takes for a Gigahost deployment) inside that window,
// and judge the outcome by selection after an ordinary background probe sweep, not by
// inspecting a marker the test itself set.

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

const ownershipTestKey = "test-secret-key-1234567890123456"

// pauseFirstEnrollmentEvent wraps the runtime enrollment owner registered on the
// pool so that its FIRST invocation blocks until resume is called. Later
// invocations pass straight through to the real owner.
func pauseFirstEnrollmentEvent(t *testing.T, p *Pool) (entered <-chan struct{}, resume func()) {
	t.Helper()
	p.mu.RLock()
	owner := p.enrollmentReleaseHook
	p.mu.RUnlock()
	if owner == nil {
		t.Fatal("fixture: no runtime enrollment owner is registered on the pool")
	}
	in := make(chan struct{})
	gate := make(chan struct{})
	var first sync.Once
	p.SetEnrollmentReleaseHook(func(ctx context.Context, serverID, retiredTunnelID int64) {
		paused := false
		first.Do(func() { paused = true })
		if paused {
			close(in)
			<-gate
		}
		owner(ctx, serverID, retiredTunnelID)
	})
	var once sync.Once
	release := func() { once.Do(func() { close(gate) }) }
	t.Cleanup(release)
	return in, release
}

func waitEntered(t *testing.T, entered <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s never reached the runtime enrollment owner", what)
	}
}

// admittedAfterBackgroundProbe runs an ordinary background sweep (plain context,
// successful outer handshake) and reports whether the server became selectable.
func admittedAfterBackgroundProbe(t *testing.T, hp *HealthProber, pool *Pool, serverID int64) bool {
	t.Helper()
	hp.SetProbeFunc(testProbeSuccessHelper)
	if err := hp.ProbeAll(context.Background())[serverID]; err != nil {
		t.Fatalf("background probe of server %d: %v", serverID, err)
	}
	for _, active := range pool.GetActiveTunnels() {
		if active.ServerID == serverID {
			return true
		}
	}
	return false
}

func durablyPending(t *testing.T, db *database.DB, serverID int64) bool {
	t.Helper()
	pending, err := db.GetBackendPendingEnrollments(context.Background())
	if err != nil {
		t.Fatalf("read durable enrollments: %v", err)
	}
	return pending[serverID]
}

// assertQuarantinedUntilQualified checks the replacement is gated by BOTH owners,
// refuses selection after a successful handshake-only sweep, and that its own
// current qualification still admits it and releases both owners.
func assertQuarantinedUntilQualified(t *testing.T, hp *HealthProber, pool *Pool, db *database.DB, serverID, replacementID int64) {
	t.Helper()
	if !durablyPending(t, db, serverID) {
		t.Fatal("deploy-created replacement is not durably quarantined")
	}
	if !hp.IsPendingEnrollment(serverID) {
		t.Fatal("deploy-created replacement is not quarantined in the runtime owner")
	}
	if admittedAfterBackgroundProbe(t, hp, pool, serverID) {
		t.Fatal("deploy-created replacement became selectable on a handshake-only sweep, without its own qualification")
	}
	cur, err := pool.GetTunnel(serverID)
	if err != nil {
		t.Fatalf("read replacement: %v", err)
	}
	if cur.ID != replacementID {
		t.Fatalf("replacement identity changed: %d -> %d", replacementID, cur.ID)
	}
	if cur.Status != models.TunnelStatusConnecting {
		t.Fatalf("unqualified replacement status = %q, want %q", cur.Status, models.TunnelStatusConnecting)
	}

	// Its own qualification is the release point, through the production commit.
	if err := pool.PromoteTunnelWithEnrollmentRelease(
		context.Background(), serverID, cur.ID, cur.StateVersion, models.TunnelStatusActive, 20,
	); err != nil {
		t.Fatalf("current qualification of the replacement: %v", err)
	}
	if durablyPending(t, db, serverID) {
		t.Fatal("current qualification did not release the durable quarantine")
	}
	if hp.IsPendingEnrollment(serverID) {
		t.Fatal("current qualification did not release the runtime quarantine")
	}
	if !admittedAfterBackgroundProbe(t, hp, pool, serverID) {
		t.Fatal("qualified replacement is not selectable")
	}
}

// TestDeployCreatedReplacementStaysQuarantinedAcrossRetiredRelease forces the
// removal's unlocked release window and creates the replacement through the deploy
// add inside it. The replacement is never marked by the test; the only marking is
// what the production consumer does (enableDeployBackend marks before it enables,
// which with an empty slot cannot know the future tunnel).
func TestDeployCreatedReplacementStaysQuarantinedAcrossRetiredRelease(t *testing.T) {
	cases := []struct {
		name            string
		retiredEnrolled bool // the retired backend was itself mid-enrollment
		premarkInWindow bool // the consumer's pre-enable marking lands while the slot is empty
	}{
		{"deploy-add-only", false, false},
		{"retired-enrollment", true, false},
		{"consumer-premark-in-window", false, true},
		{"retired-enrollment-and-premark", true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newEnrollmentLifecycleFixture(t)
			if tc.retiredEnrolled {
				f.markEnrolled(t)
			}
			retiredID := f.mustTunnelID(t)

			entered, resume := pauseFirstEnrollmentEvent(t, f.pool)
			removed := make(chan error, 1)
			go func() { removed <- f.pool.RemoveTunnel(context.Background(), f.server) }()
			waitEntered(t, entered, "the removal")

			// --- the unlocked window: the deployment's own steps ---
			if tc.premarkInWindow {
				f.prober.SetPendingEnrollment(f.server, true)
			}
			deploy := context.WithValue(context.Background(), DeployEnrollmentKey, true)
			replacement, err := f.pool.AddTunnel(deploy, f.server, "192.0.2.231:51820", "deploy-replacement")
			if err != nil {
				t.Fatalf("deploy add inside the window: %v", err)
			}
			if replacement.ID == retiredID {
				t.Fatalf("fixture: replacement reused retired id %d", retiredID)
			}

			resume()
			if err := <-removed; err != nil {
				t.Fatalf("removal: %v", err)
			}
			assertQuarantinedUntilQualified(t, f.prober, f.pool, f.prober.db, f.server, replacement.ID)
		})
	}
}

// reloadedStore is a pool and prober reconstructed from the file exactly as
// service startup does it: open, sync, reset health, then the prober restores
// durable quarantine.
type reloadedStore struct {
	db     *database.DB
	pool   *Pool
	prober *HealthProber
}

func reloadStore(t *testing.T, path string) *reloadedStore {
	t.Helper()
	ctx := context.Background()
	db, err := database.Open(path, ownershipTestKey)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	pool := NewPool(db)
	if err := pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("sync from store: %v", err)
	}
	if err := pool.ResetEnabledHealthForStartup(ctx); err != nil {
		t.Fatalf("startup health reset: %v", err)
	}
	return &reloadedStore{db: db, pool: pool, prober: NewHealthProber(pool, db, DefaultHealthConfig())}
}

func (r *reloadedStore) close(t *testing.T) {
	t.Helper()
	if err := r.db.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
}

// newDeployedStore creates a file-backed store with one deploy-enrolled backend.
func newDeployedStore(t *testing.T) (path string, serverID int64) {
	t.Helper()
	ctx := context.Background()
	path = filepath.Join(t.TempDir(), "ownership.db")
	db, err := database.Open(path, ownershipTestKey)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	serverID, err = db.CreateServer(ctx, &models.Server{Name: "ownership", Host: "192.0.2.240"})
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	pool := NewPool(db)
	_ = NewHealthProber(pool, db, DefaultHealthConfig())
	deploy := context.WithValue(ctx, DeployEnrollmentKey, true)
	if _, err := pool.AddTunnel(deploy, serverID, "192.0.2.240:51820", "deploy-retired"); err != nil {
		t.Fatalf("deploy add: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	return path, serverID
}

// TestReloadedEnrollmentReplacementStaysQuarantined covers the reload generation:
// a quarantine restored from durable state at startup belongs to the backend that
// existed then. Its removal must not clear a deploy-created replacement's
// quarantine, and the replacement must stay gated across a further reload.
func TestReloadedEnrollmentReplacementStaysQuarantined(t *testing.T) {
	path, sid := newDeployedStore(t)

	first := reloadStore(t, path)
	if !first.prober.IsPendingEnrollment(sid) {
		t.Fatal("precondition: reload did not restore the quarantine")
	}
	retired, err := first.pool.GetTunnel(sid)
	if err != nil {
		t.Fatalf("read reloaded backend: %v", err)
	}

	entered, resume := pauseFirstEnrollmentEvent(t, first.pool)
	removed := make(chan error, 1)
	go func() { removed <- first.pool.RemoveTunnel(context.Background(), sid) }()
	waitEntered(t, entered, "the removal")
	deploy := context.WithValue(context.Background(), DeployEnrollmentKey, true)
	replacement, err := first.pool.AddTunnel(deploy, sid, "192.0.2.240:51820", "deploy-replacement")
	if err != nil {
		t.Fatalf("deploy add inside the window: %v", err)
	}
	if replacement.ID == retired.ID {
		t.Fatalf("fixture: replacement reused id %d", retired.ID)
	}
	resume()
	if err := <-removed; err != nil {
		t.Fatalf("removal: %v", err)
	}

	if !first.prober.IsPendingEnrollment(sid) {
		t.Fatal("the reloaded generation's release cleared the deploy-created replacement's runtime quarantine")
	}
	if admittedAfterBackgroundProbe(t, first.prober, first.pool, sid) {
		t.Fatal("deploy-created replacement became selectable without its own qualification")
	}
	first.close(t)

	// A further restart must keep the replacement gated and still let its own
	// qualification admit it.
	second := reloadStore(t, path)
	cur, err := second.pool.GetTunnel(sid)
	if err != nil {
		t.Fatalf("read replacement after reload: %v", err)
	}
	if cur.ID != replacement.ID {
		t.Fatalf("reload changed replacement identity: %d -> %d", replacement.ID, cur.ID)
	}
	assertQuarantinedUntilQualified(t, second.prober, second.pool, second.db, sid, replacement.ID)
}

// TestReloadedPlainDeletionReleasesWithoutOverQuarantine is the control: after a
// reload, a genuine plain deletion releases both owners, and a plain manual re-add
// (not an enrollment) is not quarantined and is selectable after a healthy sweep.
func TestReloadedPlainDeletionReleasesWithoutOverQuarantine(t *testing.T) {
	path, sid := newDeployedStore(t)
	r := reloadStore(t, path)
	if !r.prober.IsPendingEnrollment(sid) {
		t.Fatal("precondition: reload did not restore the quarantine")
	}
	if err := r.pool.RemoveTunnel(context.Background(), sid); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if r.prober.IsPendingEnrollment(sid) || durablyPending(t, r.db, sid) {
		t.Fatal("plain deletion of the reloaded backend left a quarantine behind")
	}
	if _, err := r.pool.AddTunnel(context.Background(), sid, "192.0.2.240:51820", "manual-readd"); err != nil {
		t.Fatalf("plain re-add: %v", err)
	}
	if r.prober.IsPendingEnrollment(sid) || durablyPending(t, r.db, sid) {
		t.Fatal("plain re-add inherited the retired quarantine")
	}
	if !admittedAfterBackgroundProbe(t, r.prober, r.pool, sid) {
		t.Fatal("plain re-add is not selectable after a healthy sweep")
	}
}

// TestLateQualificationReleaseCannotClearReplacementQuarantine pins the other
// release point. Qualification commits through the pool and then releases the
// caller's server-keyed mark (Service.PromoteQualifiedTunnel does exactly this,
// after the pool lock is dropped). If the qualified backend is removed and a
// deploy-created replacement appears before that late release, the release
// belongs to the qualified generation and must not clear the replacement.
func TestLateQualificationReleaseCannotClearReplacementQuarantine(t *testing.T) {
	f := newEnrollmentLifecycleFixture(t)
	if err := f.pool.RemoveTunnel(context.Background(), f.server); err != nil {
		t.Fatalf("precondition remove: %v", err)
	}
	deploy := context.WithValue(context.Background(), DeployEnrollmentKey, true)
	f.prober.SetPendingEnrollment(f.server, true) // consumer premark, empty slot
	qualified, err := f.pool.AddTunnel(deploy, f.server, "192.0.2.231:51820", "deploy-qualified")
	if err != nil {
		t.Fatalf("deploy add: %v", err)
	}
	if err := f.pool.PromoteTunnelWithEnrollmentRelease(
		context.Background(), f.server, qualified.ID, qualified.StateVersion, models.TunnelStatusActive, 20,
	); err != nil {
		t.Fatalf("qualification commit: %v", err)
	}

	// --- the gap before the late release: removal and a deploy-created replacement ---
	if err := f.pool.RemoveTunnel(context.Background(), f.server); err != nil {
		t.Fatalf("remove the qualified backend: %v", err)
	}
	f.prober.SetPendingEnrollment(f.server, true) // the replacement's own premark
	replacement, err := f.pool.AddTunnel(deploy, f.server, "192.0.2.231:51820", "deploy-replacement")
	if err != nil {
		t.Fatalf("deploy add of the replacement: %v", err)
	}

	// --- the qualified generation's late server-keyed release ---
	f.prober.SetPendingEnrollment(f.server, false)

	assertQuarantinedUntilQualified(t, f.prober, f.pool, f.prober.db, f.server, replacement.ID)
}
