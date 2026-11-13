package vpn

// Enrollment ownership through the service consumer (issue #794 group B).
//
// The Gigahost deploy path marks the server pending, then enables the backend
// through Service.EnableBackendWithConfig with the deploy-enrollment context. That
// mark is server-keyed and is taken before the replacement tunnel exists, so the
// replacement's quarantine must come from the deploy add itself. These tests drive
// the real service methods for delete, deploy re-enable, a late server-keyed
// release and a restart, and judge the result by admission (the ingress candidate
// set) and the store, never by a marker the test set on the replacement's behalf.

import (
	"context"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

// assertNotAdmittedAfterProbe runs an ordinary background probe whose outer
// handshake succeeds and asserts the backend is still not an ingress candidate.
func assertNotAdmittedAfterProbe(t *testing.T, s *Service, serverID int64) {
	t.Helper()
	s.prober.SetProbeFunc(func(context.Context, string, string, string, string, string, any, any, int, int, time.Duration) (time.Duration, error) {
		return 10 * time.Millisecond, nil
	})
	cur, err := s.pool.GetTunnel(serverID)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = s.ProbeTunnel(context.Background(), cur)
	s.mu.Lock()
	candidates := s.admissibleIngressCandidatesLocked()
	s.mu.Unlock()
	for _, c := range candidates {
		if c.ServerID == serverID {
			after, _ := s.pool.GetTunnel(serverID)
			t.Fatalf("unqualified deploy-created replacement was admitted on a handshake-only probe (status=%s)", after.Status)
		}
	}
}

// TestServiceDeployReplacementQuarantinedUntilOwnQualification exercises the
// service path a reinstall takes: retire the enrolled backend, deploy-enable a
// replacement, let a stale server-keyed release for the retired generation arrive,
// restart, and only then qualify the replacement.
func TestServiceDeployReplacementQuarantinedUntilOwnQualification(t *testing.T) {
	db := setupTestDB(t)
	svc, sid, _, _, _ := setupTestVPNService(t, db)
	ctx := context.Background()
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	retired, err := svc.pool.GetTunnel(sid)
	if err != nil {
		t.Fatal(err)
	}
	svc.SetPendingEnrollment(sid, true) // the retired backend was mid-enrollment

	if err := svc.DeleteBackend(ctx, sid); err != nil {
		t.Fatalf("delete backend: %v", err)
	}

	// The deploy consumer: server-keyed mark before the tunnel exists, then the
	// deploy-context enable that creates the replacement.
	svc.SetPendingEnrollment(sid, true)
	deploy := context.WithValue(ctx, tunnel.DeployEnrollmentKey, true)
	if err := svc.EnableBackendWithConfig(deploy, sid); err != nil {
		t.Fatalf("deploy enable of the replacement: %v", err)
	}
	replacement, err := svc.pool.GetTunnel(sid)
	if err != nil {
		t.Fatal(err)
	}
	if replacement.ID == retired.ID {
		t.Fatalf("fixture: replacement reused tunnel id %d", retired.ID)
	}

	// A late server-keyed release for the retired generation (the shape of the
	// enable-failure and canary-failure cleanups) must not admit the replacement.
	svc.SetPendingEnrollment(sid, false)

	pending, err := db.GetBackendPendingEnrollments(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !pending[sid] || !svc.prober.IsPendingEnrollment(sid) {
		t.Fatalf("deploy-created replacement lost its quarantine: durable=%v runtime=%v",
			pending[sid], svc.prober.IsPendingEnrollment(sid))
	}
	assertNotAdmittedAfterProbe(t, svc, sid)

	// Restart: a fresh pool and prober over the same store.
	restartedPool := tunnel.NewPool(db)
	restartedPool.SetMultiProtocolEnabled(true)
	if err := restartedPool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	if err := restartedPool.ResetEnabledHealthForStartup(ctx); err != nil {
		t.Fatal(err)
	}
	restarted := tunnel.NewHealthProber(restartedPool, db, svc.prober.Config())
	if !restarted.IsPendingEnrollment(sid) {
		t.Fatal("restart lost the deploy-created replacement's quarantine")
	}
	svc.mu.Lock()
	svc.pool = restartedPool
	svc.mu.Unlock()
	svc.SetHealthProber(restarted)
	assertNotAdmittedAfterProbe(t, svc, sid)

	// Its own qualification admits it and releases both owners.
	cur, err := svc.pool.GetTunnel(sid)
	if err != nil || cur.ID != replacement.ID {
		t.Fatalf("restart changed the replacement: %+v err=%v", cur, err)
	}
	if err := svc.PromoteQualifiedTunnel(ctx, cur, 20); err != nil {
		t.Fatalf("qualify replacement: %v", err)
	}
	pending, err = db.GetBackendPendingEnrollments(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if pending[sid] || svc.prober.IsPendingEnrollment(sid) {
		t.Fatalf("qualification did not release the replacement: durable=%v runtime=%v",
			pending[sid], svc.prober.IsPendingEnrollment(sid))
	}
}
