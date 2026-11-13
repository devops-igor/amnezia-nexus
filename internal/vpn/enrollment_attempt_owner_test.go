package vpn

// Enrollment-attempt ownership at the shared service/pool seam (issue #794).
//
// Two owner findings meet here and are kept distinct:
//
//  4. Qualification A observes a backend, then a deploy enrollment B resets the
//     SAME row with UNCHANGED identity/credentials. B is a new health/quarantine
//     boundary but is invisible to identity comparison, so a fence built only on
//     models.SameTunnelIdentity (or on StateVersion, which ordinary health writes
//     also advance) cannot see it.
//  5. An AWG canary observes identity A, then the same row is re-enrolled with a
//     DIFFERENT identity B. An obsolete failure must not write disabled/health and
//     must leave B connecting, enabled and quarantined.
//
// These controls drive the real Pool, Service, HealthProber and SQLite store. The
// network outcome is not exercised: the subject is ownership of the enrollment
// attempt, not packet forwarding.

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

// attemptOwners is the three quarantine owners a qualifiable backend has.
type attemptOwners struct{ durable, pool, runtime bool }

func attemptOwnersOf(t *testing.T, s *Service, db interface {
	GetBackendPendingEnrollments(context.Context) (map[int64]bool, error)
}, serverID int64) attemptOwners {
	t.Helper()
	pending, err := db.GetBackendPendingEnrollments(context.Background())
	if err != nil {
		t.Fatalf("read durable enrollment: %v", err)
	}
	return attemptOwners{
		durable: pending[serverID],
		pool:    s.pool.EnrollmentPending(serverID),
		runtime: s.prober.IsPendingEnrollment(serverID),
	}
}

// eligible reports whether the backend is selectable at all: active-pool set and
// the live ingress candidate set. Selection is the observable consequence a false
// admission has to move, so it is asserted rather than an error code.
func attemptEligible(t *testing.T, s *Service, serverID int64) (active, ingress bool) {
	t.Helper()
	for _, a := range s.pool.GetActiveTunnels() {
		if a.ServerID == serverID {
			active = true
		}
	}
	s.mu.Lock()
	cands := s.admissibleIngressCandidatesLocked()
	s.mu.Unlock()
	for _, c := range cands {
		if c.ServerID == serverID {
			ingress = true
		}
	}
	return active, ingress
}

// enrolDeployAttempt performs a real deployment enrollment of serverID through the
// production pool entry point, and returns the observed snapshot.
func enrolDeployAttempt(t *testing.T, s *Service, serverID int64, opts tunnel.BackendTunnelOptions, endpoint string) *models.BackendTunnel {
	t.Helper()
	ctx := context.WithValue(context.Background(), tunnel.DeployEnrollmentKey, true)
	if _, err := s.pool.AddTunnelWithConfig(ctx, serverID, endpoint, "", opts); err != nil {
		t.Fatalf("deploy-enroll backend: %v", err)
	}
	cur, err := s.pool.GetTunnel(serverID)
	if err != nil || cur == nil {
		t.Fatalf("read enrolled backend: %v", err)
	}
	return cur
}

// TestObservedAttemptFenceAWG covers the AWG row shape shared by findings 4 and 5.
func TestObservedAttemptFenceAWG(t *testing.T) {
	t.Run("unchangedIdentityStaleSuccessIsInert", func(t *testing.T) {
		db := setupTestDB(t)
		svc, sid, _, _, _ := setupTestVPNService(t, db)
		ctx := context.Background()
		if err := svc.pool.SyncFromDB(ctx); err != nil {
			t.Fatal(err)
		}
		awg := tunnel.BackendTunnelOptions{Protocol: models.ProtocolAWG}
		svc.SetPendingEnrollment(sid, true)
		observed := enrolDeployAttempt(t, svc, sid, awg, "198.51.100.1:51820")
		observedCopy := *observed
		// Unchanged-identity re-enrollment: same row, same endpoint, same keys.
		svc.SetPendingEnrollment(sid, true)
		attemptB := enrolDeployAttempt(t, svc, sid, awg, observed.Endpoint)
		if attemptB.ID != observed.ID {
			t.Fatalf("fixture: row id changed %d -> %d", observed.ID, attemptB.ID)
		}
		if !models.SameTunnelIdentity(&observedCopy, attemptB) {
			t.Fatal("fixture: identity changed; this control is the UNCHANGED-identity case")
		}
		if attemptB.StateVersion == observedCopy.StateVersion {
			t.Fatal("fixture: no new health boundary")
		}

		if err := svc.PromoteQualifiedTunnel(ctx, &observedCopy, 20); !errors.Is(err, tunnel.ErrTunnelGenerationRetired) {
			t.Fatalf("stale attempt A promotion: err = %v, want ErrTunnelGenerationRetired", err)
		}
		live, err := svc.pool.GetTunnel(sid)
		if err != nil {
			t.Fatal(err)
		}
		row, err := db.GetBackendTunnelByServerID(ctx, sid)
		if err != nil || row == nil {
			t.Fatalf("read durable row: %v", err)
		}
		if live.Status != models.TunnelStatusConnecting || row.Status != models.TunnelStatusConnecting {
			t.Fatalf("stale attempt A admitted B: runtime=%q durable=%q", live.Status, row.Status)
		}
		if own := attemptOwnersOf(t, svc, db, sid); !own.durable || !own.pool || !own.runtime {
			t.Fatalf("stale attempt A released B's quarantine: %+v", own)
		}
		if act, ing := attemptEligible(t, svc, sid); act || ing {
			t.Fatalf("stale attempt A made B selectable: active=%v ingress=%v", act, ing)
		}

		// B's OWN qualification still works, and releases all three owners.
		liveB, err := svc.pool.GetTunnel(sid)
		if err != nil {
			t.Fatal(err)
		}
		if err := svc.PromoteQualifiedTunnel(ctx, liveB, 20); err != nil {
			t.Fatalf("current attempt B qualification refused: %v", err)
		}
		if own := attemptOwnersOf(t, svc, db, sid); own.durable || own.pool || own.runtime {
			t.Fatalf("B's own qualification did not release its quarantine: %+v", own)
		}
		if act, _ := attemptEligible(t, svc, sid); !act {
			t.Fatal("B was not admitted by its own qualification")
		}
	})

	t.Run("benignHealthAdvanceStillPromotes", func(t *testing.T) {
		db := setupTestDB(t)
		svc, sid, _, _, _ := setupTestVPNService(t, db)
		ctx := context.Background()
		if err := svc.pool.SyncFromDB(ctx); err != nil {
			t.Fatal(err)
		}
		awg := tunnel.BackendTunnelOptions{Protocol: models.ProtocolAWG}
		svc.SetPendingEnrollment(sid, true)
		observed := enrolDeployAttempt(t, svc, sid, awg, "198.51.100.1:51820")
		observedCopy := *observed
		// An ordinary health write on the SAME attempt advances the version. A
		// version-equality fence would wrongly refuse this.
		if err := svc.pool.SetTunnelStatus(ctx, sid, models.TunnelStatusConnecting, 5); err != nil {
			t.Fatal(err)
		}
		advanced, err := svc.pool.GetTunnel(sid)
		if err != nil {
			t.Fatal(err)
		}
		if advanced.StateVersion <= observedCopy.StateVersion {
			t.Fatalf("fixture: version did not advance %d -> %d", observedCopy.StateVersion, advanced.StateVersion)
		}
		if advanced.EnrollmentAttempt != observedCopy.EnrollmentAttempt {
			t.Fatal("fixture: an ordinary health write changed the enrollment attempt")
		}
		if err := svc.PromoteQualifiedTunnel(ctx, &observedCopy, 20); err != nil {
			t.Fatalf("legitimate health-version advance blocked promotion: %v", err)
		}
		if own := attemptOwnersOf(t, svc, db, sid); own.durable || own.pool || own.runtime {
			t.Fatalf("promotion after a benign advance did not release quarantine: %+v", own)
		}
		if act, _ := attemptEligible(t, svc, sid); !act {
			t.Fatal("backend was not admitted after a benign health advance")
		}
	})

	t.Run("changedIdentityStaleFailureIsInert", func(t *testing.T) {
		db := setupTestDB(t)
		svc, sid, _, _, _ := setupTestVPNService(t, db)
		ctx := context.Background()
		if err := svc.pool.SyncFromDB(ctx); err != nil {
			t.Fatal(err)
		}
		awg := tunnel.BackendTunnelOptions{Protocol: models.ProtocolAWG}
		svc.SetPendingEnrollment(sid, true)
		observed := enrolDeployAttempt(t, svc, sid, awg, "198.51.100.1:51820")
		observedCopy := *observed
		// Same-row re-enrollment with a DIFFERENT endpoint (finding5's shape, driven
		// through the deploy enrollment rather than a host-update handler).
		svc.SetPendingEnrollment(sid, true)
		attemptB := enrolDeployAttempt(t, svc, sid, awg, "198.51.100.99:51820")
		if attemptB.ID != observed.ID {
			t.Fatalf("fixture: row id changed %d -> %d", observed.ID, attemptB.ID)
		}
		if models.SameTunnelIdentity(&observedCopy, attemptB) {
			t.Fatal("fixture: identity did not change")
		}
		if attemptB.Status != models.TunnelStatusConnecting || !attemptB.Enabled {
			t.Fatalf("fixture: B not connecting/enabled: %+v", attemptB)
		}
		if own := attemptOwnersOf(t, svc, db, sid); !own.durable || !own.pool {
			t.Fatalf("fixture: B is not quarantined: %+v", own)
		}
		before := *attemptB

		err := svc.WithdrawObservedEnrollment(ctx, &observedCopy)
		if !errors.Is(err, tunnel.ErrTunnelGenerationRetired) {
			t.Fatalf("stale attempt failure withdrawal: err = %v, want ErrTunnelGenerationRetired", err)
		}
		live, err := svc.pool.GetTunnel(sid)
		if err != nil {
			t.Fatal(err)
		}
		row, err := db.GetBackendTunnelByServerID(ctx, sid)
		if err != nil || row == nil {
			t.Fatalf("read durable row: %v", err)
		}
		if live.Status != before.Status || live.DisableReason != before.DisableReason ||
			live.StateVersion != before.StateVersion || live.Enabled != before.Enabled {
			t.Fatalf("stale failure drifted B: status=%q reason=%q v=%d enabled=%v; want %q/%q/%d/%v",
				live.Status, live.DisableReason, live.StateVersion, live.Enabled,
				before.Status, before.DisableReason, before.StateVersion, before.Enabled)
		}
		if row.Status != before.Status || row.DisableReason != before.DisableReason || !row.Enabled {
			t.Fatalf("stale failure persisted on B: status=%q reason=%q enabled=%v", row.Status, row.DisableReason, row.Enabled)
		}
		if own := attemptOwnersOf(t, svc, db, sid); !own.durable || !own.pool {
			t.Fatalf("stale failure released B's quarantine: %+v", own)
		}
		if act, ing := attemptEligible(t, svc, sid); act || ing {
			t.Fatalf("stale failure made B selectable: active=%v ingress=%v", act, ing)
		}

		// The current owner's failure still withdraws legitimately.
		if err := svc.WithdrawObservedEnrollment(ctx, live); err != nil {
			t.Fatalf("current-owner withdrawal: %v", err)
		}
		after, err := svc.pool.GetTunnel(sid)
		if err != nil {
			t.Fatal(err)
		}
		if after.Enabled {
			t.Fatal("a genuinely failed current owner was left administratively enabled")
		}
	})
}

// TestObservedAttemptFenceProtocols proves the shared enrollment/promotion seam keeps
// its protocol compatibility: the attempt fence must not be AWG-specific.
func TestObservedAttemptFenceProtocols(t *testing.T) {
	cases := []struct {
		name string
		opts tunnel.BackendTunnelOptions
	}{
		{"vless", tunnel.BackendTunnelOptions{
			Protocol: models.ProtocolVLESS,
			ProtocolParams: json.RawMessage(`{"uuid":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",` +
				`"port":443,"server_name":"vless.example.com",` +
				`"public_key":"K4Z2q0m1nJ9v3xY8wT7rS6pQ5oN4lM3kJ2hG1fE0dC8","short_id":"0123456789abcdef"}`),
		}},
		{"naive", tunnel.BackendTunnelOptions{
			Protocol: models.ProtocolNaive,
			ProtocolParams: json.RawMessage(`{"domain":"naive.example.com","port":443,` +
				`"username":"fixture-user","password":"fixture-pass"}`),
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := setupTestDB(t)
			svc, _, _, _, _ := setupTestVPNService(t, db)
			svc.pool.SetMultiProtocolEnabled(true)
			ctx := context.Background()
			if err := svc.pool.SyncFromDB(ctx); err != nil {
				t.Fatal(err)
			}
			// A fresh server slot: the seeded row is AWG, and changing an existing
			// backend's protocol is correctly refused by the pool, so the
			// proxy-protocol cases need their own slot rather than a switch.
			sid, err := db.CreateServer(ctx, &models.Server{Name: tc.name + "-attempt", Host: "198.51.100.1"})
			if err != nil {
				t.Fatalf("create server: %v", err)
			}
			svc.SetPendingEnrollment(sid, true)
			observed := enrolDeployAttempt(t, svc, sid, tc.opts, "198.51.100.1:443")
			observedCopy := *observed
			// Unchanged-identity re-enrollment on the same protocol.
			svc.SetPendingEnrollment(sid, true)
			attemptB := enrolDeployAttempt(t, svc, sid, tc.opts, observed.Endpoint)
			if attemptB.ID != observed.ID || !models.SameTunnelIdentity(&observedCopy, attemptB) {
				t.Fatalf("fixture: not an unchanged-identity same-row re-enrollment: id %d->%d", observed.ID, attemptB.ID)
			}

			if err := svc.PromoteQualifiedTunnel(ctx, &observedCopy, 20); !errors.Is(err, tunnel.ErrTunnelGenerationRetired) {
				t.Fatalf("stale promotion for %s: err = %v, want retired", tc.name, err)
			}
			if own := attemptOwnersOf(t, svc, db, sid); !own.durable || !own.pool {
				t.Fatalf("stale promotion for %s released quarantine: %+v", tc.name, own)
			}
			// The current attempt still qualifies and releases.
			live, err := svc.pool.GetTunnel(sid)
			if err != nil {
				t.Fatal(err)
			}
			if err := svc.PromoteQualifiedTunnel(ctx, live, 20); err != nil {
				t.Fatalf("current attempt qualification for %s: %v", tc.name, err)
			}
			if own := attemptOwnersOf(t, svc, db, sid); own.durable || own.pool {
				t.Fatalf("current attempt for %s did not release quarantine: %+v", tc.name, own)
			}
		})
	}
}

// TestAttemptOwnershipIsRuntimeOnlyAndDurableQuarantineAuthoritative exercises the
// chosen persistence stance through real pool reload rather than asserting it.
//
// The enrollment attempt is deliberately runtime-only: no observation survives a
// process restart, so a reloaded row starts a fresh attempt. That makes the DURABLE
// quarantine marker — not the attempt id — the authoritative gate across a reload.
// This control proves exactly that, in three steps:
//
//  1. A deploy-enrolled B is quarantined; a restart reloads the same row with a
//     FRESH attempt id and the durable marker still holds it out of selection.
//  2. A stale owner release carrying the PRE-restart attempt id cannot clear it.
//  3. B's own post-reload qualification still admits it and releases both owners.
func TestAttemptOwnershipIsRuntimeOnlyAndDurableQuarantineAuthoritative(t *testing.T) {
	db := setupTestDB(t)
	svc, sid, _, _, _ := setupTestVPNService(t, db)
	ctx := context.Background()
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	awg := tunnel.BackendTunnelOptions{Protocol: models.ProtocolAWG}
	svc.SetPendingEnrollment(sid, true)
	enrolled := enrolDeployAttempt(t, svc, sid, awg, "198.51.100.1:51820")
	if enrolled.EnrollmentAttempt == 0 {
		t.Fatal("fixture: the deploy enrollment recorded no attempt")
	}
	preRestartAttempt := enrolled.EnrollmentAttempt

	// --- restart: a fresh pool + prober over the SAME durable store ---
	restartedPool := tunnel.NewPool(db)
	restartedPool.SetMultiProtocolEnabled(true)
	if err := restartedPool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	if err := restartedPool.ResetEnabledHealthForStartup(ctx); err != nil {
		t.Fatal(err)
	}
	restarted := tunnel.NewHealthProber(restartedPool, db, svc.prober.Config())
	svc.mu.Lock()
	svc.pool = restartedPool
	svc.mu.Unlock()
	svc.SetHealthProber(restarted)

	reloaded, err := svc.pool.GetTunnel(sid)
	if err != nil || reloaded == nil {
		t.Fatalf("read reloaded row: %v", err)
	}
	// The attempt is runtime-only, so the reloaded row carries a fresh (zero) attempt.
	if reloaded.EnrollmentAttempt == preRestartAttempt {
		t.Fatalf("fixture: the attempt id survived a reload (%d); it is meant to be runtime-only",
			reloaded.EnrollmentAttempt)
	}

	// 1. The durable quarantine is still authoritative after the reload.
	if own := attemptOwnersOf(t, svc, db, sid); !own.durable {
		t.Fatalf("the durable quarantine did not survive the reload: %+v", own)
	}
	if act, ing := attemptEligible(t, svc, sid); act || ing {
		t.Fatalf("the reloaded row became selectable: active=%v ingress=%v", act, ing)
	}

	// 2. A stale owner release carrying the PRE-restart attempt id cannot clear it.
	svc.SetHealthProber(restarted)
	restarted.MarkEnrollmentForAttempt(sid, reloaded.ID, preRestartAttempt)
	restarted.ReleaseEnrollmentForAttempt(sid, preRestartAttempt)
	if own := attemptOwnersOf(t, svc, db, sid); !own.durable {
		t.Fatalf("a stale pre-restart release cleared the durable quarantine: %+v", own)
	}
	if act, _ := attemptEligible(t, svc, sid); act {
		t.Fatal("a stale pre-restart release made the row selectable")
	}

	// 3. Post-reload qualification of the CURRENT row still admits it.
	current, err := svc.pool.GetTunnel(sid)
	if err != nil || current == nil {
		t.Fatalf("read current row: %v", err)
	}
	if err := svc.PromoteQualifiedTunnel(ctx, current, 20); err != nil {
		t.Fatalf("post-reload current qualification refused: %v", err)
	}
	if own := attemptOwnersOf(t, svc, db, sid); own.durable || own.pool {
		t.Fatalf("post-reload qualification did not release quarantine: %+v", own)
	}
	if act, _ := attemptEligible(t, svc, sid); !act {
		t.Fatal("the post-reload qualified row was not admitted")
	}
}

// TestEnrollmentMarkerReleaseIsAttemptExact pins the release predicate directly, so
// the attempt half of marker ownership is exercised on each of its answers rather than
// only through the promotion and reload paths above.
func TestEnrollmentMarkerReleaseIsAttemptExact(t *testing.T) {
	db := setupTestDB(t)
	svc, sid, _, _, _ := setupTestVPNService(t, db)
	ctx := context.Background()
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	awg := tunnel.BackendTunnelOptions{Protocol: models.ProtocolAWG}
	svc.SetPendingEnrollment(sid, true)
	observed := enrolDeployAttempt(t, svc, sid, awg, "198.51.100.1:51820")
	observedCopy := *observed
	svc.SetPendingEnrollment(sid, true)
	attemptB := enrolDeployAttempt(t, svc, sid, awg, observed.Endpoint)
	if attemptB.EnrollmentAttempt == observedCopy.EnrollmentAttempt {
		t.Fatal("fixture: the re-enrollment did not start a new attempt")
	}

	// Re-assert B's runtime mark so the recorded owner is B.
	svc.prober.MarkEnrollmentForAttempt(sid, attemptB.ID, attemptB.EnrollmentAttempt)
	if !svc.prober.IsPendingEnrollment(sid) {
		t.Fatal("fixture: B is not runtime-quarantined")
	}

	// A release carrying A's attempt must NOT clear B's mark.
	svc.prober.ReleaseEnrollmentForAttempt(sid, observedCopy.EnrollmentAttempt)
	if !svc.prober.IsPendingEnrollment(sid) {
		t.Fatal("a release from the PREVIOUS enrollment cleared the current attempt's mark")
	}
	// The durable marker is untouched by any runtime release.
	if own := attemptOwnersOf(t, svc, db, sid); !own.durable {
		t.Fatalf("a runtime release cleared the durable quarantine: %+v", own)
	}

	// B's own attempt may release the caller mark. IsPendingEnrollment also reports
	// the pool's generation gate, which B legitimately still holds, so the observable
	// that moves is the pool/durable pair plus continued ineligibility, not that OR.
	svc.prober.ReleaseEnrollmentForAttempt(sid, attemptB.EnrollmentAttempt)
	if act, ing := attemptEligible(t, svc, sid); act || ing {
		t.Fatalf("releasing the caller mark made an unqualified attempt selectable: active=%v ingress=%v", act, ing)
	}
	if own := attemptOwnersOf(t, svc, db, sid); !own.durable || !own.pool {
		t.Fatalf("releasing the caller mark disturbed B's real quarantine: %+v", own)
	}
}
