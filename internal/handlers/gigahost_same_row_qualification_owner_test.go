package handlers

// Same-row AWG qualification ownership (issue #794 group B).
//
// The delete/re-create shape is covered by the file this one extends. This file adds
// the ADJACENT shape that a backend row can change identity WITHOUT changing its id:
// a legitimate endpoint update (server host correction) walks
// servers -> backend_lifecycle -> pool.SetTunnelEndpoint, which rewrites the endpoint
// and bumps StateVersion on the SAME backend row.
//
// Under that schedule an in-flight AWG canary verdict is about an identity that no
// longer exists. It must be inert: not only must the guarded withdrawal refuse it, but
// no earlier health writer may record `disabled`/`health` for the replacement identity
// either — such a record is false, and the withdrawal's correctness cannot undo it.
//
// The schedule is reproduced from the independently executed audit probe
// (same_row_host_canary_probe_test.go, sha256 a8965d84…97bb906). The bytes are retained
// as provenance; this is the committed derivative that keeps the guarantee enforced.
//
// Subject: real deployment handler, host-update handler, Service, Pool and SQLite. The
// provider, SSH transport and outer/inner network verdicts are the standard fixtures.

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
	"github.com/go-chi/chi/v5"
)

// updateServerHostThroughHandler moves a server's endpoint through the production
// host-update handler, which is how an operator corrects a backend address.
func updateServerHostThroughHandler(t *testing.T, h *Handlers, serverID int64, host string) {
	t.Helper()
	router := chi.NewRouter()
	router.Post("/servers/{server_id}/host", h.UpdateServerHostHandler)
	req := httptest.NewRequest("POST",
		fmt.Sprintf("/servers/%d/host", serverID),
		strings.NewReader(fmt.Sprintf(`{"host":%q}`, host)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("host-update handler failed: status=%d body=%s", rec.Code, rec.Body.String())
	}
}

// sameRowReplacementFixture moves the observed backend onto a new endpoint during the
// AWG inner canary and returns a holder for the replacement identity plus the canary
// verdict.
//
// The replacement is returned through a POINTER so the deploy's late assignment is
// visible to the caller; returning the value itself would freeze it at call time, before
// the canary seam ever runs.
//
// The preconditions asserted here are the ones that make the case meaningful: SAME row
// id, DIFFERENT identity, and an unqualified but administratively enabled baseline.
func sameRowReplacementFixture(
	t *testing.T, h *Handlers, verdict error,
) (**models.BackendTunnel, *int64, *bool) {
	t.Helper()
	replacement := new(*models.BackendTunnel)
	serverID := new(int64)
	enrolledAtObservation := new(bool)
	h.vpnSvc.SetCanaryProbeFunc(func(_ context.Context, observed *models.BackendTunnel) error {
		*serverID = observed.ServerID
		updateServerHostThroughHandler(t, h, observed.ServerID, "198.51.100.99")
		current, err := h.vpnSvc.GetTunnel(observed.ServerID)
		if err != nil || current == nil {
			t.Fatalf("read the same-row replacement: %v", err)
		}
		if current.ID != observed.ID {
			t.Fatalf("fixture: the row id changed (%d -> %d); this control is about same-row identity changes",
				observed.ID, current.ID)
		}
		if models.SameTunnelIdentity(observed, current) {
			t.Fatal("fixture: the host update did not change the backend identity")
		}
		if !current.Enabled || current.Status != models.TunnelStatusConnecting {
			t.Fatalf("fixture: replacement baseline enabled=%v status=%q, want enabled/connecting",
				current.Enabled, current.Status)
		}
		*replacement = current
		// Enrollment as the deployment itself established it, before this verdict.
		marks, markErr := h.db.GetBackendPendingEnrollments(context.Background())
		if markErr != nil {
			t.Fatalf("read the enrollment baseline: %v", markErr)
		}
		*enrolledAtObservation = marks[observed.ServerID]
		return verdict
	})
	return replacement, serverID, enrolledAtObservation
}

// requireSameRowReplacementUntouched asserts the replacement kept EXACTLY the state it
// had before the obsolete verdict: status, reason, state version, enabled flag — in
// memory and in the store.
func requireSameRowReplacementUntouched(
	t *testing.T, h *Handlers, before *models.BackendTunnel, enrolledBefore bool,
) {
	t.Helper()
	ctx := context.Background()
	live, err := h.vpnSvc.GetTunnel(before.ServerID)
	if err != nil || live == nil {
		t.Fatalf("read the live result: %v", err)
	}
	if !models.SameTunnelIdentity(live, before) {
		t.Fatal("the replacement identity changed")
	}
	if live.Status != before.Status || live.DisableReason != before.DisableReason ||
		live.StateVersion != before.StateVersion || live.Enabled != before.Enabled {
		t.Fatalf("an obsolete AWG verdict mutated the same-row replacement: status=%q reason=%q version=%d enabled=%v; want status=%q reason=%q version=%d enabled=%v",
			live.Status, live.DisableReason, live.StateVersion, live.Enabled,
			before.Status, before.DisableReason, before.StateVersion, before.Enabled)
	}
	durable, err := h.db.GetBackendTunnelByServerID(ctx, before.ServerID)
	if err != nil || durable == nil {
		t.Fatalf("read the durable result: %v", err)
	}
	if durable.ID != before.ID {
		t.Fatalf("durable row id = %d, want the replacement row %d", durable.ID, before.ID)
	}
	if durable.Status != before.Status || durable.DisableReason != before.DisableReason || !durable.Enabled {
		t.Fatalf("an obsolete AWG verdict persisted on the replacement: status=%q reason=%q enabled=%v; want status=%q reason=%q enabled=true",
			durable.Status, durable.DisableReason, durable.Enabled,
			before.Status, before.DisableReason)
	}
	pending, err := h.db.GetBackendPendingEnrollments(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// The stale completion must be inert for enrollment: it may neither add a
	// quarantine for the replacement nor release the one its own deployment holds.
	if pending[before.ServerID] != enrolledBefore {
		t.Fatalf("an obsolete AWG verdict changed the replacement's enrollment: pending=%v, want unchanged %v",
			pending[before.ServerID], enrolledBefore)
	}
}

// TestSameRowHostReplacementSurvivesObsoleteAWGCanaryFailure is the retained
// same-row regression: an endpoint correction lands while the old AWG canary is in
// flight, and the obsolete failure verdict must leave the replacement exactly as it was.
func TestSameRowHostReplacementSurvivesObsoleteAWGCanaryFailure(t *testing.T) {
	h, _, _ := setupDeployTestEnv(t)
	before, serverID, enrolledBefore := sameRowReplacementFixture(t, h,
		errors.New("old AWG inner canary timed out"))

	_, err := h.DeployGigahostOrder(context.Background(), GigahostDeployRequest{
		OrderID: "ord_test_1001", SSHPassword: "ValidSSHPass123!",
		ServerName: "same-row-obsolete-failure", Protocol: "awg", Port: "51820", WaitReady: true,
	})
	if *before == nil {
		t.Fatalf("fixture: the same-row replacement was never observed (deploy err=%v)", err)
	}
	if err == nil {
		t.Fatal("an obsolete failed qualification reported a ready deployment")
	}
	if *serverID != (*before).ServerID {
		t.Fatalf("fixture: server ids diverged (%d vs %d)", *serverID, (*before).ServerID)
	}
	requireSameRowReplacementUntouched(t, h, *before, *enrolledBefore)
}

// TestSameRowHostReplacementSurvivesObsoleteAWGCanarySuccess is the success-side
// counterpart, so the same-row guarantee is not proven only for the failure writer.
func TestSameRowHostReplacementSurvivesObsoleteAWGCanarySuccess(t *testing.T) {
	h, _, _ := setupDeployTestEnv(t)
	before, _, enrolledBefore := sameRowReplacementFixture(t, h, nil)

	_, err := h.DeployGigahostOrder(context.Background(), GigahostDeployRequest{
		OrderID: "ord_test_1001", SSHPassword: "ValidSSHPass123!",
		ServerName: "same-row-obsolete-success", Protocol: "awg", Port: "51820", WaitReady: true,
	})
	if *before == nil {
		t.Fatalf("fixture: the same-row replacement was never observed (deploy err=%v)", err)
	}
	requireSameRowReplacementUntouched(t, h, *before, *enrolledBefore)
}

// TestCurrentOwnerAWGCanaryFailureStillRecordsAndWithdraws is the positive control the
// correction needs most: a GENUINE inner-canary failure of the backend that still owns
// its slot must keep the established semantics — recorded as disabled/health and
// withdrawn (administratively disabled, still quarantined).
//
// Without this, "ignore obsolete verdicts" could silently become "ignore failures".
func TestCurrentOwnerAWGCanaryFailureStillRecordsAndWithdraws(t *testing.T) {
	h, _, provider := setupDeployTestEnv(t)
	provider.getDeployStatusFn = func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
		return &gigahost.DeployStatusResponse{
			ServerID:   2110,
			Status:     gigahost.StatusReady,
			AssignedIP: "198.51.100.70",
		}, nil
	}
	// The outer handshake succeeds and the identity does not change; only the inner
	// payload verdict fails, and it belongs to the current owner.
	var canaryCalls atomic.Int64
	h.vpnSvc.SetCanaryProbeFunc(func(context.Context, *models.BackendTunnel) error {
		canaryCalls.Add(1)
		return errors.New("inner canary: payload did not traverse")
	})

	_, err := h.DeployGigahostOrder(context.Background(), GigahostDeployRequest{
		OrderID: "ord_test_1001", SSHPassword: "ValidSSHPass123!",
		ServerName: "current-owner-canary-failure", Protocol: "awg", Port: "51820", WaitReady: true,
	})
	if err == nil {
		t.Fatal("a genuine canary failure reported a ready deployment")
	}
	if canaryCalls.Load() == 0 {
		t.Fatal("the canary seam never ran: the control proves nothing")
	}
	backends, listErr := h.vpnSvc.GetBackends(context.Background())
	if listErr != nil || len(backends) != 1 {
		t.Fatalf("backends=%d err=%v, want exactly one backend", len(backends), listErr)
	}
	live := backends[0]
	if live.Status != models.TunnelStatusDisabled || live.DisableReason != models.DisableReasonHealth {
		t.Fatalf("genuine current-owner canary failure = status=%q reason=%q, want disabled/health",
			live.Status, live.DisableReason)
	}
	if live.Enabled {
		t.Fatal("a backend that failed its own canary was left administratively enabled")
	}
	pending, getErr := h.db.GetBackendPendingEnrollments(context.Background())
	if getErr != nil {
		t.Fatal(getErr)
	}
	if !pending[live.ServerID] {
		t.Fatal("a backend that failed its own canary released its durable quarantine")
	}
}
