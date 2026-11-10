package vpn

// Positive admission cases for issue #731. The fixture and helpers live in
// canary_admission_e2e_test.go; this file holds only the two admitted cases and
// the #742 interaction, so each file stays inside the repository size budget.

import (
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// TestCanaryAdmission_ActiveControlValidatesFixture is the fixture-validity
// control: with the backend genuinely active the same path carries bidirectional
// payload for both peers. Without it a later refusal could just be a broken
// fixture.
func TestCanaryAdmission_ActiveControlValidatesFixture(t *testing.T) {
	e := newCanaryAdmissionEnv(t)
	cases := []struct {
		name  string
		peer  enginePeer
		saved string
	}{
		{"existing", e.existing, e.existingSaved},
		{"fresh", e.fresh, e.freshSaved},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := e.dial(t, tc.peer, tc.saved, 10*time.Second, "canary-control-"+tc.name)
			if err != nil {
				t.Fatalf("active backend did not carry the client: %v", err)
			}
			if err := echo(c, "canary-admission-active-control-"+tc.name, 5*time.Second); err != nil {
				t.Fatalf("active backend did not carry payload: %v", err)
			}
			if o := e.ownership(t, tc.peer.publicKey); !o.admitted || o.backendTunnelID != e.blocked.ID {
				t.Fatalf("active control ownership = %+v", o)
			}
		})
	}
}

// TestCanaryAdmission_NewClientOnBlockedBackendWithFreshCanary proves the
// headline requirement: a brand-new portal client is admitted onto a
// handshake-blocked backend while its attached inner path is proven alive, and
// carries bidirectional payload with correct session/route/gauge identity.
func TestCanaryAdmission_NewClientOnBlockedBackendWithFreshCanary(t *testing.T) {
	e := newCanaryAdmissionEnv(t)
	cur := e.sweepFailingOuter(t)
	if cur.Status != models.TunnelStatusHandshakeBlocked {
		t.Fatalf("fixture: backend status = %q, want handshake_blocked", cur.Status)
	}
	if cur.ActiveConnections != 0 {
		t.Fatalf("fixture: backend already has %d sessions", cur.ActiveConnections)
	}

	c, err := e.dial(t, e.fresh, e.freshSaved, 10*time.Second, "canary-new-client")
	if err != nil {
		t.Fatalf("new client refused on a canary-proven blocked backend: %v", err)
	}
	e.requireAdmittedOnBlockedBackend(t, e.fresh.publicKey, 1)
	if err := echo(c, "canary-admission-new-client-payload", 5*time.Second); err != nil {
		t.Fatalf("admitted client got no bidirectional payload: %v", err)
	}
}

// TestCanaryAdmission_RouteLossReadmission proves the second admitted case: a
// client whose forwarder route was lost while pinned to the blocked backend is
// re-admitted there with payload, instead of being refused or moved.
func TestCanaryAdmission_RouteLossReadmission(t *testing.T) {
	e := newCanaryAdmissionEnv(t)
	c, err := e.dial(t, e.existing, e.existingSaved, 10*time.Second, "canary-route-loss")
	if err != nil {
		t.Fatalf("initial admission on the active backend: %v", err)
	}
	if err := echo(c, "canary-admission-pre-block", 5*time.Second); err != nil {
		t.Fatalf("pre-block payload: %v", err)
	}
	cur := e.sweepFailingOuter(t)
	if cur.Status != models.TunnelStatusHandshakeBlocked {
		t.Fatalf("fixture: backend status = %q", cur.Status)
	}
	// Preservation: the established route is untouched by the outer failure.
	if err := echo(c, "canary-admission-preserved-route", 5*time.Second); err != nil {
		t.Fatalf("existing route lost when the backend became blocked: %v", err)
	}

	e.svc.forwarder.UnregisterSession(e.existing.publicKey)
	if got := e.svc.forwarder.RouteSessionID(e.existing.publicKey); got != "" {
		t.Fatalf("fixture: route still present after unregister (%q)", got)
	}
	if err := echo(c, "canary-admission-readmitted", 10*time.Second); err != nil {
		t.Fatalf("route-loss peer was not re-admitted with payload: %v", err)
	}
	e.requireAdmittedOnBlockedBackend(t, e.existing.publicKey, 1)
}

// TestCanaryAdmission_SlowOuterSuccessPreservesThenAdmits covers the #742
// interaction: a slow outer SUCCESS on a session-carrying blocked backend keeps
// the preservation label, and because the inner canary succeeded on that same
// sweep the backend also stays admissible for a new client.
func TestCanaryAdmission_SlowOuterSuccessPreservesThenAdmits(t *testing.T) {
	e := newCanaryAdmissionEnv(t)
	c, err := e.dial(t, e.existing, e.existingSaved, 10*time.Second, "canary-slow-existing")
	if err != nil {
		t.Fatalf("initial admission: %v", err)
	}
	if cur := e.sweepFailingOuter(t); cur.Status != models.TunnelStatusHandshakeBlocked {
		t.Fatalf("fixture: status = %q", cur.Status)
	}
	cur := e.sweepSlowOuterSuccess(t)
	if cur.Status != models.TunnelStatusHandshakeBlocked {
		t.Fatalf("slow outer success changed a session-carrying blocked backend to %q, want handshake_blocked preserved", cur.Status)
	}
	if err := echo(c, "canary-admission-slow-preserved", 5*time.Second); err != nil {
		t.Fatalf("slow outer success disturbed the established route: %v", err)
	}
	// The same slow sweep ran the inner canary, so a new client must be admitted.
	nc, err := e.dial(t, e.fresh, e.freshSaved, 10*time.Second, "canary-slow-new")
	if err != nil {
		t.Fatalf("new client refused after a canary-proven slow outer success: %v", err)
	}
	if err := echo(nc, "canary-admission-slow-new-payload", 5*time.Second); err != nil {
		t.Fatalf("newly admitted client got no payload: %v", err)
	}
	o := e.ownership(t, e.fresh.publicKey)
	if !o.admitted || o.backendTunnelID != e.blocked.ID || o.activeConns != 2 {
		t.Fatalf("slow-success admission ownership = %+v (want 2 sessions on the blocked backend)", o)
	}
	if o.tunnelStatus != models.TunnelStatusHandshakeBlocked {
		t.Fatalf("status = %q, want handshake_blocked preserved", o.tunnelStatus)
	}
}
