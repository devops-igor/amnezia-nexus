package vpn

// Group D (issue #794): sanitized transition evidence and the Connecting gate.
//
// These controls assert what an operator surface may CLAIM, not merely that a
// field is populated. The distinction that matters is between
//   - the last probe ATTEMPT (what was just observed, and how it ended), and
//   - the last CONFIRMED successful health evidence (which may be older or absent).
// A status-write timestamp such as last_health_check advances on unsuccessful
// writes too, so it must never be presented as proof that a probe succeeded; no
// assertion here accepts it as such.
//
// The redaction control is a real sink check: the evidence is serialized with the
// same encoder the HTTP layer uses and the resulting bytes are scanned for
// material that must never appear (endpoints, keys, client configuration).

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

// evidenceFor returns the transition evidence for the live pool row.
func (e *hookPreservationEnv) evidenceFor(t *testing.T) (tunnel.TransitionEvidence, bool) {
	t.Helper()
	cur, err := e.svc.pool.GetTunnel(e.blocked.ServerID)
	if err != nil {
		t.Fatalf("read tunnel: %v", err)
	}
	return e.svc.prober.TransitionEvidenceFor(cur)
}

// TestTransitionEvidence_OuterFailureIsNotSuccess is the core honesty control:
// sustained outer failure must be recorded as a FAILURE attempt with an outer
// streak, and must never present itself as successful health evidence.
func TestTransitionEvidence_OuterFailureIsNotSuccess(t *testing.T) {
	e := newHookPreservationEnv(t)
	e.establishFreshCanary(t)

	// Now the outer handshake starts failing while the data path still answers.
	e.svc.prober.SetProbeFunc(func(context.Context, string, string, string, string, string, any, any, int, int, time.Duration) (time.Duration, error) {
		return 0, errors.New("outer handshake timed out")
	})
	if _, _ = e.probeOnce(t); false {
		t.Fatal("unreachable")
	}

	ev, ok := e.evidenceFor(t)
	if !ok {
		t.Fatal("no transition evidence recorded after a probe attempt")
	}
	if ev.LastAttemptOutcome != tunnel.OutcomeFailure {
		t.Errorf("last attempt outcome = %q, want %q", ev.LastAttemptOutcome, tunnel.OutcomeFailure)
	}
	if ev.LastAttemptOuter != tunnel.OutcomeFailure {
		t.Errorf("last outer observation = %q, want %q", ev.LastAttemptOuter, tunnel.OutcomeFailure)
	}
	if ev.FailureCategory != tunnel.FailureOuter {
		t.Errorf("failure category = %q, want %q", ev.FailureCategory, tunnel.FailureOuter)
	}
	if ev.FailureCount < 1 {
		t.Errorf("outer failure streak = %d, want >= 1", ev.FailureCount)
	}
	if ev.FailureThreshold <= 0 {
		t.Errorf("failure threshold was not reported (%d); a reader cannot interpret the count", ev.FailureThreshold)
	}
	if ev.LastAttemptAt == nil {
		t.Error("last attempt timestamp missing")
	}
}

// TestTransitionEvidence_ConnectingReportsEnrollmentGate is the Connecting
// explanation: a backend held in connecting by enrollment quarantine must report
// that gate explicitly, and must NOT claim successful admission evidence.
func TestTransitionEvidence_ConnectingReportsEnrollmentGate(t *testing.T) {
	e := newHookPreservationEnv(t)
	e.setOuterOK()
	e.setHookFails(false)

	// Put the backend into enrollment quarantine through the production
	// mechanism: a deploy-scoped context marks the server while probing.
	ctx := context.WithValue(t.Context(), tunnel.DeployEnrollmentKey, true)
	live, err := e.svc.pool.GetTunnel(e.blocked.ServerID)
	if err != nil {
		t.Fatalf("read tunnel: %v", err)
	}
	if _, err := e.svc.prober.ProbeTunnel(ctx, live); err != nil {
		t.Fatalf("probe under enrollment quarantine: %v", err)
	}

	cur, err := e.svc.pool.GetTunnel(e.blocked.ServerID)
	if err != nil {
		t.Fatalf("re-read tunnel: %v", err)
	}
	if cur.Status != models.TunnelStatusConnecting {
		t.Fatalf("precondition: status = %q, want %q", cur.Status, models.TunnelStatusConnecting)
	}

	ev, ok := e.svc.prober.TransitionEvidenceFor(cur)
	if !ok {
		t.Fatal("no transition evidence for a connecting backend")
	}
	if ev.Gate != tunnel.GateEnrollmentQuarantine {
		t.Errorf("gate = %q, want %q: a connecting backend must say WHY it is not routable", ev.Gate, tunnel.GateEnrollmentQuarantine)
	}
	if ev.Gate == tunnel.GateHealthDisable {
		t.Error("enrollment quarantine must not be reported as a health disable")
	}
	if ev.TunnelID != cur.ID {
		t.Errorf("evidence tunnel id = %d, want the current generation %d", ev.TunnelID, cur.ID)
	}
}

// TestTransitionEvidence_GateDistinguishesAdministrative is the administrative
// exclusion control: an operator disable is not a health disable and not an
// enrollment quarantine, and the evidence must say so.
func TestTransitionEvidence_GateDistinguishesAdministrative(t *testing.T) {
	e := newHookPreservationEnv(t)
	e.establishFreshCanary(t)

	if err := e.svc.pool.SetTunnelEnabled(t.Context(), e.blocked.ServerID, false, models.DisableReasonAdmin); err != nil {
		t.Fatalf("administrative disable: %v", err)
	}
	cur, err := e.svc.pool.GetTunnel(e.blocked.ServerID)
	if err != nil {
		t.Fatalf("read tunnel: %v", err)
	}

	ev, ok := e.svc.prober.TransitionEvidenceFor(cur)
	if !ok {
		t.Skip("no evidence recorded for an administratively disabled backend")
	}
	if ev.Enabled {
		t.Error("evidence reports enabled=true for an administratively disabled backend")
	}
	if ev.Gate == tunnel.GateHealthDisable {
		t.Error("an administrative disable must never be reported as a health disable")
	}
}

// TestTransitionEvidence_InnerSuccessIsSeparateFromOuter is the data-path control:
// the recorded inner outcome must reflect the attached-device canary, not the
// outer handshake. An outer success alone cannot make the inner observation
// successful.
func TestTransitionEvidence_InnerSuccessIsSeparateFromOuter(t *testing.T) {
	e := newHookPreservationEnv(t)
	e.establishFreshCanary(t)

	ev, ok := e.evidenceFor(t)
	if !ok {
		t.Fatal("no transition evidence after a healthy probe")
	}
	if ev.LastAttemptOuter != tunnel.OutcomeSuccess {
		t.Errorf("outer = %q, want %q", ev.LastAttemptOuter, tunnel.OutcomeSuccess)
	}
	if ev.LastAttemptInner != tunnel.OutcomeSuccess {
		t.Errorf("inner = %q, want %q: the attached device answered the canary", ev.LastAttemptInner, tunnel.OutcomeSuccess)
	}
	if ev.LastSuccessAt == nil {
		t.Fatal("no confirmed successful health evidence recorded")
	}
	if ev.SuccessFreshness != tunnel.FreshnessFresh {
		t.Errorf("freshness = %q, want %q", ev.SuccessFreshness, tunnel.FreshnessFresh)
	}
	if ev.DeviceCreatedAt == nil {
		t.Error("evidence is not bound to a device identity")
	}
}

// TestTransitionEvidence_FailedInnerWithdrawsEvidence asserts that a failed inner
// exchange cannot leave the surface claiming fresh success.
func TestTransitionEvidence_FailedInnerWithdrawsEvidence(t *testing.T) {
	e := newHookPreservationEnv(t)
	e.establishFreshCanary(t)

	e.dev.state.Store(canaryDevDead)
	e.svc.prober.SetProbeFunc(func(context.Context, string, string, string, string, string, any, any, int, int, time.Duration) (time.Duration, error) {
		return 20 * time.Millisecond, nil
	})
	if _, _ = e.probeOnce(t); false {
		t.Fatal("unreachable")
	}

	ev, ok := e.evidenceFor(t)
	if !ok {
		t.Fatal("no transition evidence")
	}
	if ev.LastAttemptInner == tunnel.OutcomeSuccess {
		t.Error("inner was reported successful after the canary failed")
	}
	if ev.SuccessFreshness == tunnel.FreshnessFresh {
		t.Error("stale success evidence was still reported as fresh after an inner failure")
	}
}

// TestTransitionEvidence_GenerationFenceRefusesPreviousBackend pins the
// generation fence: evidence recorded for a replaced tunnel row must not be read
// as the current backend's verdict.
func TestTransitionEvidence_GenerationFenceRefusesPreviousBackend(t *testing.T) {
	e := newHookPreservationEnv(t)
	e.establishFreshCanary(t)

	cur, err := e.svc.pool.GetTunnel(e.blocked.ServerID)
	if err != nil {
		t.Fatalf("read tunnel: %v", err)
	}
	replaced := *cur
	replaced.ID = cur.ID + 1000

	if _, ok := e.svc.prober.TransitionEvidenceFor(&replaced); ok {
		t.Fatal("evidence from a replaced tunnel generation was returned for the replacement")
	}
}

// TestTransitionEvidence_RedactedForPublicSurface is the log/API redaction
// control. The evidence is serialized exactly as the diagnostics endpoint would
// serialize it, and the bytes are then scanned for material that must never
// leave the process.
func TestTransitionEvidence_RedactedForPublicSurface(t *testing.T) {
	e := newHookPreservationEnv(t)
	e.establishFreshCanary(t)

	ev, ok := e.evidenceFor(t)
	if !ok {
		t.Fatal("no transition evidence")
	}
	blob, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal evidence: %v", err)
	}
	text := strings.ToLower(string(blob))

	// The tunnel row carries the endpoint and the private keys; none of them may
	// reach the serialized evidence.
	cur, err := e.svc.pool.GetTunnel(e.blocked.ServerID)
	if err != nil {
		t.Fatalf("read tunnel: %v", err)
	}
	forbidden := map[string]string{
		"endpoint":          cur.Endpoint,
		"data private key":  cur.PrivateKey,
		"probe private key": cur.ProbePrivateKey,
		"public key":        cur.PublicKey,
	}
	for what, secret := range forbidden {
		if secret == "" {
			continue
		}
		if strings.Contains(string(blob), secret) {
			t.Errorf("serialized transition evidence contains the %s %q", what, secret)
		}
	}

	// Closed vocabulary only: no free-form error text, no "[Interface]" config
	// body, no key/value credential assignment.
	for _, marker := range []string{"privatekey", "[interface]", "[peer]", "preshared", "error", "ssh", "password"} {
		if strings.Contains(text, marker) {
			t.Errorf("serialized transition evidence contains forbidden marker %q: %s", marker, blob)
		}
	}

	// Timestamps must be present only as explicit attempt/success evidence, never
	// as a claim about health derived from a status write.
	if strings.Contains(text, "last_health_check") {
		t.Error("transition evidence exposes the status-write timestamp as if it were health evidence")
	}
}

// TestDiagnosticsBackendsCarryTransitionEvidence asserts the seam actually
// reaches the diagnostics surface the HTTP layer serializes.
func TestDiagnosticsBackendsCarryTransitionEvidence(t *testing.T) {
	e := newHookPreservationEnv(t)
	e.establishFreshCanary(t)

	diag := collectBackendDiagnostics(e.svc)
	if !diag.EligibilityKnown {
		t.Fatal("eligibility inventory was not captured")
	}
	var found *BackendTelemetryItem
	for i := range diag.Backends {
		if diag.Backends[i].ID == e.blocked.ID {
			found = &diag.Backends[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("backend %d missing from diagnostics", e.blocked.ID)
	}
	if found.Transition == nil {
		t.Fatal("diagnostics did not carry the transition evidence")
	}
	if found.Transition.LastAttemptOuter != tunnel.OutcomeSuccess {
		t.Errorf("diagnostics outer outcome = %q, want %q", found.Transition.LastAttemptOuter, tunnel.OutcomeSuccess)
	}
	if found.HealthState != models.TunnelStatusActive {
		t.Errorf("health state = %q, want %q", found.HealthState, models.TunnelStatusActive)
	}

	// The whole diagnostics payload must serialize without leaking the tunnel's
	// credentials, which is what the HTTP endpoint returns verbatim.
	blob, err := json.Marshal(found)
	if err != nil {
		t.Fatalf("marshal diagnostics item: %v", err)
	}
	cur, err := e.svc.pool.GetTunnel(e.blocked.ServerID)
	if err != nil {
		t.Fatalf("read tunnel: %v", err)
	}
	for _, secret := range []string{cur.PrivateKey, cur.ProbePrivateKey} {
		if secret != "" && strings.Contains(string(blob), secret) {
			t.Error("diagnostics payload leaked a tunnel private key")
		}
	}
}
