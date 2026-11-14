package vpn

// Observed-owner finalization through the Service consumer (issue #794 group B).
//
// A qualification observes a backend, does network work against it, and only then
// decides. The decision must apply to the generation it OBSERVED. The replacement
// an operator creates in the meantime owns its own qualification, and a verdict
// about credentials it never had must neither admit it (success) nor disable,
// detach or quarantine it (failure/refusal).
//
// These controls drive the real Service methods: EnableBackend, DeleteBackend,
// PromoteQualifiedTunnel, WithdrawObservedEnrollment, the pool's transactional
// promotion, the real prober marker owners and the real SQLite store. Nothing here
// sets a marker on a replacement's behalf or asserts on an internal check alone.
//
// Stated limit: no remote network, no device underlay, no deployment. The
// generation changes are performed through the production administrative entry
// points, and the network outcome is the injected qualification verdict, exactly
// as the retained independent counterexamples do.

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

// replacementProxyParams is a second, distinct proxy identity for the same server
// slot: same protocol, different endpoint and different client credentials. An
// id-only fence cannot distinguish it from the observed generation.
const replacementProxyParams = `{"uuid":"cccccccc-cccc-4ccc-8ccc-cccccccccccc","port":8443,` +
	`"server_name":"replacement.example.com",` +
	`"public_key":"K4Z2q0m1nJ9v3xY8wT7rS6pQ5oN4lM3kJ2hG1fE0dC8","short_id":"0123456789abcdef"}`

// predecessorProxyParams is the identity the observation is made against.
const predecessorProxyParams = `{"uuid":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","port":9443,` +
	`"server_name":"observed.example.com",` +
	`"public_key":"K4Z2q0m1nJ9v3xY8wT7rS6pQ5oN4lM3kJ2hG1fE0dC8","short_id":"0123456789abcdef"}`

// replacementBackendGeneration replaces the backend on serverID with a distinct
// identity through the production administrative lifecycle: retire, then enable.
// It returns the replacement the service actually registered.
func replacementBackendGeneration(t *testing.T, s *Service, serverID int64) *models.BackendTunnel {
	t.Helper()
	ctx := context.Background()
	if err := s.DeleteBackend(ctx, serverID); err != nil {
		t.Fatalf("retire the observed backend: %v", err)
	}
	// A concurrent ordinary enable, as an operator's re-create does. It is
	// deliberately NOT a deploy enrollment, so it gets no quarantine of its own:
	// the observed backend's stale verdict must not become its quarantine either.
	if err := s.EnableBackendWithConfig(ctx, serverID, tunnel.BackendTunnelOptions{
		Protocol:       models.ProtocolVLESS,
		ProtocolParams: json.RawMessage(replacementProxyParams),
	}); err != nil {
		t.Fatalf("create the replacement backend: %v", err)
	}
	replacement, err := s.pool.GetTunnel(serverID)
	if err != nil || replacement == nil {
		t.Fatalf("read the replacement backend: %v", err)
	}
	return replacement
}

// observedConnectingBackend registers serverID's proxy backend as an unqualified
// (connecting) generation and returns the snapshot a qualification would hold.
//
// The pool is synced from the store first, exactly as production startup does, so
// the slot has ONE row: without it an enable would insert a second row for the
// same server and every durable read would be about a different generation.
func observedConnectingBackend(t *testing.T, s *Service, serverID int64) *models.BackendTunnel {
	t.Helper()
	ctx := context.Background()
	if err := s.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("sync the pool from the store: %v", err)
	}
	if cur, err := s.pool.GetTunnel(serverID); err == nil && cur != nil {
		// The fixture seeds an AWG backend on this slot; a proxy generation
		// replaces it through the ordinary administrative lifecycle.
		if err := s.DeleteBackend(ctx, serverID); err != nil {
			t.Fatalf("retire the seeded backend: %v", err)
		}
	}
	if err := s.EnableBackendWithConfig(ctx, serverID, tunnel.BackendTunnelOptions{
		Protocol:       models.ProtocolVLESS,
		ProtocolParams: json.RawMessage(predecessorProxyParams),
	}); err != nil {
		t.Fatalf("enrol the observed backend: %v", err)
	}
	observed, err := s.pool.GetTunnel(serverID)
	if err != nil || observed == nil {
		t.Fatalf("read the observed backend: %v", err)
	}
	if observed.Status != models.TunnelStatusConnecting {
		t.Fatalf("fixture: observed backend status = %q, want connecting", observed.Status)
	}
	return observed
}

// requireReplacementUntouched asserts the replacement is exactly as an operator's
// successful re-create leaves it: enabled, still unqualified, not durably
// quarantined by anyone else's verdict, and still the slot's generation.
func requireReplacementUntouched(t *testing.T, s *Service, db *database.DB, replacement *models.BackendTunnel) {
	t.Helper()
	ctx := context.Background()
	live, err := s.pool.GetTunnel(replacement.ServerID)
	if err != nil || live == nil {
		t.Fatalf("read the replacement after the stale verdict: %v", err)
	}
	if live.ID != replacement.ID || !models.SameTunnelIdentity(live, replacement) {
		t.Fatalf("the replacement generation changed: got id=%d, want id=%d", live.ID, replacement.ID)
	}
	if !live.Enabled {
		t.Fatal("a retired observation administratively disabled the replacement")
	}
	if live.Status == models.TunnelStatusActive || live.Status == models.TunnelStatusDegraded {
		t.Fatalf("a retired observation admitted the replacement (status %q)", live.Status)
	}
	durable, err := db.GetBackendTunnelByServerID(ctx, replacement.ServerID)
	if err != nil || durable == nil {
		t.Fatalf("read the replacement row: %v", err)
	}
	if durable.ID != replacement.ID {
		t.Fatalf("durable row id = %d, want the replacement generation %d", durable.ID, replacement.ID)
	}
	if !durable.Enabled {
		t.Fatal("a retired observation disabled the replacement in the store")
	}
	if durable.Status == models.TunnelStatusActive || durable.Status == models.TunnelStatusDegraded {
		t.Fatalf("a retired observation admitted the replacement in the store (status %q)", durable.Status)
	}
	pending, err := db.GetBackendPendingEnrollments(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if pending[replacement.ServerID] {
		t.Fatal("a retired observation quarantined the replacement it never observed")
	}
	if s.prober.IsPendingEnrollment(replacement.ServerID) {
		t.Fatal("a retired observation left the replacement runtime-quarantined")
	}
}

// TestPromoteQualifiedTunnelRefusesRetiredGeneration is the stale-SUCCESS control:
// the promotion of an observed generation must not land on its replacement.
func TestPromoteQualifiedTunnelRefusesRetiredGeneration(t *testing.T) {
	db := setupTestDB(t)
	svc, sid, _, _, _ := setupTestVPNService(t, db)
	svc.pool.SetMultiProtocolEnabled(true)
	ctx := context.Background()

	observed := observedConnectingBackend(t, svc, sid)
	replacement := replacementBackendGeneration(t, svc, sid)

	// Asserted before the error shape: the observable harm is the replacement being
	// admitted, which a wrong error alone would not reveal.
	requireReplacementUntouched(t, svc, db, replacement)
	if err := svc.PromoteQualifiedTunnel(ctx, observed, 12); !errors.Is(err, tunnel.ErrTunnelGenerationRetired) {
		t.Fatalf("promotion of the retired generation: err = %v, want ErrTunnelGenerationRetired", err)
	}
	requireReplacementUntouched(t, svc, db, replacement)
}

// TestWithdrawObservedEnrollmentLeavesReplacementInert is the stale-FAILURE
// control: the withdrawal of an observed generation must not disable, detach or
// quarantine the replacement.
func TestWithdrawObservedEnrollmentLeavesReplacementInert(t *testing.T) {
	db := setupTestDB(t)
	svc, sid, _, _, _ := setupTestVPNService(t, db)
	svc.pool.SetMultiProtocolEnabled(true)
	ctx := context.Background()

	observed := observedConnectingBackend(t, svc, sid)
	replacement := replacementBackendGeneration(t, svc, sid)

	// Asserted before the error shape: the observable harm is the replacement being
	// disabled and quarantined, which a wrong error alone would not reveal.
	requireReplacementUntouched(t, svc, db, replacement)
	if err := svc.WithdrawObservedEnrollment(ctx, observed); !errors.Is(err, tunnel.ErrTunnelGenerationRetired) {
		t.Fatalf("withdrawal of the retired generation: err = %v, want ErrTunnelGenerationRetired", err)
	}
	requireReplacementUntouched(t, svc, db, replacement)
}

// TestWithdrawObservedEnrollmentTreatsRemovedSlotAsInert covers the other retired
// shape: the operator deleted the backend and has not created a successor. The
// observation has no target, which must be a no-op rather than an error the
// enclosing failure path turns into a second, server-keyed disable.
func TestWithdrawObservedEnrollmentTreatsRemovedSlotAsInert(t *testing.T) {
	db := setupTestDB(t)
	svc, sid, _, _, _ := setupTestVPNService(t, db)
	svc.pool.SetMultiProtocolEnabled(true)
	ctx := context.Background()

	observed := observedConnectingBackend(t, svc, sid)
	if err := svc.DeleteBackend(ctx, sid); err != nil {
		t.Fatalf("retire the observed backend: %v", err)
	}
	if err := svc.WithdrawObservedEnrollment(ctx, observed); err != nil {
		t.Fatalf("withdrawal against an empty slot: %v, want nil", err)
	}
	if _, err := svc.pool.GetTunnel(sid); !errors.Is(err, tunnel.ErrTunnelNotFound) {
		t.Fatalf("the empty slot gained a backend: %v", err)
	}
}

// TestQualifiedCurrentGenerationStillAdmitsAndReleases is the CURRENT-OWNER
// success control. It proves the identity fence did not narrow the legitimate
// path: the observed generation, still owning its slot, is admitted and both
// quarantine owners are released by its own qualification.
func TestQualifiedCurrentGenerationStillAdmitsAndReleases(t *testing.T) {
	db := setupTestDB(t)
	svc, sid, _, _, _ := setupTestVPNService(t, db)
	svc.pool.SetMultiProtocolEnabled(true)
	ctx := context.Background()

	observed := observedConnectingBackend(t, svc, sid)
	svc.SetPendingEnrollment(sid, true)
	if !svc.prober.IsPendingEnrollment(sid) {
		t.Fatal("fixture: the current generation is not quarantined")
	}

	if err := svc.PromoteQualifiedTunnel(ctx, observed, 12); err != nil {
		t.Fatalf("qualify the current generation: %v", err)
	}
	live, err := svc.pool.GetTunnel(sid)
	if err != nil || live.ID != observed.ID {
		t.Fatalf("promotion changed the generation: %v", err)
	}
	if live.Status != models.TunnelStatusActive {
		t.Fatalf("current generation status = %q, want active", live.Status)
	}
	if !live.Enabled {
		t.Fatal("a qualified backend was left administratively disabled")
	}
	durable, err := db.GetBackendTunnelByServerID(ctx, sid)
	if err != nil || durable == nil {
		t.Fatalf("read the qualified row: %v", err)
	}
	if durable.ID != live.ID {
		t.Fatalf("durable row id = %d, want the qualified generation %d", durable.ID, live.ID)
	}
	if durable.Status != models.TunnelStatusActive {
		t.Fatalf("durable status = %q, want active", durable.Status)
	}
	pending, err := db.GetBackendPendingEnrollments(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if pending[sid] {
		t.Fatal("the qualified backend kept its durable quarantine")
	}
	if svc.prober.IsPendingEnrollment(sid) {
		t.Fatal("the qualified backend kept its runtime quarantine")
	}
}

// TestWithdrawObservedEnrollmentWithdrawsTheCurrentGeneration is the CURRENT-OWNER
// failure control: a genuine failure of the generation that still owns the slot
// keeps the established withdrawal semantics.
func TestWithdrawObservedEnrollmentWithdrawsTheCurrentGeneration(t *testing.T) {
	db := setupTestDB(t)
	svc, sid, _, _, _ := setupTestVPNService(t, db)
	svc.pool.SetMultiProtocolEnabled(true)
	ctx := context.Background()

	observed := observedConnectingBackend(t, svc, sid)
	if err := svc.WithdrawObservedEnrollment(ctx, observed); err != nil {
		t.Fatalf("withdraw the current generation: %v", err)
	}
	live, err := svc.pool.GetTunnel(sid)
	if err != nil {
		t.Fatalf("read the withdrawn backend: %v", err)
	}
	if live.ID != observed.ID {
		t.Fatalf("withdrawal changed the generation: got %d, want %d", live.ID, observed.ID)
	}
	if live.Enabled {
		t.Fatal("a backend that failed its own qualification was left administratively enabled")
	}
	durable, err := db.GetBackendTunnelByServerID(ctx, sid)
	if err != nil || durable == nil {
		t.Fatalf("read the withdrawn row: %v", err)
	}
	if durable.ID != live.ID {
		t.Fatalf("durable row id = %d, want the withdrawn generation %d", durable.ID, live.ID)
	}
	if durable.Enabled {
		t.Fatal("the withdrawn backend stayed enabled in the store")
	}
	if !svc.prober.IsPendingEnrollment(sid) {
		t.Fatal("the withdrawn backend lost its runtime quarantine")
	}
}
