package vpn

import (
	"context"
	"errors"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

// R2-2 reversed-order regression: the mirror of the R2-1 schedule. The HOST
// update is parked inside its pre-lock window (after AdminGeneration was
// sampled, before its private candidate is prepared and before the Service.mu
// commit boundary), and a newer KEY update completes INSIDE that window.
//
// Contract under test (per the fenceBackendIdentityCommit contract block):
// the host commit observes the admin-generation advance, and because the row
// is STILL ENABLED (the newer operation was a key rotation, not a disable),
// it rejects its own commit as backendIdentityCommitStale. The key
// generation's committed state stays exactly as it was:
//
//   - the key's committed identity (DESIRED at ENDPOINT0) survives in the
//     pool, in SQLite, and in a freshly reloaded pool;
//   - the key's published device keeps serving — the parked host operation
//     never publishes its (ENDPOINT1, OLDKEY) candidate over it;
//   - the endpoint never moves: the host operation commits nothing, so its
//     whole compensation is the discard of its private candidate.
func TestR2_2HostCommitAfterKeyRotationRejectsStaleAdvance(t *testing.T) {
	ctx := context.Background()
	svc, id, initial := lifecycleTestService(t)
	// The fixture's EnableBackend build passes through the same prepare
	// helper this counter measures; reset so the assertions below count
	// only candidates prepared inside the test window.
	svc.ResetPreparedCandidateCountForTest()

	oldDevice := svc.GetBackendDeviceForTest(id)
	if oldDevice == nil || oldDevice.IsClosed() {
		t.Fatalf("fixture must start with an open real OLD device, got %T", oldDevice)
	}
	newHost := r2_1SwappedHost(initial.Endpoint)

	// Park the REAL host update at its pre-lock hook: after baseAdminGen was
	// sampled, before the host's private candidate exists. The R2-2 contract
	// under test: NOTHING has been prepared or published while parked.
	hostParked := make(chan struct{})
	releaseHost := make(chan struct{})
	t.Cleanup(func() {
		// Failure-path hygiene: release a parked host goroutine so it exits
		// instead of leaking. Happy path: no-op (already released below).
		select {
		case <-releaseHost:
		default:
			close(releaseHost)
		}
	})
	svc.SetUpdateBackendServerHostPreLockHook(func() {
		close(hostParked)
		<-releaseHost
	})
	t.Cleanup(func() { svc.SetUpdateBackendServerHostPreLockHook(nil) })

	hostDone := make(chan error, 1)
	go func() {
		hostDone <- svc.UpdateBackendServerHost(ctx, id, newHost)
	}()
	awaitR2_1Barrier(t, hostParked, "host update reaching its pre-lock window")

	// Park-state sanity: the parked host update has prepared NOTHING (its
	// candidate is built only after the hook) and the durable row is
	// untouched.
	if n := svc.PreparedCandidateCountForTest(); n != 0 {
		t.Fatalf("park precondition broken: the parked host update must not have prepared any candidate, got %d prepared", n)
	}
	parked, err := svc.GetTunnel(id)
	if err != nil {
		t.Fatal(err)
	}
	if parked.Endpoint != initial.Endpoint || parked.PublicKey != initial.PublicKey {
		t.Fatalf("park precondition broken: live row must be untouched at the pre-lock window, got (%q, %q)", parked.Endpoint, parked.PublicKey)
	}

	// Newer key update completes INSIDE the window: it commits DESIRED
	// durably and publishes a real device built for (ENDPOINT0, DESIRED).
	if err := svc.UpdateBackendServerPublicKey(ctx, id, r2_1DesiredKey); err != nil {
		t.Fatalf("newer key update failed inside the window: %v", err)
	}
	newerDevice := svc.GetBackendDeviceForTest(id)
	if newerDevice == nil || newerDevice == oldDevice || newerDevice.IsClosed() {
		t.Fatalf("newer key update must install a fresh open real device, got %T", newerDevice)
	}
	if n := svc.PreparedCandidateCountForTest(); n != 1 {
		t.Fatalf("window precondition broken: only the key update may have prepared a candidate inside the window, got %d prepared", n)
	}
	during, err := svc.GetTunnel(id)
	if err != nil {
		t.Fatal(err)
	}
	if during.PublicKey != r2_1DesiredKey || during.Endpoint != initial.Endpoint {
		t.Fatalf("window precondition broken: live row must be (DESIRED, ENDPOINT0), got (%q, %q)", during.PublicKey, during.Endpoint)
	}

	// Release the parked host update (clean context, no cancellation) and
	// let it reach its commit boundary. The fence must observe the newer
	// generation with the row still enabled and reject the commit.
	close(releaseHost)
	hostErr := awaitR2_1Completion(t, hostDone, "released host update")
	if !errors.Is(hostErr, backendIdentityCommitStale) {
		t.Fatalf("expected the host commit to reject the advanced generation with backendIdentityCommitStale, got %v", hostErr)
	}
	if errors.Is(hostErr, context.Canceled) {
		t.Fatalf("host update was not canceled; stale rejection must not carry a cancellation cause, got %v", hostErr)
	}

	after, err := svc.GetTunnel(id)
	if err != nil {
		t.Fatal(err)
	}
	row, err := svc.db.GetBackendTunnel(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	reloadedPool := tunnel.NewPool(svc.db)
	if err := reloadedPool.SyncFromDB(ctx); err != nil {
		t.Fatalf("fresh pool reload failed: %v", err)
	}
	reloaded, err := reloadedPool.GetTunnel(id)
	if err != nil {
		t.Fatal(err)
	}

	// --- ORACLE (a): the key generation's committed identity survived ---
	if after.PublicKey != r2_1DesiredKey || row.PublicKey != r2_1DesiredKey || reloaded.PublicKey != r2_1DesiredKey {
		t.Errorf("oracle a: key generation did not survive intact — pool/SQLite/reloaded keys (%q, %q, %q), want %q",
			after.PublicKey, row.PublicKey, reloaded.PublicKey, r2_1DesiredKey)
	}
	if after.Endpoint != initial.Endpoint || row.Endpoint != initial.Endpoint || reloaded.Endpoint != initial.Endpoint {
		t.Errorf("oracle a: the stale host commit moved the endpoint — pool/SQLite/reloaded endpoints (%q, %q, %q), want %q",
			after.Endpoint, row.Endpoint, reloaded.Endpoint, initial.Endpoint)
	}

	// --- ORACLE (b): the key's device still serves, untouched ---
	attached := svc.GetBackendDeviceForTest(id)
	if attached != newerDevice || newerDevice.IsClosed() {
		t.Errorf("oracle b: the key generation's device must keep serving after the host commit was rejected, got %T (same=%v, closed=%v)",
			attached, attached == newerDevice, attached != nil && attached.IsClosed())
	}
	if got := svc.GetBackendDeviceEndpointForTest(id); got != initial.Endpoint {
		t.Errorf("oracle b: attached device endpoint %q must stay at the key construction identity %q — the host candidate must never publish", got, initial.Endpoint)
	}
}
