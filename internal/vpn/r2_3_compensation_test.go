package vpn

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

// R2-3 permanent regressions (resolution-plan section 3, items 3-4): after the
// R2-2 preparation-first reordering, EVERY remaining rollback/compensation path
// in the key/host update flows must restore only the state owned by its own
// transaction.
//
// Compensation-path audit result this file pins (vpn.go at R2-3):
//
//	path                                    | verdict
//	----------------------------------------+--------------------------------
//	dual-write metadata rollback (endpoint  | DELETED in R2-2: preparation-
//	  and key restore + ErrVPNRollbackFailed|   first ordering left no local
//	  join, ctx.Err() rollback branch)      |   work after the durable commit,
//	                                        |   so there is nothing to roll back
//	private-candidate discard               | KEPT, generation-owned by
//	  (discardBackendForwarderCandidate)    |   construction: the candidate is
//	                                        |   operation-private until its own
//	                                        |   commit publishes it, so its
//	                                        |   failure compensation can only
//	                                        |   ever close its OWN device
//	same-endpoint reconcile attach failure  | KEPT as quarantine-lite: no
//	  (syncBackendForwarderOnHostUpdate-    |   durable write precedes the
//	  Locked → Degraded + wrapped error)    |   attach, so "keep OLD applied,
//	                                        |   mark degraded, preserve the
//	                                        |   cause" IS the truthful outcome;
//	                                        |   an OLD-restore would be a
//	                                        |   metadata-only no-op
//	publication (publishPreparedCandidate-  | NOT a compensation path: attach
//	  IfServingLocked)                      |   has no error result, so no
//	                                        |   rollback-failure is possible
//	                                        |   after the durable commit
//
// No surviving multi-write compensation window exists, so nothing needed
// generation re-binding; TestR2_1/TestR2_2 already pin that the fence — not a
// compensation — protects a newer committed generation from a stale operation.
// The discarded-candidate test below adds the missing real-device proof: the
// compensation touches ONLY its own candidate, never the serving device.

// failHostUpdateCommitTrigger fails the durable endpoint write at the real
// SQLite boundary — the exact statement Pool.SetTunnelEndpoint issues through
// UpdateBackendTunnelEndpoint. It is a database trigger, not a service stub:
// the failure this matrix needs is a failed durable write.
const failHostUpdateCommitTrigger = `
	CREATE TRIGGER fail_host_update_commit
	BEFORE UPDATE OF endpoint ON backend_tunnels
	BEGIN
		SELECT RAISE(FAIL, 'r2-3 simulated endpoint persist failure');
	END;`

// TestR2_3CompensationDiscardsOnlyItsOwnCandidate is the real-device oracle
// for the one surviving compensation path. A key update parks inside its
// private preparation window (candidate built, nothing published), a newer
// host update completes INSIDE that window, then the key request is canceled
// and released into its commit fence. The fence rejects the stale generation
// and the key operation's ONLY compensation is closing its own candidate:
// the host generation's committed device must be untouched — never rebuilt,
// never closed, never re-attached — and the committed durable/live identity
// must survive verbatim.
func TestR2_3CompensationDiscardsOnlyItsOwnCandidate(t *testing.T) {
	ctx := context.Background()
	svc, id, initial := lifecycleTestService(t)
	svc.ResetPreparedCandidateCountForTest()

	oldDevice := svc.GetBackendDeviceForTest(id)
	if oldDevice == nil || oldDevice.IsClosed() {
		t.Fatalf("fixture must start with an open real OLD device, got %T", oldDevice)
	}
	newHost := r2_1SwappedHost(initial.Endpoint)

	// B1: park the key update inside its private preparation window.
	keyParked := make(chan struct{})
	releaseKey := make(chan struct{})
	keyCtx, cancelKey := context.WithCancel(context.Background())
	defer cancelKey()
	t.Cleanup(func() {
		cancelKey()
		select {
		case <-releaseKey:
		default:
			close(releaseKey)
		}
	})
	svc.SetUpdateBackendServerPublicKeyPreLockHook(func() {
		close(keyParked)
		<-releaseKey
	})
	t.Cleanup(func() { svc.SetUpdateBackendServerPublicKeyPreLockHook(nil) })

	keyDone := make(chan error, 1)
	go func() {
		keyDone <- svc.UpdateBackendServerPublicKey(keyCtx, id, r2_1DesiredKey)
	}()
	awaitR2_1Barrier(t, keyParked, "key update reaching its private preparation window")

	// B2: a newer host update completes INSIDE the window, committing
	// ENDPOINT1 and publishing a real device built for the committed
	// identity at that moment.
	if err := svc.UpdateBackendServerHost(ctx, id, newHost); err != nil {
		t.Fatalf("newer host update failed inside the window: %v", err)
	}
	hostDevice := svc.GetBackendDeviceForTest(id)
	if hostDevice == nil || hostDevice == oldDevice || hostDevice.IsClosed() {
		t.Fatalf("newer host update must install a fresh open real device, got %T", hostDevice)
	}
	if got := svc.GetBackendDeviceEndpointForTest(id); got != mustSwappedEndpoint(t, initial.Endpoint) {
		t.Fatalf("host device must own the committed endpoint, got %q", got)
	}
	hostCommitted, err := svc.GetTunnel(id)
	if err != nil {
		t.Fatal(err)
	}
	if hostCommitted.Endpoint == initial.Endpoint {
		t.Fatalf("host update must have committed a new endpoint, got %q twice", hostCommitted.Endpoint)
	}

	// B3: cancel the parked key request and release it into the commit
	// fence. The fence observes the advanced generation and rejects the
	// commit; the typed stale error carries the cancellation cause.
	cancelKey()
	close(releaseKey)
	keyErr := awaitR2_1Completion(t, keyDone, "canceled key update")
	if !errors.Is(keyErr, backendIdentityCommitStale) || !errors.Is(keyErr, context.Canceled) {
		t.Fatalf("expected the stale fence carrying the cancellation cause, got %v", keyErr)
	}

	// ORACLE: the compensation restored exactly its own transaction's state.
	// The host generation's device must be byte-for-byte untouched: same
	// instance, still open, still owning the endpoint it was published with.
	// A metadata-only or whole-device restore behind a newer generation is
	// the defect this pins (it would close or replace the newer device).
	after := svc.GetBackendDeviceForTest(id)
	if after != hostDevice {
		t.Fatalf("compensation must not touch the newer generation's device: got %T, want the host-published device", after)
	}
	if after.IsClosed() {
		t.Fatal("the host generation's device must stay open; closing it behind committed state is a compensation beyond its own transaction")
	}
	if got := svc.GetBackendDeviceEndpointForTest(id); got != hostCommitted.Endpoint {
		t.Fatalf("host device endpoint ownership disturbed by the discarded key candidate: got %q want %q", got, hostCommitted.Endpoint)
	}

	// The host generation's committed identity survives in the live pool, in
	// SQLite, and in a freshly reloaded pool — the key operation restored
	// nothing, because nothing of its own had been published.
	live, err := svc.GetTunnel(id)
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
	for _, want := range []struct{ what, key, endpoint string }{
		{"live pool", live.PublicKey, live.Endpoint},
		{"SQLite", row.PublicKey, row.Endpoint},
		{"reloaded pool", reloaded.PublicKey, reloaded.Endpoint},
	} {
		if want.key != hostCommitted.PublicKey || want.endpoint != hostCommitted.Endpoint {
			t.Errorf("%s row (%q, %q) must equal the host generation's committed identity (%q, %q)",
				want.what, want.key, want.endpoint, hostCommitted.PublicKey, hostCommitted.Endpoint)
		}
	}
	// The rejected key operation never leaked DESIRED into any identity.
	if live.PublicKey == r2_1DesiredKey || row.PublicKey == r2_1DesiredKey || reloaded.PublicKey == r2_1DesiredKey {
		t.Error("the stale key commit leaked its desired key into durable or live identity")
	}
}

// mustSwappedEndpoint mirrors what UpdateBackendServerHost commits for
// r2_1SwappedHost(initial.Endpoint): the swapped host on the fixture's port.
func mustSwappedEndpoint(t *testing.T, origEndpoint string) string {
	t.Helper()
	host := r2_1SwappedHost(origEndpoint)
	_, port, err := net.SplitHostPort(origEndpoint)
	if err != nil {
		t.Fatalf("fixture endpoint %q must be host:port", origEndpoint)
	}
	return net.JoinHostPort(host, port)
}

// TestR2_3CancellationMatrix pins the cancellation/durability matrix for the
// key/host commit paths (feeds R2-4). Channel barriers only, no sleeps; every
// cell asserts the full metadata+device oracle:
//
//	before commit      -> OLD retained, candidate discarded (or never
//	                      prepared), no durable write;
//	during the durable commit -> the commit finishes coherently: the fence and
//	                      the fail-closed persist (Pool.SetTunnelEndpoint
//	                      persists before mutating memory) leave either all
//	                      OLD or all NEW — never a split, and the canceled
//	                      commit reports the real durable cause;
//	after commit       -> the committed state stands: published device keeps
//	                      serving, no compensation runs.
func TestR2_3CancellationMatrix(t *testing.T) {
	ctx := context.Background()

	t.Run("canceled host update before commit retains old state", func(t *testing.T) {
		svc, id, initial := lifecycleTestService(t)
		svc.ResetPreparedCandidateCountForTest()
		oldDevice := svc.GetBackendDeviceForTest(id)
		newHost := r2_1SwappedHost(initial.Endpoint)

		hostParked := make(chan struct{})
		releaseHost := make(chan struct{})
		hostCtx, cancelHost := context.WithCancel(context.Background())
		defer cancelHost()
		t.Cleanup(func() {
			cancelHost()
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
			hostDone <- svc.UpdateBackendServerHost(hostCtx, id, newHost)
		}()
		awaitR2_1Barrier(t, hostParked, "host update reaching its pre-lock window")

		// Park-state sanity: cancel BEFORE release, then let the real path
		// run. The host path checks ctx.Err() after the hook, before its
		// private preparation, so the canceled request prepares nothing.
		cancelHost()
		close(releaseHost)
		hostErr := awaitR2_1Completion(t, hostDone, "canceled host update")
		if !errors.Is(hostErr, context.Canceled) {
			t.Fatalf("expected the bare cancellation (nothing was applied), got %v", hostErr)
		}
		if errors.Is(hostErr, backendIdentityCommitStale) {
			t.Fatalf("no newer operation committed; the result must not be a stale-commit rejection, got %v", hostErr)
		}
		if n := svc.PreparedCandidateCountForTest(); n != 0 {
			t.Errorf("a request canceled before its preparation must prepare nothing, got %d prepared", n)
		}
		assertOldStateIntact(t, svc, ctx, id, initial, oldDevice)
	})

	t.Run("canceled key update before commit retains old state", func(t *testing.T) {
		svc, id, initial := lifecycleTestService(t)
		svc.ResetPreparedCandidateCountForTest()
		oldDevice := svc.GetBackendDeviceForTest(id)

		keyParked := make(chan struct{})
		releaseKey := make(chan struct{})
		keyCtx, cancelKey := context.WithCancel(context.Background())
		defer cancelKey()
		t.Cleanup(func() {
			cancelKey()
			select {
			case <-releaseKey:
			default:
				close(releaseKey)
			}
		})
		svc.SetUpdateBackendServerPublicKeyPreLockHook(func() {
			close(keyParked)
			<-releaseKey
		})
		t.Cleanup(func() { svc.SetUpdateBackendServerPublicKeyPreLockHook(nil) })

		keyDone := make(chan error, 1)
		go func() {
			keyDone <- svc.UpdateBackendServerPublicKey(keyCtx, id, r2_1DesiredKey)
		}()
		awaitR2_1Barrier(t, keyParked, "key update reaching its pre-lock window")

		// Unlike the host path, the key path deliberately has NO ctx.Err()
		// early return between the hook and the commit fence (R2-2): the
		// release reaches the fence, which judges the cancellation. The
		// private candidate IS prepared (after release) and then discarded
		// by the fence rejection — the only compensation there is.
		cancelKey()
		close(releaseKey)
		keyErr := awaitR2_1Completion(t, keyDone, "canceled key update")
		if !errors.Is(keyErr, context.Canceled) {
			t.Fatalf("expected the fence-judged cancellation, got %v", keyErr)
		}
		if errors.Is(keyErr, backendIdentityCommitStale) {
			t.Fatalf("no newer operation committed; the result must not be a stale-commit rejection, got %v", keyErr)
		}
		if n := svc.PreparedCandidateCountForTest(); n != 1 {
			t.Errorf("the released key request must have prepared exactly one private candidate for the fence to discard, got %d", n)
		}
		// No durable write: the key field never moved anywhere.
		assertOldStateIntact(t, svc, ctx, id, initial, oldDevice)
	})

	t.Run("host commit failing mid-durable-write finishes coherently", func(t *testing.T) {
		svc, id, initial := lifecycleTestService(t)
		svc.ResetPreparedCandidateCountForTest()
		oldDevice := svc.GetBackendDeviceForTest(id)
		newHost := r2_1SwappedHost(initial.Endpoint)

		// Arm the real durable-write failure BEFORE the update runs: the
		// endpoint statement fails, so the fail-closed persist leaves
		// memory untouched and the commit reports the durable cause.
		if _, err := svc.db.SQLDB().ExecContext(ctx, failHostUpdateCommitTrigger); err != nil {
			t.Fatalf("failed to install endpoint-persist failure trigger: %v", err)
		}
		t.Cleanup(func() {
			_, _ = svc.db.SQLDB().ExecContext(context.Background(), "DROP TRIGGER IF EXISTS fail_host_update_commit")
		})

		hostErr := svc.UpdateBackendServerHost(ctx, id, newHost)
		if hostErr == nil {
			t.Fatal("expected the endpoint persist failure to fail the host update")
		}
		if errors.Is(hostErr, backendIdentityCommitStale) {
			t.Fatalf("a real durable failure must be reported as such, not as a stale commit, got %v", hostErr)
		}
		if errors.Is(hostErr, context.Canceled) {
			t.Fatalf("the request was not canceled; the result must be the durable failure, got %v", hostErr)
		}
		if !strings.Contains(hostErr.Error(), "r2-3 simulated endpoint persist failure") {
			t.Errorf("the original durable cause must be preserved, got %v", hostErr)
		}
		if n := svc.PreparedCandidateCountForTest(); n != 1 {
			t.Errorf("the update must have prepared exactly one private candidate, got %d", n)
		}
		if n := svc.retiredBackendDeviceDrops.Total(); n != 0 {
			t.Errorf("a failed durable commit must not retire any serving-device loss ownership, got %d", n)
		}
		// Coherent terminal state: ALL OLD — the publish never ran because
		// the persist failed first (memory moves only on persist success).
		assertOldStateIntact(t, svc, ctx, id, initial, oldDevice)
	})

	t.Run("host update after commit stands with no compensation", func(t *testing.T) {
		svc, id, initial := lifecycleTestService(t)
		oldDevice := svc.GetBackendDeviceForTest(id)
		newHost := r2_1SwappedHost(initial.Endpoint)

		if err := svc.UpdateBackendServerHost(ctx, id, newHost); err != nil {
			t.Fatalf("host update must succeed: %v", err)
		}
		newDevice := svc.GetBackendDeviceForTest(id)
		if newDevice == nil || newDevice == oldDevice || newDevice.IsClosed() {
			t.Fatalf("the committed host generation must publish a fresh open device, got %T", newDevice)
		}
		// The host update commits the resolved host:port endpoint and leaves
		// the key field untouched.
		assertCommittedStateStands(t, svc, ctx, id, initial, mustSwappedEndpoint(t, initial.Endpoint), initial.PublicKey)
	})

	t.Run("key update after commit stands with no compensation", func(t *testing.T) {
		svc, id, initial := lifecycleTestService(t)
		oldDevice := svc.GetBackendDeviceForTest(id)

		if err := svc.UpdateBackendServerPublicKey(ctx, id, r2_1DesiredKey); err != nil {
			t.Fatalf("key update must succeed: %v", err)
		}
		newDevice := svc.GetBackendDeviceForTest(id)
		if newDevice == nil || newDevice == oldDevice || newDevice.IsClosed() {
			t.Fatalf("the committed key generation must publish a fresh open device, got %T", newDevice)
		}
		assertCommittedStateStands(t, svc, ctx, id, initial, initial.Endpoint, r2_1DesiredKey)
	})
}

// assertOldStateIntact is the full OLD-retention oracle: attached device is
// the SAME open instance with its endpoint ownership, live pool, SQLite and a
// freshly reloaded pool all still describe the fixture identity, and the
// alternative (desired) identity leaked nowhere.
func assertOldStateIntact(t *testing.T, svc *Service, ctx context.Context, id int64, initial *models.BackendTunnel, oldDevice BackendDevice) {
	t.Helper()
	attached := svc.GetBackendDeviceForTest(id)
	if attached != oldDevice {
		t.Fatalf("OLD device was replaced: got %T, want the fixture device", attached)
	}
	if attached.IsClosed() {
		t.Fatal("OLD device was closed")
	}
	live, err := svc.GetTunnel(id)
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
	for _, want := range []struct {
		what          string
		key, endpoint string
	}{
		{"live pool", live.PublicKey, live.Endpoint},
		{"SQLite", row.PublicKey, row.Endpoint},
		{"reloaded pool", reloaded.PublicKey, reloaded.Endpoint},
	} {
		if want.key != initial.PublicKey || want.endpoint != initial.Endpoint {
			t.Errorf("%s row drifted to (%q, %q), want the OLD identity (%q, %q)",
				want.what, want.key, want.endpoint, initial.PublicKey, initial.Endpoint)
		}
	}
	if live.PublicKey == r2_1DesiredKey || row.PublicKey == r2_1DesiredKey || reloaded.PublicKey == r2_1DesiredKey {
		t.Error("durable or live identity carries the desired key behind a retained OLD state")
	}
}

// assertCommittedStateStands is the post-commit oracle: the committed
// generation's identity is in pool, SQLite and a freshly reloaded pool; the
// attached device is open at its committed endpoint; nothing of the OLD
// generation was restored.
func assertCommittedStateStands(t *testing.T, svc *Service, ctx context.Context, id int64, initial *models.BackendTunnel, wantEndpoint, wantKey string) {
	t.Helper()
	if got := svc.GetBackendDeviceEndpointForTest(id); got != wantEndpoint {
		t.Errorf("attached device endpoint %q must equal the committed endpoint %q", got, wantEndpoint)
	}
	live, err := svc.GetTunnel(id)
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
	for _, want := range []struct{ what, key, endpoint string }{
		{"live pool", live.PublicKey, live.Endpoint},
		{"SQLite", row.PublicKey, row.Endpoint},
		{"reloaded pool", reloaded.PublicKey, reloaded.Endpoint},
	} {
		if want.endpoint != wantEndpoint {
			t.Errorf("%s endpoint %q must equal the committed endpoint %q", want.what, want.endpoint, wantEndpoint)
		}
		if want.key != wantKey {
			t.Errorf("%s key %q must equal the committed key %q", want.what, want.key, wantKey)
		}
	}
	if live.Endpoint == initial.Endpoint && wantEndpoint != initial.Endpoint {
		t.Error("committed endpoint regressed to the OLD endpoint")
	}
}
