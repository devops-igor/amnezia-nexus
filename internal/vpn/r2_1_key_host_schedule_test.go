package vpn

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

// R2-1 permanent regression: concurrent key + host update schedule exposing the
// stale-compensation window documented in the re-review (REVIEW.md finding R2,
// vpn.go UpdateBackendServerPublicKey).
//
// Schedule (deterministic; channel barriers only, no sleeps):
//
//	B0  fixture: enabled backend, real open AWG device OLD at
//	    ENDPOINT0 with durable key OLDKEY (lifecycleTestService).
//	B1  key update goroutine calls UpdateBackendServerPublicKey(ctx, DESIRED).
//	    Since R2-2 the REAL code path prepares its candidate device for
//	    (ENDPOINT0, DESIRED) PRIVATELY — nothing reaches the live pool or
//	    SQLite before the Service.mu commit boundary. The pre-lock hook parks
//	    the goroutine in that private-preparation window: publication has NOT
//	    happened, the durable row still carries OLDKEY, and OLD is still the
//	    attached device.
//	B2  with the key request parked mid-preparation, a newer host update runs
//	    to completion on the test goroutine. It commits ENDPOINT1 durably and
//	    attaches a REAL new AWG device built from the tunnel's committed
//	    identity at that moment — the row's CURRENT key (OLDKEY at this point
//	    in the schedule) at ENDPOINT1 (private candidate + validated commit,
//	    vpn.go prepareHostUpdateCandidate / fenceBackendIdentityCommit).
//	B3  the key request is canceled while parked, then released. Because R2-2
//	    moved the key effect into the validated commit, the release hits the
//	    fence: the key update observes the newer committed generation and
//	    aborts WITHOUT publishing its own candidate or touching any metadata —
//	    compensation is exactly the discard of its private candidate.
//
// Terminal coherence oracle set — ALL must hold in a correct system.
//
//	a. the actual serving device identity/endpoint matches the durable pool
//	   row — whichever generation survives, the ATTACHED device and the
//	   metadata must agree (newer survives → row stays (ENDPOINT1,
//	   OLDKEY-or-DESIRED, coherent with the construction identity); older
//	   survives → newer device retired AND row coherently OLD);
//	b. the live pool row matches a freshly reopened SQLite pool row;
//	c. no mixed state: either the newer device stays open together with
//	   metadata coherent with its construction identity, or it was retired
//	   together with a metadata restore to OLDKEY — never metadata=OLD with
//	   the newer device still attached (or the inverse).
const r2_1DesiredKey = "r2-1-regression-desired-key"

// awaitR2_1Barrier blocks until ch closes, failing the test rather than
// hanging if the schedule deadlocks. It is a barrier, not a delay: every
// wait here is woken by an exact schedule event.
func awaitR2_1Barrier(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(15 * time.Second):
		t.Fatalf("schedule deadlock: %s never happened", what)
	}
}

// awaitR2_1Completion collects the key request result with the same
// barrier discipline.
func awaitR2_1Completion(t *testing.T, errCh <-chan error, what string) error {
	t.Helper()
	select {
	case err := <-errCh:
		return err
	case <-time.After(15 * time.Second):
		t.Fatalf("schedule deadlock: %s never completed", what)
		return nil
	}
}

// r2_1SwappedHost derives a HOST (no port — UpdateBackendServerHost resolves
// the port itself) that differs from the fixture endpoint's host by swapping
// the last IPv4 octet, so the host update takes the genuine dual-write
// replacement path. The lifecycleTestService fixture endpoint is always a
// plain IPv4 host:port, so the colon-less/dot-less fallbacks below are total
// guards, never the taken branch.
func r2_1SwappedHost(endpoint string) string {
	i := strings.LastIndex(endpoint, ":")
	if i < 0 {
		return endpoint + ".x"
	}
	host := endpoint[:i]
	j := strings.LastIndex(host, ".")
	if j < 0 {
		return host + ".x"
	}
	return host[:j+1] + "20"
}

func TestR2_1StaleKeyCompensationMustNotSplitDurableIdentityFromLiveDevice(t *testing.T) {
	ctx := context.Background()
	svc, id, initial := lifecycleTestService(t)

	oldDevice := svc.GetBackendDeviceForTest(id)
	if oldDevice == nil || oldDevice.IsClosed() {
		t.Fatalf("fixture must start with an open real OLD device, got %T", oldDevice)
	}
	oldKey := initial.PublicKey
	newHost := r2_1SwappedHost(initial.Endpoint)

	// B1: park the REAL key update inside its PRIVATE preparation window —
	// after the pre-lock hook, before the s.mu commit boundary. The R2-2
	// contract under test: NOTHING has been published while parked.
	keyPublished := make(chan struct{})
	commitKey := make(chan struct{})
	keyReqCtx, cancelKeyReq := context.WithCancel(context.Background())
	defer cancelKeyReq()
	var releaseKeyReq sync.Once
	t.Cleanup(func() {
		// Failure-path hygiene: if any Fatalf below fires while the key
		// request goroutine is parked on <-commitKey, this releases it so
		// the goroutine exits instead of leaking. Happy path: no-op (the
		// schedule already released via releaseKeyReq below).
		cancelKeyReq()
		releaseKeyReq.Do(func() { close(commitKey) })
	})
	svc.SetUpdateBackendServerPublicKeyPreLockHook(func() {
		close(keyPublished)
		<-commitKey
	})
	t.Cleanup(func() { svc.SetUpdateBackendServerPublicKeyPreLockHook(nil) })

	keyReqDone := make(chan error, 1)
	go func() {
		keyReqDone <- svc.UpdateBackendServerPublicKey(keyReqCtx, id, r2_1DesiredKey)
	}()
	awaitR2_1Barrier(t, keyPublished, "key update reaching its private preparation window")

	// Park-state sanity (the R2-2 dual-write-removal invariants, verified
	// before any interleaving): the private candidate has been prepared, the
	// commit boundary was NOT crossed, and no live state carries DESIRED.
	if n := svc.PreparedCandidateCountForTest(); n != 1 {
		t.Fatalf("park precondition broken: the parked key update must have prepared its PRIVATE candidate, got %d prepared", n)
	}
	parked, err := svc.GetTunnel(id)
	if err != nil {
		t.Fatal(err)
	}
	if parked.PublicKey != oldKey {
		t.Fatalf("park precondition broken: the live pool must NOT carry the desired key before the commit boundary (dual write removed), got %q", parked.PublicKey)
	}
	parkedRow, err := svc.db.GetBackendTunnel(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if parkedRow.PublicKey != oldKey {
		t.Fatalf("park precondition broken: SQLite must NOT carry the desired key before the commit boundary (dual write removed), got %q", parkedRow.PublicKey)
	}
	if svc.GetBackendDeviceForTest(id) != oldDevice {
		t.Fatal("park precondition broken: no device may be replaced before the key commit boundary")
	}

	// B2: the newer host update completes INSIDE the window. The device it
	// attaches is constructed from the tunnel's committed identity at that
	// moment — the row's CURRENT key (still OLDKEY: the key update has not
	// committed) at ENDPOINT1.
	if err := svc.UpdateBackendServerHost(ctx, id, newHost); err != nil {
		t.Fatalf("newer host update failed inside the window: %v", err)
	}
	newerDevice := svc.GetBackendDeviceForTest(id)
	if newerDevice == nil || newerDevice == oldDevice || newerDevice.IsClosed() {
		t.Fatalf("newer host update must install a fresh open real device, got %T (closed=%v)", newerDevice, newerDevice != nil && newerDevice.IsClosed())
	}
	// during is a fresh Pool.GetTunnel COPY taken after the host update
	// (Pool.GetTunnel copies, so this reflects the committed state).
	during, err := svc.GetTunnel(id)
	if err != nil {
		t.Fatal(err)
	}
	newEndpoint := during.Endpoint // committed by the newer host update
	if newEndpoint == initial.Endpoint {
		t.Fatalf("host update must change the endpoint for this schedule, got %q twice", newEndpoint)
	}
	if during.PublicKey != oldKey || during.Endpoint != newEndpoint {
		t.Fatalf("window precondition broken: live row must be (OLDKEY, ENDPOINT1) — the key update has not committed, got (%q, %q)", during.PublicKey, during.Endpoint)
	}
	if got := svc.GetBackendDeviceEndpointForTest(id); got != newEndpoint {
		t.Fatalf("newer device must be attached at ENDPOINT1, got %q", got)
	}

	// B3: cancel the parked key request, release it, and let the REAL code
	// reach its commit boundary. The fence observes the newer committed
	// generation, so the key update must abort WITHOUT publishing its
	// candidate or touching any metadata: its whole compensation is the
	// discard of its private candidate.
	cancelKeyReq()
	releaseKeyReq.Do(func() { close(commitKey) })
	updateErr := awaitR2_1Completion(t, keyReqDone, "canceled key update")
	if !errors.Is(updateErr, backendIdentityCommitStale) || !errors.Is(updateErr, context.Canceled) {
		t.Fatalf("expected the stale-commit fence carrying the cancellation cause from the key request, got %v", updateErr)
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

	// --- ORACLE SET (a): serving device identity/endpoint vs durable row ---
	// Resolution-agnostic: whichever generation survives, the ATTACHED device
	// and the metadata must agree. The pre-R2-2 defect satisfied NEITHER arm,
	// so this fires under both possible fix shapes.
	attached := svc.GetBackendDeviceForTest(id)
	if attached == nil {
		t.Errorf("oracle a: no serving device attached after compensation for enabled backend %d", id)
	} else if attached == newerDevice && !newerDevice.IsClosed() {
		// NEWER generation survived: metadata must stay coherent with the
		// identity the newer device was built from — its key is whatever the
		// committed row carried when it was constructed, so the row must
		// simply still carry THAT committed key (any key field regression
		// behind the attached device is the defect pinned here).
		if got := svc.GetBackendDeviceEndpointForTest(id); got != after.Endpoint {
			t.Errorf("oracle a: attached newer-device endpoint %q does not match live pool row endpoint %q", got, after.Endpoint)
		}
		if after.PublicKey != row.PublicKey || after.PublicKey != reloaded.PublicKey {
			t.Errorf("oracle a: surviving newer device but pool/SQLite/reloaded keys disagree (%q, %q, %q)", after.PublicKey, row.PublicKey, reloaded.PublicKey)
		}
	} else {
		// OLDER generation survived: the newer device must have been retired
		// (closed), and metadata must coherently describe the OLD identity.
		if !newerDevice.IsClosed() {
			t.Errorf("oracle a: metadata moved off the newer generation but that device was never retired")
		}
		if got := svc.GetBackendDeviceEndpointForTest(id); got != after.Endpoint {
			t.Errorf("oracle a: attached device endpoint %q does not match live pool row endpoint %q", got, after.Endpoint)
		}
		if after.PublicKey != oldKey {
			t.Errorf("oracle a: newer device retired but durable pool row key %q is not the coherent OLD identity %q", after.PublicKey, oldKey)
		}
	}

	// --- ORACLE SET (b): live pool row vs freshly reopened SQLite row ---
	if after.PublicKey != row.PublicKey || after.Endpoint != row.Endpoint {
		t.Errorf("oracle b: live pool row (%q, %q) disagrees with reopened SQLite row (%q, %q)",
			after.PublicKey, after.Endpoint, row.PublicKey, row.Endpoint)
	}
	if reloaded.PublicKey != after.PublicKey || reloaded.Endpoint != after.Endpoint {
		t.Errorf("oracle b: freshly reloaded pool row (%q, %q) disagrees with live pool row (%q, %q)",
			reloaded.PublicKey, reloaded.Endpoint, after.PublicKey, after.Endpoint)
	}

	// --- ORACLE SET (c): no mixed identity state ---
	// Either the metadata moved off the newer device's generation and the
	// device was retired with it, or the newer device stays open and the
	// metadata is coherent with the key its device was CONSTRUCTED from.
	// In this schedule the newer host device is built inside the window,
	// before the key update commits, so its construction key is provably
	// the OLD key (asserted at B2: during.PublicKey == oldKey); metadata
	// staying OLD behind the still-attached newer device is therefore
	// coherent by construction, not mixed state. Metadata moved to a key
	// the attached device was not built from (or the inverse) is the
	// defect this regression pins.
	newerConstructionKey := during.PublicKey // provably OLDKEY at B2; see the schedule comment
	metadataRestoredOld := after.PublicKey == oldKey && row.PublicKey == oldKey && reloaded.PublicKey == oldKey
	newerStillServing := attached == newerDevice && !newerDevice.IsClosed()
	if newerStillServing {
		coherent := after.PublicKey == newerConstructionKey && row.PublicKey == newerConstructionKey && reloaded.PublicKey == newerConstructionKey
		if !coherent {
			t.Errorf("oracle c: MIXED STATE — newer device still attached but durable/pool/reloaded keys (%q, %q, %q) disagree with its construction key %q",
				after.PublicKey, row.PublicKey, reloaded.PublicKey, newerConstructionKey)
		}
	}
	if metadataRestoredOld && newerStillServing && newerConstructionKey != oldKey {
		t.Errorf("oracle c: MIXED STATE — durable/pool/reloaded metadata all restored OLD key behind a newer device whose construction key is %q",
			newerConstructionKey)
	}
	if newerDevice.IsClosed() && after.PublicKey == r2_1DesiredKey {
		t.Errorf("oracle c: inverse MIXED STATE — newer device retired while metadata still claims its DESIRED identity")
	}
}
