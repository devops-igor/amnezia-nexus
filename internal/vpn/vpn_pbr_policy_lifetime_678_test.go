package vpn

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// These are the permanent regression oracles for issue #678 findings F678-01 and
// F678-02 (round-1 audit HEAD c161a2a). They are the inverted successors of the
// auditor's counterexamples: each one drives the real production entry point
// through the same decisive condition the counterexample used, but now asserts
// the required behavior instead of the defect.
//
// Only the WAN PacketDevice is substituted anywhere below: a single-owner name
// registry stands in for TUNSETIFF, so no /dev/net/tun is needed. Everything else —
// the shipped middleware, the lifecycle mutexes, the real Syncer/Matcher/FileStore,
// the real SQLite settings table and the real parser — is production code.

// auditedLKGStore writes a configuration-matching on-disk last-known-good generation
// so activation can publish real rules, and so the shrink-guard baseline is genuine
// rather than absent.
func auditedLKGStore(t *testing.T, settings policy.Settings) *policy.FileStore {
	t.Helper()
	return lkgStoreFor(t, settings)
}

// TestSuccessfulActivationKeepsPolicySyncerAlive is the F678-01 regression.
//
// RED on c161a2a: startPolicyLoop derived the scheduling loop from the request
// context, so the shipped middleware's deferred cancel (and net/http's own
// request lifetime) closed the syncer the moment a *successful* PUT returned.
// PBR stayed enabled, the periodic refresh stopped, and SyncPolicyNow answered
// ErrSyncerClosed until the process restarted.
//
// The decisive condition is that the activation runs inside a real
// middleware.OperationTimeout handler and the assertions happen strictly AFTER
// that handler returned, so a regression to request-scoped lifetime fails here
// even though the activation itself succeeded.
func TestSuccessfulActivationKeepsPolicySyncerAlive(t *testing.T) {
	reg := newNameRegistry()
	withNameOwnedWANDevice(t, reg)
	svc := serviceForActivation(t)
	settings := repeatedEnableSettings(t)
	store := auditedLKGStore(t, settings)
	t.Cleanup(svc.StopPolicyRouting)

	var activationErr error
	wrapped := middleware.OperationTimeout(time.Minute)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		activationErr = svc.StartPolicyRouting(r.Context(), settings, store)
		w.WriteHeader(http.StatusOK)
	}))
	wrapped.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPut, "/api/vpn/policy", nil))
	if activationErr != nil {
		t.Fatalf("activation failed: %v", activationErr)
	}
	if !svc.PBREnabled() {
		t.Fatal("activation succeeded but PBR is not enabled")
	}

	// The request has returned at this point: the shipped middleware already ran
	// its deferred cancel. The syncer must still be live.
	//
	// The defect's signature is policy.ErrSyncerClosed: once Syncer.Run exits it
	// sets closed=true, after which every SyncPolicyNow call is refused forever.
	// A regression can also show as a call that never gets served, because the
	// request channel has no reader any more. Probing with a short per-call
	// deadline detects both: a closed syncer is refused at once, a dead loop times
	// out, and a live loop serves the request and answers it.
	deadline := time.Now().Add(5 * time.Second)
	var (
		observed policy.SyncResult
		liveErr  error
		answered bool
	)
	for time.Now().Before(deadline) {
		callCtx, callCancel := context.WithTimeout(context.Background(), 2*time.Second)
		observed, liveErr = svc.SyncPolicyNow(callCtx)
		callCancel()
		if errors.Is(liveErr, policy.ErrSyncerClosed) {
			t.Fatalf("successful enable closed its policy syncer when the HTTP request returned (F678-01): SyncPolicyNow=%v while PBR reports enabled=%t; periodic refresh and manual sync are dead until a process restart",
				liveErr, svc.PBREnabled())
		}
		if !errors.Is(liveErr, context.DeadlineExceeded) {
			answered = true
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !answered {
		t.Fatalf("on-demand sync after a successful enable never completed (F678-01): the scheduling loop is not serving requests any more")
	}
	// The loop answered. The record holds publishable rules and fetches nothing, so
	// the answer must be a publication: any error here means the live runtime could
	// not do its job after the enabling request returned.
	if liveErr != nil {
		t.Fatalf("on-demand sync on a live runtime failed: %v", liveErr)
	}
	if !observed.Published && observed.GenerationID == "" {
		t.Fatalf("on-demand sync on a live runtime produced no generation: %+v", observed)
	}
	if got := svc.PolicyStatusSnapshot().SyncState; got == "disabled" {
		t.Fatalf("policy status reports %q while PBR is enabled", got)
	}
}

// TestExplicitDisableStillStopsPolicySyncer is the adjacent control for F678-01.
//
// Detaching the loop from the request lifetime must not make it unstoppable:
// an explicit disable still has to terminate it, which is the whole reason the
// lifetime is owned by the service rather than by the request. It also proves
// the fix did not turn "disable" into a working-syncer no-op.
func TestExplicitDisableStillStopsPolicySyncer(t *testing.T) {
	reg := newNameRegistry()
	withNameOwnedWANDevice(t, reg)
	svc := serviceForActivation(t)

	settings := repeatedEnableSettings(t)
	if err := svc.StartPolicyRouting(context.Background(), settings, auditedLKGStore(t, settings)); err != nil {
		t.Fatalf("activation failed: %v", err)
	}
	assertFullyEnabled(t, svc, reg)

	svc.StopPolicyRouting()
	assertFullyDisabled(t, svc, reg)

	// After disable there is no registered runtime at all, so the sync endpoint
	// reports "not started" rather than a closed-but-enabled syncer.
	if _, err := svc.SyncPolicyNow(context.Background()); err == nil {
		t.Fatal("SyncPolicyNow succeeded after an explicit disable")
	} else if errors.Is(err, policy.ErrSyncerClosed) {
		t.Fatalf("disable left a registered but closed syncer behind: %v", err)
	}
}

// TestServiceStopStopsPolicySyncer keeps the detached loop from becoming a
// process-lifetime goroutine: service shutdown must stop it too.
func TestServiceStopStopsPolicySyncer(t *testing.T) {
	reg := newNameRegistry()
	withNameOwnedWANDevice(t, reg)
	svc := serviceForActivation(t)

	settings := repeatedEnableSettings(t)
	if err := svc.StartPolicyRouting(context.Background(), settings, auditedLKGStore(t, settings)); err != nil {
		t.Fatalf("activation failed: %v", err)
	}
	if svc.policyRuntime() == nil {
		t.Fatal("activation did not register a policy runtime")
	}

	if err := svc.Stop(); err != nil {
		t.Fatalf("service Stop: %v", err)
	}
	if svc.policyRuntime() != nil {
		t.Fatal("service shutdown left the policy runtime registered")
	}
	if got := reg.liveOwners(); got != 0 {
		t.Fatalf("service shutdown left %d live owner(s) of the WAN device name", got)
	}
}
