package vpn

// R1-4 ownership matrix — the remaining enable/re-enable boundary tests
// (issue #424 / PR #429 re-review, gaps #6/#7/#8 of the R1-4 gap analysis).
//
// Boundaries #1-#5 already have permanent tests and are NOT duplicated here:
//
//	#1 constructor/IpcSet failure ....... TestBackendCandidateFailurePreservesWorkingDevice
//	#2 Up/bind failure .................. TestBackendCandidateFailurePreservesWorkingDevice
//	#3 persistence failure .............. TestRereviewReenablePersistenceFailurePreservesWorkingDevice,
//	                                      TestEnableBackend_PersistenceFailureCleansUpAttachedDevice
//	#4 cancellation ..................... TestBackendQuarantineRetryPersistsAcrossReload (canceled ctx)
//	#5 newer-disable-wins ............... TestEnableBackend_LaterAdministrativeDisableWins (both windows),
//	                                      TestEnableBackend_IdentityChangeStillAbortsEnable/AdminDisableStillAborts
//
// What this file adds:
//
//	#6 nothing called Pool.CommitBackendEnable directly; no test proved the
//	   durable write still happens on an EXPLICIT ALREADY-ENABLED re-enable
//	   (the hook-before-persistence contract that protects the
//	   quarantine-retry fix).
//	#7 retirement-exactly-once via the EnableBackend path itself: OLD's Close
//	   is counted and its loss ownership is required to transfer EXACTLY once.
//	#8 leak checks on failure paths: runtime.NumGoroutine with a bounded
//	   settle, plus a forwarder-still-pumps-to-OLD oracle, folded into each
//	   failure test below.
//
// SQLite mechanism probe (decided the ambiguous-completion test's shape;
// probed in .scratch-r14-probe/ with the project's own driver,
// modernc.org/sqlite v1.34.5):
//
//	BEFORE UPDATE OF enabled ... RAISE(FAIL): driver error, row NOT landed
//	  (state_version unchanged, changes() = 0) — a plain persistence failure;
//	AFTER  UPDATE OF enabled ... RAISE(FAIL): driver error, row LANDED
//	  (state_version advanced, enabled=1, changes() = 1) — RAISE(FAIL) in an
//	  AFTER trigger aborts with prior changes retained, so the caller sees an
//	  error although the durable row carries the intended state.
//
// That is exactly the ambiguous completion database.CommitBackendTunnelEnable
// documents: on error it reads the row back ONCE and reports success only when
// state_version advanced by exactly one and every owned field matches.
// TestR1_4AmbiguousEnableCommitResolvesViaDurableReadback pins the AFTER case
// end-to-end through EnableBackend; the "TriggerFailureRowNotLanded" subtest
// pins the BEFORE case (returned error implies the durable row did not move).

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

// r14RetireWitness is OLD wrapped for the retirement-exactly-once test (#7).
//
// It is a tx1SinkDevice (admission-only sink, real closed-state oracle, loss
// ownership preserved through the embedded *testBackendDevice) plus a Close
// counter. publishBackendForwarderCandidate retires OLD by calling
// oldDev.Close() and transferring snapshotBackendDeviceDrops(oldDev) into
// retiredBackendDeviceDrops exactly once; the counter and the injected drop
// figure turn "exactly once" into an assertion: a refactor that retired OLD
// twice would report closes=2 and the injected drops twice over.
type r14RetireWitness struct {
	*tx1SinkDevice
	closes atomic.Int64
}

// Close counts the retirement and then performs the real close. Only the
// publication path may call this; the deferred discard path must never reach
// OLD (it closes the candidate instead).
func (d *r14RetireWitness) Close() error {
	d.closes.Add(1)
	return d.tx1SinkDevice.testBackendDevice.Close()
}

// r14AttachPumpingOld wraps the fixture's serving device in a tx1SinkDevice,
// re-registers it as the backend device, registers a forwarder session and
// starts the pumps, so the test's forwarder-still-pumps-to-OLD oracle is live
// before the operation under test runs. The sink is admission-only, so the
// test's own probe traffic never pollutes the real device's drop accounting
// (see tx1SinkDevice's rationale).
func r14AttachPumpingOld(t *testing.T, svc *Service, tun *models.BackendTunnel) *tx1SinkDevice {
	t.Helper()
	raw, ok := svc.GetBackendDeviceForTest(tun.ID).(*tunnel.AWGClientDevice)
	if !ok || raw == nil {
		t.Fatalf("fixture must start with a real AWG OLD device, got %T", svc.GetBackendDeviceForTest(tun.ID))
	}
	old := &tx1SinkDevice{
		testBackendDevice: &testBackendDevice{AWGClientDevice: raw},
		sink:              make(chan []byte, 4),
	}
	svc.SetBackendDeviceForTest(tun.ID, old)
	svc.forwarder.AttachBackendDevice(tun.ID, old)

	// Oracle self-check: the fixture really is a usable serving device.
	if _, err := old.Write(make([]byte, 20)); err != nil {
		t.Fatalf("fixture OLD must admit plaintext: %v", err)
	}
	select {
	case <-old.sink:
	case <-time.After(5 * time.Second):
		t.Fatal("fixture OLD admitted plaintext but delivered nothing to the sink")
	}

	svc.forwarder.RegisterSession("r14-session", "r14-connection", "r14-peer", "192.0.2.101", tun.ID)
	svc.forwarder.StartPumps(context.Background())
	t.Cleanup(svc.forwarder.StopPumps)
	return old
}

// r14AssertStillPumpsToOld proves OLD is still the attached serving device:
// the forwarder routes a client packet and the pump delivers it into OLD's
// sink. A candidate that was (wrongly) left attached, or an OLD that was
// (wrongly) closed, makes this fail.
func r14AssertStillPumpsToOld(t *testing.T, svc *Service, old *tx1SinkDevice) {
	t.Helper()
	if err := svc.forwarder.RouteClientToBackend("r14-peer", []byte("r14-post-failure-packet")); err != nil {
		t.Fatalf("forwarder no longer routes to the backend after the failure: %v", err)
	}
	select {
	case <-old.sink:
	case <-time.After(15 * time.Second):
		t.Error("post-failure forwarder pump delivered nothing to OLD: a candidate is still attached, or OLD was closed")
	}
}

// r14AssertNoGoroutineLeak is the bounded-settle goroutine oracle (#8). A
// regression that publishes the candidate before the fallible durable write
// leaks the published pump (pumpBackendReturns) and the routing-remediation
// retry loop on every failed enable; a leaked goroutine never exits, so a
// stable count above baseline+3 after 8s of settling is a hard failure. The
// +3 margin absorbs unrelated runtime churn; baseline MUST be sampled after
// StartPumps so the test's own pump goroutines are not counted as leaks.
func r14AssertNoGoroutineLeak(t *testing.T, baseline int) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for {
		n := runtime.NumGoroutine()
		if n <= baseline+3 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("goroutine leak on the failure path: baseline %d, still %d (allowed baseline+%d) after 8s of settling",
				baseline, n, 3)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// TestR1_4ExplicitReenablePersistsDurableIntent pins gap #6: the explicit
// already-enabled re-enable must still perform its durable enabled-intent
// write. Pool.CommitBackendEnable runs the setTunnelEnabledHook BEFORE
// persistence, and the hook here reads the durable row to prove that order
// directly: at hook time the row must still carry the pre-commit
// state_version, and after EnableBackend returns it must carry exactly
// pre+1 — one statement, advanced once, behind a hook that ran first. This is
// the quarantine-retry contract ("explicit same-state intent reaches durable
// storage") pinned on the CommitBackendEnable path.
func TestR1_4ExplicitReenablePersistsDurableIntent(t *testing.T) {
	t.Run("SameStateExplicitReenable", func(t *testing.T) {
		ctx := context.Background()
		svc, id, tun := lifecycleTestService(t)

		pre, err := svc.db.GetBackendTunnel(ctx, tun.ID)
		if err != nil || pre == nil {
			t.Fatalf("failed to read durable pre-state: %v", err)
		}
		preVersion := pre.StateVersion
		genBefore := svc.pool.AdminGeneration(id)

		type r14HookCall struct {
			serverID      int64
			enabled       bool
			disableReason string
			versionAtHook int64
		}
		var (
			mu    sync.Mutex
			calls []r14HookCall
		)
		svc.pool.SetSetTunnelEnabledHookForTest(func(_ context.Context, serverID int64, enabled bool, reason string) error {
			// The hook runs under Pool.mu, so it must not call back into the
			// pool; the durable row is read straight from the database
			// instead. That is the point: it observes the row BEFORE the
			// enabled-intent statement runs.
			version := int64(-1)
			if row, err := svc.db.GetBackendTunnel(ctx, tun.ID); err == nil && row != nil {
				version = row.StateVersion
			}
			mu.Lock()
			calls = append(calls, r14HookCall{serverID: serverID, enabled: enabled, disableReason: reason, versionAtHook: version})
			mu.Unlock()
			return nil
		})
		t.Cleanup(func() { svc.pool.SetSetTunnelEnabledHookForTest(nil) })

		if err := svc.EnableBackend(ctx, id); err != nil {
			t.Fatalf("explicit already-enabled re-enable must succeed, got: %v", err)
		}

		mu.Lock()
		got := calls
		mu.Unlock()
		if len(got) != 1 {
			t.Fatalf("exactly one enabled-intent persistence hook call expected (the enable commits ONE durable write), got %d", len(got))
		}
		if got[0].serverID != id {
			t.Errorf("hook called for server %d, want %d", got[0].serverID, id)
		}
		if !got[0].enabled {
			t.Error("hook must observe enabled=true administrative intent")
		}
		if got[0].disableReason != models.DisableReasonNone {
			t.Errorf("hook disable reason = %q, want %q", got[0].disableReason, models.DisableReasonNone)
		}
		if got[0].versionAtHook != preVersion {
			t.Errorf("hook must run BEFORE persistence: durable state_version at hook time = %d, want pre-commit %d",
				got[0].versionAtHook, preVersion)
		}

		row, err := svc.db.GetBackendTunnel(ctx, tun.ID)
		if err != nil || row == nil {
			t.Fatalf("failed to read durable post-state: %v", err)
		}
		if !row.Enabled {
			t.Error("durable row must carry enabled=1 after an explicit re-enable")
		}
		if row.DisableReason != models.DisableReasonNone {
			t.Errorf("durable disable_reason = %q, want %q", row.DisableReason, models.DisableReasonNone)
		}
		if row.StateVersion != preVersion+1 {
			t.Errorf("durable state_version = %d, want pre+1 = %d (the enable commit advances the row exactly once)",
				row.StateVersion, preVersion+1)
		}
		if genAfter := svc.pool.AdminGeneration(id); genAfter <= genBefore {
			t.Errorf("administrative intent must advance AdminGeneration, %d -> %d", genBefore, genAfter)
		}
		if dev := svc.GetBackendDeviceForTest(tun.ID); dev == nil {
			t.Error("a successful re-enable must leave a serving device registered for the backend")
		}
	})

	t.Run("HealthDisabledProvenanceSurvivesReenable", func(t *testing.T) {
		ctx := context.Background()
		svc, id, tun := lifecycleTestService(t)

		// A health-disabled backend carries provenance the administrative
		// toggle must not erase — durably, not just in memory.
		if err := svc.pool.ForceDisableTunnelInMemory(id, models.DisableReasonHealth); err != nil {
			t.Fatalf("failed to inject health-disable provenance: %v", err)
		}
		pre, err := svc.db.GetBackendTunnel(ctx, tun.ID)
		if err != nil || pre == nil {
			t.Fatalf("failed to read durable pre-state: %v", err)
		}
		preVersion := pre.StateVersion

		var hookCalls int
		svc.pool.SetSetTunnelEnabledHookForTest(func(context.Context, int64, bool, string) error {
			hookCalls++
			return nil
		})
		t.Cleanup(func() { svc.pool.SetSetTunnelEnabledHookForTest(nil) })

		if err := svc.EnableBackend(ctx, id); err != nil {
			t.Fatalf("re-enabling a health-disabled backend must succeed, got: %v", err)
		}
		if hookCalls != 1 {
			t.Fatalf("exactly one enabled-intent persistence hook call expected, got %d", hookCalls)
		}

		row, err := svc.db.GetBackendTunnel(ctx, tun.ID)
		if err != nil || row == nil {
			t.Fatalf("failed to read durable post-state: %v", err)
		}
		if !row.Enabled {
			t.Error("durable row must carry enabled=1 after the administrative re-enable")
		}
		if row.DisableReason != models.DisableReasonHealth {
			t.Errorf("durable disable_reason = %q, want %q (health provenance survives an administrative toggle)",
				row.DisableReason, models.DisableReasonHealth)
		}
		if row.StateVersion != preVersion+1 {
			t.Errorf("durable state_version = %d, want pre+1 = %d", row.StateVersion, preVersion+1)
		}
		live, err := svc.pool.GetTunnel(id)
		if err != nil {
			t.Fatalf("GetTunnel failed: %v", err)
		}
		if !live.Enabled || live.DisableReason != models.DisableReasonHealth {
			t.Errorf("live row = enabled=%v reason=%q, want enabled=true reason=%q",
				live.Enabled, live.DisableReason, models.DisableReasonHealth)
		}
	})
}

// TestR1_4ReenableRetiresOldExactlyOnce pins gap #7: on the successful
// re-enable path, OLD is retired EXACTLY once — one Close, and its loss
// ownership transferred into retiredBackendDeviceDrops exactly once (the
// injected 11 must not double). A regression that retired OLD both in the
// durable-commit path and at publication would report closes=2 and 22.
func TestR1_4ReenableRetiresOldExactlyOnce(t *testing.T) {
	ctx := context.Background()
	svc, id, tun := lifecycleTestService(t)

	if raw := svc.GetBackendDeviceForTest(tun.ID); raw == nil {
		t.Fatal("fixture must start with a registered serving device")
	}
	witness := &r14RetireWitness{
		tx1SinkDevice: &tx1SinkDevice{
			testBackendDevice: &testBackendDevice{AWGClientDevice: svc.GetBackendDeviceForTest(tun.ID).(*tunnel.AWGClientDevice)},
			sink:              make(chan []byte, 4),
		},
	}
	// Loss ownership only OLD owns; if retirement transfers it twice the
	// retired total reads 22, not 11.
	witness.dropCount.Store(11)
	svc.SetBackendDeviceForTest(tun.ID, witness)
	svc.forwarder.AttachBackendDevice(tun.ID, witness)

	// Oracle self-check: OLD is a usable serving device before the re-enable.
	if _, err := witness.Write(make([]byte, 20)); err != nil {
		t.Fatalf("fixture OLD must admit plaintext: %v", err)
	}
	select {
	case <-witness.sink:
	case <-time.After(5 * time.Second):
		t.Fatal("fixture OLD admitted plaintext but delivered nothing to the sink")
	}

	// Anti-vacuity: prove preparation actually ran for the enable under test.
	svc.ResetPreparedCandidateCountForTest()

	if err := svc.EnableBackend(ctx, id); err != nil {
		t.Fatalf("explicit re-enable must succeed, got: %v", err)
	}

	if n := svc.PreparedCandidateCountForTest(); n != 1 {
		t.Fatalf("expected exactly 1 prepared candidate for the re-enable, got %d; the test is vacuous if preparation never ran", n)
	}
	if got := witness.closes.Load(); got != 1 {
		t.Errorf("OLD must be retired (closed) exactly once on the enable path, got %d closes", got)
	}
	if !witness.IsClosed() {
		t.Error("retired OLD must report closed")
	}
	if n := svc.retiredBackendDeviceDrops.Total(); n != 11 {
		t.Errorf("OLD's loss ownership must transfer into the retirement accumulator exactly once, got %d, want 11", n)
	}
	newDev := svc.GetBackendDeviceForTest(tun.ID)
	if newDev == nil || newDev == witness {
		t.Error("the re-enabled backend must be served by the newly published candidate device")
	}
}

// TestR1_4AmbiguousEnableCommitResolvesViaDurableReadback pins the ambiguous
// completion half of the SQLite probe (case AFTER): the single durable enable
// statement lands, THEN the abort fires, so the driver returns an error for a
// row that carries the intended state. The boundary must resolve that with its
// one bounded durable readback and report SUCCESS — not leave the caller to
// conclude the previous serving state is untouched while the durable row is
// already enabled.
func TestR1_4AmbiguousEnableCommitResolvesViaDurableReadback(t *testing.T) {
	ctx := context.Background()
	svc, id, tun := lifecycleTestService(t)

	pre, err := svc.db.GetBackendTunnel(ctx, tun.ID)
	if err != nil || pre == nil {
		t.Fatalf("failed to read durable pre-state: %v", err)
	}
	preVersion := pre.StateVersion

	// AFTER UPDATE: the row lands first (probe case B), then RAISE(FAIL)
	// aborts with the change retained. Only CommitBackendTunnelEnable's
	// statement updates the enabled column during this enable (Pool.AddTunnel
	// rewrites identity columns without touching enabled, so the trigger does
	// not fire for it).
	if _, err := svc.db.SQLDB().ExecContext(ctx, `
		CREATE TRIGGER r14_ambiguous_enable
		AFTER UPDATE OF enabled ON backend_tunnels
		BEGIN
			SELECT RAISE(FAIL, 'r14 ambiguous enable commit');
		END;
	`); err != nil {
		t.Fatalf("failed to create ambiguity trigger: %v", err)
	}
	// Drop the trigger before lifecycleTestService's DisableBackend cleanup
	// runs (t.Cleanup is LIFO).
	t.Cleanup(func() {
		_, _ = svc.db.SQLDB().ExecContext(context.Background(), `DROP TRIGGER IF EXISTS r14_ambiguous_enable`)
	})

	if err := svc.EnableBackend(ctx, id); err != nil {
		t.Fatalf("an enable commit whose durable row landed must be resolved as success by the bounded readback, got: %v", err)
	}

	row, err := svc.db.GetBackendTunnel(ctx, tun.ID)
	if err != nil || row == nil {
		t.Fatalf("failed to read durable post-state: %v", err)
	}
	if !row.Enabled {
		t.Error("durable row must carry enabled=1 after the ambiguous commit resolves")
	}
	if row.StateVersion != preVersion+1 {
		t.Errorf("durable state_version = %d, want pre+1 = %d (the row landed exactly once)",
			row.StateVersion, preVersion+1)
	}
	if dev := svc.GetBackendDeviceForTest(tun.ID); dev == nil {
		t.Error("a resolved enable must leave a serving device registered for the backend")
	}
}

// TestR1_4PersistenceFailurePathsKeepOldPumpingAndLeakNothing pins gap #8 on
// the two deterministic persistence-failure injections:
//
//   - the hook injection fails CommitBackendEnable before any database access;
//   - the BEFORE-trigger injection fails the real UPDATE statement with the
//     row NOT landed (probe case BEFORE: state_version unchanged).
//
// Both must leave OLD open, registered, owning its endpoint, keeping its loss
// ownership, and STILL BEING PUMPED by the forwarder; both must advance no
// administrative state; and neither may leak a goroutine (a pre-R1-3
// regression that published before the durable write leaks the published pump
// and the routing-remediation loop on exactly these paths).
func TestR1_4PersistenceFailurePathsKeepOldPumpingAndLeakNothing(t *testing.T) {
	t.Run("HookFailure", func(t *testing.T) {
		ctx := context.Background()
		svc, id, tun := lifecycleTestService(t)
		old := r14AttachPumpingOld(t, svc, tun)
		old.dropCount.Store(7) // loss ownership that must NOT be retired on failure

		pre, err := svc.db.GetBackendTunnel(ctx, tun.ID)
		if err != nil || pre == nil {
			t.Fatalf("failed to read durable pre-state: %v", err)
		}
		preVersion := pre.StateVersion

		// Baseline AFTER StartPumps: the test's own pump goroutines are not
		// leaks. Everything the failed enable spawns and fails to reap counts
		// against this baseline.
		baseline := runtime.NumGoroutine()
		genBefore := svc.pool.AdminGeneration(id)

		svc.pool.SetSetTunnelEnabledHookForTest(func(context.Context, int64, bool, string) error {
			return errors.New("r14 injected durable enable failure")
		})
		t.Cleanup(func() { svc.pool.SetSetTunnelEnabledHookForTest(nil) })

		failed := svc.EnableBackend(ctx, id)
		if failed == nil {
			t.Fatal("expected EnableBackend to fail on the injected durable-write error")
		}
		if stage := BackendEnableStage(failed); stage != "persist_enable" {
			t.Fatalf("expected stage=persist_enable, got %q (err: %v)", stage, failed)
		}

		// OLD is completely intact — the R1-3 guarantee on this path.
		if old.IsClosed() {
			t.Error("persistence failure closed OLD; it is the only usable device for this enabled backend")
		}
		if got := svc.GetBackendDeviceForTest(tun.ID); got != old {
			t.Errorf("persistence failure must leave OLD registered for the backend, got %T", got)
		}
		if got := svc.GetBackendDeviceEndpointForTest(tun.ID); got != tun.Endpoint {
			t.Errorf("persistence failure must leave OLD's endpoint ownership intact, got %q want %q", got, tun.Endpoint)
		}
		if n := svc.retiredBackendDeviceDrops.Total(); n != 0 {
			t.Errorf("a failed enable must not retire OLD's loss ownership, got %d dropped packets retired", n)
		}
		if gen := svc.pool.AdminGeneration(id); gen != genBefore {
			t.Errorf("an aborted enable commit must not advance AdminGeneration, %d -> %d", genBefore, gen)
		}

		// The durable row did not move: the hook fails BEFORE the single
		// durable write and before any normalization.
		row, err := svc.db.GetBackendTunnel(ctx, tun.ID)
		if err != nil || row == nil {
			t.Fatalf("failed to read durable post-state: %v", err)
		}
		if row.StateVersion != preVersion {
			t.Errorf("a failed enable commit must not advance the durable row, state_version %d -> %d", preVersion, row.StateVersion)
		}

		// OLD is still being pumped — no candidate was left attached.
		r14AssertStillPumpsToOld(t, svc, old)

		// And nothing from the failed enable is still running.
		r14AssertNoGoroutineLeak(t, baseline)
	})

	t.Run("TriggerFailureRowNotLanded", func(t *testing.T) {
		ctx := context.Background()
		svc, id, tun := lifecycleTestService(t)
		old := r14AttachPumpingOld(t, svc, tun)
		old.dropCount.Store(7)

		pre, err := svc.db.GetBackendTunnel(ctx, tun.ID)
		if err != nil || pre == nil {
			t.Fatalf("failed to read durable pre-state: %v", err)
		}
		preVersion := pre.StateVersion

		// BEFORE UPDATE: the statement aborts before landing (probe case A:
		// state_version unchanged, changes() = 0). The returned error must
		// mean the durable row did NOT move — the failure half of the
		// ambiguity contract, on the real database path rather than the hook.
		if _, err := svc.db.SQLDB().ExecContext(ctx, `
			CREATE TRIGGER r14_fail_enable
			BEFORE UPDATE OF enabled ON backend_tunnels
			BEGIN
				SELECT RAISE(FAIL, 'r14 simulated persistence failure');
			END;
		`); err != nil {
			t.Fatalf("failed to create failure trigger: %v", err)
		}
		t.Cleanup(func() {
			_, _ = svc.db.SQLDB().ExecContext(context.Background(), `DROP TRIGGER IF EXISTS r14_fail_enable`)
		})

		baseline := runtime.NumGoroutine()

		failed := svc.EnableBackend(ctx, id)
		if failed == nil {
			t.Fatal("expected EnableBackend to fail on the trigger-rejected durable write")
		}
		if stage := BackendEnableStage(failed); stage != "persist_enable" {
			t.Fatalf("expected stage=persist_enable, got %q (err: %v)", stage, failed)
		}
		if !strings.Contains(failed.Error(), "r14 simulated persistence failure") {
			t.Fatalf("expected the injected trigger rejection in the error chain, got: %v", failed)
		}

		// The readback must have concluded NOT landed: the durable row is
		// byte-for-byte where it was.
		row, err := svc.db.GetBackendTunnel(ctx, tun.ID)
		if err != nil || row == nil {
			t.Fatalf("failed to read durable post-state: %v", err)
		}
		if row.StateVersion != preVersion {
			t.Errorf("trigger-rejected commit must leave the durable row unmoved, state_version %d -> %d",
				preVersion, row.StateVersion)
		}

		// OLD intact and still pumped.
		if old.IsClosed() {
			t.Error("persistence failure closed OLD; it is the only usable device for this enabled backend")
		}
		if got := svc.GetBackendDeviceForTest(tun.ID); got != old {
			t.Errorf("persistence failure must leave OLD registered for the backend, got %T", got)
		}
		if n := svc.retiredBackendDeviceDrops.Total(); n != 0 {
			t.Errorf("a failed enable must not retire OLD's loss ownership, got %d dropped packets retired", n)
		}
		r14AssertStillPumpsToOld(t, svc, old)

		r14AssertNoGoroutineLeak(t, baseline)
	})
}
