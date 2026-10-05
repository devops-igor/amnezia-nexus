package vpn

import (
	"context"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

// TestR1_2PrePublicationFailureLeavesOldIntact is the R1-2 acceptance test.
//
// It pins the PREPARATION/PUBLICATION split itself, independently of R1-3.
// Where TestRereviewReenablePersistenceFailurePreservesWorkingDevice injects a
// failure in the durable enabled-state write that still runs AFTER publication
// (R1-3's subject), this test injects a failure strictly BEFORE publication and
// therefore asserts exactly what R1-2 promises:
//
//   - the candidate was fully constructed, configured and started, privately,
//     outside Service.mu and with no live-pool identity publication;
//   - OLD survives it completely: still open, still registered for the
//     backend, still owning its endpoint, still admitting plaintext;
//   - only the candidate was closed;
//   - an unpublished candidate contributes NO served-device retirement prefix.
//
// The failure is a REAL concurrent administrative disable injected through the
// existing post-AddTunnel hook, which advances AdminGeneration. That is the
// AdminGeneration fence inside finishEnableBackend, which now runs AFTER
// preparation and BEFORE publication.
func TestR1_2PrePublicationFailureLeavesOldIntact(t *testing.T) {
	ctx := context.Background()
	svc, id, tun := lifecycleTestService(t)

	// The fixture's own enabling EnableBackend already prepared (and published)
	// one candidate. Count only the enable under test.
	svc.ResetPreparedCandidateCountForTest()

	raw, ok := svc.GetBackendDeviceForTest(tun.ID).(*tunnel.AWGClientDevice)
	if !ok || raw == nil {
		t.Fatalf("fixture must start with a real AWG OLD device, got %T", svc.GetBackendDeviceForTest(tun.ID))
	}
	old := &testBackendDevice{AWGClientDevice: raw, inPacketsCh: make(chan []byte, 4)}
	old.dropCount.Store(7) // loss ownership that must NOT be retired pre-publication
	svc.SetBackendDeviceForTest(tun.ID, old)
	svc.forwarder.AttachBackendDevice(tun.ID, old)

	// Oracle self-check: the fixture really is a usable serving device.
	if _, err := old.Write(make([]byte, 20)); err != nil {
		t.Fatalf("fixture OLD must admit plaintext: %v", err)
	}
	<-old.inPacketsCh

	// Inject a genuine concurrent administrative change AFTER AddTunnel (so the
	// candidate has been, or is about to be, prepared) but BEFORE publication.
	// ForceDisableTunnelInMemory advances AdminGeneration without touching the
	// device, which is exactly the "a newer administrative operation completed"
	// condition the fence must catch.
	svc.SetEnableBackendPostAddTunnelHookForTest(func() {
		if err := svc.pool.ForceDisableTunnelInMemory(id, "admin"); err != nil {
			t.Errorf("failed to inject concurrent administrative disable: %v", err)
		}
	})
	t.Cleanup(func() { svc.SetEnableBackendPostAddTunnelHookForTest(nil) })

	err := svc.EnableBackend(ctx, id)
	if err == nil {
		t.Fatal("expected EnableBackend to fail: a newer administrative disable must fence this enable")
	}
	if stage := BackendEnableStage(err); stage != "state_changed" {
		t.Fatalf("expected the pre-publication fence to reject with stage=state_changed, got %q (err: %v)", stage, err)
	}

	// OLD must be completely intact: this is the R1-2 guarantee.
	if old.IsClosed() {
		t.Error("pre-publication failure closed OLD; it is the only usable device for this enabled backend")
	}
	if got := svc.GetBackendDeviceForTest(tun.ID); got != old {
		t.Errorf("pre-publication failure must leave OLD registered for the backend, got %T", got)
	}
	if got := svc.GetBackendDeviceEndpointForTest(tun.ID); got != tun.Endpoint {
		t.Errorf("pre-publication failure must leave OLD's endpoint ownership intact, got %q want %q", got, tun.Endpoint)
	}
	if _, werr := old.Write(make([]byte, 20)); werr != nil {
		t.Errorf("OLD no longer admits plaintext after a pre-publication failure: %v", werr)
	} else {
		select {
		case <-old.inPacketsCh:
		default:
			t.Error("OLD accepted plaintext but delivered nothing to the pump sink")
		}
	}

	// An unpublished candidate is not a retired SERVING device: it must
	// contribute no retirement prefix, and OLD's 7 packets must still be OLD's.
	if n := svc.retiredBackendDeviceDrops.Total(); n != 0 {
		t.Errorf("a pre-publication failure must not retire OLD loss ownership, got %d dropped packets retired", n)
	}

	// Discriminating oracle. At HEAD, preparation and publication were ONE
	// atomic call (attachBackendForwarder), so there was no pre-publication
	// window: this fence fired before any device was built, and the test would
	// pass vacuously. R1-2 splits the two, so the candidate is now genuinely
	// constructed and started before the fence runs, and must then be
	// discarded. Assert preparation actually happened.
	if n := svc.PreparedCandidateCountForTest(); n != 1 {
		t.Fatalf("expected exactly 1 prepared candidate discarded pre-publication, got %d; "+
			"the test is vacuous if preparation never ran", n)
	}

	// And the discard must have closed the candidate without touching OLD:
	// the forwarder must still be pumping into OLD. This is the observable
	// proof that no candidate was ever attached.
	svc.forwarder.RegisterSession("r12-session", "r12-connection", "r12-peer", "192.0.2.100", tun.ID)
	svc.forwarder.StartPumps(ctx)
	t.Cleanup(svc.forwarder.StopPumps)
	if err := svc.forwarder.RouteClientToBackend("r12-peer", []byte("post-failure-forwarder-packet")); err != nil {
		t.Errorf("forwarder no longer routes to the backend after the pre-publication failure: %v", err)
	} else {
		select {
		case <-old.inPacketsCh:
		case <-time.After(15 * time.Second):
			t.Error("post-failure forwarder pump delivered nothing to OLD: a candidate is still attached")
		}
	}
}
