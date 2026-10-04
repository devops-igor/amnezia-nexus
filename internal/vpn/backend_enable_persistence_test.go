package vpn

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

// tx1SinkDevice is the ADMISSION-ONLY sink OLD is wrapped in for this test.
//
// Why not plain testBackendDevice: its Write pushes to the sink AND THEN
// delegates to the real AWGClientDevice, i.e. it injects the test's own probe
// packets into the real VirtualTUN inbound queue. Nothing in this test drains
// that queue through the AWG engine, so those probes surface as real inbound
// queue-full losses and, worse, as SHUTDOWN drains when the failed enable
// closes OLD. Both are attributed to OLD by snapshotBackendDeviceDrops at the
// retirement site, so the test's own traffic contaminates exactly the figure
// line 122 measures. This sink therefore admits the packet to the explicit
// channel and stops there.
//
// What it deliberately preserves:
//
//   - the CLOSED-STATE oracle. Write reports the real device's closed state,
//     so "OLD no longer admits plaintext after the failed enable" (line 127)
//     still fires at HEAD instead of being masked by a sink that always accepts.
//   - the LOSS-OWNERSHIP oracle. It embeds *testBackendDevice, so the injected
//     dropCount (7) is still reported through DeviceStats().DropsExternal and
//     is still transferred into retiredBackendDeviceDrops at the premature
//     retirement site. Suppressing the sink traffic must not suppress that:
//     line 122 is genuine R1 evidence, not fixture noise.
//
// Read, Close, IsClosed, DeviceStats and the drop counters all stay the real
// AWGClientDevice's — only the inbound injection is removed.
type tx1SinkDevice struct {
	*testBackendDevice
	sink chan []byte
}

// Write admits p to the sink when the underlying device is open, and reports
// the real device's closed state when it is not. It never injects into the
// real VirtualTUN, so the test's own probes cannot pollute OLD's drop
// accounting.
func (d *tx1SinkDevice) Write(p []byte) (int, error) {
	if d.AWGClientDevice.IsClosed() {
		return 0, errors.New("device closed")
	}
	buf := make([]byte, len(p))
	copy(buf, p)
	select {
	case d.sink <- buf:
	default:
	}
	return len(p), nil
}

// enablePersistFailureTrigger is a REAL SQLite durability failure installed at
// the actual administrative write boundary (UpdateBackendTunnelEnabled, the
// statement Pool.SetTunnelEnabled issues). It is deliberately a database
// trigger rather than a service hook: the failure this test needs is a failed
// durable write, not a returned error from a stub.
const enablePersistFailureTrigger = `
	CREATE TRIGGER fail_reenable_enable_persist
	BEFORE UPDATE OF enabled ON backend_tunnels
	BEGIN
		SELECT RAISE(FAIL, 'tx1 simulated enable persistence failure');
	END;`

// awaitEnablePacket waits for one packet to reach the explicit sink owned by
// the fixture device. This is an event barrier (a receive on a channel fed by
// the real forwarder write pump), not a sleep and not a wait that crosses a
// sampling throttle: if the pump never delivers, the test fails.
func awaitEnablePacket(t *testing.T, sink <-chan []byte, what string) {
	t.Helper()
	select {
	case <-sink:
	case <-time.After(15 * time.Second):
		t.Fatalf("%s: no packet delivered to the OLD device sink", what)
	}
}

// TestRereviewReenablePersistenceFailurePreservesWorkingDevice is the permanent
// acceptance test for TX-1 / R1-1 of the backend mutation ownership contract
// recorded on finishEnableBackend.
//
// Scenario: a backend that is ALREADY enabled, with a real, open, attached and
// forwarding OLD AWG device, is enabled again. Only the enable-persistence
// write fails (real SQLite). The candidate's constructor and startup succeed.
//
// Required terminal state (contract, "persistence-failure behavior" and the
// terminal-state oracle):
//
//	OLD identity in SQLite+pool; actual OLD still open, attached and
//	forwarding; the candidate closed and unpublished; the original error
//	retained; live and freshly reloaded SQLite agree.
//
// At the reviewed HEAD this fails because attachBackendForwarder publishes the
// candidate and closes OLD *before* the fallible SetTunnelEnabled write, and the
// persist_enable error path then detaches and closes the candidate — leaving
// Enabled=true in both live memory and SQLite with no usable device at all, and
// OLD's loss ownership already transferred into the retirement prefix.
func TestRereviewReenablePersistenceFailurePreservesWorkingDevice(t *testing.T) {
	ctx := context.Background()
	svc, id, tun := lifecycleTestService(t)

	raw, ok := svc.GetBackendDeviceForTest(tun.ID).(*tunnel.AWGClientDevice)
	if !ok || raw == nil {
		t.Fatalf("fixture must start with a real AWG OLD device, got %T", svc.GetBackendDeviceForTest(tun.ID))
	}
	// Wrap the real device in an admission-only sink so packets written by the
	// forwarder pump land in an explicit channel with no competing TUN
	// consumer, and so the test's own probes never enter OLD's real drop
	// accounting (see tx1SinkDevice).
	old := &tx1SinkDevice{
		testBackendDevice: &testBackendDevice{AWGClientDevice: raw},
		sink:              make(chan []byte, 4),
	}
	old.dropCount.Store(7) // loss ownership that must NOT be retired on failure
	svc.SetBackendDeviceForTest(tun.ID, old)
	svc.forwarder.AttachBackendDevice(tun.ID, old)
	svc.forwarder.RegisterSession("tx1-session", "tx1-connection", "tx1-peer", "192.0.2.100", tun.ID)
	svc.forwarder.StartPumps(ctx)
	t.Cleanup(svc.forwarder.StopPumps)

	// Oracle self-check: the fixture really admits plaintext and really
	// delivers a client packet through the forwarder into OLD's sink. Without
	// this, a later failure could not be attributed to the enable attempt.
	if _, err := old.Write(make([]byte, 20)); err != nil {
		t.Fatalf("fixture OLD must admit plaintext: %v", err)
	}
	awaitEnablePacket(t, old.sink, "pre-enable direct write")
	if err := svc.forwarder.RouteClientToBackend("tx1-peer", []byte("pre-enable-forwarder-packet")); err != nil {
		t.Fatalf("pre-enable RouteClientToBackend failed: %v", err)
	}
	awaitEnablePacket(t, old.sink, "pre-enable forwarder pump")

	// Arm the real durable-write failure. Registered after lifecycleTestService
	// so it is dropped before that fixture's DisableBackend cleanup runs.
	if _, err := svc.db.SQLDB().ExecContext(ctx, enablePersistFailureTrigger); err != nil {
		t.Fatalf("failed to install enable-persistence failure trigger: %v", err)
	}
	t.Cleanup(func() {
		_, _ = svc.db.SQLDB().ExecContext(context.Background(), "DROP TRIGGER IF EXISTS fail_reenable_enable_persist")
	})

	err := svc.EnableBackend(ctx, id)
	if err == nil {
		t.Fatal("expected EnableBackend to fail when the enable persistence write fails")
	}
	if stage := BackendEnableStage(err); stage != "persist_enable" {
		t.Fatalf("expected stage=persist_enable, got %q (err: %v)", stage, err)
	}
	if !strings.Contains(err.Error(), "tx1 simulated enable persistence failure") {
		t.Fatalf("original durable cause must be retained, got: %v", err)
	}

	// OLD must still be the owned, attached device: open, usable and
	// forwarding. This is the assertion the reviewed HEAD violates.
	if old.IsClosed() {
		t.Error("OLD device was closed by a failed enable-persistence write; it is the only usable device for this enabled backend")
	}
	if got := svc.GetBackendDeviceForTest(tun.ID); got != old {
		t.Errorf("failed enable must leave OLD registered for the backend, got %T", got)
	}
	if got := svc.GetBackendDeviceEndpointForTest(tun.ID); got != tun.Endpoint {
		t.Errorf("failed enable must leave OLD's endpoint ownership intact, got %q want %q", got, tun.Endpoint)
	}

	// An unpublished candidate contributes no served-device retirement prefix.
	if n := svc.retiredBackendDeviceDrops.Total(); n != 0 {
		t.Errorf("a pre-publication failure must not retire OLD loss ownership, got %d dropped packets retired", n)
	}

	// Packet admission and pump delivery through OLD must still work.
	if _, werr := old.Write(make([]byte, 20)); werr != nil {
		t.Errorf("OLD no longer admits plaintext after the failed enable: %v", werr)
	} else {
		awaitEnablePacket(t, old.sink, "post-failure direct write")
	}
	if rerr := svc.forwarder.RouteClientToBackend("tx1-peer", []byte("post-failure-forwarder-packet")); rerr != nil {
		t.Errorf("forwarder no longer routes to the backend after the failed enable: %v", rerr)
	} else {
		awaitEnablePacket(t, old.sink, "post-failure forwarder pump")
	}

	// Live memory and freshly reloaded SQLite must agree, and both must still
	// describe OLD: this backend was already enabled, so a failed re-enable
	// leaves administrative intent untouched.
	live, lerr := svc.pool.GetTunnel(id)
	if lerr != nil {
		t.Fatalf("live GetTunnel failed: %v", lerr)
	}
	row, rerr2 := svc.db.GetBackendTunnel(ctx, tun.ID)
	if rerr2 != nil {
		t.Fatalf("GetBackendTunnel failed: %v", rerr2)
	}
	if row == nil {
		t.Fatal("backend row disappeared")
	}
	if !live.Enabled || !row.Enabled {
		t.Errorf("failed re-enable must not alter administrative intent: live=%v row=%v", live.Enabled, row.Enabled)
	}
	if live.PublicKey != tun.PublicKey || row.PublicKey != tun.PublicKey ||
		live.Endpoint != tun.Endpoint || row.Endpoint != tun.Endpoint {
		t.Errorf("failed re-enable must leave OLD identity in pool and SQLite: live=%q/%q row=%q/%q want %q/%q",
			live.PublicKey, live.Endpoint, row.PublicKey, row.Endpoint, tun.PublicKey, tun.Endpoint)
	}

	reloadedPool := tunnel.NewPool(svc.db)
	if serr := reloadedPool.SyncFromDB(ctx); serr != nil {
		t.Fatalf("fresh pool reload failed: %v", serr)
	}
	reloaded, gerr := reloadedPool.GetTunnel(id)
	if gerr != nil {
		t.Fatalf("freshly reloaded GetTunnel failed: %v", gerr)
	}
	if reloaded.Enabled != live.Enabled || reloaded.PublicKey != live.PublicKey || reloaded.Endpoint != live.Endpoint {
		t.Errorf("live and freshly reloaded SQLite state disagree: live=%v/%q/%q reloaded=%v/%q/%q",
			live.Enabled, live.PublicKey, live.Endpoint,
			reloaded.Enabled, reloaded.PublicKey, reloaded.Endpoint)
	}
}
