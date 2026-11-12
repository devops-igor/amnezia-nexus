package handlers

// Release of the workers the shared handler fixtures create, and the controls
// that prove the release completes.
//
// Both shared fixtures start real background work. setupTestHandlers creates an
// SSH client pool, whose constructor starts a keep-alive loop and a sweep loop.
// newInstallEnv enables a backend through the real VPN service, which starts the
// production return-path reader over an in-process amneziawg device. Neither
// resource used to be released, so every test that used a fixture left its
// workers running for the remaining life of the test binary.
//
// The release is each fixture's own object lifecycle, not a shutdown of the
// process: a fixture registers cleanup for the objects it created, and the
// observations below are keyed to one object's receiver pointer rather than to a
// process-wide goroutine count, so an unrelated test in the same binary can
// neither satisfy nor spoil them.

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn"
)

const (
	// fixtureStackBufSize bounds the goroutine dump used for the observations.
	// runtime.Stack fills the buffer exactly when the dump does not fit, so a
	// full buffer means the dump is truncated: a worker past the cut would be
	// invisible and would count as zero. Reading it is fail-closed.
	fixtureStackBufSize = 8 << 20
	// fixtureReleaseTimeout bounds the poll for a worker transition. The release
	// signals the worker; the goroutine still has to be scheduled out.
	fixtureReleaseTimeout = 5 * time.Second
	// fixtureAbsenceWindow is how long a control waits to confirm a worker that
	// should NOT have been released is still alive. The release path completes in
	// about a millisecond, so a short window already excludes one having happened.
	fixtureAbsenceWindow = 250 * time.Millisecond

	fixtureSSHKeepAliveFrame = "ssh.(*SSHClientPool).keepAliveLoop"
	fixtureSSHSweepFrame     = "ssh.(*SSHClientPool).sweepLoop"
	fixtureReturnReaderFrame = "vpn.(*Service).pumpBackendReturns"

	// fixtureBackendAWGPublicKey is a syntactically valid base64 WireGuard public
	// key, so a control backend can be enabled without any real host involved.
	fixtureBackendAWGPublicKey = "x9aB1234567890abcdef1234567890abcdef1234567="
)

// fixtureGoroutineDump returns the complete goroutine dump, or fails the test
// rather than handing back a truncated one.
func fixtureGoroutineDump(t *testing.T) string {
	t.Helper()
	buf := make([]byte, fixtureStackBufSize)
	n := runtime.Stack(buf, true)
	if n >= len(buf) {
		t.Fatalf("goroutine dump filled %d bytes and is truncated; worker counts would be unknown, not zero", fixtureStackBufSize)
	}
	return string(buf[:n])
}

// fixtureOwnedWorkers counts the goroutines currently executing method on the
// exact receiver. Goroutine dumps print the receiver in the frame line, e.g.
// "ssh.(*SSHClientPool).keepAliveLoop(0xc0002598f0)", so this distinguishes one
// fixture's worker from every other worker of the same kind.
func fixtureOwnedWorkers(t *testing.T, dump, method string, receiver any) int {
	t.Helper()
	return strings.Count(dump, fmt.Sprintf("%s(%p", method, receiver))
}

// waitFixtureOwnedWorkers polls until the receiver owns exactly want workers.
// The transition is the evidence: neither the presence of a worker right after
// construction nor its absence right after a signal proves anything on its own.
func waitFixtureOwnedWorkers(t *testing.T, method string, receiver any, want int, what string) {
	t.Helper()
	deadline := time.Now().Add(fixtureReleaseTimeout)
	for {
		got := fixtureOwnedWorkers(t, fixtureGoroutineDump(t), method, receiver)
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: %d owned workers, want %d", what, got, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// releaseFixtureSSHPool closes the pool a fixture created. Close signals the
// stop channel and then joins both loops on the pool's wait group, so the loops
// are finished when it returns.
func releaseFixtureSSHPool(t *testing.T, pool *ssh.SSHClientPool) {
	t.Helper()
	if pool == nil {
		return
	}
	if err := pool.Close(); err != nil {
		t.Errorf("closing the fixture SSH client pool: %v", err)
	}
}

// releaseFixtureVPNService releases every backend device the fixture's service
// owns, then stops the service.
//
// DisableBackend is the release: it is the production administrative disable,
// which detaches the forwarder device, closes it and marks the tunnel disabled.
// Closing the device is what unblocks the return-path reader.
//
// Service.Stop is deliberately not the primary mechanism. It returns immediately
// for a service that was never Started, and every handler fixture builds its
// service without starting it, so a Stop-only teardown would leave the reader
// running. It is still called last, so a service a test did start is shut down
// through its own lifecycle.
func releaseFixtureVPNService(t *testing.T, svc *vpn.Service) {
	t.Helper()
	if svc == nil {
		return
	}
	backends, err := svc.GetBackends(context.Background())
	if err != nil {
		t.Logf("listing the fixture's backends for release: %v", err)
	}
	for _, tun := range backends {
		releaseFixtureBackend(t, svc, tun)
	}
	if err := svc.Stop(); err != nil {
		t.Errorf("stopping the fixture VPN service: %v", err)
	}
}

// releaseFixtureBackend releases one backend's device and then verifies it,
// rather than assuming the release happened. A device still open here keeps its
// return-path reader alive for the rest of the test binary.
func releaseFixtureBackend(t *testing.T, svc *vpn.Service, tun *models.BackendTunnel) {
	t.Helper()
	if tun == nil {
		return
	}
	if err := svc.DisableBackend(context.Background(), tun.ServerID); err != nil {
		// The disable persists the administrative state before it releases the
		// device, so a test that already closed the database fails here. The
		// device is still this fixture's to close, and closing it is the step
		// that ends the reader.
		t.Logf("disabling fixture backend %d for release: %v", tun.ServerID, err)
	}
	dev := svc.GetBackendDeviceForTest(tun.ID)
	if dev == nil {
		return
	}
	if !dev.IsClosed() {
		t.Errorf("fixture backend %d still owns an open device after release", tun.ID)
		_ = dev.Close()
	}
}

// TestFixtureSSHPoolReleasesItsWorkersAtTeardown drives the shared fixture in a
// subtest and then observes the pool from outside it, after the subtest's own
// cleanup has run.
func TestFixtureSSHPoolReleasesItsWorkersAtTeardown(t *testing.T) {
	var pool *ssh.SSHClientPool
	t.Run("the fixture is in use", func(t *testing.T) {
		h, _, _ := setupTestHandlers(t)
		concrete, ok := h.sshPool.(*ssh.SSHClientPool)
		if !ok {
			t.Fatalf("the fixture no longer creates the real SSH client pool (got %T); this control would prove nothing", h.sshPool)
		}
		pool = concrete
		waitFixtureOwnedWorkers(t, fixtureSSHKeepAliveFrame, pool, 1, "keep-alive loop while the fixture is in use")
		waitFixtureOwnedWorkers(t, fixtureSSHSweepFrame, pool, 1, "sweep loop while the fixture is in use")
	})
	// The subtest's cleanup has run, so nothing it created may still be running.
	if pool == nil {
		t.Fatal("the fixture was never built")
	}
	waitFixtureOwnedWorkers(t, fixtureSSHKeepAliveFrame, pool, 0, "keep-alive loop after fixture teardown")
	waitFixtureOwnedWorkers(t, fixtureSSHSweepFrame, pool, 0, "sweep loop after fixture teardown")
}

// TestFixtureVPNServiceReleasesBackendDeviceAtTeardown is the same control for
// the install fixture's VPN service and the backend device it enables.
func TestFixtureVPNServiceReleasesBackendDeviceAtTeardown(t *testing.T) {
	var (
		svc   *vpn.Service
		dev   vpn.BackendDevice
		tunID int64
	)
	t.Run("the fixture installs a backend", func(t *testing.T) {
		env := newInstallEnv(t, models.ProtocolAWG)
		env.seedOrder("ord_teardown", 9101, "198.51.100.101")
		env.seedManagedCredential("ord_teardown")
		env.providerServes("ord_teardown", 9101, "198.51.100.101")
		env.approve("ord_teardown", models.ProtocolAWG, "51820", installFixtureFingerprint)
		env.trackerAndInstall()

		got := env.requireState("ord_teardown", models.SetupStateReady)
		tun, err := env.h.vpnSvc.GetTunnel(got.NexusServerID)
		if err != nil || tun == nil {
			t.Fatalf("no backend tunnel after a completed install: %v", err)
		}
		svc, tunID = env.h.vpnSvc, tun.ID
		dev = svc.GetBackendDeviceForTest(tun.ID)
		if dev == nil {
			t.Fatal("the enabled backend owns no device, so this control would prove nothing")
		}
		if dev.IsClosed() {
			t.Fatal("the backend device is already closed while the test still uses it")
		}
		waitFixtureOwnedWorkers(t, fixtureReturnReaderFrame, svc, 1, "return-path reader while the backend is enabled")
	})
	if svc == nil || dev == nil {
		t.Fatal("the fixture never produced an enabled backend")
	}
	if !dev.IsClosed() {
		t.Fatalf("the fixture left the device of backend tunnel %d open after teardown", tunID)
	}
	waitFixtureOwnedWorkers(t, fixtureReturnReaderFrame, svc, 0, "return-path reader after fixture teardown")
}

// enableControlBackend builds a service the way the handler fixtures do — a
// never-Started service over a real database — and enables one real backend on
// it, so the control has a device and a return-path reader to observe.
func enableControlBackend(t *testing.T) (*vpn.Service, vpn.BackendDevice) {
	t.Helper()
	db, err := database.Open(t.TempDir()+"/teardown_control.db", testSecretKey)
	if err != nil {
		t.Fatalf("open the control database: %v", err)
	}
	svc, err := vpn.NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("build the service the way the fixture does (nil VPN config): %v", err)
	}
	ctx := context.Background()
	serverID, err := db.CreateServer(ctx, &models.Server{
		Name: "teardown-control", Host: "198.51.100.102", SSHPort: 22, SSHUser: "root", SSHPass: "fixture-only",
		Protocols: map[string]any{"awg": map[string]any{
			"installed":  true,
			"port":       51820,
			"public_key": fixtureBackendAWGPublicKey,
		}},
		CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("create the backend server row: %v", err)
	}
	if err := svc.EnableBackend(ctx, serverID); err != nil {
		t.Fatalf("enable a backend on the control service: %v", err)
	}
	tun, err := svc.GetTunnel(serverID)
	if err != nil || tun == nil {
		t.Fatalf("no backend tunnel after enable: %v", err)
	}
	dev := svc.GetBackendDeviceForTest(tun.ID)
	if dev == nil {
		t.Fatal("the enabled backend owns no device, so this control would prove nothing")
	}
	// The control must not leak what it demonstrates. Closing the device first is
	// what ends the reader, and it needs no database.
	t.Cleanup(func() {
		_ = dev.Close()
		_ = svc.Stop()
		_ = db.Close()
	})
	return svc, dev
}

// TestStopAloneDoesNotReleaseFixtureBackend is the control for the original
// defect: the issue names "stop the VPN service" as the repair, but Stop returns
// immediately for a service that was never Started, which is exactly how both
// handler fixtures build theirs. Keeping this property under test is what stops
// a Stop-only change from later passing as a release.
func TestStopAloneDoesNotReleaseFixtureBackend(t *testing.T) {
	svc, dev := enableControlBackend(t)

	// The old prescribed teardown, applied on its own. The reader must be
	// observed alive first: a goroutine spawned by enable takes a moment to be
	// scheduled, and "absent before, absent after" would prove nothing.
	waitFixtureOwnedWorkers(t, fixtureReturnReaderFrame, svc, 1, "return-path reader before Stop")
	if err := svc.Stop(); err != nil {
		t.Fatalf("stopping the control service: %v", err)
	}
	if dev.IsClosed() {
		t.Fatal("Stop closed the device, so this control no longer represents the original defect")
	}
	// Watch the whole settle window rather than sampling once: a release that
	// did happen would take the reader to zero within it, and that must fail.
	deadline := time.Now().Add(fixtureAbsenceWindow)
	for {
		if n := fixtureOwnedWorkers(t, fixtureGoroutineDump(t), fixtureReturnReaderFrame, svc); n != 1 {
			t.Fatalf("return-path readers after Stop alone = %d, want 1 (Stop is not a release for a never-Started service)", n)
		}
		if time.Now().After(deadline) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestFixtureRepeatedCyclesOwnNoWorkersAfterEachRelease runs several independent
// fixture lifetimes in one binary and checks each one returns to zero, so a leak
// that a single cycle would hide behind an earlier cycle's workers is visible.
func TestFixtureRepeatedCyclesOwnNoWorkersAfterEachRelease(t *testing.T) {
	for cycle := 0; cycle < 3; cycle++ {
		var pool *ssh.SSHClientPool
		t.Run(fmt.Sprintf("cycle %d", cycle), func(t *testing.T) {
			h, _, _ := setupTestHandlers(t)
			concrete, ok := h.sshPool.(*ssh.SSHClientPool)
			if !ok {
				t.Fatalf("the fixture no longer creates the real SSH client pool (got %T)", h.sshPool)
			}
			pool = concrete
			waitFixtureOwnedWorkers(t, fixtureSSHKeepAliveFrame, pool, 1, "keep-alive loop during the cycle")
		})
		if pool == nil {
			t.Fatalf("cycle %d never built the fixture", cycle)
		}
		waitFixtureOwnedWorkers(t, fixtureSSHKeepAliveFrame, pool, 0, fmt.Sprintf("keep-alive loop left behind by cycle %d", cycle))
		waitFixtureOwnedWorkers(t, fixtureSSHSweepFrame, pool, 0, fmt.Sprintf("sweep loop left behind by cycle %d", cycle))
	}
}
