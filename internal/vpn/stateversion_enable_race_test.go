package vpn

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// blockingPeerAdder parks inside registerBackendPortalPeers — the multi-second
// SSH peer-registration window that sits between Pool.AddTunnel and
// finishEnableBackend — until released. This is the real concurrency window, not
// an artificial one.
type blockingPeerAdder struct {
	release chan struct{}
	entered chan struct{}
	once    sync.Once
	armed   atomic.Bool
}

func (m *blockingPeerAdder) GetServerStatus(ctx context.Context, server *models.Server) (map[string]any, error) {
	return nil, nil
}

func (m *blockingPeerAdder) AddClient(ctx context.Context, server *models.Server, clientParams map[string]any) (map[string]any, error) {
	if !m.armed.Load() {
		return map[string]any{"client_id": "peer"}, nil
	}
	m.once.Do(func() { close(m.entered) })
	<-m.release
	return map[string]any{"client_id": "peer"}, nil
}

func newStateVersionRaceService(t *testing.T, name, host, pubKey string) (*Service, *blockingPeerAdder, int64) {
	t.Helper()
	ctx := context.Background()
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	srvID, err := db.CreateServer(ctx, &models.Server{
		Name: name, Host: host,
		Protocols: map[string]any{"awg": map[string]any{
			"installed": true, "port": 51820, "public_key": pubKey,
		}},
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}
	adder := &blockingPeerAdder{release: make(chan struct{}), entered: make(chan struct{})}
	svc.SetAWGStatusProvider(adder)
	return svc, adder, srvID
}

// awaitEnableWindow blocks until the EnableBackend goroutine is parked inside
// the peer-registration window.
func awaitEnableWindow(t *testing.T, adder *blockingPeerAdder) {
	t.Helper()
	select {
	case <-adder.entered:
	case <-time.After(15 * time.Second):
		t.Fatal("EnableBackend never reached the peer-registration window")
	}
}

// TestEnableBackend_RoutineHealthTickDoesNotAbortEnable is the permanent
// regression for the round-3 backend-enable HTTP 500.
//
// It drives the REAL HealthProber (one full ProbeAll, success path) against the
// REAL EnableBackend while EnableBackend is parked in its SSH window. Before the
// fix that tick reached Pool.setTunnelStatus, advanced the live pool entry's
// StateVersion, and tripped the blanket version-equality guard in
// finishEnableBackend, so a routine background observation aborted a legitimate
// administrative enable with stage=state_changed.
//
// This test fails on the old behaviour and passes on the new.
func TestEnableBackend_RoutineHealthTickDoesNotAbortEnable(t *testing.T) {
	ctx := context.Background()
	svc, adder, srvID := newStateVersionRaceService(t, "health-tick-race", "198.51.100.93", "health-tick-pubkey")

	svc.SetProbeFunc(func(context.Context, string, string, string, string, string, any, any, int, int, time.Duration) (time.Duration, error) {
		return 12 * time.Millisecond, nil
	})

	adder.armed.Store(true)
	enableErr := make(chan error, 1)
	go func() { enableErr <- svc.EnableBackend(ctx, srvID) }()
	awaitEnableWindow(t, adder)

	before, err := svc.pool.GetTunnel(srvID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}

	// The real writer: one routine background health tick.
	probeResults := svc.prober.ProbeAll(ctx)
	perr, probed := probeResults[srvID]
	if !probed {
		t.Fatalf("expected the prober to probe server %d, got results %v", srvID, probeResults)
	}
	if perr != nil {
		t.Fatalf("routine probe reported an error, so this is not a valid reproduction: %v", perr)
	}

	after, err := svc.pool.GetTunnel(srvID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	if after.StateVersion <= before.StateVersion {
		t.Fatalf("reproduction is void: the health tick did not advance StateVersion (%d -> %d); "+
			"this test no longer exercises the race", before.StateVersion, after.StateVersion)
	}

	close(adder.release)

	if err := <-enableErr; err != nil {
		t.Fatalf("a routine health tick must not abort the enable; got: %v", err)
	}

	got, err := svc.pool.GetTunnel(srvID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	if !got.Enabled {
		t.Error("expected the backend to be left administratively enabled")
	}
}

// TestEnableBackend_IdentityChangeStillAbortsEnable pins the half of the old
// contract that is genuine. A health observation is benign, but a rewrite of the
// tunnel identity the portal peers were just registered against is a real
// conflict and must still abort — so the fix is not a wholesale removal of the
// guard.
func TestEnableBackend_IdentityChangeStillAbortsEnable(t *testing.T) {
	t.Run("EndpointRewriteAborts", func(t *testing.T) {
		ctx := context.Background()
		svc, adder, srvID := newStateVersionRaceService(t, "endpoint-race", "198.51.100.94", "endpoint-race-pubkey")

		if err := svc.EnableBackend(ctx, srvID); err != nil {
			t.Fatalf("initial EnableBackend failed: %v", err)
		}
		tun, err := svc.pool.GetTunnel(srvID)
		if err != nil {
			t.Fatalf("GetTunnel failed: %v", err)
		}

		adder.armed.Store(true)
		enableErr := make(chan error, 1)
		go func() { enableErr <- svc.EnableBackend(ctx, srvID) }()
		awaitEnableWindow(t, adder)

		// A genuine identity change: the endpoint this enable's peers were
		// registered against is rewritten mid-flight.
		if err := svc.pool.SetTunnelEndpoint(ctx, tun.ID, "198.51.100.94:51821"); err != nil {
			t.Fatalf("SetTunnelEndpoint failed: %v", err)
		}

		close(adder.release)
		err = <-enableErr
		if err == nil {
			t.Fatal("expected EnableBackend to abort on a concurrent endpoint rewrite, got nil")
		}
		if !strings.Contains(err.Error(), "identity modified concurrently") {
			t.Fatalf("expected the identity-change abort, got: %v", err)
		}
	})

	t.Run("AdminDisableStillAborts", func(t *testing.T) {
		ctx := context.Background()
		svc, adder, srvID := newStateVersionRaceService(t, "admin-race", "198.51.100.95", "admin-race-pubkey")

		adder.armed.Store(true)
		enableErr := make(chan error, 1)
		go func() { enableErr <- svc.EnableBackend(ctx, srvID) }()
		awaitEnableWindow(t, adder)

		if err := svc.pool.SetTunnelEnabled(ctx, srvID, false, models.DisableReasonAdmin); err != nil {
			t.Fatalf("SetTunnelEnabled failed: %v", err)
		}

		close(adder.release)
		err := <-enableErr
		if err == nil {
			t.Fatal("expected EnableBackend to abort on a concurrent administrative disable, got nil")
		}
		if !strings.Contains(err.Error(), "administratively disabled") {
			t.Fatalf("expected the administrative-disable abort, got: %v", err)
		}
	})
}

// TestEnableBackend_LaterAdministrativeDisableWins verifies that an older in-flight
// enable operation cannot re-enable a backend after an intervening administrative
// enable/disable cycle completes. The completed newer administrative disable must win.
func TestEnableBackend_LaterAdministrativeDisableWins(t *testing.T) {
	t.Run("PeerRegistrationWindow", func(t *testing.T) {
		ctx := context.Background()
		svc, adder, srvID := newStateVersionRaceService(t, "admin-cycle-peer", "192.0.2.90", "peer-window-pubkey")

		// Start disabled.
		if err := svc.EnableBackend(ctx, srvID); err != nil {
			t.Fatalf("initial EnableBackend failed: %v", err)
		}
		if err := svc.DisableBackend(ctx, srvID); err != nil {
			t.Fatalf("initial DisableBackend failed: %v", err)
		}

		tunBefore, err := svc.pool.GetTunnel(srvID)
		if err != nil {
			t.Fatalf("GetTunnel failed: %v", err)
		}
		if tunBefore.Enabled {
			t.Fatal("expected backend to start disabled")
		}

		// Older enable A starts while disabled and parks in the SSH peer registration window.
		adder.armed.Store(true)
		enableAErr := make(chan error, 1)
		go func() {
			enableAErr <- svc.EnableBackend(ctx, srvID)
		}()
		awaitEnableWindow(t, adder)
		adder.armed.Store(false)

		// Later enable B completes, then later disable C completes.
		if err := svc.EnableBackend(ctx, srvID); err != nil {
			t.Fatalf("intervening EnableBackend B failed: %v", err)
		}
		if err := svc.DisableBackend(ctx, srvID); err != nil {
			t.Fatalf("intervening DisableBackend C failed: %v", err)
		}

		// Resume older enable A.
		close(adder.release)
		errA := <-enableAErr
		if errA == nil {
			t.Fatal("expected older enable A to fail after intervening administrative disable C, got nil")
		}
		if stage := BackendEnableStage(errA); stage != "state_changed" {
			t.Fatalf("expected stage=state_changed for older enable A, got %q (err: %v)", stage, errA)
		}

		// Assert that in-memory pool retains disabled state with DisableReasonAdmin.
		tunFinal, err := svc.pool.GetTunnel(srvID)
		if err != nil {
			t.Fatalf("GetTunnel final failed: %v", err)
		}
		if tunFinal.Enabled {
			t.Error("older in-flight enable A overrode newer completed disable C in memory")
		}
		if tunFinal.DisableReason != models.DisableReasonAdmin {
			t.Errorf("expected disable_reason=%q, got %q", models.DisableReasonAdmin, tunFinal.DisableReason)
		}

		// Assert persisted database row remains disabled.
		if svc.db != nil {
			dbTun, err := svc.db.GetBackendTunnel(ctx, tunFinal.ID)
			if err != nil {
				t.Fatalf("GetBackendTunnel from DB failed: %v", err)
			}
			if dbTun == nil || dbTun.Enabled {
				t.Error("older in-flight enable A overrode newer completed disable C in database")
			}
		}

		// Assert no forwarder device is attached.
		if dev := svc.GetBackendDeviceForTest(tunFinal.ID); dev != nil {
			t.Error("older in-flight enable A reattached data-plane device after newer disable C")
		}
	})

	t.Run("PostAddTunnelHook", func(t *testing.T) {
		ctx := context.Background()
		svc, _, srvID := newStateVersionRaceService(t, "admin-cycle-hook", "192.0.2.91", "hook-pubkey")

		// Start disabled.
		if err := svc.EnableBackend(ctx, srvID); err != nil {
			t.Fatalf("initial EnableBackend failed: %v", err)
		}
		if err := svc.DisableBackend(ctx, srvID); err != nil {
			t.Fatalf("initial DisableBackend failed: %v", err)
		}

		var laterErr error
		svc.SetEnableBackendPostAddTunnelHookForTest(func() {
			svc.SetEnableBackendPostAddTunnelHookForTest(nil)
			if laterErr = svc.EnableBackend(ctx, srvID); laterErr != nil {
				return
			}
			laterErr = svc.DisableBackend(ctx, srvID)
		})

		olderErr := svc.EnableBackend(ctx, srvID)
		if laterErr != nil {
			t.Fatalf("later administrative operation failed: %v", laterErr)
		}
		if olderErr == nil {
			t.Fatal("expected older enable to fail after intervening disable, got nil")
		}
		if stage := BackendEnableStage(olderErr); stage != "state_changed" {
			t.Fatalf("expected stage=state_changed, got %q (err: %v)", stage, olderErr)
		}

		tunFinal, err := svc.pool.GetTunnel(srvID)
		if err != nil {
			t.Fatalf("GetTunnel final failed: %v", err)
		}
		if tunFinal.Enabled {
			t.Error("older in-flight enable overrode newer completed disable")
		}
		if tunFinal.DisableReason != models.DisableReasonAdmin {
			t.Errorf("expected disable_reason=%q, got %q", models.DisableReasonAdmin, tunFinal.DisableReason)
		}

		if dev := svc.GetBackendDeviceForTest(tunFinal.ID); dev != nil {
			t.Error("older in-flight enable reattached device after newer disable")
		}
	})
}

// TestEnableBackend_PersistenceFailureCleansUpAttachedDevice verifies that if database
// persistence fails during SetTunnelEnabled in finishEnableBackend, the operation fails
// with stage=persist_enable and any forwarder device attached during the operation is cleaned up.
func TestEnableBackend_PersistenceFailureCleansUpAttachedDevice(t *testing.T) {
	ctx := context.Background()
	svc, _, srvID := newStateVersionRaceService(t, "persist-fail", "192.0.2.92", "persist-pubkey")

	// Start disabled.
	if err := svc.EnableBackend(ctx, srvID); err != nil {
		t.Fatalf("initial EnableBackend failed: %v", err)
	}
	if err := svc.DisableBackend(ctx, srvID); err != nil {
		t.Fatalf("initial DisableBackend failed: %v", err)
	}

	tunBefore, err := svc.pool.GetTunnel(srvID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}

	// Install a trigger that causes UPDATE of enabled on backend_tunnels to fail.
	_, err = svc.db.SQLDB().ExecContext(ctx, `
		CREATE TRIGGER fail_backend_enable
		BEFORE UPDATE OF enabled ON backend_tunnels
		BEGIN
			SELECT RAISE(FAIL, 'simulated database persistence failure');
		END;
	`)
	if err != nil {
		t.Fatalf("failed to create fail trigger: %v", err)
	}

	err = svc.EnableBackend(ctx, srvID)
	if err == nil {
		t.Fatal("expected EnableBackend to fail when DB update fails, got nil")
	}
	if stage := BackendEnableStage(err); stage != "persist_enable" {
		t.Fatalf("expected stage=persist_enable, got %q (err: %v)", stage, err)
	}

	// Assert in-memory pool state: must remain disabled.
	tunFinal, err := svc.pool.GetTunnel(srvID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	if tunFinal.Enabled {
		t.Error("backend tunnel in memory was marked enabled despite persistence failure")
	}

	// Assert forwarder device was detached and cleaned up.
	if dev := svc.GetBackendDeviceForTest(tunBefore.ID); dev != nil {
		t.Error("backend device remained registered in service after persistence failure")
	}
}
