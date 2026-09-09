package endpoint

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-web-ui-go/internal/models"
)

// Regression test for the idle-timeout reaper discarding CheckTimeouts'
// result: heartbeatLoop now passes each reaped session to the registered
// SessionReaperHook so the caller can clean up forwarder routes, pool
// counters, and sticky affinity (same teardown as an explicit disconnect).
func TestHeartbeatLoopInvokesReaperHook(t *testing.T) {
	cfg := ListenerConfig{
		ListenPort:  testFreePort(t),
		IdleTimeout: 50 * time.Millisecond, // reap quickly
	}
	sm := NewSessionManager(nil, nil)

	el, err := NewListener(cfg, nil, nil, nil, sm, nil)
	if err != nil {
		t.Fatalf("NewListener failed: %v", err)
	}

	reaped := make(chan *models.VPNSession, 8)
	el.SetSessionReaperHook(func(ctx context.Context, sess *models.VPNSession) {
		select {
		case reaped <- sess:
		default:
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := el.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer func() { _ = el.Stop() }()

	// A session that goes idle must be reaped and handed to the hook.
	if _, err := sm.CreateSession(ctx, "u-idle", "peer-idle", "10.77.0.1", 1); err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// The heartbeat ticks every 30s; shrink the wait by forcing one tick via
	// the first sweep after start. Wait up to 35s for the reap.
	deadline := time.Now().Add(35 * time.Second)
	var got *models.VPNSession
	for time.Now().Before(deadline) {
		select {
		case s := <-reaped:
			got = s
		default:
		}
		if got != nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if got == nil {
		t.Fatal("reaper hook was never invoked for the idle session")
	}
	if got.PeerPublicKey != "peer-idle" {
		t.Errorf("reaped wrong session: peer=%s", got.PeerPublicKey)
	}

	// The session must have been closed in the manager.
	if _, ok := sm.GetSession("peer-idle"); ok {
		t.Error("session still present in manager after reap")
	}
}

func testFreePort(t *testing.T) int {
	t.Helper()
	// Port 0 would be rejected by ListenerConfig validation; grab a real free
	// UDP port the same way the vpn service tests do.
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("failed to grab free port: %v", err)
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).Port
}
