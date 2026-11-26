package ssh

// The SSH transport is the boundary every session for a managed server passes
// through. These cases prove the refusal by counting TCP connections on a real
// listener: an absent server costs no connection at all, while a listed server
// still reaches the network in the same run.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// countingListener accepts and immediately closes every connection, so the count
// is exactly the number of attempts made.
func countingListener(t *testing.T) (port int, accepted *int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var count int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.AddInt32(&count, 1)
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-done
	})

	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split listener address: %v", err)
	}
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("read listener port %q: %v", portStr, err)
	}
	return port, &count
}

func waitForAttempts(t *testing.T, accepted *int32, want int32) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for atomic.LoadInt32(accepted) < want {
		if time.Now().After(deadline) {
			t.Fatalf("only %d of %d expected connections reached the listener", atomic.LoadInt32(accepted), want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestPoolGet_RefusesProviderAbsentServer(t *testing.T) {
	port, accepted := countingListener(t)
	ctx := context.Background()

	pool := NewSSHClientPool(PoolConfig{IdleTimeout: time.Minute, KeepAlivePeriod: time.Minute, SweepInterval: time.Minute}, nil)
	defer func() { _ = pool.Close() }()

	// The password matters: without one the transport would fail while building auth
	// methods, and the refusal under test would be masked by a different error.
	absent := &models.Server{
		ID: 1, Name: "provider absent", Host: "127.0.0.1", SSHPort: port, SSHUser: "root", SSHPass: "test-password",
		ProviderAbsentAt: time.Now().UTC().Format(time.RFC3339),
	}
	// A password keeps the auth-method build from failing before the dial, so the
	// live control really reaches the network.
	live := &models.Server{ID: 2, Name: "still listed", Host: "127.0.0.1", SSHPort: port, SSHUser: "root", SSHPass: "test-password"}

	if _, err := pool.Get(ctx, absent); !errors.Is(err, ErrProviderAbsent) {
		t.Fatalf("Get on an absent server returned %v, want ErrProviderAbsent", err)
	}
	if got := atomic.LoadInt32(accepted); got != 0 {
		t.Fatalf("the absent server opened %d connection(s)", got)
	}

	// Live control: the same pool and the same address still reach the network. The
	// handshake fails because the listener is not an SSH server, and that failure is
	// the proof that a connection was attempted.
	if _, err := pool.Get(ctx, live); err == nil {
		t.Fatal("expected the SSH handshake to fail against a bare listener")
	}
	waitForAttempts(t, accepted, 1)
	if got := atomic.LoadInt32(accepted); got != 1 {
		t.Fatalf("expected exactly one connection attempt (the listed server), got %d", got)
	}
}

func TestDialFromServer_RefusesProviderAbsentServer(t *testing.T) {
	port, accepted := countingListener(t)
	ctx := context.Background()

	absent := &models.Server{
		ID: 3, Name: "provider absent", Host: "127.0.0.1", SSHPort: port, SSHUser: "root",
		ProviderAbsentAt: time.Now().UTC().Format(time.RFC3339),
	}
	if _, err := DialFromServer(ctx, absent, nil); !errors.Is(err, ErrProviderAbsent) {
		t.Fatalf("DialFromServer on an absent server returned %v, want ErrProviderAbsent", err)
	}
	if got := atomic.LoadInt32(accepted); got != 0 {
		t.Fatalf("the absent server opened %d connection(s)", got)
	}
}
