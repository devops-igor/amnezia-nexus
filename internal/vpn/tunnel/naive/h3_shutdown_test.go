package naive

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// startSilentUDP listens on UDP, never replies (so a QUIC handshake stalls),
// counts received datagrams and signals the first one on the returned channel.
func startSilentUDP(t *testing.T) (string, *atomic.Int64, <-chan struct{}) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })

	var count atomic.Int64
	first := make(chan struct{})
	go func() {
		buf := make([]byte, 2048)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
			if count.Add(1) == 1 {
				close(first)
			}
		}
	}()
	return pc.LocalAddr().String(), &count, first
}

func newSilentH3Dialer(t *testing.T) (*Dialer, *atomic.Int64, <-chan struct{}) {
	t.Helper()
	addr, count, first := startSilentUDP(t)
	d, err := New(addr, models.NaiveProxyParams{
		Username: "u", Password: "p", Domain: testCamouflageDomain, EnableH3: true,
	})
	if err != nil {
		t.Fatalf("New dialer: %v", err)
	}
	return d, count, first
}

func TestDialer_H3_NoNewConnectionAfterClose(t *testing.T) {
	d, count, _ := newSilentH3Dialer(t)
	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if _, err := d.getH3Conn(ctx); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("getH3Conn after Close: got %v, want net.ErrClosed", err)
	}
	if _, err := d.DialContext(ctx, "tcp", "127.0.0.1:1"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("DialContext after Close: got %v, want net.ErrClosed", err)
	}
	// Give any (buggy) handshake time to emit its Initial packet.
	time.Sleep(200 * time.Millisecond)
	if n := count.Load(); n != 0 {
		t.Fatalf("server saw %d QUIC datagrams after Close, want 0", n)
	}
}

func TestDialer_H3_StalledHandshakeBlocksNeitherWaiterNorClose(t *testing.T) {
	d, _, first := newSilentH3Dialer(t)

	leaderCtx, cancelLeader := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelLeader()
	leaderErr := make(chan error, 1)
	go func() {
		_, err := d.getH3Conn(leaderCtx)
		leaderErr <- err
	}()

	select {
	case <-first:
	case <-time.After(5 * time.Second):
		t.Fatal("handshake never started")
	}

	// A second caller with a short deadline must give up on its own context.
	waiterCtx, cancelWaiter := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancelWaiter()
	start := time.Now()
	if _, err := d.getH3Conn(waiterCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiter: got %v, want context.DeadlineExceeded", err)
	}
	if el := time.Since(start); el > time.Second {
		t.Fatalf("waiter took %v, want < 1s", el)
	}

	// Close must abort the stalled handshake promptly and release the leader.
	start = time.Now()
	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if el := time.Since(start); el > time.Second {
		t.Fatalf("Close took %v, want < 1s", el)
	}
	select {
	case err := <-leaderErr:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("leader: got %v, want net.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("leader handshake not aborted by Close")
	}
}
