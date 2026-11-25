package ssh

// Two different silences can consume the same liveness budget, and they must not
// be confused:
//
//   - the presence lookup never answered, so nothing was measured and the
//     connection must be left exactly as it is (errLivenessUnknown);
//   - the lookup answered and the keepalive was written, but the peer never
//     replied, so the socket itself is unresponsive and must be replaced
//     (errLivenessUnresponsive).
//
// These cases pin both, with a live control and with the absent-server refusal
// under the same unresponsive conditions.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestPresenceLookupAndHungSocketAreDistinct(t *testing.T) {
	t.Run("pending lookup is unknown and writes nothing", func(t *testing.T) {
		peer := NewMockSSHServer(t, "root", "pass")
		defer peer.Close()
		store := newGatedPresenceStore(996)
		pool := NewSSHClientPool(PoolConfig{KeepAlivePeriod: time.Hour, SweepInterval: time.Hour, ReplyTimeout: testReplyBudget}, store)
		defer pool.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		row := &models.Server{ID: 996, Host: peer.Host(), SSHPort: peer.Port(), SSHUser: "root", SSHPass: "pass"}
		handle, err := pool.Get(ctx, row)
		if err != nil {
			t.Fatal(err)
		}
		client, ok := handle.(*Client)
		if !ok {
			t.Fatalf("checkout returned %T", handle)
		}

		// Validation's own read answers; the read inside the request wrapper is
		// held, so the budget expires before the gate admits.
		store.arm(1, 2, 0)
		pings := peer.keepalives.Load()
		begin := time.Now()
		alive, err := client.alive(ctx)
		elapsed := time.Since(begin)
		t.Logf("budget=%s hold=%s pending lookup returned after %s", testReplyBudget, testGateHold, elapsed)
		if !errors.Is(err, errLivenessUnknown) || alive {
			t.Fatalf("pending lookup = (%t, %v), want (false, %v)", alive, err, errLivenessUnknown)
		}
		if errors.Is(err, errLivenessUnresponsive) {
			t.Error("a pending lookup was classified as an unresponsive socket")
		}
		if elapsed < testReplyBudget || elapsed >= testGateHold {
			t.Errorf("returned after %s, want after the %s budget and before the read was released", elapsed, testReplyBudget)
		}
		if got := peer.keepalives.Load(); got != pings {
			t.Errorf("a pending lookup wrote %d keepalive(s) to the peer", got-pings)
		}
		store.releaseGate()
	})

	t.Run("written keepalive with no reply is unresponsive", func(t *testing.T) {
		peer := NewMockSSHServer(t, "root", "pass")
		defer peer.Close()
		pool := NewSSHClientPool(PoolConfig{KeepAlivePeriod: time.Hour, SweepInterval: time.Hour, ReplyTimeout: testReplyBudget}, newWindowPresenceStore(997))
		defer pool.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		row := &models.Server{ID: 997, Host: peer.Host(), SSHPort: peer.Port(), SSHUser: "root", SSHPass: "pass"}
		handle, err := pool.Get(ctx, row)
		if err != nil {
			t.Fatal(err)
		}
		client, ok := handle.(*Client)
		if !ok {
			t.Fatalf("checkout returned %T", handle)
		}

		peer.SetIgnoreKeepalives(true)
		pings := peer.keepalives.Load()
		begin := time.Now()
		alive, err := client.alive(ctx)
		elapsed := time.Since(begin)
		t.Logf("budget=%s hung socket returned after %s", testReplyBudget, elapsed)
		if !errors.Is(err, errLivenessUnresponsive) || alive {
			t.Fatalf("hung socket = (%t, %v), want (false, %v)", alive, err, errLivenessUnresponsive)
		}
		if errors.Is(err, errLivenessUnknown) {
			t.Error("an unresponsive socket was classified as an unmeasured lookup")
		}
		if elapsed < testReplyBudget || elapsed > 4*testReplyBudget {
			t.Errorf("returned after %s, want just past the %s budget", elapsed, testReplyBudget)
		}
		if got := peer.keepalives.Load(); got != pings+1 {
			t.Errorf("the hung socket received %d keepalive(s), want exactly 1: the request was not written", got-pings)
		}

		// Live control in the same run: the host is healthy, so a fresh connection
		// to it answers immediately. The stale socket is dropped by the checkout
		// rather than reused; a request left unanswered on a live connection also
		// desynchronises the multiplexer, which is why the socket is replaced
		// instead of re-validated.
		peer.SetIgnoreKeepalives(false)
		connects := peer.connects.Load()
		replacement, err := pool.Get(ctx, row)
		if err != nil {
			t.Fatalf("checkout after the hung socket: %v", err)
		}
		if fresh, ok := replacement.(*Client); !ok || fresh == client {
			t.Fatal("checkout reused the hung socket")
		}
		if got := peer.connects.Load(); got != connects+1 {
			t.Errorf("replacement opened %d connection(s), want 1", got-connects)
		}
		out, _, code, err := replacement.RunCommand(ctx, "echo answered-control")
		if err != nil || code != 0 || out != "answered-control" {
			t.Fatalf("replacement command = (%q, %d, %v)", out, code, err)
		}
	})
}

func TestPoolReplacesUnresponsiveSocket(t *testing.T) {
	peer := NewMockSSHServer(t, "root", "pass")
	defer peer.Close()
	controlPeer := NewMockSSHServer(t, "root", "pass")
	defer controlPeer.Close()
	pool := NewSSHClientPool(PoolConfig{KeepAlivePeriod: time.Hour, SweepInterval: time.Hour, ReplyTimeout: testReplyBudget}, newWindowPresenceStore(998))
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	row := &models.Server{ID: 998, Host: peer.Host(), SSHPort: peer.Port(), SSHUser: "root", SSHPass: "pass"}
	handle, err := pool.Get(ctx, row)
	if err != nil {
		t.Fatal(err)
	}
	stale, ok := handle.(*Client)
	if !ok {
		t.Fatalf("checkout returned %T", handle)
	}
	runParkingCommand(t, ctx, stale)
	controlRow := &models.Server{ID: 999, Host: controlPeer.Host(), SSHPort: controlPeer.Port(), SSHUser: "root", SSHPass: "pass"}
	control, err := pool.Get(ctx, controlRow)
	if err != nil {
		t.Fatal(err)
	}

	peer.SetIgnoreKeepalives(true)
	connects := peer.connects.Load()
	begin := time.Now()
	pool.pingAll()
	elapsed := time.Since(begin)
	t.Logf("budget=%s maintenance returned after %s", testReplyBudget, elapsed)

	if elapsed < testReplyBudget || elapsed > 4*testReplyBudget {
		t.Errorf("maintenance returned after %s, want just past the %s budget", elapsed, testReplyBudget)
	}
	if pool.Len() != 1 {
		t.Errorf("pool length %d after maintenance, want 1: the unresponsive entry was kept", pool.Len())
	}
	if !stale.closed {
		t.Error("the unresponsive connection was not closed")
	}

	// The same host accepts a fresh connection: the replacement is validated
	// through the normal checkout path and serves work.
	peer.SetIgnoreKeepalives(false)
	fresh, err := pool.Get(ctx, row)
	if err != nil {
		t.Fatalf("checkout after replacement: %v", err)
	}
	if got := peer.connects.Load(); got != connects+1 {
		t.Errorf("replacement opened %d connection(s), want 1", got-connects)
	}
	runParkingCommand(t, ctx, fresh)

	// Live control: the listed control row kept its connection and answered.
	if pool.Len() != 2 {
		t.Errorf("pool length %d after replacement, want 2", pool.Len())
	}
	runParkingCommand(t, ctx, control)
}

func TestPoolCheckoutReplacesUnresponsiveSocketInsteadOfRefusing(t *testing.T) {
	peer := NewMockSSHServer(t, "root", "pass")
	defer peer.Close()
	pool := NewSSHClientPool(PoolConfig{KeepAlivePeriod: time.Hour, SweepInterval: time.Hour, ReplyTimeout: testReplyBudget}, newWindowPresenceStore(1001))
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	row := &models.Server{ID: 1001, Host: peer.Host(), SSHPort: peer.Port(), SSHUser: "root", SSHPass: "pass"}
	handle, err := pool.Get(ctx, row)
	if err != nil {
		t.Fatal(err)
	}
	stale, ok := handle.(*Client)
	if !ok {
		t.Fatalf("checkout returned %T", handle)
	}
	runParkingCommand(t, ctx, stale)

	peer.SetIgnoreKeepalives(true)
	connects := peer.connects.Load()
	begin := time.Now()
	replacement, err := pool.Get(ctx, row)
	elapsed := time.Since(begin)
	t.Logf("budget=%s checkout returned after %s", testReplyBudget, elapsed)

	if err != nil || replacement == nil {
		t.Fatalf("checkout of a hung pooled socket = (%v, %v), want a fresh connection", replacement, err)
	}
	if fresh, ok := replacement.(*Client); ok && fresh == stale {
		t.Fatal("checkout returned the hung socket")
	}
	if !stale.closed {
		t.Error("the hung socket was not closed after its replacement")
	}
	if got := peer.connects.Load(); got != connects+1 {
		t.Errorf("checkout opened %d replacement connection(s), want 1", got-connects)
	}
	if elapsed < testReplyBudget || elapsed > 4*testReplyBudget {
		t.Errorf("checkout returned after %s, want just past the %s budget", elapsed, testReplyBudget)
	}
	if pool.Len() != 1 {
		t.Errorf("pool length %d after replacement, want 1", pool.Len())
	}
	peer.SetIgnoreKeepalives(false)
	out, _, code, err := replacement.RunCommand(ctx, "echo replacement-control")
	if err != nil || code != 0 || out != "replacement-control" {
		t.Fatalf("replacement command = (%q, %d, %v)", out, code, err)
	}
}

func TestPoolUnresponsiveSocketStillRefusesAbsentServer(t *testing.T) {
	peer := NewMockSSHServer(t, "root", "pass")
	defer peer.Close()
	store := newWindowPresenceStore(1002)
	pool := NewSSHClientPool(PoolConfig{KeepAlivePeriod: time.Hour, SweepInterval: time.Hour, ReplyTimeout: testReplyBudget}, store)
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	row := &models.Server{ID: 1002, Host: peer.Host(), SSHPort: peer.Port(), SSHUser: "root", SSHPass: "pass"}
	handle, err := pool.Get(ctx, row)
	if err != nil {
		t.Fatal(err)
	}
	stale, ok := handle.(*Client)
	if !ok {
		t.Fatalf("checkout returned %T", handle)
	}

	// The socket is silent and the row is absent at the same time: absence keeps
	// priority, so the gate refuses before anything is written and no fresh
	// attempt is made.
	peer.SetIgnoreKeepalives(true)
	store.arm(0, 0) // every read answers absent
	pings, connects := peer.keepalives.Load(), peer.connects.Load()
	pool.pingAll()
	if pool.Len() != 1 {
		t.Errorf("pool length %d after an absent verdict, want 1: the parked entry was dropped", pool.Len())
	}
	if stale.closed {
		t.Error("the absent server's parked connection was closed")
	}
	if got := peer.keepalives.Load(); got != pings {
		t.Errorf("the absent server received %d keepalive(s)", got-pings)
	}
	if got, err := pool.Get(ctx, row); !errors.Is(err, ErrProviderAbsent) || got != nil {
		t.Fatalf("absent checkout = (%v, %v), want the refusal", got, err)
	}
	if got := peer.connects.Load(); got != connects {
		t.Errorf("the absent server got %d fresh attempt(s)", got-connects)
	}
}
