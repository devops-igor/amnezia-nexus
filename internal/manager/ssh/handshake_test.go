package ssh

// Lifetime tests for the transport handshake.
//
// The subject is the real Connect against a controlled loopback peer, so the
// pinned x/crypto exchange runs for real. Three peer behaviours are covered:
// a peer that accepts and says nothing, a peer that sends its identification
// string and then stalls key exchange, and a real SSH server for the positive
// control.
//
// The positive control asserts the opposite property from the negative ones:
// after a successful handshake the connection must remain usable well past the
// handshake budget, which is what proves the deadline was cleared rather than
// left armed on a long-lived session.

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

// fixturePeer is a loopback TCP peer under test control.
type fixturePeer struct {
	listener *net.TCPListener
	accepted chan net.Conn
}

// newFixturePeer starts a peer that accepts connections and applies onAccept to
// each one. onAccept runs on its own goroutine per connection.
func newFixturePeer(t *testing.T, onAccept func(net.Conn)) *fixturePeer {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	peer := &fixturePeer{listener: listener, accepted: make(chan net.Conn, 4)}
	done := make(chan struct{})
	t.Cleanup(func() {
		_ = listener.Close()
		<-done
	})
	go func() {
		defer close(done)
		for {
			conn, err := listener.AcceptTCP()
			if err != nil {
				return
			}
			peer.accepted <- conn
			if onAccept != nil {
				go onAccept(conn)
			}
		}
	}()
	return peer
}

func (p *fixturePeer) port() int {
	return p.listener.Addr().(*net.TCPAddr).Port
}

// waitConn returns the connection the peer accepted, failing if the client never
// arrived.
func (p *fixturePeer) waitConn(t *testing.T) net.Conn {
	t.Helper()
	select {
	case conn := <-p.accepted:
		return conn
	case <-time.After(2 * time.Second):
		t.Fatal("the client never connected to the fixture peer")
		return nil
	}
}

// connectResult carries one Connect outcome.
type connectResult struct {
	err     error
	elapsed time.Duration
	client  *Client
}

// connectAsync runs Connect and reports its outcome with the elapsed time.
func connectAsync(ctx context.Context, cfg Config) <-chan connectResult {
	ch := make(chan connectResult, 1)
	go func() {
		start := time.Now()
		client, err := Dial(ctx, cfg)
		ch <- connectResult{err: err, elapsed: time.Since(start), client: client}
	}()
	return ch
}

// awaitConnect waits for the outcome, failing the test if Connect never returns.
func awaitConnect(t *testing.T, ch <-chan connectResult, bound time.Duration) connectResult {
	t.Helper()
	select {
	case res := <-ch:
		return res
	case <-time.After(bound):
		t.Fatalf("Connect did not return within %s", bound)
		return connectResult{}
	}
}

// TestConnectBoundsSilentSSHPeer proves a peer that accepts TCP and never sends
// an identification string cannot hold Connect past the configured budget.
func TestConnectBoundsSilentSSHPeer(t *testing.T) {
	peer := newFixturePeer(t, nil)
	var silent net.Conn
	t.Cleanup(func() {
		if silent != nil {
			_ = silent.Close()
		}
	})
	peerDone := make(chan net.Conn, 1)
	go func() { peerDone <- peer.waitConn(t) }()

	cfg := Config{
		Host: "127.0.0.1", Port: peer.port(), User: "fixture", Password: "fixture-only",
		Timeout: 150 * time.Millisecond, HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	}
	res := awaitConnect(t, connectAsync(context.Background(), cfg), 5*time.Second)
	select {
	case silent = <-peerDone:
	default:
	}

	if res.err == nil {
		t.Fatal("a silent peer must not authenticate")
	}
	if res.client != nil {
		t.Fatal("a failed handshake must not return a client")
	}
	if res.elapsed > 2*time.Second {
		t.Fatalf("Connect waited %s for a silent peer, want it bounded near %s",
			res.elapsed, cfg.Timeout)
	}
}

// TestConnectCancellationClosesInFlightSocket proves cancellation interrupts the
// transport exchange AND closes the socket it was reading, rather than leaving
// the peer with a half-open connection.
func TestConnectCancellationClosesInFlightSocket(t *testing.T) {
	peer := newFixturePeer(t, nil)
	defer func() {
		select {
		case conn := <-peer.accepted:
			_ = conn.Close()
		default:
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// No configured timeout: only the caller's cancellation can end this.
	cfg := Config{
		Host: "127.0.0.1", Port: peer.port(), User: "fixture", Password: "fixture-only",
		Timeout: time.Hour, HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	}
	ch := connectAsync(ctx, cfg)

	conn := peer.waitConn(t)
	defer conn.Close()

	// The peer stays silent, so the exchange is blocked when cancellation lands.
	time.Sleep(100 * time.Millisecond)
	canceledAt := time.Now()
	cancel()

	res := awaitConnect(t, ch, 5*time.Second)
	if res.err == nil {
		t.Fatal("a canceled handshake must fail")
	}
	if !errors.Is(res.err, context.Canceled) {
		t.Fatalf("Connect error = %v, want the caller's cancellation", res.err)
	}
	if res.elapsed > 2*time.Second {
		t.Fatalf("Connect returned %s after cancellation, want it prompt", res.elapsed)
	}

	// The raw socket must have been closed on our side: the peer's read reaches
	// end-of-stream instead of hanging on a connection nobody will finish using.
	// The client's own identification string is already buffered, so the read
	// loop drains that before it can observe the close.
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set peer read deadline: %v", err)
	}
	buf := make([]byte, 512)
	for {
		_, readErr := conn.Read(buf)
		if readErr == nil {
			continue
		}
		if netErr, ok := readErr.(net.Error); ok && netErr.Timeout() {
			t.Fatal("the canceled handshake left the socket open: the peer read timed out")
		}
		break
	}
	if time.Since(canceledAt) > 2*time.Second {
		t.Fatal("the socket close was not observed near the cancellation")
	}
}

// TestConnectBoundsStalledKeyExchange proves the bound covers the exchange after
// the peer has identified itself, which is the stall a provisioning host
// typically shows: the banner arrives and key exchange never does.
func TestConnectBoundsStalledKeyExchange(t *testing.T) {
	peer := newFixturePeer(t, func(conn net.Conn) {
		// A valid identification string, then nothing at all.
		_, _ = conn.Write([]byte("SSH-2.0-fixture_1.0\r\n"))
	})

	cfg := Config{
		Host: "127.0.0.1", Port: peer.port(), User: "fixture", Password: "fixture-only",
		Timeout: 150 * time.Millisecond, HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	}
	res := awaitConnect(t, connectAsync(context.Background(), cfg), 5*time.Second)
	if res.err == nil {
		t.Fatal("a peer that stalls key exchange must not authenticate")
	}
	if res.elapsed > 2*time.Second {
		t.Fatalf("Connect waited %s on a stalled key exchange, want it bounded near %s",
			res.elapsed, cfg.Timeout)
	}
}

// TestConnectHonoursCallerDeadline proves the bound also follows the caller's
// context: a worker whose attempt deadline is shorter than the configured
// connection budget must not wait out the longer one.
func TestConnectHonoursCallerDeadline(t *testing.T) {
	peer := newFixturePeer(t, nil)
	defer func() {
		select {
		case conn := <-peer.accepted:
			_ = conn.Close()
		default:
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	cfg := Config{
		Host: "127.0.0.1", Port: peer.port(), User: "fixture", Password: "fixture-only",
		Timeout: time.Hour, HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	}
	res := awaitConnect(t, connectAsync(ctx, cfg), 5*time.Second)
	if res.err == nil {
		t.Fatal("a handshake that hit its deadline must fail")
	}
	if !errors.Is(res.err, context.DeadlineExceeded) {
		t.Fatalf("Connect error = %v, want the caller's deadline", res.err)
	}
	if res.elapsed > 2*time.Second {
		t.Fatalf("Connect waited %s on a %s caller deadline, want it bounded by the caller",
			res.elapsed, 150*time.Millisecond)
	}
}

// TestConnectCancelledDuringHandshakeReturnsNoSession proves the last window:
// a caller that gives up while the handshake is finishing must not be handed a
// live session. The host-key callback runs inside the exchange, so cancelling
// there makes the race deterministic.
func TestConnectCancelledDuringHandshakeReturnsNoSession(t *testing.T) {
	server := NewMockSSHServer(t, "root", "pass")
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := Config{
		Host: server.Host(), Port: server.Port(), User: "root", Password: "pass",
		Timeout: 5 * time.Second,
		HostKeyCallback: func(string, net.Addr, gossh.PublicKey) error {
			cancel()
			return nil
		},
	}
	res := awaitConnect(t, connectAsync(ctx, cfg), 5*time.Second)
	if res.err == nil {
		if res.client != nil {
			_ = res.client.Close()
		}
		t.Fatal("a handshake finished after cancellation must not be handed back")
	}
	if !errors.Is(res.err, context.Canceled) {
		t.Fatalf("Connect error = %v, want the caller's cancellation", res.err)
	}
	if res.client != nil {
		t.Fatal("a canceled handshake returned a client")
	}
}

// closerSpy records whether it was closed.
type closerSpy struct{ closed bool }

func (c *closerSpy) Close() error {
	c.closed = true
	return nil
}

// deadConn is a net.Conn whose deadline operations fail, which is the only way an
// established socket can refuse to be bounded or cleared.
type deadConn struct {
	net.Conn
	refuseSet bool
	closed    bool
}

func (c *deadConn) SetDeadline(time.Time) error {
	if c.closed {
		return net.ErrClosed
	}
	if c.refuseSet {
		return errors.New("fixture: deadline refused")
	}
	return nil
}

func (c *deadConn) Close() error {
	c.closed = true
	return nil
}

// TestHandshakeBoundOperationsReportSocketRefusal covers the two deadline
// operations' answers, including the one exception the clear tolerates: a peer
// that closed the socket as the handshake completed must not fail a handshake
// that actually succeeded.
func TestHandshakeBoundOperationsReportSocketRefusal(t *testing.T) {
	if err := boundHandshake(&deadConn{refuseSet: true}, time.Second); err == nil {
		t.Fatal("a refused handshake bound must be reported, not ignored")
	}
	conn := &deadConn{}
	if err := boundHandshake(conn, 150*time.Millisecond); err != nil {
		t.Fatalf("boundHandshake: %v", err)
	}
	if err := clearHandshakeBound(&deadConn{refuseSet: true}); err == nil {
		t.Fatal("a refused deadline clear on a live socket must be reported, not ignored")
	}
	if err := clearHandshakeBound(&deadConn{refuseSet: true, closed: true}); err != nil {
		t.Fatalf("an already-closed socket must not fail a successful handshake: %v", err)
	}
	if err := clearHandshakeBound(conn); err != nil {
		t.Fatalf("clearHandshakeBound: %v", err)
	}
}

// TestConnectTimeoutFallsBackToTheDefault proves an omitted budget is still
// bounded rather than becoming an infinite one.
func TestConnectTimeoutFallsBackToTheDefault(t *testing.T) {
	for _, given := range []time.Duration{0, -time.Second} {
		if got := connectTimeout(given); got != defaultConnectTimeout {
			t.Fatalf("connectTimeout(%s) = %s, want the %s default", given, got, defaultConnectTimeout)
		}
	}
	if got := connectTimeout(2 * time.Second); got != 2*time.Second {
		t.Fatalf("connectTimeout(2s) = %s, want the configured value preserved", got)
	}
}

// TestAbandonIfCancelledClosesOnlyCancelledSessions covers the guard's two
// answers directly, because the window it protects (cancellation landing while
// the handshake completes) is not reliably reachable from outside.
func TestAbandonIfCancelledClosesOnlyCancelledSessions(t *testing.T) {
	live := &closerSpy{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := abandonIfCancelled(ctx, live); err != nil {
		t.Fatalf("an active caller must not abandon its session: %v", err)
	}
	if live.closed {
		t.Fatal("an active caller's session was closed")
	}

	stopped := &closerSpy{}
	canceled, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	err := abandonIfCancelled(canceled, stopped)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("abandonIfCancelled error = %v, want the cancellation", err)
	}
	if !stopped.closed {
		t.Fatal("a canceled caller's session was left open")
	}
}

// TestConnectSuccessfulHandshakeOutlivesItsBudget is the positive control: a real
// SSH server completes the handshake under a short connection budget, and the
// resulting session still works after that budget has elapsed. A handshake-only
// deadline left armed on the socket would fail the command below.
func TestConnectSuccessfulHandshakeOutlivesItsBudget(t *testing.T) {
	server := NewMockSSHServer(t, "root", "pass")
	defer server.Close()

	cfg := Config{
		Host: server.Host(), Port: server.Port(), User: "root", Password: "pass",
		Timeout: 250 * time.Millisecond, HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	}
	res := awaitConnect(t, connectAsync(context.Background(), cfg), 5*time.Second)
	if res.err != nil {
		t.Fatalf("a valid handshake must succeed: %v", res.err)
	}
	client := res.client
	defer func() { _ = client.Close() }()

	// Well past the configured handshake budget.
	time.Sleep(600 * time.Millisecond)

	stdout, _, code, err := client.RunCommand(context.Background(), "uname -sr && cat /etc/os-release 2>/dev/null | head -2")
	if err != nil || code != 0 {
		t.Fatalf("the session must outlive the handshake budget: code=%d err=%v", code, err)
	}
	if strings.TrimSpace(stdout) == "" {
		t.Fatal("the session returned no output after the handshake budget")
	}
	if !client.IsAlive() {
		t.Fatal("the connection is not usable after the handshake budget")
	}
}
