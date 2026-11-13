package naive

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// loopbackEndpointPair is one loopback port held by the fixture for both TCP and
// UDP at the same time. The dual-stack proxy fixture needs both protocols
// reachable on one address, so the port has to be reserved for both before
// either protocol serves traffic.
type loopbackEndpointPair struct {
	tcp net.Listener
	udp *net.UDPConn
}

// port returns the single port number shared by the TCP and UDP halves.
func (p *loopbackEndpointPair) port() (int, error) {
	if p == nil || p.tcp == nil || p.udp == nil {
		return 0, errors.New("endpoint pair is incomplete")
	}
	_, tcpPort, err := net.SplitHostPort(p.tcp.Addr().String())
	if err != nil {
		return 0, fmt.Errorf("split tcp address: %w", err)
	}
	_, udpPort, err := net.SplitHostPort(p.udp.LocalAddr().String())
	if err != nil {
		return 0, fmt.Errorf("split udp address: %w", err)
	}
	if tcpPort != udpPort {
		return 0, fmt.Errorf("tcp port %s and udp port %s differ", tcpPort, udpPort)
	}
	port, err := strconv.Atoi(tcpPort)
	if err != nil {
		return 0, fmt.Errorf("parse port %q: %w", tcpPort, err)
	}
	return port, nil
}

// close releases both halves. It is deliberately tolerant of a half-built pair
// and of repeated calls, because it is also the failure path of the fixture.
func (p *loopbackEndpointPair) close() {
	if p == nil {
		return
	}
	if p.udp != nil {
		_ = p.udp.Close()
		p.udp = nil
	}
	if p.tcp != nil {
		_ = p.tcp.Close()
		p.tcp = nil
	}
}

// listenLoopbackTCP is the TCP half of port-pair allocation. It is a parameter of
// acquireLoopbackPortPair so the failed-setup path can be driven with real
// sockets instead of waiting for a probabilistic port collision.
func listenLoopbackTCP(address string) (net.Listener, error) {
	return net.Listen("tcp", address)
}

// acquireLoopbackPortPair returns a TCP listener and a UDP socket already bound
// and held on the same loopback port.
//
// A TCP-selected ephemeral port is not a reservation for UDP: the two protocol
// port spaces are independent, so a port that is momentarily free for TCP can
// already belong to an unrelated UDP socket. Binding UDP first and then taking
// the same number for TCP, while the UDP socket stays held, makes the pair true
// by construction instead of by luck.
//
// Selection is bounded to attempts. Every rejected candidate is released before
// the next attempt, and when all attempts fail the returned error names the host,
// the attempt budget and the last underlying cause.
func acquireLoopbackPortPair(
	host string,
	attempts int,
	newTCP func(address string) (net.Listener, error),
) (*loopbackEndpointPair, error) {
	if attempts <= 0 {
		return nil, fmt.Errorf("fixture port pair: attempts must be positive, got %d", attempts)
	}
	if newTCP == nil {
		return nil, errors.New("fixture port pair: tcp listener constructor is nil")
	}
	ip, err := loopbackOnly(host)
	if err != nil {
		return nil, err
	}

	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip})
		if err != nil {
			lastErr = fmt.Errorf("attempt %d: reserve udp on %s: %w", attempt, host, err)
			continue
		}

		address := net.JoinHostPort(host, strconv.Itoa(udpConn.LocalAddr().(*net.UDPAddr).Port))
		ln, err := newTCP(address)
		if err != nil {
			// The UDP socket is already owned by this attempt; release it before
			// retrying so a failed attempt cannot leave a port held.
			_ = udpConn.Close()
			lastErr = fmt.Errorf("attempt %d: reserve tcp on %s: %w", attempt, address, err)
			continue
		}

		return &loopbackEndpointPair{tcp: ln, udp: udpConn}, nil
	}

	return nil, fmt.Errorf(
		"fixture port pair: no usable loopback TCP/UDP port on %s after %d attempts: %w",
		host, attempts, lastErr,
	)
}

// loopbackOnly rejects anything that is not a literal loopback IP, so a fixture
// misconfiguration cannot bind a routable address.
func loopbackOnly(host string) (net.IP, error) {
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("fixture port pair: host %q is not an IP address", host)
	}
	if !ip.IsLoopback() {
		return nil, fmt.Errorf("fixture port pair: host %q is not a loopback address", host)
	}
	return ip, nil
}

// fixtureResources releases fixture-owned endpoints in reverse acquisition order.
// Setup registers each owned resource as soon as it is acquired, so a fatal part
// way through setup still tears down everything already held instead of leaving a
// bound socket behind for the rest of the package run.
type fixtureResources struct {
	cleanups []func()
}

func (r *fixtureResources) add(cleanup func()) {
	r.cleanups = append(r.cleanups, cleanup)
}

func (r *fixtureResources) release() {
	cleanups := r.cleanups
	r.cleanups = nil
	for i := len(cleanups) - 1; i >= 0; i-- {
		cleanups[i]()
	}
}

// TestLoopbackEndpointPair_HoldsTCPAndUDPOnSamePort proves the allocation
// contract the dual-stack fixture depends on: both protocols are bound on one
// port and both are actually usable at the same time.
func TestLoopbackEndpointPair_HoldsTCPAndUDPOnSamePort(t *testing.T) {
	pair, err := acquireLoopbackPortPair("127.0.0.1", 4, listenLoopbackTCP)
	if err != nil {
		t.Fatalf("acquire loopback endpoint pair: %v", err)
	}
	defer pair.close()

	port, err := pair.port()
	if err != nil {
		t.Fatalf("shared port: %v", err)
	}
	if port <= 0 {
		t.Fatalf("shared port = %d, want a real ephemeral port", port)
	}

	// A TCP connect only completes when the listener really owns the port.
	conn, err := net.DialTimeout("tcp", pair.tcp.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("tcp connect to %s: %v", pair.tcp.Addr(), err)
	}
	_ = conn.Close()

	// A UDP datagram only arrives when the socket really owns the port.
	client, err := net.DialUDP("udp", nil, pair.udp.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial udp to %s: %v", pair.udp.LocalAddr(), err)
	}
	defer func() { _ = client.Close() }()

	payload := []byte("pair")
	if _, err := client.Write(payload); err != nil {
		t.Fatalf("udp write: %v", err)
	}
	if err := pair.udp.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set udp read deadline: %v", err)
	}
	buf := make([]byte, 16)
	n, _, err := pair.udp.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("udp read: %v", err)
	}
	if got := string(buf[:n]); got != string(payload) {
		t.Fatalf("udp payload = %q, want %q", got, payload)
	}
}

// TestLoopbackEndpointPair_ReleasesUDPWhenTCPAllocationFails is the negative
// control for the failed-setup path: with a real TCP-step failure and a bounded
// budget, every reserved UDP socket is released and the error is terminal and
// specific instead of being swallowed or retried forever.
func TestLoopbackEndpointPair_ReleasesUDPWhenTCPAllocationFails(t *testing.T) {
	const attempts = 3

	var asked []string
	forcedFailure := func(address string) (net.Listener, error) {
		asked = append(asked, address)
		return nil, errors.New("forced fixture tcp allocation failure")
	}

	pair, err := acquireLoopbackPortPair("127.0.0.1", attempts, forcedFailure)
	if err == nil {
		pair.close()
		t.Fatal("expected terminal failure when no TCP half can be reserved")
	}
	if pair != nil {
		t.Fatalf("pair = %+v, want nil on failure", pair)
	}
	if len(asked) != attempts {
		t.Fatalf("tcp allocation attempts = %d, want the bounded budget %d", len(asked), attempts)
	}
	if !strings.Contains(err.Error(), "after 3 attempts") {
		t.Fatalf("error %q does not state the attempt budget", err)
	}

	for _, address := range asked {
		_, portStr, splitErr := net.SplitHostPort(address)
		if splitErr != nil {
			t.Fatalf("split attempted address %q: %v", address, splitErr)
		}
		port, convErr := strconv.Atoi(portStr)
		if convErr != nil {
			t.Fatalf("parse attempted port %q: %v", portStr, convErr)
		}
		probe, listenErr := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		if listenErr != nil {
			t.Fatalf("attempt on udp port %d left the socket held: %v", port, listenErr)
		}
		_ = probe.Close()
	}
}

// TestLoopbackEndpointPair_RejectsUnusableRequests pins the bounded, meaningful
// failure behavior for inputs that must not touch a socket at all.
func TestLoopbackEndpointPair_RejectsUnusableRequests(t *testing.T) {
	calls := 0
	counting := func(string) (net.Listener, error) {
		calls++
		return nil, errors.New("must not be called")
	}

	cases := []struct {
		name     string
		host     string
		attempts int
		want     string
	}{
		{name: "zero attempts", host: "127.0.0.1", attempts: 0, want: "attempts must be positive"},
		{name: "negative attempts", host: "127.0.0.1", attempts: -1, want: "attempts must be positive"},
		{name: "non-ip host", host: "localhost", attempts: 2, want: "not an IP address"},
		{name: "routable host", host: "192.0.2.10", attempts: 2, want: "not a loopback address"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pair, err := acquireLoopbackPortPair(tc.host, tc.attempts, counting)
			if err == nil {
				pair.close()
				t.Fatalf("expected rejection for host %q attempts %d", tc.host, tc.attempts)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want it to mention %q", err, tc.want)
			}
			if calls != 0 {
				t.Fatalf("tcp constructor called %d times, want no socket work for a rejected request", calls)
			}
		})
	}
}

// TestDualStackFixture_TCPSelectedPortIsNotFreeForUDP is the original-assumption
// negative control. It reproduces the v1 helper's reasoning with real sockets: a
// port taken for TCP is not reserved for UDP, so binding UDP on it fails with
// EADDRINUSE while an unrelated UDP socket owns the number. This is the mechanism
// behind the reported fixture setup failure, and it must stay demonstrable.
func TestDualStackFixture_TCPSelectedPortIsNotFreeForUDP(t *testing.T) {
	const maxCandidates = 8

	var (
		occupant *net.UDPConn
		tcpLn    net.Listener
		port     int
	)
	// A UDP-occupied port is normally free in the TCP space, but a single
	// candidate could coincidentally be taken for TCP too. Bounded candidate
	// selection keeps the control deterministic without weakening it: every
	// candidate is a real held socket, and the assertion is on a real socket.
	for candidate := 1; candidate <= maxCandidates; candidate++ {
		u, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		if err != nil {
			t.Fatalf("occupy udp: %v", err)
		}
		candidatePort := u.LocalAddr().(*net.UDPAddr).Port
		ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(candidatePort)))
		if err != nil {
			_ = u.Close()
			continue
		}
		occupant, tcpLn, port = u, ln, candidatePort
		break
	}
	if occupant == nil || tcpLn == nil {
		t.Fatalf("no udp occupant with a free matching tcp port after %d candidates", maxCandidates)
	}
	defer func() { _ = occupant.Close() }()
	defer func() { _ = tcpLn.Close() }()

	// The v1 assumption: a TCP-selected port is free for the H3 UDP relay.
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err == nil {
		_ = relay.Close()
		t.Fatalf("udp port %d was bindable although %s already owned it", port, occupant.LocalAddr())
	}
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("udp bind on occupied port %d: error = %v, want EADDRINUSE", port, err)
	}
}

// TestDualStackH2H3Fixture_TeardownReleasesBothProtocols proves the returned
// cleanup returns the reserved port to the kernel for TCP and UDP alike, so a
// test that finishes cannot block the next fixture that needs the same port.
func TestDualStackH2H3Fixture_TeardownReleasesBothProtocols(t *testing.T) {
	h2Addr, _, cleanup := setupDualStackH2H3Server(t, "testuser", "testpass")

	_, portStr, err := net.SplitHostPort(h2Addr)
	if err != nil {
		t.Fatalf("split h2 address %q: %v", h2Addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse h2 port %q: %v", portStr, err)
	}

	cleanup()

	tcpLn, err := net.Listen("tcp", h2Addr)
	if err != nil {
		t.Fatalf("tcp port %d still held after teardown: %v", port, err)
	}
	defer func() { _ = tcpLn.Close() }()

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatalf("udp port %d still held after teardown: %v", port, err)
	}
	_ = udpConn.Close()
}
