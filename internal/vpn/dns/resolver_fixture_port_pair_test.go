package gatewaydns

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
)

// This file owns the one helper the resolver fixtures use to obtain a port that
// is reachable on TCP and UDP at the same time. The no-plaintext-downgrade
// oracles need exactly that: the encrypted entry and the plaintext responder must
// share one port number, because a downgrade would reuse the entry's own port.

// loopbackPortPair is one loopback address held by TCP and UDP together.
type loopbackPortPair struct {
	tcp net.Listener
	udp net.PacketConn
}

// addr is the loopback address both halves are bound to.
func (p *loopbackPortPair) addr() netip.AddrPort {
	if p == nil || p.tcp == nil {
		return netip.AddrPort{}
	}
	addr, err := netip.ParseAddrPort(p.tcp.Addr().String())
	if err != nil {
		return netip.AddrPort{}
	}
	return addr
}

// close releases both halves. It tolerates a half-built pair and repeated calls,
// because it is also the failure path of the fixture.
func (p *loopbackPortPair) close() {
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

// loopbackPortPairAttempts bounds how many candidates acquisition may reject
// before it reports that no pair is available.
const loopbackPortPairAttempts = 16

// listenLoopbackTCP4 is the TCP half of acquisition. It is a parameter of
// acquireLoopbackPortPair so the collision and exhaustion paths can be driven with
// real sockets instead of waiting for a probabilistic collision.
func listenLoopbackTCP4(address string) (net.Listener, error) {
	return net.Listen("tcp4", address)
}

// acquireLoopbackPortPair returns a TCP listener and a UDP socket already bound
// and held on the same loopback port.
//
// A TCP-selected ephemeral port is not a reservation for UDP: the two protocol
// port spaces are independent, so a number that is momentarily free for TCP can
// already belong to an unrelated UDP socket. Binding UDP first and then taking the
// same number for TCP, while the UDP socket stays held, makes the pair true by
// construction instead of by luck, and it is the order that fails safely: if the
// TCP number is taken the candidate is dropped and another one is tried.
//
// Selection is bounded. Every rejected candidate is released before the next
// attempt, and when all attempts fail the returned error names the attempt budget
// and the last underlying cause.
func acquireLoopbackPortPair(attempts int, newTCP func(address string) (net.Listener, error)) (*loopbackPortPair, error) {
	if attempts <= 0 {
		return nil, fmt.Errorf("fixture port pair: attempts must be positive, got %d", attempts)
	}
	if newTCP == nil {
		return nil, errors.New("fixture port pair: tcp listener constructor is nil")
	}

	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		udpConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			lastErr = fmt.Errorf("attempt %d: reserve udp on 127.0.0.1: %w", attempt, err)
			continue
		}

		address := udpConn.LocalAddr().String()
		tcpListener, err := newTCP(address)
		if err != nil {
			// The UDP socket belongs to this attempt alone; release it before the
			// next one so a rejected candidate cannot leave a port held.
			_ = udpConn.Close()
			lastErr = fmt.Errorf("attempt %d: reserve tcp on %s: %w", attempt, address, err)
			continue
		}

		return &loopbackPortPair{tcp: tcpListener, udp: udpConn}, nil
	}

	return nil, fmt.Errorf("fixture port pair: no usable loopback TCP/UDP port after %d attempts: %w", attempts, lastErr)
}

// newLoopbackPortPair is the fixture entry point: it acquires a pair or fails the
// test, and registers the release so a fatal part way through setup cannot leave a
// bound socket behind for the rest of the package run.
func newLoopbackPortPair(t *testing.T) *loopbackPortPair {
	t.Helper()
	pair, err := acquireLoopbackPortPair(loopbackPortPairAttempts, listenLoopbackTCP4)
	if err != nil {
		t.Fatalf("%v", err)
	}
	t.Cleanup(pair.close)
	return pair
}

// TestLoopbackPortPair_ReservesBothTransportsOnOneNumber is the success oracle:
// both halves exist, share one non-zero loopback port, and the port really is
// reachable on both protocols at the same time.
func TestLoopbackPortPair_ReservesBothTransportsOnOneNumber(t *testing.T) {
	pair := newLoopbackPortPair(t)
	addr := pair.addr()
	if !addr.IsValid() || addr.Port() == 0 {
		t.Fatalf("pair address = %v, want a bound loopback port", addr)
	}
	if !addr.Addr().IsLoopback() {
		t.Fatalf("pair address = %v, want loopback only", addr)
	}
	if got := pair.udp.LocalAddr().String(); got != addr.String() {
		t.Fatalf("udp half = %s, tcp half = %s, want the same number", got, addr)
	}

	// A dial to the TCP half must be accepted, which proves the listener is live
	// on the pair's number rather than a placeholder.
	accepted := make(chan struct{})
	go func() {
		conn, err := pair.tcp.Accept()
		if err != nil {
			return
		}
		close(accepted)
		_ = conn.Close()
	}()
	conn, err := net.DialTimeout("tcp4", addr.String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial the pair's tcp half: %v", err)
	}
	_ = conn.Close()
	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("the pair's tcp half did not accept a connection")
	}
}

// TestLoopbackPortPair_RetriesPastARealCollision forces a genuine collision on the
// first candidate with a real socket and requires the next candidate to be used.
func TestLoopbackPortPair_RetriesPastARealCollision(t *testing.T) {
	var blocked net.Listener
	candidates := 0
	pair, err := acquireLoopbackPortPair(8, func(address string) (net.Listener, error) {
		candidates++
		if candidates == 1 {
			// Take the first candidate's TCP number for real, then let the real
			// constructor try it so the kernel reports the conflict.
			holder, err := net.Listen("tcp4", address)
			if err != nil {
				return nil, err
			}
			blocked = holder
			return listenLoopbackTCP4(address)
		}
		return listenLoopbackTCP4(address)
	})
	if blocked != nil {
		defer func() { _ = blocked.Close() }()
	}
	if err != nil {
		t.Fatalf("acquisition did not recover from a real collision: %v", err)
	}
	defer pair.close()
	if candidates < 2 {
		t.Fatalf("candidates tried = %d, want at least 2 after a collision", candidates)
	}
	if blocked == nil {
		t.Fatal("the collision control never bound its holder")
	}
	blockedAddr, err := netip.ParseAddrPort(blocked.Addr().String())
	if err != nil {
		t.Fatalf("parse blocked address: %v", err)
	}
	if pair.addr().Port() == blockedAddr.Port() {
		t.Fatalf("pair reused the collided port %d", blockedAddr.Port())
	}
}

// TestLoopbackPortPair_ExhaustionReleasesCandidates requires the bounded failure
// path to report its budget and cause and to leave no candidate socket held.
func TestLoopbackPortPair_ExhaustionReleasesCandidates(t *testing.T) {
	const attempts = 3
	var candidates []string
	pair, err := acquireLoopbackPortPair(attempts, func(address string) (net.Listener, error) {
		candidates = append(candidates, address)
		return nil, errors.New("forced tcp reservation failure")
	})
	if pair != nil {
		pair.close()
		t.Fatal("exhaustion returned a pair")
	}
	if err == nil {
		t.Fatal("exhaustion returned no error")
	}
	if len(candidates) != attempts {
		t.Fatalf("candidates tried = %d want %d", len(candidates), attempts)
	}
	wantErr := fmt.Sprintf("after %d attempts", attempts)
	if !strings.Contains(err.Error(), wantErr) || !strings.Contains(err.Error(), "forced tcp reservation failure") {
		t.Fatalf("exhaustion error = %q, want the attempt budget and the last cause", err)
	}
	for _, address := range candidates {
		// A released candidate can be bound again on UDP; a leaked one cannot.
		conn, err := net.ListenPacket("udp4", address)
		if err != nil {
			t.Fatalf("candidate %s was not released: %v", address, err)
		}
		_ = conn.Close()
	}
}

// TestLoopbackPortPair_CleanupReleasesBothHalves requires the fixture cleanup to
// give back both protocols, so one test cannot starve the rest of the package.
func TestLoopbackPortPair_CleanupReleasesBothHalves(t *testing.T) {
	var addr netip.AddrPort
	t.Run("fixture", func(t *testing.T) {
		addr = newLoopbackPortPair(t).addr()
	})
	if !addr.IsValid() {
		t.Fatal("fixture did not record a pair address")
	}
	listener, err := net.Listen("tcp4", addr.String())
	if err != nil {
		t.Fatalf("tcp half was not released: %v", err)
	}
	_ = listener.Close()
	conn, err := net.ListenPacket("udp4", addr.String())
	if err != nil {
		t.Fatalf("udp half was not released: %v", err)
	}
	_ = conn.Close()
}

// TestLoopbackPortPair_TCPFirstDoesNotReserveUDP records the defect the pair
// removes, with real sockets: a number bound for TCP is not thereby reserved for
// UDP, so the old "bind TCP then bind UDP on that number" order can fail in
// fixture setup before any assertion runs.
func TestLoopbackPortPair_TCPFirstDoesNotReserveUDP(t *testing.T) {
	holder, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("hold udp: %v", err)
	}
	defer func() { _ = holder.Close() }()
	taken := holder.LocalAddr().String()

	tcpListener, err := net.Listen("tcp4", taken)
	if err != nil {
		t.Fatalf("the same number is free for tcp while udp holds it: %v", err)
	}
	defer func() { _ = tcpListener.Close() }()

	second, err := net.ListenPacket("udp4", taken)
	if err == nil {
		_ = second.Close()
		t.Fatalf("udp on the tcp number %s succeeded while another socket held it", taken)
	}
}

// TestLoopbackPortPair_PlaintextOracleSeesTheEntryPort requires the oracle's
// sensor to stay attached to the encrypted entry's own number after the pair
// rewrite: a plaintext query sent to the entry port must reach the plaintext
// responder. Without this, a pair that reserved two different numbers would make
// every "zero plaintext hits" assertion pass for the wrong reason.
func TestLoopbackPortPair_PlaintextOracleSeesTheEntryPort(t *testing.T) {
	ca := newDoTTestCA(t)
	certificate, _ := ca.issue(t, dotLeafOptions{ips: []net.IP{net.ParseIP("127.0.0.1")}})
	server := startDoHTestServer(t, certificate, true, dohAnswerHandler(t, "203.0.113.120"))
	hits := startPlaintextResponder(t, server.pair.udp, "203.0.113.121")

	if got, want := server.pair.udp.LocalAddr().String(), server.addr.String(); got != want {
		t.Fatalf("plaintext responder bound to %s but the encrypted entry is %s", got, want)
	}

	query := new(mdns.Msg)
	query.SetQuestion("plaintext-oracle.example.", mdns.TypeA)
	body, err := query.Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}
	conn, err := net.Dial("udp4", server.addr.String())
	if err != nil {
		t.Fatalf("dial the entry port: %v", err)
	}
	if _, err := conn.Write(body); err != nil {
		t.Fatalf("write a plaintext query to the entry port: %v", err)
	}
	_ = conn.Close()

	deadline := time.Now().Add(5 * time.Second)
	for hits.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("plaintext oracle observed %d queries on the entry port, want 1", got)
	}
}
