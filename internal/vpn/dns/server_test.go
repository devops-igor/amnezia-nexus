package gatewaydns

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
	mdns "github.com/miekg/dns"
)

type mockResolver struct {
	mu       sync.Mutex
	delay    time.Duration
	exchange func(ctx context.Context, req *mdns.Msg) (*mdns.Msg, error)
}

func (m *mockResolver) Exchange(ctx context.Context, req *mdns.Msg) (*mdns.Msg, error) {
	m.mu.Lock()
	delay := m.delay
	fn := m.exchange
	m.mu.Unlock()

	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if fn != nil {
		return fn(ctx, req)
	}
	resp := new(mdns.Msg)
	resp.SetReply(req)
	resp.Answer = append(resp.Answer, &mdns.A{
		Hdr: mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 300},
		A:   net.ParseIP("93.184.216.34").To4(),
	})
	return resp, nil
}

type staticPolicySource struct {
	snapshot *policy.Snapshot
}

func (s *staticPolicySource) Current() *policy.Snapshot {
	return s.snapshot
}

func TestServer_QueryValidation(t *testing.T) {
	res := &mockResolver{}
	srv, err := NewServer(ServerConfig{
		Gateway: netip.MustParseAddrPort("10.0.0.1:53"),
	}, res, &staticPolicySource{})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// 1. Non-query opcode (e.g. UPDATE) -> NOTIMP
	reqUpdate := new(mdns.Msg)
	reqUpdate.Opcode = mdns.OpcodeUpdate
	reqUpdate.SetQuestion("example.com.", mdns.TypeA)
	resp, err := srv.ServeDNSMessage(context.Background(), nil, "sess-1", reqUpdate, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Rcode != mdns.RcodeNotImplemented {
		t.Errorf("expected NOTIMP for update opcode, got %d", resp.Rcode)
	}

	// 2. Class other than IN -> REFUSED
	reqClass := new(mdns.Msg)
	reqClass.SetQuestion("example.com.", mdns.TypeA)
	reqClass.Question[0].Qclass = mdns.ClassCHAOS
	resp, err = srv.ServeDNSMessage(context.Background(), nil, "sess-1", reqClass, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Rcode != mdns.RcodeRefused {
		t.Errorf("expected REFUSED for CHAOS class, got %d", resp.Rcode)
	}

	// 3. ANY query -> REFUSED
	reqANY := new(mdns.Msg)
	reqANY.SetQuestion("example.com.", mdns.TypeANY)
	resp, err = srv.ServeDNSMessage(context.Background(), nil, "sess-1", reqANY, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Rcode != mdns.RcodeRefused {
		t.Errorf("expected REFUSED for ANY query, got %d", resp.Rcode)
	}
}

func TestServer_InflightLimits(t *testing.T) {
	blockCh := make(chan struct{})
	res := &mockResolver{
		exchange: func(ctx context.Context, req *mdns.Msg) (*mdns.Msg, error) {
			select {
			case <-blockCh:
				resp := new(mdns.Msg)
				resp.SetReply(req)
				return resp, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
	}

	srv, _ := NewServer(ServerConfig{
		Gateway:               netip.MustParseAddrPort("10.0.0.1:53"),
		MaxInflightPerSession: 1,
		MaxInflight:           2,
	}, res, &staticPolicySource{})

	req := new(mdns.Msg)
	req.SetQuestion("example.com.", mdns.TypeA)

	// Launch 1 query in background that blocks
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = srv.ServeDNSMessage(context.Background(), nil, "sess-busy", req, false)
	}()

	// Wait briefly for first query to acquire token
	time.Sleep(10 * time.Millisecond)

	// Second query for same session should immediately receive SERVFAIL
	resp, err := srv.ServeDNSMessage(context.Background(), nil, "sess-busy", req, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Rcode != mdns.RcodeServerFailure {
		t.Errorf("expected SERVFAIL when session inflight is full, got %d", resp.Rcode)
	}

	close(blockCh)
	wg.Wait()
}

func TestServer_ResponseShaping(t *testing.T) {
	res := &mockResolver{
		exchange: func(ctx context.Context, req *mdns.Msg) (*mdns.Msg, error) {
			resp := new(mdns.Msg)
			resp.SetReply(req)
			resp.AuthenticatedData = true // Upstream sets AD
			// Add large payload to test UDP truncation (>512 bytes)
			for i := 0; i < 30; i++ {
				resp.Answer = append(resp.Answer, &mdns.TXT{
					Hdr: mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeTXT, Class: mdns.ClassINET, Ttl: 300},
					Txt: []string{"some long TXT record content to push packet size past 512 bytes threshold"},
				})
			}
			return resp, nil
		},
	}

	srv, _ := NewServer(ServerConfig{
		Gateway: netip.MustParseAddrPort("10.0.0.1:53"),
	}, res, &staticPolicySource{})

	req := new(mdns.Msg)
	req.SetQuestion("example.com.", mdns.TypeTXT)
	req.Id = 777

	// UDP request without EDNS -> capped at 512 bytes, should be truncated (TC=1)
	resp, err := srv.ServeDNSMessage(context.Background(), nil, "sess-shape", req, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Id != 777 {
		t.Errorf("expected client ID 777, got %d", resp.Id)
	}
	if resp.AuthenticatedData {
		t.Errorf("AD flag must be cleared on response")
	}
	if !resp.Truncated {
		t.Errorf("expected UDP response to be truncated (TC=1) due to size > 512")
	}

	// TCP request -> not truncated
	respTCP, err := srv.ServeDNSMessage(context.Background(), nil, "sess-shape", req, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if respTCP.Truncated {
		t.Errorf("expected TCP response not to be truncated")
	}
}

func TestServer_ServeUDPAndTCP(t *testing.T) {
	res := &mockResolver{}
	srv, _ := NewServer(ServerConfig{
		Gateway: netip.MustParseAddrPort("10.0.0.1:53"),
	}, res, &staticPolicySource{})

	udpConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen UDP: %v", err)
	}
	defer udpConn.Close()

	tcpListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen TCP: %v", err)
	}
	defer tcpListener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = srv.Serve(ctx, nil, udpConn, tcpListener)
	}()

	// 1. Test UDP exchange
	clientUDP, err := net.Dial("udp4", udpConn.LocalAddr().String())
	if err != nil {
		t.Fatalf("failed to dial UDP: %v", err)
	}
	defer clientUDP.Close()

	reqUDP := new(mdns.Msg)
	reqUDP.SetQuestion("udp.example.com.", mdns.TypeA)
	reqUDPBytes, _ := reqUDP.Pack()

	_, err = clientUDP.Write(reqUDPBytes)
	if err != nil {
		t.Fatalf("failed to write UDP: %v", err)
	}
	buf := make([]byte, 1024)
	_ = clientUDP.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := clientUDP.Read(buf)
	if err != nil {
		t.Fatalf("failed to read UDP reply: %v", err)
	}
	respUDP := new(mdns.Msg)
	if err := respUDP.Unpack(buf[:n]); err != nil {
		t.Fatalf("failed to unpack UDP reply: %v", err)
	}
	if len(respUDP.Answer) != 1 {
		t.Errorf("expected 1 answer from UDP serve, got %d", len(respUDP.Answer))
	}

	// 2. Test TCP exchange
	clientTCP, err := net.Dial("tcp4", tcpListener.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial TCP: %v", err)
	}
	defer clientTCP.Close()

	reqTCP := new(mdns.Msg)
	reqTCP.SetQuestion("tcp.example.com.", mdns.TypeA)
	reqTCPBytes, _ := reqTCP.Pack()

	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(reqTCPBytes)))
	_, _ = clientTCP.Write(lenBuf[:])
	_, _ = clientTCP.Write(reqTCPBytes)

	_ = clientTCP.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = io.ReadFull(clientTCP, lenBuf[:])
	if err != nil {
		t.Fatalf("failed to read TCP frame len: %v", err)
	}
	respLen := binary.BigEndian.Uint16(lenBuf[:])
	respBuf := make([]byte, respLen)
	_, err = io.ReadFull(clientTCP, respBuf)
	if err != nil {
		t.Fatalf("failed to read TCP frame payload: %v", err)
	}
	respTCP := new(mdns.Msg)
	if err := respTCP.Unpack(respBuf); err != nil {
		t.Fatalf("failed to unpack TCP reply: %v", err)
	}
	if len(respTCP.Answer) != 1 {
		t.Errorf("expected 1 answer from TCP serve, got %d", len(respTCP.Answer))
	}

	// 3. Test Shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("shutdown failed: %v", err)
	}
}

func TestServer_ShutdownDrainWithLateConnections(t *testing.T) {
	res := &mockResolver{}
	srv, err := NewServer(ServerConfig{
		Gateway:      netip.MustParseAddrPort("10.0.0.1:53"),
		QueryTimeout: 500 * time.Millisecond,
	}, res, &staticPolicySource{})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	tcpListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen TCP: %v", err)
	}
	defer tcpListener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = srv.Serve(ctx, nil, nil, tcpListener)
	}()

	// 1. Establish an idle TCP connection that never sends bytes.
	idleConn, err := net.Dial("tcp4", tcpListener.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial idle connection: %v", err)
	}
	defer idleConn.Close()

	// Wait briefly for idleConn to be accepted by server.
	time.Sleep(20 * time.Millisecond)

	// 2. Concurrently dial multiple late connections while triggering Shutdown.
	var dialWg sync.WaitGroup
	for i := 0; i < 10; i++ {
		dialWg.Add(1)
		go func() {
			defer dialWg.Done()
			c, dErr := net.DialTimeout("tcp4", tcpListener.Addr().String(), 500*time.Millisecond)
			if dErr == nil {
				defer c.Close()
				// Read until EOF or close
				buf := make([]byte, 64)
				_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
				_, _ = c.Read(buf)
			}
		}()
	}

	// 3. Trigger Shutdown with a strict timeout.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("shutdown failed or timed out with late connections: %v", err)
	}

	dialWg.Wait()
}
