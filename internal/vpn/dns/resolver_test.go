package gatewaydns

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"

	mdns "github.com/miekg/dns"
)

type mockDNSServer struct {
	serverUDP *mdns.Server
	serverTCP *mdns.Server
	udpAddr   netip.AddrPort
	tcpAddr   netip.AddrPort
}

func startMockServer(t *testing.T, handler mdns.Handler) *mockDNSServer {
	t.Helper()

	udpConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen UDP: %v", err)
	}
	udpAddr := netip.MustParseAddrPort(udpConn.LocalAddr().String())

	tcpListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		_ = udpConn.Close()
		t.Fatalf("failed to listen TCP: %v", err)
	}
	tcpAddr := netip.MustParseAddrPort(tcpListener.Addr().String())

	sUDP := &mdns.Server{PacketConn: udpConn, Handler: handler}
	sTCP := &mdns.Server{Listener: tcpListener, Handler: handler}

	go func() { _ = sUDP.ActivateAndServe() }()
	go func() { _ = sTCP.ActivateAndServe() }()

	t.Cleanup(func() {
		_ = sUDP.Shutdown()
		_ = sTCP.Shutdown()
	})

	return &mockDNSServer{
		serverUDP: sUDP,
		serverTCP: sTCP,
		udpAddr:   udpAddr,
		tcpAddr:   tcpAddr,
	}
}

func TestResolver_ConfigValidation(t *testing.T) {
	// No upstreams
	_, err := NewUpstreamResolver(ResolverConfig{})
	if err != ErrNoUpstreams {
		t.Errorf("expected ErrNoUpstreams, got %v", err)
	}

	// More than 3 upstreams
	_, err = NewUpstreamResolver(ResolverConfig{
		Upstreams: []netip.AddrPort{
			netip.MustParseAddrPort("1.1.1.1:53"),
			netip.MustParseAddrPort("8.8.8.8:53"),
			netip.MustParseAddrPort("9.9.9.9:53"),
			netip.MustParseAddrPort("8.8.4.4:53"),
		},
	})
	if err != ErrTooManyUpstreams {
		t.Errorf("expected ErrTooManyUpstreams, got %v", err)
	}

	// Loopback rejected when not allowed
	_, err = NewUpstreamResolver(ResolverConfig{
		Upstreams: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:53")},
	})
	if err == nil {
		t.Errorf("expected error for loopback upstream")
	}

	// Loopback allowed when configured
	r, err := NewUpstreamResolver(ResolverConfig{
		Upstreams:             []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:53")},
		AllowLoopbackUpstream: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.cfg.QueryTimeout != defaultQueryTimeout || r.cfg.AttemptTimeout != defaultAttemptTimeout {
		t.Errorf("expected default timeouts, got query=%v attempt=%v", r.cfg.QueryTimeout, r.cfg.AttemptTimeout)
	}
}

func TestResolver_SuccessfulExchange(t *testing.T) {
	handler := mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
		m := new(mdns.Msg)
		m.SetReply(req)
		m.Answer = append(m.Answer, &mdns.A{
			Hdr: mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 300},
			A:   net.ParseIP("93.184.216.34").To4(),
		})
		_ = w.WriteMsg(m)
	})

	server := startMockServer(t, handler)
	r, err := NewUpstreamResolver(ResolverConfig{
		Upstreams:             []netip.AddrPort{server.udpAddr},
		AllowLoopbackUpstream: true,
	})
	if err != nil {
		t.Fatalf("failed to create resolver: %v", err)
	}

	req := new(mdns.Msg)
	req.SetQuestion("example.com.", mdns.TypeA)
	req.Id = 12345

	resp, err := r.Exchange(context.Background(), req)
	if err != nil {
		t.Fatalf("Exchange failed: %v", err)
	}
	if resp.Id != 12345 {
		t.Errorf("expected original client ID 12345, got %d", resp.Id)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer record, got %d", len(resp.Answer))
	}
	aRec, ok := resp.Answer[0].(*mdns.A)
	if !ok || aRec.A.String() != "93.184.216.34" {
		t.Errorf("unexpected answer: %v", resp.Answer[0])
	}
}

func TestResolver_TCPFallbackOnTruncated(t *testing.T) {
	// If query comes over UDP, return TC=1.
	// If query comes over TCP, return full answer.
	handler := mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
		m := new(mdns.Msg)
		m.SetReply(req)

		// Check if connection is UDP (PacketConn) or TCP
		if _, ok := w.RemoteAddr().(*net.UDPAddr); ok {
			m.Truncated = true
			_ = w.WriteMsg(m)
			return
		}

		m.Answer = append(m.Answer, &mdns.A{
			Hdr: mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60},
			A:   net.ParseIP("1.1.1.1").To4(),
		})
		_ = w.WriteMsg(m)
	})

	// To test TCP fallback to same port, let's bind both UDP and TCP on the same port.
	udpConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen UDP: %v", err)
	}
	port := udpConn.LocalAddr().(*net.UDPAddr).Port

	tcpListener, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		_ = udpConn.Close()
		t.Fatalf("failed to listen TCP on same port: %v", err)
	}
	targetAddr := netip.MustParseAddrPort(udpConn.LocalAddr().String())

	sUDP := &mdns.Server{PacketConn: udpConn, Handler: handler}
	sTCP := &mdns.Server{Listener: tcpListener, Handler: handler}
	go func() { _ = sUDP.ActivateAndServe() }()
	go func() { _ = sTCP.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = sUDP.Shutdown()
		_ = sTCP.Shutdown()
	})

	r, err := NewUpstreamResolver(ResolverConfig{
		Upstreams:             []netip.AddrPort{targetAddr},
		AllowLoopbackUpstream: true,
	})
	if err != nil {
		t.Fatalf("failed to create resolver: %v", err)
	}

	req := new(mdns.Msg)
	req.SetQuestion("fallback.example.com.", mdns.TypeA)
	req.Id = 42

	resp, err := r.Exchange(context.Background(), req)
	if err != nil {
		t.Fatalf("Exchange failed: %v", err)
	}
	if resp.Truncated {
		t.Errorf("expected non-truncated answer after TCP fallback")
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer record, got %d", len(resp.Answer))
	}
}

func TestResolver_AlternateUpstreamRetry(t *testing.T) {
	var primaryHits atomic.Int32
	var altHits atomic.Int32

	// Primary returns SERVFAIL
	primaryHandler := mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
		primaryHits.Add(1)
		m := new(mdns.Msg)
		m.SetReply(req)
		m.Rcode = mdns.RcodeServerFailure
		_ = w.WriteMsg(m)
	})
	primaryServer := startMockServer(t, primaryHandler)

	// Alternate returns SUCCESS
	altHandler := mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
		altHits.Add(1)
		m := new(mdns.Msg)
		m.SetReply(req)
		m.Answer = append(m.Answer, &mdns.A{
			Hdr: mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 300},
			A:   net.ParseIP("8.8.8.8").To4(),
		})
		_ = w.WriteMsg(m)
	})
	altServer := startMockServer(t, altHandler)

	r, err := NewUpstreamResolver(ResolverConfig{
		Upstreams:             []netip.AddrPort{primaryServer.udpAddr, altServer.udpAddr},
		AllowLoopbackUpstream: true,
	})
	if err != nil {
		t.Fatalf("failed to create resolver: %v", err)
	}

	req := new(mdns.Msg)
	req.SetQuestion("retry.example.com.", mdns.TypeA)

	resp, err := r.Exchange(context.Background(), req)
	if err != nil {
		t.Fatalf("Exchange failed: %v", err)
	}
	if primaryHits.Load() != 1 {
		t.Errorf("expected 1 hit on primary, got %d", primaryHits.Load())
	}
	if altHits.Load() != 1 {
		t.Errorf("expected 1 hit on alternate, got %d", altHits.Load())
	}
	if resp.Rcode != mdns.RcodeSuccess {
		t.Errorf("expected RcodeSuccess from alternate, got %d", resp.Rcode)
	}
}

func TestResolver_NXDOMAINTerminal(t *testing.T) {
	var primaryHits atomic.Int32
	var altHits atomic.Int32

	primaryHandler := mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
		primaryHits.Add(1)
		m := new(mdns.Msg)
		m.SetReply(req)
		m.Rcode = mdns.RcodeNameError
		_ = w.WriteMsg(m)
	})
	primaryServer := startMockServer(t, primaryHandler)

	altHandler := mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
		altHits.Add(1)
	})
	altServer := startMockServer(t, altHandler)

	r, err := NewUpstreamResolver(ResolverConfig{
		Upstreams:             []netip.AddrPort{primaryServer.udpAddr, altServer.udpAddr},
		AllowLoopbackUpstream: true,
	})
	if err != nil {
		t.Fatalf("failed to create resolver: %v", err)
	}

	req := new(mdns.Msg)
	req.SetQuestion("nonexistent.example.com.", mdns.TypeA)

	resp, err := r.Exchange(context.Background(), req)
	if err != nil {
		t.Fatalf("Exchange failed: %v", err)
	}
	if resp.Rcode != mdns.RcodeNameError {
		t.Errorf("expected NXDOMAIN, got %d", resp.Rcode)
	}
	if primaryHits.Load() != 1 {
		t.Errorf("expected 1 hit on primary, got %d", primaryHits.Load())
	}
	if altHits.Load() != 0 {
		t.Errorf("NXDOMAIN should be terminal; alternate should not be contacted, got %d hits", altHits.Load())
	}
}
