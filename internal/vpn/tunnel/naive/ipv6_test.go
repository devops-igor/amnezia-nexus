package naive

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/loadbalancer"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel/streambridge"
	"github.com/miekg/dns"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

func TestDialer_IPv6_EndpointParsing(t *testing.T) {
	validCases := []struct {
		name     string
		endpoint string
		wantHost string
		wantPort int
	}{
		{
			name:     "bracketed ipv6 standard port",
			endpoint: "[2001:db8::10]:443",
			wantHost: "2001:db8::10",
			wantPort: 443,
		},
		{
			name:     "bracketed ipv6 custom port",
			endpoint: "[2001:db8::10]:8443",
			wantHost: "2001:db8::10",
			wantPort: 8443,
		},
		{
			name:     "bracketed ipv6 loopback",
			endpoint: "[::1]:443",
			wantHost: "::1",
			wantPort: 443,
		},
		{
			name:     "bracketed ipv6 with spaces",
			endpoint: "  [2001:db8::10]:443  ",
			wantHost: "2001:db8::10",
			wantPort: 443,
		},
		{
			name:     "hostname with aaaa",
			endpoint: "ipv6-backend.example.com:443",
			wantHost: "ipv6-backend.example.com",
			wantPort: 443,
		},
	}

	p := models.NaiveProxyParams{
		Username: "user",
		Password: "pass",
		Domain:   testCamouflageDomain,
	}

	for _, tc := range validCases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := New(tc.endpoint, p)
			if err != nil {
				t.Fatalf("New(%q) unexpected error: %v", tc.endpoint, err)
			}
			defer d.Close()

			host, portStr, err := net.SplitHostPort(d.endpoint)
			if err != nil {
				t.Fatalf("SplitHostPort(%q) failed: %v", d.endpoint, err)
			}
			if host != tc.wantHost {
				t.Errorf("host = %q, want %q", host, tc.wantHost)
			}
			if portStr != strings.TrimSpace(portStr) {
				t.Errorf("portStr has unexpected spaces: %q", portStr)
			}
			// Verify TLS ServerName strictly matches camouflage domain, never the transport IP
			if d.tlsCfg.ServerName != testCamouflageDomain {
				t.Errorf("ServerName = %q, want %q", d.tlsCfg.ServerName, testCamouflageDomain)
			}
			if d.tlsCfg.InsecureSkipVerify {
				t.Error("InsecureSkipVerify must be false")
			}
		})
	}

	invalidCases := []struct {
		name     string
		endpoint string
	}{
		{
			name:     "unbracketed ipv6 with port",
			endpoint: "2001:db8::10:443",
		},
		{
			name:     "bracketed ipv6 missing port",
			endpoint: "[2001:db8::10]",
		},
		{
			name:     "unbracketed ipv6 missing port",
			endpoint: "2001:db8::10",
		},
		{
			name:     "bracketed ipv6 port out of range",
			endpoint: "[2001:db8::10]:70000",
		},
		{
			name:     "empty endpoint",
			endpoint: "",
		},
		{
			name:     "missing host",
			endpoint: ":443",
		},
	}

	for _, tc := range invalidCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.endpoint, p)
			if err == nil {
				t.Fatalf("New(%q) expected error, got nil", tc.endpoint)
			}
		})
	}
}

func TestDialer_IPv6_H2_DialIPv4CONNECT(t *testing.T) {
	// 1. IPv4 TCP echo target (simulating client payload destination)
	echoAddr, cleanupEcho := setupTCPEchoServer(t)
	defer cleanupEcho()

	// 2. IPv6 Naive H2 backend listening on [::1]:port
	proxyAddr, cleanupH2 := setupTestH2ServerIPv6(t, "testuser", "testpass", true)
	defer cleanupH2()

	p := models.NaiveProxyParams{
		Username: "testuser",
		Password: "testpass",
		Domain:   testCamouflageDomain,
		EnableH3: false,
	}

	d, err := New(proxyAddr, p)
	if err != nil {
		t.Fatalf("New dialer: %v", err)
	}
	defer d.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Dial IPv4 address through IPv6 NaiveProxy backend
	conn, err := d.DialContext(ctx, "tcp", echoAddr)
	if err != nil {
		t.Fatalf("DialContext IPv6 -> IPv4 target failed: %v", err)
	}
	defer conn.Close()

	// Verify transport address family is IPv6
	remoteAddr := conn.RemoteAddr().String()
	if !strings.HasPrefix(remoteAddr, "[::1]:") {
		t.Errorf("expected remote transport address to be IPv6 [::1]:..., got %q", remoteAddr)
	}

	// Verify 64 KiB payload round-trip through the IPv6 tunnel to IPv4 target
	const payloadSize = 64 * 1024
	verifyEchoPayload(t, conn, payloadSize, "H2-IPv6")
}

func TestDialer_IPv6_H3_DialIPv4CONNECT(t *testing.T) {
	// 1. IPv4 TCP echo target
	echoAddr, cleanupEcho := setupTCPEchoServer(t)
	defer cleanupEcho()

	// 2. IPv6 Naive H3 backend listening on [::1]:port (UDP)
	proxyAddr, cleanupH3 := setupTestH3ServerIPv6(t, "testuser", "testpass", true)
	defer cleanupH3()

	p := models.NaiveProxyParams{
		Username: "testuser",
		Password: "testpass",
		Domain:   testCamouflageDomain,
		EnableH3: true,
	}

	d, err := New(proxyAddr, p)
	if err != nil {
		t.Fatalf("New dialer: %v", err)
	}
	defer d.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := d.DialContext(ctx, "tcp", echoAddr)
	if err != nil {
		t.Fatalf("DialContext H3 IPv6 -> IPv4 target failed: %v", err)
	}
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	if !strings.HasPrefix(remoteAddr, "[::1]:") {
		t.Errorf("expected remote transport address to be IPv6 [::1]:..., got %q", remoteAddr)
	}

	const payloadSize = 64 * 1024
	verifyEchoPayload(t, conn, payloadSize, "H3-IPv6")
}

func setupDeterministicAAAADNS(t *testing.T, domain string, ipv6 net.IP) (*net.Resolver, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen UDP for DNS: %v", err)
	}

	dnsServer := &dns.Server{PacketConn: pc, Net: "udp"}
	normalizedTarget := strings.TrimSuffix(domain, ".") + "."

	dnsServer.Handler = dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		for _, q := range r.Question {
			if strings.EqualFold(q.Name, normalizedTarget) && q.Qtype == dns.TypeAAAA {
				m.Answer = append(m.Answer, &dns.AAAA{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeAAAA,
						Class:  dns.ClassINET,
						Ttl:    60,
					},
					AAAA: ipv6,
				})
			}
		}
		_ = w.WriteMsg(m)
	})

	serverStarted := make(chan struct{})
	dnsServer.NotifyStartedFunc = func() {
		close(serverStarted)
	}
	go func() {
		_ = dnsServer.ActivateAndServe()
	}()

	select {
	case <-serverStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("dns server failed to start within 2s")
	}

	dnsAddr := pc.LocalAddr().String()
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", dnsAddr)
		},
	}

	cleanup := func() {
		_ = dnsServer.Shutdown()
	}
	return resolver, cleanup
}

func TestDialer_IPv6_AAAA_HostnameResolution(t *testing.T) {
	echoAddr, cleanupEcho := setupTCPEchoServer(t)
	defer cleanupEcho()

	proxyAddr, cleanupH2 := setupTestH2ServerIPv6(t, "testuser", "testpass", true)
	defer cleanupH2()

	_, portStr, err := net.SplitHostPort(proxyAddr)
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}

	const aaaaDomain = "aaaa-backend.example.com"
	resolver, cleanupDNS := setupDeterministicAAAADNS(t, aaaaDomain, net.ParseIP("::1"))
	defer cleanupDNS()

	p := models.NaiveProxyParams{
		Username: "testuser",
		Password: "testpass",
		Domain:   testCamouflageDomain,
		EnableH3: false,
	}

	d, err := New(net.JoinHostPort(aaaaDomain, portStr), p, WithResolver(resolver))
	if err != nil {
		t.Fatalf("New dialer with AAAA hostname: %v", err)
	}
	defer d.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := d.DialContext(ctx, "tcp", echoAddr)
	if err != nil {
		t.Fatalf("DialContext through AAAA hostname: %v", err)
	}
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	if !strings.HasPrefix(remoteAddr, "[::1]:") {
		t.Errorf("expected remote address IPv6 loopback [::1]:..., got %q", remoteAddr)
	}

	const payloadSize = 32 * 1024
	verifyEchoPayload(t, conn, payloadSize, "AAAA-H2")
}

func TestDialer_IPv6_AAAA_H3_HostnameResolution(t *testing.T) {
	echoAddr, cleanupEcho := setupTCPEchoServer(t)
	defer cleanupEcho()

	proxyAddr, cleanupH3 := setupTestH3ServerIPv6(t, "testuser", "testpass", true)
	defer cleanupH3()

	_, portStr, err := net.SplitHostPort(proxyAddr)
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}

	const aaaaDomain = "aaaa-h3-backend.example.com"
	resolver, cleanupDNS := setupDeterministicAAAADNS(t, aaaaDomain, net.ParseIP("::1"))
	defer cleanupDNS()

	p := models.NaiveProxyParams{
		Username: "testuser",
		Password: "testpass",
		Domain:   testCamouflageDomain,
		EnableH3: true,
	}

	d, err := New(net.JoinHostPort(aaaaDomain, portStr), p, WithResolver(resolver))
	if err != nil {
		t.Fatalf("New dialer with AAAA hostname for H3: %v", err)
	}
	defer d.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := d.DialContext(ctx, "tcp", echoAddr)
	if err != nil {
		t.Fatalf("DialContext through AAAA hostname with H3: %v", err)
	}
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	if !strings.HasPrefix(remoteAddr, "[::1]:") {
		t.Errorf("expected remote address IPv6 loopback [::1]:..., got %q", remoteAddr)
	}

	const payloadSize = 32 * 1024
	verifyEchoPayload(t, conn, payloadSize, "AAAA-H3")
}

func TestProbeNaiveProxy_IPv6_SuccessAndFailure(t *testing.T) {
	proxyAddr, cleanupH2 := setupTestH2ServerIPv6(t, "testuser", "testpass", true)
	defer cleanupH2()

	p := models.NaiveProxyParams{
		Username: "testuser",
		Password: "testpass",
		Domain:   testCamouflageDomain,
		EnableH3: false,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. Success probe against IPv6 backend
	latencyMS, err := ProbeNaiveProxy(ctx, proxyAddr, p, 3*time.Second)
	if err != nil {
		t.Fatalf("ProbeNaiveProxy against IPv6 backend failed: %v", err)
	}
	if latencyMS <= 0 {
		t.Errorf("expected positive latencyMS, got %d", latencyMS)
	}

	// 2. ProbeNaiveProxyTunnel wrapper
	rawParams, _ := json.Marshal(p)
	tun := &models.BackendTunnel{
		ID:             99,
		Endpoint:       proxyAddr,
		Protocol:       models.ProtocolNaive,
		ProtocolParams: rawParams,
	}
	latencyTunnel, err := ProbeNaiveProxyTunnel(ctx, tun, 3*time.Second)
	if err != nil {
		t.Fatalf("ProbeNaiveProxyTunnel failed: %v", err)
	}
	if latencyTunnel <= 0 {
		t.Errorf("expected positive latencyMS from tunnel probe, got %d", latencyTunnel)
	}

	// 3. Simulated failure: unreachable IPv6 blackhole
	blackholeIPv6 := "[2001:db8::1]:54321"
	_, err = ProbeNaiveProxy(ctx, blackholeIPv6, p, 100*time.Millisecond)
	if err == nil {
		t.Fatal("expected probe to fail on unreachable IPv6 address, got nil")
	}
}

type simulatedIPv4Client struct {
	ep     *channel.Endpoint
	stack  *stack.Stack
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	ip     netip.Addr
}

func newSimulatedIPv4Client(t *testing.T, dev *streambridge.Device) *simulatedIPv4Client {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	ep := channel.New(1024, 1280, "")
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
		HandleLocal:        false,
	})

	const nicID tcpip.NICID = 1
	if err := s.CreateNIC(nicID, ep); err != nil {
		cancel()
		t.Fatalf("simulatedIPv4Client CreateNIC: %v", err)
	}

	clientIP := netip.MustParseAddr("10.10.10.2")
	protoAddr := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFromSlice(clientIP.AsSlice()).WithPrefix(),
	}
	if err := s.AddProtocolAddress(nicID, protoAddr, stack.AddressProperties{}); err != nil {
		cancel()
		t.Fatalf("simulatedIPv4Client AddProtocolAddress: %v", err)
	}

	s.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         nicID,
		},
	})

	sc := &simulatedIPv4Client{
		ep:     ep,
		stack:  s,
		ctx:    ctx,
		cancel: cancel,
		ip:     clientIP,
	}

	sc.wg.Add(1)
	go func() {
		defer sc.wg.Done()
		for {
			pkt := sc.ep.ReadContext(sc.ctx)
			if pkt == nil {
				return
			}
			v := pkt.ToView()
			if v != nil {
				_, _ = dev.Write(v.AsSlice())
				v.Release()
			}
			pkt.DecRef()
		}
	}()

	go func() {
		buf := make([]byte, 2048)
		for {
			n, err := dev.Read(buf)
			if err != nil {
				return
			}
			if n > 0 {
				inPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
					Payload: buffer.MakeWithData(buf[:n]),
				})
				sc.ep.InjectInbound(ipv4.ProtocolNumber, inPkt)
				inPkt.DecRef()
			}
		}
	}()

	return sc
}

func (c *simulatedIPv4Client) DialTCP(ctx context.Context, addr string) (*gonet.TCPConn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	dstIP, err := netip.ParseAddr(host)
	if err != nil {
		return nil, err
	}

	fullAddr := tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(dstIP.AsSlice()),
		Port: uint16(port),
	}
	return gonet.DialContextTCP(ctx, c.stack, fullAddr, ipv4.ProtocolNumber)
}

func (c *simulatedIPv4Client) Close() {
	c.cancel()
	c.ep.Close()
	c.stack.Close()
	c.wg.Wait()
	c.stack.Wait()
}

type lbDataplaneDispatcher struct {
	mu           sync.Mutex
	sm           *loadbalancer.StickySessionManager
	tunnels      []*models.BackendTunnel
	peerKey      string
	dialers      map[int64]*Dialer
	lastSelected int64
	lastRemote   string
	lastDest     string
	dialCount    map[int64]int
}

func (l *lbDataplaneDispatcher) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	l.mu.Lock()
	req := &loadbalancer.RoutingRequest{
		PeerPublicKey:    l.peerKey,
		AvailableTunnels: l.tunnels,
	}
	tun, _, err := l.sm.GetOrAssignBackend(ctx, req)
	if err != nil {
		l.mu.Unlock()
		return nil, err
	}
	l.lastSelected = tun.ID
	l.lastDest = address
	l.dialCount[tun.ID]++
	dialer := l.dialers[tun.ID]
	l.mu.Unlock()

	conn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}

	l.mu.Lock()
	l.lastRemote = conn.RemoteAddr().String()
	l.mu.Unlock()

	return conn, nil
}

func findLocalNonLoopbackIPv4() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err == nil {
		_ = conn.Close()
		if udpAddr, ok := conn.LocalAddr().(*net.UDPAddr); ok && udpAddr.IP.To4() != nil && !udpAddr.IP.IsLoopback() {
			return udpAddr.IP.String(), nil
		}
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ip4 := ipNet.IP.To4(); ip4 != nil {
				return ip4.String(), nil
			}
		}
	}
	return "", errors.New("no non-loopback IPv4 address found")
}

func setupTCPEchoServerOnLocalIP(t *testing.T) (string, func()) {
	t.Helper()
	localIP, err := findLocalNonLoopbackIPv4()
	if err != nil {
		t.Fatalf("findLocalNonLoopbackIPv4: %v", err)
	}
	return setupTCPEchoServerOnAddr(t, net.JoinHostPort(localIP, "0"))
}

func TestDataplane_IPv4Client_To_LB_IPv6NaiveBackend_RoundTripAndFailover(t *testing.T) {
	// 1. Destination IPv4 TCP echo target (simulating destination server on the Internet)
	echoAddr, cleanupEcho := setupTCPEchoServerOnLocalIP(t)
	defer cleanupEcho()

	var (
		muConn            sync.Mutex
		proxyDestIPv6List []string
		proxyDestIPv4List []string
	)

	// 2. IPv6 Naive backend listening on [::1]:port
	proxyAddrIPv6, cleanupH2IPv6 := setupTestH2ServerIPv6(t, "user-ipv6", "pass-ipv6", true, func(authority string) {
		muConn.Lock()
		defer muConn.Unlock()
		proxyDestIPv6List = append(proxyDestIPv6List, authority)
	})
	defer cleanupH2IPv6()

	// 3. IPv4 Naive backend listening on 127.0.0.1:port
	proxyAddrIPv4, cleanupH2IPv4 := setupTestH2Server(t, "user-ipv4", "pass-ipv4", true, func(authority string) {
		muConn.Lock()
		defer muConn.Unlock()
		proxyDestIPv4List = append(proxyDestIPv4List, authority)
	})
	defer cleanupH2IPv4()

	pIPv6 := models.NaiveProxyParams{
		Username: "user-ipv6",
		Password: "pass-ipv6",
		Domain:   testCamouflageDomain,
		EnableH3: false,
	}
	dIPv6, err := New(proxyAddrIPv6, pIPv6)
	if err != nil {
		t.Fatalf("New IPv6 dialer: %v", err)
	}
	defer dIPv6.Close()

	pIPv4 := models.NaiveProxyParams{
		Username: "user-ipv4",
		Password: "pass-ipv4",
		Domain:   testCamouflageDomain,
		EnableH3: false,
	}
	dIPv4, err := New(proxyAddrIPv4, pIPv4)
	if err != nil {
		t.Fatalf("New IPv4 dialer: %v", err)
	}
	defer dIPv4.Close()

	tunIPv6 := &models.BackendTunnel{
		ID:       10,
		ServerID: 100,
		Endpoint: proxyAddrIPv6,
		Protocol: models.ProtocolNaive,
		Status:   "active",
		Enabled:  true,
	}
	tunIPv4 := &models.BackendTunnel{
		ID:       20,
		ServerID: 200,
		Endpoint: proxyAddrIPv4,
		Protocol: models.ProtocolNaive,
		Status:   "active",
		Enabled:  true,
	}

	availablePool := []*models.BackendTunnel{tunIPv6, tunIPv4}

	caps := loadbalancer.CapacityConfig{
		MaxTotalPeers:      100,
		MaxPeersPerBackend: 10,
		AffinityTTL:        10 * time.Minute,
	}
	base := loadbalancer.NewRoundRobinBalancer(caps)
	sm := loadbalancer.NewStickySessionManager(nil, base, caps)

	const clientPeerKey = "client-peer-key-1"
	sm.AssignPeerAffinity(clientPeerKey, tunIPv6.ID)

	disp := &lbDataplaneDispatcher{
		sm:      sm,
		tunnels: availablePool,
		peerKey: clientPeerKey,
		dialers: map[int64]*Dialer{
			tunIPv6.ID: dIPv6,
			tunIPv4.ID: dIPv4,
		},
		dialCount: make(map[int64]int),
	}

	// 4. Create Nexus streambridge backed by the load-balancing dispatcher dialer
	bridgeDev, err := streambridge.New(streambridge.Config{
		DialTimeout:         5 * time.Second,
		TCPHalfCloseTimeout: 1 * time.Second,
	}, disp)
	if err != nil {
		t.Fatalf("streambridge.New: %v", err)
	}
	defer bridgeDev.Close()

	// 5. Create simulated IPv4 client sending L3 packets into streambridge
	client := newSimulatedIPv4Client(t, bridgeDev)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Scenario Part A: Complete round trip through LB-selected IPv6 Naive backend
	conn1, err := client.DialTCP(ctx, echoAddr)
	if err != nil {
		t.Fatalf("client.DialTCP through streambridge (IPv6 backend): %v", err)
	}

	const payloadSize = 16 * 1024
	payload1 := make([]byte, payloadSize)
	if _, err := rand.Read(payload1); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	writeErrCh := make(chan error, 1)
	go func() {
		_, err := conn1.Write(payload1)
		writeErrCh <- err
	}()

	recvBuf1 := make([]byte, payloadSize)
	if _, err := io.ReadFull(conn1, recvBuf1); err != nil {
		t.Fatalf("ReadFull response from IPv6 backend dataplane: %v", err)
	}
	if err := <-writeErrCh; err != nil {
		t.Fatalf("Write to IPv6 backend dataplane: %v", err)
	}
	if !bytes.Equal(payload1, recvBuf1) {
		t.Fatal("dataplane payload mismatch over IPv6 Naive backend")
	}
	_ = conn1.Close()

	disp.mu.Lock()
	if disp.lastSelected != tunIPv6.ID {
		t.Fatalf("expected LB to select IPv6 tunnel %d, got %d", tunIPv6.ID, disp.lastSelected)
	}
	if disp.lastDest != echoAddr {
		t.Fatalf("expected dispatcher destination %q, got %q", echoAddr, disp.lastDest)
	}
	if !strings.HasPrefix(disp.lastRemote, "[::1]:") {
		t.Fatalf("expected remote transport address to be IPv6 [::1]:..., got %q", disp.lastRemote)
	}
	if disp.dialCount[tunIPv6.ID] != 1 {
		t.Fatalf("expected 1 dial to IPv6 backend, got %d", disp.dialCount[tunIPv6.ID])
	}
	disp.mu.Unlock()

	muConn.Lock()
	if len(proxyDestIPv6List) != 1 || proxyDestIPv6List[0] != echoAddr {
		t.Fatalf("expected IPv6 proxy to receive CONNECT destination %q, got %v", echoAddr, proxyDestIPv6List)
	}
	muConn.Unlock()

	// Scenario Part B: Selected IPv6 backend is marked unhealthy -> failover to alternate healthy Naive backend
	tunIPv6.Status = "degraded"
	failoverRes, err := sm.HandleFailover(ctx, tunIPv6.ID, availablePool, models.ProtocolNaive)
	if err != nil {
		t.Fatalf("HandleFailover on IPv6 degradation failed: %v", err)
	}
	if len(failoverRes.Migrations) != 1 {
		t.Fatalf("expected 1 migration, got %d", len(failoverRes.Migrations))
	}
	if failoverRes.Migrations[0].NewBackendTunnelID != tunIPv4.ID {
		t.Fatalf("expected failover to healthy IPv4 backend %d, got %d", tunIPv4.ID, failoverRes.Migrations[0].NewBackendTunnelID)
	}

	aff, ok := sm.GetPeerAffinity(clientPeerKey)
	if !ok || aff != tunIPv4.ID {
		t.Fatalf("expected peer affinity updated to IPv4 backend %d, got %d (ok=%v)", tunIPv4.ID, aff, ok)
	}

	// Scenario Part C: Subsequent connection from client routes to alternate healthy Naive backend
	conn2, err := client.DialTCP(ctx, echoAddr)
	if err != nil {
		t.Fatalf("client.DialTCP through streambridge after failover (IPv4 backend): %v", err)
	}

	payload2 := make([]byte, payloadSize)
	if _, err := rand.Read(payload2); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	go func() {
		_, err := conn2.Write(payload2)
		writeErrCh <- err
	}()

	recvBuf2 := make([]byte, payloadSize)
	if _, err := io.ReadFull(conn2, recvBuf2); err != nil {
		t.Fatalf("ReadFull response from IPv4 backend dataplane after failover: %v", err)
	}
	if err := <-writeErrCh; err != nil {
		t.Fatalf("Write to IPv4 backend dataplane after failover: %v", err)
	}
	if !bytes.Equal(payload2, recvBuf2) {
		t.Fatal("dataplane payload mismatch over IPv4 Naive backend after failover")
	}
	_ = conn2.Close()

	disp.mu.Lock()
	if disp.lastSelected != tunIPv4.ID {
		t.Fatalf("expected LB to select failover IPv4 tunnel %d, got %d", tunIPv4.ID, disp.lastSelected)
	}
	if disp.lastDest != echoAddr {
		t.Fatalf("expected dispatcher destination %q, got %q", echoAddr, disp.lastDest)
	}
	if !strings.HasPrefix(disp.lastRemote, "127.0.0.1:") {
		t.Fatalf("expected remote transport address to be IPv4 127.0.0.1:..., got %q", disp.lastRemote)
	}
	if disp.dialCount[tunIPv4.ID] != 1 {
		t.Fatalf("expected 1 dial to IPv4 backend, got %d", disp.dialCount[tunIPv4.ID])
	}
	disp.mu.Unlock()

	muConn.Lock()
	if len(proxyDestIPv4List) != 1 || proxyDestIPv4List[0] != echoAddr {
		t.Fatalf("expected IPv4 proxy to receive CONNECT destination %q, got %v", echoAddr, proxyDestIPv4List)
	}
	muConn.Unlock()

	// Scenario Part D: Flow accounting verification
	stats := bridgeDev.FlowStats()
	if stats.Total < 2 {
		t.Errorf("expected at least 2 flows in streambridge, got %d", stats.Total)
	}
	if stats.DialFailures != 0 {
		t.Errorf("expected 0 dial failures, got %d", stats.DialFailures)
	}
	if stats.Rejected != 0 {
		t.Errorf("expected 0 rejected flows, got %d", stats.Rejected)
	}
}
