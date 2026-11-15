package vpn

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"github.com/devops-igor/amnezia-nexus/internal/manager/awg"
	"github.com/devops-igor/amnezia-nexus/internal/policy"
	gatewaydns "github.com/devops-igor/amnezia-nexus/internal/vpn/dns"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
	mdns "github.com/miekg/dns"
)

// continuityClient is a real client network stack. Its outbound packets enter
// the production forwarder entry point and performed DNS replies arrive through
// the session's return path, so an unmodified client accepts every answer.
type continuityClient struct {
	dev   tun.Device
	stack *netstack.Net
	stop  chan struct{}
	done  chan struct{}
}

func newContinuityClient(t *testing.T, fwd *forwarder.Forwarder, peerKey string, clientIP netip.Addr) (*continuityClient, *forwarder.ReturnPath) {
	t.Helper()
	dev, stack, err := netstack.CreateNetTUN([]netip.Addr{clientIP}, nil, 1500)
	if err != nil {
		t.Fatalf("failed to create client netstack: %v", err)
	}
	path := forwarder.NewReturnPath(func(_, _ string, packet []byte) (int, error) {
		return dev.Write([][]byte{packet}, 0)
	})
	c := &continuityClient{dev: dev, stack: stack, stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(c.done)
		buf := make([][]byte, 1)
		buf[0] = make([]byte, 1500)
		sizes := make([]int, 1)
		for {
			select {
			case <-c.stop:
				return
			default:
			}
			n, err := dev.Read(buf, sizes, 0)
			if err != nil {
				return
			}
			if n > 0 && sizes[0] > 0 {
				pkt := make([]byte, sizes[0])
				copy(pkt, buf[0][:sizes[0]])
				_ = fwd.RouteClientToBackend(peerKey, pkt)
			}
		}
	}()
	return c, path
}

func (c *continuityClient) close() {
	close(c.stop)
	_ = c.dev.Close()
	select {
	case <-c.done:
	case <-time.After(2 * time.Second):
	}
}

func continuityUDPQuery(t *testing.T, stack *netstack.Net, dst netip.AddrPort, name string, id uint16) *mdns.Msg {
	t.Helper()
	conn, err := stack.DialUDPAddrPort(netip.AddrPort{}, dst)
	if err != nil {
		t.Fatalf("client failed to dial %s over UDP: %v", dst, err)
	}
	defer conn.Close()
	req := new(mdns.Msg)
	req.SetQuestion(name, mdns.TypeA)
	req.Id = id
	payload, err := req.Pack()
	if err != nil {
		t.Fatalf("failed to pack DNS query: %v", err)
	}
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("failed to write DNS query to %s: %v", dst, err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("no UDP reply from %s: %v", dst, err)
	}
	resp := new(mdns.Msg)
	if err := resp.Unpack(buf[:n]); err != nil {
		t.Fatalf("failed to unpack UDP reply from %s: %v", dst, err)
	}
	return resp
}

func continuityTCPQuery(t *testing.T, stack *netstack.Net, dst netip.AddrPort, name string, id uint16) *mdns.Msg {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := stack.DialContextTCPAddrPort(ctx, dst)
	if err != nil {
		t.Fatalf("client failed to dial %s over TCP: %v", dst, err)
	}
	defer conn.Close()
	req := new(mdns.Msg)
	req.SetQuestion(name, mdns.TypeA)
	req.Id = id
	payload, err := req.Pack()
	if err != nil {
		t.Fatalf("failed to pack DNS query: %v", err)
	}
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(payload)))
	if _, err := conn.Write(lenBuf[:]); err != nil {
		t.Fatalf("failed to write TCP length to %s: %v", dst, err)
	}
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("failed to write TCP query to %s: %v", dst, err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		t.Fatalf("no TCP reply length from %s: %v", dst, err)
	}
	respBuf := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		t.Fatalf("no TCP reply payload from %s: %v", dst, err)
	}
	resp := new(mdns.Msg)
	if err := resp.Unpack(respBuf); err != nil {
		t.Fatalf("failed to unpack TCP reply from %s: %v", dst, err)
	}
	return resp
}

// TestPolicyDNSContinuity_ServesIssuedGatewayProfileAfterDisable is the F817-01
// regression: a configuration issued while policy routing was active keeps
// naming the gateway, and that address must keep answering over UDP and TCP
// after a real ConfigurePBR/TeardownPBR cycle. New inactive downloads keep the
// legacy defaults, external port 53 is not intercepted, and no direct-path
// evidence is created while disabled.
func TestPolicyDNSContinuity_ServesIssuedGatewayProfileAfterDisable(t *testing.T) {
	gateway := netip.MustParseAddr("10.100.0.1")
	clientIP := netip.MustParseAddr("10.100.0.2")
	const (
		backendID int64 = 9017
		peerKey         = "continuity-peer"
		sessionID       = "continuity-session"
	)
	afterDisableIP := netip.MustParseAddr("93.184.216.35")

	oldResolver := newDNSContinuityResolver
	newDNSContinuityResolver = func(gatewaydns.ResolverConfig) (gatewaydns.Resolver, error) {
		return &mockPBRResolver{exchange: func(_ context.Context, req *mdns.Msg) (*mdns.Msg, error) {
			resp := new(mdns.Msg)
			resp.SetReply(req)
			resp.Answer = append(resp.Answer, &mdns.A{
				Hdr: mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 300},
				A:   net.IP(afterDisableIP.AsSlice()),
			})
			return resp, nil
		}}, nil
	}
	defer func() { newDNSContinuityResolver = oldResolver }()

	fwd := forwarder.NewForwarder(nil, "10.100.0.0/16", 64)
	fwd.AttachBackendDevice(backendID, &mockPBRDevice{})
	client, path := newContinuityClient(t, fwd, peerKey, clientIP)
	defer client.close()
	fwd.RegisterSessionWithReturnPath(sessionID, "continuity-connection", peerKey, clientIP.String(), backendID, path)

	svc := &Service{forwarder: fwd}
	defer svc.closeDNSContinuity()
	cfg := newSteeringPBRConfig(t, gateway)
	if err := svc.ConfigurePBR(cfg); err != nil {
		t.Fatalf("ConfigurePBR failed: %v", err)
	}

	issued, _ := svc.clientConfigDNSServers()
	if issued != gateway.String() {
		t.Fatalf("active configuration DNS = %q, want the gateway %q", issued, gateway.String())
	}
	issuedAddr := netip.AddrPortFrom(netip.MustParseAddr(issued), 53)

	// Positive control: the policy resolver answers the issued address while
	// policy routing is active.
	if reply := continuityUDPQuery(t, client.stack, issuedAddr, "active.example.", 100); reply.Rcode != mdns.RcodeSuccess {
		t.Fatalf("active gateway query failed with rcode %v", reply.Rcode)
	}

	if err := svc.TeardownPBR(); err != nil {
		t.Fatalf("TeardownPBR failed: %v", err)
	}
	if fwd.PBREnabled() {
		t.Fatal("policy routing still enabled after teardown")
	}
	if got1, got2 := svc.clientConfigDNSServers(); got1 != awg.AWGDefaults["dns1"] || got2 != awg.AWGDefaults["dns2"] {
		t.Fatalf("inactive generated configuration DNS = %q, %q; want the legacy defaults", got1, got2)
	}

	// The retained profile address keeps answering on both transports.
	udpReply := continuityUDPQuery(t, client.stack, issuedAddr, "after-disable.example.", 101)
	if len(udpReply.Answer) != 1 {
		t.Fatalf("issued gateway DNS over UDP after disable: got %d answers, want 1", len(udpReply.Answer))
	}
	tcpReply := continuityTCPQuery(t, client.stack, issuedAddr, "after-disable-tcp.example.", 102)
	if len(tcpReply.Answer) != 1 {
		t.Fatalf("issued gateway DNS over TCP after disable: got %d answers, want 1", len(tcpReply.Answer))
	}

	// The continuity responder must not grant DIRECT routing authority.
	if got := cfg.RouteCache.Lookup(sessionID, afterDisableIP); got != policy.Unknown {
		t.Fatalf("continuity answer produced routing evidence: decision = %v, want Unknown", got)
	}

	// External port 53 keeps its previous routing while policy routing is off.
	external := netip.AddrPortFrom(netip.MustParseAddr("8.8.8.8"), 53)
	extConn, err := client.stack.DialUDPAddrPort(netip.AddrPort{}, external)
	if err != nil {
		t.Fatalf("client failed to dial external resolver: %v", err)
	}
	defer extConn.Close()
	extQuery := new(mdns.Msg)
	extQuery.SetQuestion("external.example.", mdns.TypeA)
	extPayload, err := extQuery.Pack()
	if err != nil {
		t.Fatalf("failed to pack external query: %v", err)
	}
	if _, err := extConn.Write(extPayload); err != nil {
		t.Fatalf("failed to write external query: %v", err)
	}
	_ = extConn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := extConn.Read(make([]byte, 4096)); err == nil {
		t.Fatal("external port 53 was answered while policy routing was disabled")
	}
	backend, ok := fwd.GetBackendPacketChannel(backendID)
	if !ok {
		t.Fatal("fixture backend queue absent")
	}
	select {
	case pkt := <-backend:
		if got := netip.AddrFrom4([4]byte{pkt[16], pkt[17], pkt[18], pkt[19]}); got != external.Addr() {
			t.Fatalf("backend packet destination = %s, want the external resolver %s", got, external.Addr())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("external DNS did not take the legacy path to the backend")
	}

	// A second enable/disable cycle keeps the responder installed.
	cfg2 := newSteeringPBRConfig(t, gateway)
	if err := svc.ConfigurePBR(cfg2); err != nil {
		t.Fatalf("second ConfigurePBR failed: %v", err)
	}
	if err := svc.TeardownPBR(); err != nil {
		t.Fatalf("second TeardownPBR failed: %v", err)
	}
	if reply := continuityUDPQuery(t, client.stack, issuedAddr, "after-restart.example.", 103); len(reply.Answer) != 1 {
		t.Fatalf("issued gateway DNS after a second disable cycle: got %d answers, want 1", len(reply.Answer))
	}
}

// TestDefaultPolicyUpstreamsMatchClientDNS pins the policy resolver's upstream
// pair so a blocked provider cannot silently return, and keeps it identical to
// the addresses generated client configurations push.
func TestDefaultPolicyUpstreamsMatchClientDNS(t *testing.T) {
	upstreams := defaultPolicyUpstreams()
	want := []netip.AddrPort{
		netip.MustParseAddrPort("94.140.14.14:53"),
		netip.MustParseAddrPort("94.140.15.15:53"),
	}
	if len(upstreams) != len(want) {
		t.Fatalf("default policy upstreams = %v, want %v", upstreams, want)
	}
	for i := range want {
		if upstreams[i] != want[i] {
			t.Fatalf("default policy upstream %d = %s, want %s", i, upstreams[i], want[i])
		}
	}
	if got, wantAddr := upstreams[0].Addr().String(), awg.AWGDefaults["dns1"]; got != wantAddr {
		t.Fatalf("primary upstream %s does not match the client configuration resolver %s", got, wantAddr)
	}
	if got, wantAddr := upstreams[1].Addr().String(), awg.AWGDefaults["dns2"]; got != wantAddr {
		t.Fatalf("alternate upstream %s does not match the client configuration resolver %s", got, wantAddr)
	}
}
