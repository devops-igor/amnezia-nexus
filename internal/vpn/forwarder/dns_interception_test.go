package forwarder

import (
	"net/netip"
	"sync/atomic"
	"testing"
)

// recordingDNSHandler counts the packets the forwarder submits to the policy
// resolver and reports them as handled, so a test can tell interception apart
// from the ordinary proxy path.
type recordingDNSHandler struct {
	calls atomic.Int64
}

func (h *recordingDNSHandler) HandleDNSPacket(_ string, _ string, _ string, _ *ReturnPath, _ []byte) (bool, error) {
	h.calls.Add(1)
	return true, nil
}

// TestDNSInterception_InactivePolicyIsNotIntercepted is the negative control:
// with policy routing inactive, port-53 traffic is not intercepted even while a
// DNS handler is installed, and keeps the legacy path toward the backend.
func TestDNSInterception_InactivePolicyIsNotIntercepted(t *testing.T) {
	fwd := NewForwarder(nil, "10.100.0.0/16", 100)
	fwd.SetPBREnabled(false)

	backendID := int64(301)
	fwd.AttachBackendDevice(backendID, newMockPacketDev())

	handler := &recordingDNSHandler{}
	fwd.SetDNSHandler(handler)

	peerKey := "peer-dns-inactive"
	clientIP := "10.100.0.25"
	path := newTestCaptureReturnPath()
	fwd.RegisterSessionWithReturnPath("s-dns-inactive", "c-dns-inactive", peerKey, clientIP, backendID, path.path)

	for i, dst := range []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("10.100.0.1")} {
		pkt := buildTestIPv4UDPPacket(netip.MustParseAddr(clientIP), dst, uint16(41000+i), 53, []byte("dns-query"))
		if err := fwd.RouteClientToBackend(peerKey, pkt); err != nil {
			t.Fatalf("target %s: expected the legacy path to accept the packet, got %v", dst, err)
		}
	}

	if got := handler.calls.Load(); got != 0 {
		t.Fatalf("inactive policy intercepted %d DNS packets", got)
	}
	if got := len(fwd.backendQueues[backendID]); got != 2 {
		t.Fatalf("expected both packets on the legacy backend queue, got %d", got)
	}
}

// TestDNSInterception_ProhibitedDestinationIsNotIntercepted proves interception
// never turns a prohibited destination into an answer: the existing drop runs
// before the DNS handler, so a private address on port 53 is still refused and
// never reaches the resolver or the backend.
func TestDNSInterception_ProhibitedDestinationIsNotIntercepted(t *testing.T) {
	fwd, _, _, _ := setupForwarderWithPBR(t)

	backendID := int64(303)
	fwd.AttachBackendDevice(backendID, newMockPacketDev())

	handler := &recordingDNSHandler{}
	fwd.SetDNSHandler(handler)

	peerKey := "peer-dns-prohibited"
	clientIP := "10.100.0.27"
	path := newTestCaptureReturnPath()
	fwd.RegisterSessionWithReturnPath("s-dns-prohibited", "c-dns-prohibited", peerKey, clientIP, backendID, path.path)

	pkt := buildTestIPv4UDPPacket(netip.MustParseAddr(clientIP), netip.MustParseAddr("192.168.50.1"), 43000, 53, []byte("dns-query"))
	if err := fwd.RouteClientToBackend(peerKey, pkt); err == nil {
		t.Fatal("prohibited destination on port 53 was accepted")
	}
	if got := handler.calls.Load(); got != 0 {
		t.Fatalf("prohibited destination was intercepted %d times", got)
	}
	if got := len(fwd.backendQueues[backendID]); got != 0 {
		t.Fatalf("prohibited destination was queued toward the backend %d times", got)
	}
}

// TestDNSInterception_LegacyServesGatewayDNSOnly proves the dispatch contract at
// the forwarder boundary: while policy routing is inactive an installed responder
// is consulted only for the designated gateway address on port 53. External port
// 53 keeps its legacy path and never reaches the responder.
func TestDNSInterception_LegacyServesGatewayDNSOnly(t *testing.T) {
	fwd := NewForwarder(nil, "10.100.0.0/16", 100)
	fwd.SetPBREnabled(false)
	gateway := netip.MustParseAddr("10.100.0.1")
	fwd.SetGatewayDNSIP(gateway)

	backendID := int64(304)
	fwd.AttachBackendDevice(backendID, newMockPacketDev())

	handler := &recordingDNSHandler{}
	fwd.SetDNSHandler(handler)

	peerKey := "peer-dns-legacy"
	clientIP := "10.100.0.28"
	path := newTestCaptureReturnPath()
	fwd.RegisterSessionWithReturnPath("s-dns-legacy", "c-dns-legacy", peerKey, clientIP, backendID, path.path)

	cases := []struct {
		name          string
		dst           netip.Addr
		dstPort       uint16
		wantIntercept bool
	}{
		{"gateway resolver", gateway, 53, true},
		{"external resolver", netip.MustParseAddr("8.8.8.8"), 53, false},
		{"gateway non-dns port", gateway, 443, false},
	}

	for i, tc := range cases {
		queuedBefore := len(fwd.backendQueues[backendID])
		callsBefore := handler.calls.Load()
		pkt := buildTestIPv4UDPPacket(netip.MustParseAddr(clientIP), tc.dst, uint16(44000+i), tc.dstPort, []byte("payload"))
		if err := fwd.RouteClientToBackend(peerKey, pkt); err != nil {
			t.Fatalf("%s: route failed: %v", tc.name, err)
		}
		intercepted := handler.calls.Load() == callsBefore+1
		if intercepted != tc.wantIntercept {
			t.Fatalf("%s: intercepted=%v, want %v", tc.name, intercepted, tc.wantIntercept)
		}
		if queued := len(fwd.backendQueues[backendID]) - queuedBefore; intercepted && queued != 0 {
			t.Fatalf("%s: intercepted packet was also queued toward the backend", tc.name)
		} else if !intercepted && queued != 1 {
			t.Fatalf("%s: non-intercepted packet was not queued toward the backend", tc.name)
		}
	}
}

// TestDNSInterception_ActivePolicyInterceptsPort53Only proves that while policy
// routing is active every plain DNS packet is submitted to the policy resolver
// whatever its destination, while other ports keep their ordinary routing.
func TestDNSInterception_ActivePolicyInterceptsPort53Only(t *testing.T) {
	fwd, _, _, _ := setupForwarderWithPBR(t)

	backendID := int64(302)
	fwd.AttachBackendDevice(backendID, newMockPacketDev())

	handler := &recordingDNSHandler{}
	fwd.SetDNSHandler(handler)

	peerKey := "peer-dns-active"
	clientIP := "10.100.0.26"
	path := newTestCaptureReturnPath()
	fwd.RegisterSessionWithReturnPath("s-dns-active", "c-dns-active", peerKey, clientIP, backendID, path.path)

	cases := []struct {
		name          string
		dst           string
		dstPort       uint16
		wantIntercept bool
	}{
		{"foreign resolver", "8.8.8.8", 53, true},
		{"gateway resolver", "10.100.0.1", 53, true},
		{"foreign non-dns port", "8.8.8.8", 443, false},
		{"dns on a non-53 port", "8.8.8.8", 5353, false},
	}

	for i, tc := range cases {
		queuedBefore := len(fwd.backendQueues[backendID])
		callsBefore := handler.calls.Load()
		pkt := buildTestIPv4UDPPacket(netip.MustParseAddr(clientIP), netip.MustParseAddr(tc.dst), uint16(42000+i), tc.dstPort, []byte("payload"))
		if err := fwd.RouteClientToBackend(peerKey, pkt); err != nil {
			t.Fatalf("%s: route failed: %v", tc.name, err)
		}
		intercepted := handler.calls.Load() == callsBefore+1
		if intercepted != tc.wantIntercept {
			t.Fatalf("%s: intercepted=%v, want %v", tc.name, intercepted, tc.wantIntercept)
		}
		if queued := len(fwd.backendQueues[backendID]) - queuedBefore; intercepted && queued != 0 {
			t.Fatalf("%s: intercepted packet was also queued toward the backend", tc.name)
		} else if !intercepted && queued != 1 {
			t.Fatalf("%s: non-intercepted packet was not queued toward the backend", tc.name)
		}
	}
}
