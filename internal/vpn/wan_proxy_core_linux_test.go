//go:build linux

package vpn

// Userspace control for the proxy half of the S4 qualification.
//
// The full S4 body calls newS4Fixture(), which creates a veth pair and a peer
// network namespace, so it can only run on a runner with root and namespaces. The
// proxy half that fails does not need any of that: it is a userspace gVisor netstack
// driven through the production Forwarder pumps. Everything here is the SAME
// production object graph the S4 body builds, with no namespace, veth, TUN device,
// sysctl, sudo or external traffic.
//
// Two tests, deliberately separate, because they answer different questions:
//
//   - TestS4ProxyBackendStackAnswersTheClientDatagram proves the backend stack itself
//     echoes a datagram shaped exactly as the S4 body sends one.
//   - TestS4ProxyCoreMovesPacketThroughPumps proves the production dispatch ->
//     pumpBackendQueue -> device.Write -> echo -> device.Read -> RouteBackendToClient
//     -> pumpClientQueue -> ReturnPath chain delivers that echo to the owning peer.
//
// A pass of both places any remaining S4 failure in the namespace-dependent wiring
// that only the hosted topology supplies.

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

// TestS4ProxyBackendStackAnswersTheClientDatagram isolates the backend stack: write one
// datagram with the S4 body's own addresses and expect the echo back on the same device.
func TestS4ProxyBackendStackAnswersTheClientDatagram(t *testing.T) {
	dev, stop, err := s4BuildBackendEcho()
	if err != nil {
		t.Fatalf("build backend echo device: %v", err)
	}
	defer stop()
	t.Logf("backend device: %T (userspace netstack; no /dev/net/tun, no namespace)", dev)

	replies := make(chan []byte, 4)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, readErr := dev.Read(buf)
			if readErr != nil {
				return
			}
			if n < 28 || buf[0]>>4 != 4 {
				continue
			}
			cp := make([]byte, n)
			copy(cp, buf[:n])
			replies <- cp
		}
	}()

	// Exactly the datagram the S4 body routes: the proxied client -> UNKNOWN dst:53.
	pkt := s4UDPPacketWithChecksums(
		netip.MustParseAddr(s4ProxyBackendClientIP), s4ProxyDstIP, 5555, 53, []byte("proxy-probe"))
	if n, writeErr := dev.Write(pkt); writeErr != nil || n == 0 {
		t.Fatalf("inject into the backend stack: n=%d err=%v", n, writeErr)
	}

	select {
	case reply := <-replies:
		src, dst := netipAddrAt(reply, 12), netipAddrAt(reply, 16)
		payload := string(reply[28:])
		t.Logf("echo: src=%s dst=%s payload=%q", src, dst, payload)
		if payload != "ECHO:proxy-probe" {
			t.Fatalf("echo payload = %q, want %q", payload, "ECHO:proxy-probe")
		}
		if dst != s4ProxyBackendClientIP {
			t.Fatalf("echo destination = %s, want the client %s", dst, s4ProxyBackendClientIP)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the backend stack did not answer the injected client datagram within 5s")
	}
}

// TestS4ProxyCoreMovesPacketThroughPumps drives the production chain and requires the
// echo to reach the owning peer's ReturnPath.
func TestS4ProxyCoreMovesPacketThroughPumps(t *testing.T) {
	backendDev, stopBackend, err := s4BuildBackendEcho()
	if err != nil {
		t.Fatalf("build backend echo device: %v", err)
	}
	defer stopBackend()

	fwd := forwarder.NewForwarder(nil, "10.100.0.0/16", 100)
	fwd.AttachBackendDevice(s4ProxyBackendID, backendDev)

	replies := newS4PeerReplies()
	path := forwarder.NewReturnPath(func(peerKey, assignedIP string, packet []byte) (int, error) {
		replies.add(peerKey, packet)
		return len(packet), nil
	})
	fwd.RegisterSessionWithReturnPath("sess-proxy", "conn-proxy", "peer-s4-proxy",
		s4ProxyBackendClientIP, s4ProxyBackendID, path)

	fwd.StartPumps(context.Background())
	defer fwd.StopPumps()

	// The production reader drains the backend device into the return path, exactly as
	// the service does for a real backend tunnel.
	go func() {
		buf := make([]byte, 2048)
		for {
			n, readErr := backendDev.Read(buf)
			if readErr != nil {
				return
			}
			if n < 20 || buf[0]>>4 != 4 {
				continue
			}
			_ = fwd.RouteBackendToClient(s4ProxyBackendID, buf[:n],
				netip.AddrFrom4([4]byte{buf[16], buf[17], buf[18], buf[19]}).String())
		}
	}()

	pkt := s4UDPPacketWithChecksums(
		netip.MustParseAddr(s4ProxyBackendClientIP), s4ProxyDstIP, 5555, 53, []byte("proxy-probe"))
	if err := fwd.RouteClientToBackend("peer-s4-proxy", pkt); err != nil {
		t.Fatalf("route the proxied client packet: %v", err)
	}

	reply, ok := s4WaitReplyPrefix(replies, "peer-s4-proxy", "ECHO:proxy-probe", 5*time.Second)
	if !ok {
		t.Fatalf("no proxy reply reached the owning peer through the production pumps; packets delivered: %d",
			len(replies.packets("peer-s4-proxy")))
	}
	t.Logf("reply reached the owning peer: src=%s dst=%s", netipAddrAt(reply, 12), netipAddrAt(reply, 16))
}

// netipAddrAt renders the IPv4 address at off as a dotted quad.
func netipAddrAt(pkt []byte, off int) string {
	if len(pkt) < off+4 {
		return "<short>"
	}
	return netip.AddrFrom4([4]byte{pkt[off], pkt[off+1], pkt[off+2], pkt[off+3]}).String()
}

// TestS4PayloadOffset pins the offset rule the waiter depends on, including the two
// shapes the S4 body actually uses: a UDP echo (20 + 8) and a TCP echo (20 + 20).
func TestS4PayloadOffset(t *testing.T) {
	udp := s4UDPPacketWithChecksums(netip.MustParseAddr("10.100.0.12"),
		s4ProxyDstIP, 5555, 53, []byte("ECHO:proxy-probe"))
	if off, ok := s4PayloadOffset(udp); !ok || off != 28 {
		t.Fatalf("UDP payload offset = %d (ok=%v), want 28", off, ok)
	}
	if got := string(udp[28:]); got != "ECHO:proxy-probe" {
		t.Fatalf("derived UDP payload = %q", got)
	}

	tcp := buildTestPBRTCPPacket(netip.MustParseAddr("10.100.0.11"), s4ProxyDstIP, 23456, 8080, []byte("ECHO:s4-tcp-probe"))
	if off, ok := s4PayloadOffset(tcp); !ok || off != 40 {
		t.Fatalf("TCP payload offset = %d (ok=%v), want 40", off, ok)
	}
	if got := string(tcp[40:]); got != "ECHO:s4-tcp-probe" {
		t.Fatalf("derived TCP payload = %q", got)
	}

	for name, pkt := range map[string][]byte{
		"empty":         nil,
		"short":         {0x45},
		"not IPv4":      {0x65, 0, 0, 0, 0, 0, 0, 0, 0, 17},
		"unknown proto": makeUnknownProtoPacket(),
	} {
		if off, ok := s4PayloadOffset(pkt); ok {
			t.Fatalf("%s: expected no offset, got %d", name, off)
		}
	}
}

// makeUnknownProtoPacket builds a minimal IPv4 header carrying a protocol byte that is
// neither TCP nor UDP, so the offset rule must decline to guess.
func makeUnknownProtoPacket() []byte {
	p := make([]byte, 28)
	p[0] = 0x45
	p[9] = 99
	return p
}
