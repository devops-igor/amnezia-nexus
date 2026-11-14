//go:build with_utls

package handlers

// Authentic AWG traffic qualification at the PRODUCTION device and canary.
//
// The AWG branch of production qualification is not an application exchange. It runs the
// in-tunnel packet canary (`tunnel.ProbePacketDevice`): a real ICMP echo to 1.1.1.1 with a DNS
// fallback, written through the attached `PacketDevice` and answered from the far side of the
// tunnel. So authentic AWG evidence requires a real encrypted amneziawg exchange with a real
// peer whose IP stack actually answers.
//
// This fixture provides exactly that peer:
//
//	production tunnel.NewAWGClientDevice (real userspace amneziawg, allowed_ip=0.0.0.0/0)
//	  -> real UDP, real Curve25519 keys, real obfuscation parameters
//	  -> real amneziawg server device on a loopback port
//	       -> real gVisor netstack that OWNS 1.1.1.1
//	       -> a real IP stack answers the echo, and the reply travels back encrypted
//
// Fixture boundaries, stated: the provider answer, the SSH transport to the "host" and the
// protocol installation are controlled outcomes, as in every earlier checkpoint. The traffic
// path is not among them - there is no success callback, no error callback, no destination
// override and no synthesized canary reply.
//
// Scope: the AWG qualification device and canary. Naive remains a separate applicability
// obligation, and nothing here is claimed about kernel routing.

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

// awgProbeTimeout bounds one canary attempt in these fixtures.
const awgProbeTimeout = 10 * time.Second

// awgTestDialParams are the obfuscation parameters both sides must agree on.
//
// They are deliberately the identity dialect (jc=0, no junk, magic headers 1..4) rather than
// production's defaults. A peer and a client that disagree drop the handshake silently, and
// jc>0 makes the initiation a separate junk datagram that complicates a loopback fixture
// without adding authenticity. Keys, handshake and encryption are untouched.
func awgTestDialParams() map[string]any {
	return map[string]any{
		"jc": 0, "jmin": 0, "jmax": 0, "s1": 0, "s2": 0, "s3": 0, "s4": 0,
		"h1": 1, "h2": 2, "h3": 3, "h4": 4,
	}
}

// authenticAWGPeer is a real amneziawg server device reachable on a loopback UDP port.
type authenticAWGPeer struct {
	// endpoint is host:port the production client device dials.
	endpoint string
	// serverPort is the same port as a number, for server-row dial metadata.
	serverPort int
	// serverPublicKey is the base64 key the client must target.
	serverPublicKey string
	// clientPrivateKey is the base64 private key the client must present.
	clientPrivateKey string

	dev      *device.Device
	pingConn *netstack.PingConn
	stopOnce sync.Once
}

// startAuthenticAWGPeer builds a real AWG server whose netstack owns - or, for the negative,
// does not own - the production canary destination.
//
//	answerCanary=true  -> the stack owns 1.1.1.1, so the real ICMP echo arriving through the
//	                      tunnel is answered by a real IP stack and the reply returns encrypted.
//	answerCanary=false -> the stack owns a different address, so the handshake and transport
//	                      still complete but the canary packet has no local owner and is never
//	                      answered. That is the "handshake works, payload does not" negative,
//	                      expressed through the peer's real configuration, not a hook.
func startAuthenticAWGPeer(t *testing.T, answerCanary bool) *authenticAWGPeer {
	t.Helper()

	serverPriv, serverPub := newAWGKeypair(t)
	clientPriv, clientPub := newAWGKeypair(t)

	canaryAddr := netip.MustParseAddr("1.1.1.1")
	stackAddrs := []netip.Addr{canaryAddr}
	if !answerCanary {
		stackAddrs = []netip.Addr{netip.MustParseAddr("10.99.99.99")}
	}
	tunDev, stack, err := netstack.CreateNetTUN(stackAddrs, nil, 1280)
	if err != nil {
		t.Fatalf("create AWG peer netstack: %v", err)
	}
	// A real ICMP endpoint inside the peer's stack: the peer's own IP stack is what answers,
	// not a userland copy of the packet.
	pingConn, err := stack.ListenPingAddr(canaryAddr)
	if err != nil {
		_ = tunDev.Close()
		t.Fatalf("peer ICMP endpoint on the canary address: %v", err)
	}

	dev := device.NewDevice(tunDev, conn.NewDefaultBind(),
		device.NewLogger(device.LogLevelSilent, "authentic-awg-peer"))

	// Reserve a loopback UDP port, then release it: the engine binds its own socket in Up().
	probe, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		_ = pingConn.Close()
		dev.Close()
		t.Fatalf("peer udp listen: %v", err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	_ = probe.Close()

	if err := dev.IpcSet(buildAWGPeerIPC(serverPriv, clientPub, port)); err != nil {
		_ = pingConn.Close()
		dev.Close()
		t.Fatalf("peer IpcSet: %v", err)
	}
	if err := dev.Up(); err != nil {
		_ = pingConn.Close()
		dev.Close()
		t.Fatalf("peer Up: %v", err)
	}

	peer := &authenticAWGPeer{
		endpoint:         fmt.Sprintf("127.0.0.1:%d", port),
		serverPort:       port,
		serverPublicKey:  serverPub,
		clientPrivateKey: clientPriv,
		dev:              dev,
		pingConn:         pingConn,
	}
	t.Cleanup(peer.stop)
	return peer
}

// stop tears the peer down exactly once.
func (p *authenticAWGPeer) stop() {
	if p == nil {
		return
	}
	p.stopOnce.Do(func() {
		if p.pingConn != nil {
			_ = p.pingConn.Close()
		}
		// device.Close() closes the TUN it was built on; closing that TUN again would
		// double-close the netstack's event channel and panic.
		if p.dev != nil {
			p.dev.Close()
		}
	})
}

// newAWGKeypair returns (privateBase64, publicBase64) using the repository's own Curve25519
// generator, so the encoding matches what the panel and the engine both expect.
func newAWGKeypair(t *testing.T) (string, string) {
	t.Helper()
	pub, priv, err := tunnel.GenerateCurve25519KeyPair()
	if err != nil {
		t.Fatalf("generate AWG keypair: %v", err)
	}
	return priv, pub
}

// buildAWGPeerIPC renders the server-side UAPI configuration.
//
// It mirrors the production client config: the server presents its own private key, treats the
// client's public key as its only peer, listens on the loopback port the client dials, and uses
// the same obfuscation dialect so the handshake is not silently dropped.
func buildAWGPeerIPC(serverPrivBase64, clientPubBase64 string, listenPort int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", base64ToHexKey(serverPrivBase64))
	fmt.Fprintf(&b, "listen_port=%d\n", listenPort)
	fmt.Fprintf(&b, "jc=0\njmin=0\njmax=0\n")
	fmt.Fprintf(&b, "s1=0\ns2=0\ns3=0\ns4=0\n")
	fmt.Fprintf(&b, "h1=1\nh2=2\nh3=3\nh4=4\n")
	fmt.Fprintf(&b, "public_key=%s\n", base64ToHexKey(clientPubBase64))
	fmt.Fprintf(&b, "allowed_ip=0.0.0.0/0\n")
	return b.String()
}

// base64ToHexKey converts the panel's base64 key encoding to the engine's hex UAPI encoding.
func base64ToHexKey(v string) string {
	raw, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(raw)
}

// awgPacketPump is the read surface the canary needs.
type awgPacketPump interface {
	Read([]byte) (int, error)
}

// pumpAWGDevice runs the device read loop the production forwarder runs.
//
// This is required, not optional: `probeSingleICMP` takes the `CanaryResponseDemuxer` path
// because the production AWG device implements `RegisterCanaryResponseHook`, and those hooks
// fire only from `AWGClientDevice.Read`. In production the forwarder is that reader. Without it
// the echoed reply stays queued and every probe times out for a fixture reason.
func pumpAWGDevice(ctx context.Context, dev awgPacketPump) {
	go func() {
		buf := make([]byte, 2048)
		for {
			if _, err := dev.Read(buf); err != nil {
				return
			}
			if ctx.Err() != nil {
				return
			}
		}
	}()
}

// dialProductionAWGDevice builds the exact device production builds for an AWG backend.
func dialProductionAWGDevice(t *testing.T, peer *authenticAWGPeer) *tunnel.AWGClientDevice {
	t.Helper()
	dev, err := tunnel.NewAWGClientDevice("awg-traffic-proof", peer.endpoint,
		peer.clientPrivateKey, peer.serverPublicKey, 1280, awgTestDialParams())
	if err != nil {
		t.Fatalf("create production AWG client device: %v", err)
	}
	t.Cleanup(func() { _ = dev.Close() })
	return dev
}
