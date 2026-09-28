package ingress

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"

	"github.com/devops-igor/amnezia-nexus/internal/manager/awg"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/clientawg"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/loadbalancer"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/virtualtun"
)

// This file holds the end-to-end interop coverage for issue #388: a REAL
// upstream client engine (amneziawg-go device) behind a REAL portal device
// (clientawg.ClientAWGDevice) feeding the ingress Router over its plaintext
// boundary, with a REAL forwarder underneath. It mirrors the #387 interop
// pattern (internal/vpn/clientawg/interoperability_test.go): synthetic keys,
// in-memory VirtualTUNs, localhost UDP transport, bounded waits, no readiness
// sleeps. The session-1 fakes (fakeSession/admissionCounter) are deliberately
// not reused here except through the shared buildPacket helper.
//
// Compromise documented for QA (spec-sanctioned): the backend side of the
// forwarder is a fake sink device (recordingDevice) instead of two live AWG
// backend tunnels. Driving real backends would add a second and third
// upstream engine plus handshake choreography whose only additional
// assertion — "the bytes leave the tunnel intact" — is forwarder/queue
// behavior already covered by the forwarder package's own tests. Backend
// selection semantics are asserted at the admission boundary instead
// (TestInteropBackendSelectionBothTunnels).

const (
	interopBackend1 = int64(601)
	interopBackend2 = int64(602)
	// interopPortalSubnet matches the leases used below; the forwarder only
	// consults it for the issue-#89 rebind guard, which the ingress path
	// never triggers (the router always submits packets whose source equals
	// the route's assigned IP).
	interopPortalSubnet = "10.60.0.0/24"
	interopAppDst       = "198.51.100.1"
	interopMTU          = 1280
)

// interopHandshakeTimeout bounds one fresh upstream handshake plus first
// plaintext delivery, and interopAbsenceWindow bounds "nothing was delivered"
// observations. Both are deadlines, not sleeps: a healthy localhost
// handshake completes in well under a second even under -race.
const (
	interopHandshakeTimeout = 15 * time.Second
	interopAbsenceWindow    = 400 * time.Millisecond
)

// recordingDevice is the fake backend sink at the forwarder boundary: packets
// the router submits arrive byte-exact in the channel.
type recordingDevice struct {
	ch chan []byte
}

func newRecordingDevice() *recordingDevice {
	return &recordingDevice{ch: make(chan []byte, 1024)}
}

func (d *recordingDevice) Read(p []byte) (int, error) {
	pkt, ok := <-d.ch
	if !ok {
		return 0, errors.New("recordingDevice: closed")
	}
	return copy(p, pkt), nil
}

func (d *recordingDevice) Write(p []byte) (int, error) {
	cp := make([]byte, len(p))
	copy(cp, p)
	d.ch <- cp
	return len(p), nil
}

func (d *recordingDevice) Close() error { return nil }

// interopSession and interopBackend implement the handle seams.
type interopSession struct {
	id         string
	assignedIP string
}

func (s *interopSession) SessionID() string  { return s.id }
func (s *interopSession) AssignedIP() string { return s.assignedIP }

type interopBackend struct{ id int64 }

func (b *interopBackend) TunnelID() int64 { return b.id }

// interopAdmission models the production admission surface with the two
// properties the router's contract relies on (#86): rekey-stable live-session
// reuse and serialized check-then-allocate against a per-backend capacity
// gauge. Backend selection is configured per peer before the test fires
// packets (production selects via the load balancer; that selection logic is
// loadbalancer's own coverage — here it is the test's input).
type interopAdmission struct {
	mu          sync.Mutex
	capacity    map[int64]int // backendTunnelID -> remaining peer slots
	byBackend   map[string]int64
	assignedIPs map[string]string
	mismatchIPs map[string]string // peer -> divergent session IP (fault injection)
	sessions    map[string]*interopSession
	calls       map[string]int
	totalCalls  int
	refuseFor   map[string]error // one-shot per-peer refusal
}
func newInteropAdmission(capacityPerBackend int) *interopAdmission {
	return &interopAdmission{
		capacity:    map[int64]int{interopBackend1: capacityPerBackend, interopBackend2: capacityPerBackend},
		byBackend:   make(map[string]int64),
		assignedIPs: make(map[string]string),
		mismatchIPs: make(map[string]string),
		sessions:    make(map[string]*interopSession),
		calls:       make(map[string]int),
		refuseFor:   make(map[string]error),
	}
}

// selectBackend pins a peer to a backend tunnel and records its durable IP
// (the lease a real admission resolves from the session store).
func (a *interopAdmission) selectBackend(peerPublicKey string, backendID int64, assignedIP string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.byBackend[peerPublicKey] = backendID
	a.assignedIPs[peerPublicKey] = assignedIP
}

// divergeSessionIP makes the NEXT created session for the peer report a
// wrong assigned IP — the resolver/session-store divergence the second
// ownership fence exists for.
func (a *interopAdmission) divergeSessionIP(peerPublicKey, wrongIP string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.mismatchIPs[peerPublicKey] = wrongIP
}

func (a *interopAdmission) EnsureSession(o PeerOwnership) (SessionHandle, BackendHandle, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err, ok := a.refuseFor[o.PeerPublicKey]; ok {
		delete(a.refuseFor, o.PeerPublicKey)
		return nil, nil, err
	}
	// Rekey-stable: a live session is reused, never recreated — the #86
	// contract the router's rekey stability relies on.
	if sess, ok := a.sessions[o.PeerPublicKey]; ok {
		return sess, &interopBackend{a.byBackend[o.PeerPublicKey]}, nil
	}
	a.calls[o.PeerPublicKey]++
	a.totalCalls++
	backend := a.byBackend[o.PeerPublicKey]
	if backend == 0 {
		panic("interopAdmission: peer has no backend selected")
	}
	if a.capacity[backend] <= 0 {
		// The production capacity mechanism: FilterHealthy finds no
		// backend with free slots (MaxPeersPerBackend) and admission
		// fails with ErrNoActiveBackends.
		return nil, nil, fmt.Errorf("admission: %w", loadbalancer.ErrNoActiveBackends)
	}
	assignedIP := a.assignedIPs[o.PeerPublicKey]
	if wrong, ok := a.mismatchIPs[o.PeerPublicKey]; ok {
		assignedIP = wrong
	}
	a.capacity[backend]--
	sess := &interopSession{
		id:         fmt.Sprintf("interop-sess-%d", a.totalCalls),
		assignedIP: assignedIP,
	}
	a.sessions[o.PeerPublicKey] = sess
	return sess, &interopBackend{backend}, nil
}

func (a *interopAdmission) callsFor(peerPublicKey string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.calls[peerPublicKey]
}

// sessionID returns the peer's live session ID ("" when none exists).
func (a *interopAdmission) sessionID(peerPublicKey string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if sess, ok := a.sessions[peerPublicKey]; ok {
		return sess.id
	}
	return ""
}

// interopFixture wires the full plaintext ingress path under test:
//
//	upstream engine(s) -> clientawg.ClientAWGDevice (portal) -> Router ->
//	forwarder.Forwarder -> recordingDevice sinks on both backend tunnels.
type interopFixture struct {
	portal    *clientawg.ClientAWGDevice
	publicKey string // the portal device's real public key
	router    *Router
	resolver  *Resolver
	admission *interopAdmission
	fwd       *forwarder.Forwarder
	backend1  *recordingDevice
	backend2  *recordingDevice
}

func newInteropFixture(t *testing.T, portalPeers []clientawg.Peer, admission *interopAdmission, resolver *Resolver) *interopFixture {
	t.Helper()
	private, public := interopKeys(t)
	portal, err := clientawg.NewDevice(clientawg.Config{
		PrivateKey: private,
		PublicKey:  public,
		TUN:        virtualtun.Config{Name: "interop-portal", MTU: interopMTU},
		Peers:      portalPeers,
	})
	if err != nil {
		t.Fatalf("portal device: %v", err)
	}
	t.Cleanup(func() { _ = portal.Close() })

	fwd := forwarder.NewForwarder(nil, interopPortalSubnet)
	be1, be2 := newRecordingDevice(), newRecordingDevice()
	fwd.AttachBackendDevice(interopBackend1, be1)
	fwd.AttachBackendDevice(interopBackend2, be2)
	// Real forwarder, real pumps: RouteClientToBackend only enqueues; the
	// backend pump is what moves queued packets to the sink device (the
	// same pump production runs).
	fwd.StartPumps(t.Context())

	router := NewRouter(resolver, admission, fwd, nil)
	return &interopFixture{
		portal:    portal,
		publicKey: public,
		router:    router,
		resolver:  resolver,
		admission: admission,
		fwd:       fwd,
		backend1:  be1,
		backend2:  be2,
	}
}

// seedPeer registers a peer end to end: durable resolver lease + admission
// backend selection. The portal-side peer must already exist (constructed
// with the device). Returns the peer's assigned /32.
func (f *interopFixture) seedPeer(t *testing.T, peerPublicKey, assignedIP string, backendID int64) netip.Prefix {
	t.Helper()
	ip := netip.MustParseAddr(assignedIP)
	if err := f.resolver.Update(PeerOwnership{
		PeerPublicKey: peerPublicKey,
		ConnectionID:  fmt.Sprintf("interop-conn-%s", assignedIP),
		UserID:        "interop-user",
		IP:            ip,
	}); err != nil {
		t.Fatalf("seed resolver lease for %s: %v", assignedIP, err)
	}
	f.admission.selectBackend(peerPublicKey, backendID, assignedIP)
	return netip.PrefixFrom(ip, 32)
}

// upstreamClient is one real amneziawg-go engine bound to an in-memory TUN.
type upstreamClient struct {
	dev *device.Device
	vt  *virtualtun.VirtualTUN
}

func (uc *upstreamClient) inject(t *testing.T, pkt []byte) {
	t.Helper()
	if err := uc.vt.InjectInbound(pkt); err != nil {
		t.Fatalf("upstream inject: %v", err)
	}
}

// startUpstreamClient builds a real upstream engine from a Nexus-generated
// config (#387 pattern) bound to the fixture's real portal identity. The
// caller injects application packets into the returned engine; a handshake
// is initiated by the first send.
func (f *interopFixture) startUpstreamClient(t *testing.T, clientPrivate, clientIP, name string) *upstreamClient {
	t.Helper()
	endpoint := fmt.Sprintf("127.0.0.1:%d", f.portalListenPort(t))
	saved := awg.RenderClientConfig(clientPrivate, clientIP, f.publicKey, "", endpoint, "", "", "1280", &awg.AWGParams{}, nil)
	vt, err := virtualtun.New(virtualtun.Config{Name: name, MTU: interopMTU})
	if err != nil {
		t.Fatal(err)
	}
	dev := device.NewDevice(vt, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, name))
	uc := &upstreamClient{dev: dev, vt: vt}
	t.Cleanup(dev.Close)
	if err := dev.IpcSet(configToUAPI(t, saved)); err != nil {
		t.Fatal("upstream rejected saved generated configuration")
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}
	return uc
}

func (f *interopFixture) portalListenPort(t *testing.T) int {
	t.Helper()
	status, err := f.portal.Status()
	if err != nil {
		t.Fatalf("portal status: %v", err)
	}
	if status.ListenPort == 0 {
		t.Fatal("portal listen port missing")
	}
	return status.ListenPort
}

// startPump continuously moves plaintext from the portal boundary into the
// router until the test ends — the standing stand-in for #393's receive
// loop. Errors are intentionally ignored: drops (including capacity
// rejections) are the router's classified, counted outcomes and are asserted
// through StatsSnapshot, not pump plumbing.
func (f *interopFixture) startPump(t *testing.T) {
	t.Helper()
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	go func() {
		for {
			select {
			case <-done:
				return
			default:
			}
			pkt, err := f.portal.ReceiveOutbound()
			if err != nil {
				return
			}
			_ = f.router.HandlePacket(append([]byte(nil), pkt...))
		}
	}()
}

func interopKeys(t *testing.T) (string, string) {
	t.Helper()
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(private.Bytes()), base64.StdEncoding.EncodeToString(private.PublicKey().Bytes())
}

// configToUAPI is #387's test adapter for the wg-quick fields emitted by
// Nexus. It translates syntax, never changes the saved configuration's
// values. Address, DNS and MTU are host-interface settings; the in-memory
// test TUN supplies the MTU.
func configToUAPI(t *testing.T, saved string) string {
	t.Helper()
	names := map[string]string{
		"PrivateKey": "private_key", "PublicKey": "public_key", "PresharedKey": "preshared_key",
		"HeaderProtectionKey": "header_protection_key", "ContentPaddingAddition": "content_padding_addition",
		"RekeyAfterTime": "rekey_after_time", "RekeyTimeout": "rekey_timeout", "RejectAfterTime": "reject_after_time",
		"KeepaliveTimeout": "keepalive_timeout", "MaxHandshakeAttempts": "max_handshake_attempts",
		"PersistentKeepalive": "persistent_keepalive_interval", "Endpoint": "endpoint", "ListenPort": "listen_port",
		"RandomTrailers": "random_trailers", "DisableCookies": "disable_cookies",
	}
	var out strings.Builder
	for _, line := range strings.Split(saved, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "[") || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatal("malformed generated config line")
		}
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		if name == "Address" || name == "DNS" || name == "MTU" {
			continue
		}
		if name == "AllowedIPs" {
			for _, ip := range strings.Split(value, ",") {
				fmt.Fprintf(&out, "allowed_ip=%s\n", strings.TrimSpace(ip))
			}
			continue
		}
		target, ok := names[name]
		if !ok {
			switch name {
			case "Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5":
				target = strings.ToLower(name)
			default:
				t.Fatalf("unhandled generated config field %s", name)
			}
		}
		switch name {
		case "PrivateKey", "PublicKey", "PresharedKey", "HeaderProtectionKey":
			key, err := base64.StdEncoding.DecodeString(value)
			if err != nil || len(key) != 32 {
				t.Fatalf("invalid generated %s", name)
			}
			value = hex.EncodeToString(key)
		case "RandomTrailers", "DisableCookies":
			if value == "on" {
				value = "true"
			}
			if value == "off" {
				value = "false"
			}
		}
		fmt.Fprintf(&out, "%s=%s\n", target, value)
	}
	return out.String()
}

// interopUDPPacket is a valid UDP/IPv4 datagram with a marker in the payload
// (the #387 helper, repeated test-locally because that file anchors a
// different package).
func interopUDPPacket(src, dst netip.Addr, marker uint32) []byte {
	p := make([]byte, 32)
	p[0], p[8], p[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	copy(p[12:16], src.AsSlice())
	copy(p[16:20], dst.AsSlice())
	binary.BigEndian.PutUint16(p[20:22], 40000)
	binary.BigEndian.PutUint16(p[22:24], 40001)
	binary.BigEndian.PutUint16(p[24:26], 12)
	binary.BigEndian.PutUint32(p[28:], marker)
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(p[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(p[10:12], ^uint16(sum))
	return p
}

// awaitBackendPacket fails the test unless a byte-exact copy of want reaches
// the backend sink within timeout.
func awaitBackendPacket(t *testing.T, sink *recordingDevice, want []byte, timeout time.Duration) {
	t.Helper()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		select {
		case pkt := <-sink.ch:
			if bytes.Equal(pkt, want) {
				return
			}
			// Unrelated traffic on this sink: keep waiting.
		case <-deadline.C:
			t.Fatalf("expected packet (src %s) missing at backend sink within %s", netip.AddrFrom4([4]byte{want[12], want[13], want[14], want[15]}), timeout)
		}
	}
}

// assertNoBackendPacket fails the test if a byte-exact copy of want reaches
// the sink within the absence window.
func assertNoBackendPacket(t *testing.T, sink *recordingDevice, want []byte, label string) {
	t.Helper()
	deadline := time.NewTimer(interopAbsenceWindow)
	defer deadline.Stop()
	for {
		select {
		case pkt := <-sink.ch:
			if bytes.Equal(pkt, want) {
				t.Fatalf("%s reached the backend sink (defense failed)", label)
			}
		case <-deadline.C:
			return
		}
	}
}

// TestInteropMultiPeerRoutingToRealForwarder is acceptance criterion 1: three
// peers with distinct assigned /32s, each behind its own REAL upstream engine;
// application traffic from each peer crosses the real portal device, is
// admitted by the router, and reaches the backend route through the real
// forwarder byte-exact — with exactly one admission per peer.
func TestInteropMultiPeerRoutingToRealForwarder(t *testing.T) {
	admission := newInteropAdmission(8)
	resolver := NewResolver()

	const peers = 3
	clientPrivs := make([]string, peers)
	clientPubs := make([]string, peers)
	portalPeers := make([]clientawg.Peer, 0, peers)
	ips := make([]netip.Addr, peers)
	for i := range clientPrivs {
		clientPrivs[i], clientPubs[i] = interopKeys(t)
		ips[i] = netip.AddrFrom4([4]byte{10, 60, 0, byte(i + 2)})
		portalPeers = append(portalPeers, clientawg.Peer{PublicKey: clientPubs[i], AllowedIP: netip.PrefixFrom(ips[i], 32)})
	}

	fx := newInteropFixture(t, portalPeers, admission, resolver)
	for i := range clientPubs {
		fx.seedPeer(t, clientPubs[i], ips[i].String(), interopBackend1)
	}
	fx.startPump(t)

	for i := range clientPrivs {
		uc := fx.startUpstreamClient(t, clientPrivs[i], ips[i].String(), fmt.Sprintf("interop-multi-%d", i))
		uc.inject(t, interopUDPPacket(ips[i], netip.MustParseAddr(interopAppDst), uint32(0x3880+i)))
		want := interopUDPPacket(ips[i], netip.MustParseAddr(interopAppDst), uint32(0x3880+i))
		awaitBackendPacket(t, fx.backend1, want, interopHandshakeTimeout)

		if got := admission.callsFor(clientPubs[i]); got != 1 {
			t.Fatalf("peer %d: admission ran %d times, want 1", i, got)
		}
		if got := fx.fwd.RouteSessionID(clientPubs[i]); got != admission.sessionID(clientPubs[i]) || got == "" {
			t.Fatalf("peer %d: forwarder route session %q does not match admitted session %q", i, got, admission.sessionID(clientPubs[i]))
		}
	}

	stats := fx.router.StatsSnapshot()
	if stats.AdmittedSessions != peers {
		t.Fatalf("AdmittedSessions = %d, want %d", stats.AdmittedSessions, peers)
	}
	if stats.OwnershipMismatchDrops != 0 || stats.UnmappedSourceIPDrops != 0 || stats.MalformedPacketDrops != 0 {
		t.Fatalf("unexpected drops on the happy path: %+v", stats)
	}
	if _, _, routes := fx.fwd.GetStats(); routes != peers {
		t.Fatalf("forwarder holds %d routes, want %d", routes, peers)
	}
}

// TestInteropBackendSelectionBothTunnels is acceptance criterion 2: peer A is
// admitted onto backend tunnel 1, peer B onto backend tunnel 2 (selection is
// modeled at the admission boundary — see the file-level compromise note) and
// each peer's traffic surfaces ONLY on its own tunnel's sink.
func TestInteropBackendSelectionBothTunnels(t *testing.T) {
	admission := newInteropAdmission(8)
	resolver := NewResolver()

	// Key pairs are generated as (private, public) pairs ONCE: the portal
	// authorizes the public key whose matching private key the engine uses.
	privA, pubA := interopKeys(t)
	privB, pubB := interopKeys(t)
	ipA := netip.MustParseAddr("10.60.0.20")
	ipB := netip.MustParseAddr("10.60.0.21")
	portalPeers := []clientawg.Peer{
		{PublicKey: pubA, AllowedIP: netip.PrefixFrom(ipA, 32)},
		{PublicKey: pubB, AllowedIP: netip.PrefixFrom(ipB, 32)},
	}

	fx := newInteropFixture(t, portalPeers, admission, resolver)
	fx.seedPeer(t, pubA, ipA.String(), interopBackend1)
	fx.seedPeer(t, pubB, ipB.String(), interopBackend2)
	fx.startPump(t)

	ucA := fx.startUpstreamClient(t, privA, ipA.String(), "interop-be-a")
	ucB := fx.startUpstreamClient(t, privB, ipB.String(), "interop-be-b")

	dst := netip.MustParseAddr(interopAppDst)
	pktA := interopUDPPacket(ipA, dst, 0x388000A1)
	pktB := interopUDPPacket(ipB, dst, 0x388000B2)
	ucA.inject(t, pktA)
	ucB.inject(t, pktB)

	awaitBackendPacket(t, fx.backend1, pktA, interopHandshakeTimeout)
	awaitBackendPacket(t, fx.backend2, pktB, interopHandshakeTimeout)

	// Cross-tunnel isolation: A's traffic never surfaces on backend 2 and
	// vice versa (checked after both deliveries settled).
	assertNoBackendPacket(t, fx.backend2, pktA, "peer A packet on backend 2")
	assertNoBackendPacket(t, fx.backend1, pktB, "peer B packet on backend 1")

	// The route each admission produced is bound to the selected tunnel.
	if got := fx.fwd.RouteSessionID(pubA); got != admission.sessionID(pubA) {
		t.Fatalf("peer A route session %q, want admitted %q", got, admission.sessionID(pubA))
	}
	if got := fx.fwd.RouteSessionID(pubB); got != admission.sessionID(pubB) {
		t.Fatalf("peer B route session %q, want admitted %q", got, admission.sessionID(pubB))
	}
	stats := fx.router.StatsSnapshot()
	if stats.AdmittedSessions != 2 {
		t.Fatalf("AdmittedSessions = %d, want 2", stats.AdmittedSessions)
	}
}

// TestInteropRekeyStableThroughRealHandshake is acceptance criterion 3: the
// upstream transport session is replaced (a second REAL engine with the same
// identity completes a fresh handshake), and the Nexus route session ID and
// admission count must not change: no second admission, no route mutation.
func TestInteropRekeyStableThroughRealHandshake(t *testing.T) {
	admission := newInteropAdmission(8)
	resolver := NewResolver()

	privKey, pubKey := interopKeys(t)
	ip := netip.MustParseAddr("10.60.0.30")
	portalPeers := []clientawg.Peer{{PublicKey: pubKey, AllowedIP: netip.PrefixFrom(ip, 32)}}

	fx := newInteropFixture(t, portalPeers, admission, resolver)
	fx.seedPeer(t, pubKey, ip.String(), interopBackend1)
	fx.startPump(t)

	dst := netip.MustParseAddr(interopAppDst)
	first := interopUDPPacket(ip, dst, 0x38800001)
	rekey := interopUDPPacket(ip, dst, 0x38800002)

	// First engine: fresh handshake, admission, routing.
	uc1 := fx.startUpstreamClient(t, privKey, ip.String(), "interop-rekey-1")
	uc1.inject(t, first)
	awaitBackendPacket(t, fx.backend1, first, interopHandshakeTimeout)

	sessionBefore := admission.sessionID(pubKey)
	routeBefore := fx.fwd.RouteSessionID(pubKey)
	if sessionBefore == "" || routeBefore != sessionBefore {
		t.Fatalf("pre-rekey state: session %q route %q", sessionBefore, routeBefore)
	}
	if got := admission.callsFor(pubKey); got != 1 {
		t.Fatalf("admission ran %d times before rekey, want 1", got)
	}

	// Upstream rekey: the first engine disappears (its transport dies with
	// the closed socket) and an identical engine — same private key, same
	// leased IP, NEW transport session — completes a fresh handshake with
	// the portal. Nexus never sees any of this: only continued plaintext
	// from the same assigned IP.
	uc1.dev.Close()
	uc2 := fx.startUpstreamClient(t, privKey, ip.String(), "interop-rekey-2")
	uc2.inject(t, rekey)
	awaitBackendPacket(t, fx.backend1, rekey, interopHandshakeTimeout)

	if got := admission.callsFor(pubKey); got != 1 {
		t.Fatalf("admission ran %d times across the rekey, want 1", got)
	}
	if got := admission.sessionID(pubKey); got != sessionBefore {
		t.Fatalf("Nexus session changed across rekey: %q -> %q", sessionBefore, got)
	}
	if got := fx.fwd.RouteSessionID(pubKey); got != routeBefore {
		t.Fatalf("route session ID changed across rekey: %q -> %q", routeBefore, got)
	}
	if stats := fx.router.StatsSnapshot(); stats.AdmittedSessions != 1 {
		t.Fatalf("AdmittedSessions = %d after rekey, want 1", stats.AdmittedSessions)
	}
}

// TestInteropWrongSourceAndRevokedLeaseDefense covers acceptance criteria 4
// and 5 at the full-stack boundary:
//
//  1. admission-time ownership divergence (the resolver/session-store
//     disagreement the upstream engine cannot prevent): the real packet is
//     dropped, counted as ownership_mismatch, and no route is created.
//  2. a crafted wrong-source plaintext aimed at an already-admitted peer
//     (what fence #2/#3 are for once the upstream AllowedIPs fence is gone):
//     dropped by the forwarder's #89 spoof guard, zero route mutation.
//  3. unknown source: a revoked lease (#391 Remove) turns the peer's next
//     REAL packet into an unmapped drop with no re-admission; a crafted
//     packet from an unowned address is likewise dropped and counted.
func TestInteropWrongSourceAndRevokedLeaseDefense(t *testing.T) {
	admission := newInteropAdmission(8)
	resolver := NewResolver()

	privM, pubM := interopKeys(t)
	privA, pubA := interopKeys(t)
	privB, pubB := interopKeys(t)
	ipA := netip.MustParseAddr("10.60.0.40")
	ipB := netip.MustParseAddr("10.60.0.41")
	ipM := netip.MustParseAddr("10.60.0.42")
	portalPeers := []clientawg.Peer{
		{PublicKey: pubA, AllowedIP: netip.PrefixFrom(ipA, 32)},
		{PublicKey: pubB, AllowedIP: netip.PrefixFrom(ipB, 32)},
		{PublicKey: pubM, AllowedIP: netip.PrefixFrom(ipM, 32)},
	}

	fx := newInteropFixture(t, portalPeers, admission, resolver)
	fx.seedPeer(t, pubA, ipA.String(), interopBackend1)
	fx.seedPeer(t, pubB, ipB.String(), interopBackend1)
	fx.seedPeer(t, pubM, ipM.String(), interopBackend1)
	fx.startPump(t)
	dst := netip.MustParseAddr(interopAppDst)

	// Scenario 1: admission divergence for peer M. Upstream AllowedIPs is
	// fence #1 and CANNOT prevent this: the packet's source genuinely
	// matches M's durable lease — it is the admission result that
	// disagrees with the resolver. The router must drop, count, and never
	// route.
	admission.divergeSessionIP(pubM, "10.60.0.99")
	ucM := fx.startUpstreamClient(t, privM, ipM.String(), "interop-mismatch")
	mPkt := interopUDPPacket(ipM, dst, 0x388000A1)
	ucM.inject(t, mPkt)
	// The packet is in flight through the real engine/UDP/portal pipeline;
	// wait (bounded) for the drop to be counted.
	mismatchDeadline := time.NewTimer(interopHandshakeTimeout)
	defer mismatchDeadline.Stop()
	for {
		if stats := fx.router.StatsSnapshot(); stats.OwnershipMismatchDrops == 1 {
			break
		}
		select {
		case <-mismatchDeadline.C:
			t.Fatalf("mismatch drop never counted; stats = %+v", fx.router.StatsSnapshot())
		case <-time.After(50 * time.Millisecond):
		}
	}
	if _, _, routes := fx.fwd.GetStats(); routes != 0 {
		t.Fatalf("forwarder holds %d routes after mismatch, want 0", routes)
	}
	stats := fx.router.StatsSnapshot()
	if stats.AdmittedSessions != 0 {
		t.Fatalf("mismatch stats = %+v, want 0 admitted", stats)
	}
	if got := admission.callsFor(pubM); got != 1 {
		t.Fatalf("mismatched peer admission ran %d times, want 1", got)
	}

	// Peers A and B are admitted for real: each behind its own engine,
	// each routed to its own backend sink, establishing live route state
	// for the wrong-source and revocation scenarios below.
	ucA := fx.startUpstreamClient(t, privA, ipA.String(), "interop-spoof-a")
	ucB := fx.startUpstreamClient(t, privB, ipB.String(), "interop-spoof-b")
	pktA := interopUDPPacket(ipA, dst, 0x388000A2)
	pktB := interopUDPPacket(ipB, dst, 0x388000B1)
	ucA.inject(t, pktA)
	ucB.inject(t, pktB)
	awaitBackendPacket(t, fx.backend1, pktA, interopHandshakeTimeout)
	awaitBackendPacket(t, fx.backend1, pktB, interopHandshakeTimeout)
	routeA, routeB := fx.fwd.RouteSessionID(pubA), fx.fwd.RouteSessionID(pubB)

	// Scenario 2: fence #1 at the engine boundary. A real portal engine
	// enforces cryptokey routing on its decrypt path — a peer's plaintext
	// may only carry that peer's assigned /32 as source — so a wrong-source
	// packet (B's engine emitting A's address) is silently discarded by the
	// portal engine itself and never reaches the router. The ingress
	// boundary must not depend on this: it keeps its own fences (the
	// admission divergence above, resolver membership below) for exactly
	// the states AllowedIPs cannot see.
	wrongSrc := interopUDPPacket(ipA, dst, 0x388000B2)
	ucB.inject(t, wrongSrc)
	assertNoBackendPacket(t, fx.backend1, wrongSrc, "wrong-source packet")
	assertNoBackendPacket(t, fx.backend2, wrongSrc, "wrong-source packet")
	if fx.fwd.RouteSessionID(pubA) != routeA || fx.fwd.RouteSessionID(pubB) != routeB {
		t.Fatal("route state mutated by a wrong-source packet")
	}
	if admission.callsFor(pubA) != 1 || admission.callsFor(pubB) != 1 {
		t.Fatal("wrong-source packet triggered re-admission")
	}
	if stats := fx.router.StatsSnapshot(); stats.OwnershipMismatchDrops != 1 {
		t.Fatalf("OwnershipMismatchDrops = %d, want still 1 (engine fence, not router)", stats.OwnershipMismatchDrops)
	}

	// Scenario 3a: revoking B's durable lease (#391 Remove) must turn B's
	// next REAL packet into an unmapped drop, with no re-admission.
	if _, ok := fx.resolver.Remove(pubB); !ok {
		t.Fatal("resolver Remove failed")
	}
	pktB2 := interopUDPPacket(ipB, dst, 0x388000B3)
	ucB.inject(t, pktB2)
	assertNoBackendPacket(t, fx.backend1, pktB2, "packet from revoked peer")
	if got := admission.callsFor(pubB); got != 1 {
		t.Fatalf("revoked peer re-admitted (calls = %d), want 1", got)
	}

	// Scenario 3b: a crafted packet from an unowned address is likewise
	// dropped and counted as unmapped.
	unowned := interopUDPPacket(netip.MustParseAddr("10.60.0.250"), dst, 0x388000FF)
	if err := fx.router.HandlePacket(append([]byte(nil), unowned...)); !errors.Is(err, ErrDropUnmapped) {
		t.Fatalf("unowned-source packet = %v, want unmapped drop", err)
	}
	stats = fx.router.StatsSnapshot()
	if stats.UnmappedSourceIPDrops != 2 {
		t.Fatalf("UnmappedSourceIPDrops = %d, want 2 (revoked peer + unowned address)", stats.UnmappedSourceIPDrops)
	}
	if stats.OwnershipMismatchDrops != 1 {
		t.Fatalf("OwnershipMismatchDrops = %d, want 1", stats.OwnershipMismatchDrops)
	}
}

// TestInteropCapacityInvariantSingleSlotBackend is acceptance criterion 6,
// mirroring capacity_stress_test.go expectations at the ingress boundary: a
// backend modeled with MaxPeersPerBackend=1 receives two concurrent
// first-packets for two distinct peers. Exactly one peer may be admitted;
// the other must be rejected with the production capacity error
// (ErrNoActiveBackends) and counted — never double-admitted.
func TestInteropCapacityInvariantSingleSlotBackend(t *testing.T) {
	admission := newInteropAdmission(1) // both tunnels: one peer slot each
	resolver := NewResolver()

	privP, pubP := interopKeys(t)
	privQ, pubQ := interopKeys(t)
	ipP := netip.MustParseAddr("10.60.0.50")
	ipQ := netip.MustParseAddr("10.60.0.51")
	portalPeers := []clientawg.Peer{
		{PublicKey: pubP, AllowedIP: netip.PrefixFrom(ipP, 32)},
		{PublicKey: pubQ, AllowedIP: netip.PrefixFrom(ipQ, 32)},
	}

	fx := newInteropFixture(t, portalPeers, admission, resolver)
	fx.seedPeer(t, pubP, ipP.String(), interopBackend1)
	fx.seedPeer(t, pubQ, ipQ.String(), interopBackend1) // same single-slot backend
	fx.startPump(t)

	ucP := fx.startUpstreamClient(t, privP, ipP.String(), "interop-cap-p")
	ucQ := fx.startUpstreamClient(t, privQ, ipQ.String(), "interop-cap-q")

	dst := netip.MustParseAddr(interopAppDst)
	wantP := interopUDPPacket(ipP, dst, 0x38800051)
	wantQ := interopUDPPacket(ipQ, dst, 0x38800052)

	// Race the first packets: inject from both engines on a cadence until
	// the invariant has been observably enforced. Deadlines bound the
	// loop; nothing sleeps unconditionally.
	deadline := time.NewTimer(interopHandshakeTimeout)
	defer deadline.Stop()
	tick := time.NewTicker(150 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-deadline.C:
			t.Fatal("capacity race did not settle in time")
		case <-tick.C:
			_ = ucP.vt.InjectInbound(wantP)
			_ = ucQ.vt.InjectInbound(wantQ)
		}
		_, _, routes := fx.fwd.GetStats()
		stats := fx.router.StatsSnapshot()
		if routes >= 1 && stats.AdmissionRejectedDrops >= 1 && stats.AdmittedSessions >= 1 {
			break
		}
	}

	// Exactly one peer owns the single slot.
	_, _, routes := fx.fwd.GetStats()
	if routes != 1 {
		t.Fatalf("forwarder holds %d routes, want exactly 1 (double admission)", routes)
	}
	stats := fx.router.StatsSnapshot()
	if stats.AdmittedSessions != 1 {
		t.Fatalf("AdmittedSessions = %d, want exactly 1", stats.AdmittedSessions)
	}
	winner, loser := pubP, pubQ
	wantWinner := wantP
	if fx.fwd.RouteSessionID(pubQ) != "" && fx.fwd.RouteSessionID(pubP) == "" {
		winner, loser, wantWinner = pubQ, pubP, wantQ
	}
	if fx.fwd.RouteSessionID(winner) == "" || fx.fwd.RouteSessionID(loser) != "" {
		t.Fatalf("capacity winner/loser reversed: route(%s)=%q route(%s)=%q",
			"winner", fx.fwd.RouteSessionID(winner), "loser", fx.fwd.RouteSessionID(loser))
	}
	if got := admission.sessionID(loser); got != "" {
		t.Fatalf("loser peer got a session %q despite a full backend", got)
	}
	if got := admission.callsFor(loser); got < 1 {
		t.Fatalf("loser peer admission attempts = %d, want >= 1", got)
	}

	// The winner's traffic flows; the loser's never does.
	awaitBackendPacket(t, fx.backend1, wantWinner, interopHandshakeTimeout)
	wantLoser := wantP
	if loser == pubQ {
		wantLoser = wantQ
	}
	assertNoBackendPacket(t, fx.backend1, wantLoser, "rejected peer packet")

	// The rejection is classified with the production capacity cause: the
	// admission fixture fails the overflow attempt with
	// loadbalancer.ErrNoActiveBackends and the router counts it.
	if stats.AdmissionRejectedDrops < 1 {
		t.Fatalf("AdmissionRejectedDrops = %d, want >= 1", stats.AdmissionRejectedDrops)
	}
}
