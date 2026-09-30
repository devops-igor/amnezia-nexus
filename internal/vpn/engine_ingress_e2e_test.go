package vpn

// Production-shaped upstream ingress E2E for issue #388 Rework B: a REAL
// upstream client engine (amneziawg-go device) behind the engine's REAL
// portal (clientawg.ClientAWGDevice built from the service's durable
// vpn_config identity), pumped by the engine's production receive loop into
// the REAL service admission primitive (EnsureBackendSessionForIngress) and
// the service's REAL forwarder. It copies the router_interop_test.go pattern
// (#387 interop): ecdh X25519 keys via awg.RenderClientConfig +
// configToUAPI, in-memory VirtualTUNs, localhost UDP transport, bounded
// waits, no readiness sleeps.
//
// Compromise documented for QA (spec-sanctioned, mirrors the interop file):
// the service forwarder's backend sides are attached as nil devices. This
// creates each backend queue (GetBackendPacketChannel observes the packets)
// while deliberately NOT draining them to fake backend tunnels: production
// backend drain is the tunnel pumps' job, covered by the forwarder package's
// own tests. The assertion surface here is the BACKEND QUEUE boundary —
// past admission and route registration, which is exactly what Rework B
// added.

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/clientawg"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/virtualtun"
)

// engineHandshakeTimeout bounds one fresh upstream handshake plus first
// plaintext delivery through admission and the forwarder queue.
const engineHandshakeTimeout = 15 * time.Second

// newIngressEngineService builds a test service whose durable vpn_config
// carries a REAL portal identity and listen port, exactly the state
// clientawg.LoadConfig fail-closed requires (the custom-listener fixture's
// config has no persisted private key). The returned service's portal
// keypair is generated and persisted by NewVPNService/UpdateConfig.
func newIngressEngineService(t *testing.T, db *database.DB, cfgMutators ...func(*models.VPNConfig)) *Service {
	t.Helper()
	svc, _, _, _, _ := setupTestVPNService(t, db, cfgMutators...)
	ctx := t.Context()
	cfg, err := svc.GetConfig(ctx)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	// The upstream engine must reach the portal over localhost: persist a
	// free port and the matching public endpoint BEFORE any client config
	// is rendered (UpdateConfig persists the vpn_config snapshot).
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	cfg.ListenPort = socket.LocalAddr().(*net.UDPAddr).Port
	if err := socket.Close(); err != nil {
		t.Fatal(err)
	}
	cfg.PublicEndpoint = fmt.Sprintf("127.0.0.1:%d", cfg.ListenPort)
	if err := svc.UpdateConfig(ctx, cfg); err != nil {
		t.Fatalf("persist portal identity: %v", err)
	}
	return svc
}

// enginePeer is one REAL portal client: a real keypair, a durable
// connection whose client_id is the public key and whose client_params
// carry the durable assigned_ip lease (the resolver's load source), and
// the rendered config the upstream engine consumes.
type enginePeer struct {
	privateKey string
	publicKey  string
	assignedIP string
}

// newEnginePeer mints a real client for the portal: it issues the config
// through Service.GenerateClientConfig (the production issuance path, so
// client_id/assigned_ip land durably exactly as production writes them)
// and returns the identity pieces the tests need.
func newEnginePeer(t *testing.T, svc *Service, db *database.DB, username string) (enginePeer, string) {
	t.Helper()
	ctx := t.Context()
	userID, err := db.CreateUser(ctx, &models.User{Username: username, Role: "user", Enabled: true})
	if err != nil {
		t.Fatalf("create user %s: %v", username, err)
	}
	saved, _, err := svc.GenerateClientConfig(ctx, userID)
	if err != nil {
		t.Fatalf("generate client config for %s: %v", username, err)
	}
	conns, err := db.GetConnectionsByUserID(ctx, userID)
	if err != nil || len(conns) != 1 {
		t.Fatalf("connections for %s: %d rows, %v", username, len(conns), err)
	}
	assigned, ok := conns[0].ClientParams["assigned_ip"].(string)
	if !ok || assigned == "" {
		t.Fatalf("no durable assigned_ip persisted for %s: %+v", username, conns[0].ClientParams)
	}
	privateKey := configField(t, saved, "PrivateKey")
	return enginePeer{
		privateKey: privateKey,
		publicKey:  conns[0].ClientID,
		assignedIP: assigned,
	}, saved
}

// configField pulls one wg-quick field out of a rendered client config
// (RenderClientConfig emits "Name = value" with spaces around the equals).
func configField(t *testing.T, saved, name string) string {
	t.Helper()
	for _, line := range strings.Split(saved, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok && strings.TrimSpace(k) == name {
			return strings.TrimSpace(v)
		}
	}
	t.Fatalf("field %s missing from rendered config", name)
	return ""
}

// engineKeys derives one X25519 keypair in the rendered base64 form (used
// for extra peers whose configs are never rendered).
func engineKeys(t *testing.T) (string, string) {
	t.Helper()
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(private.Bytes()),
		base64.StdEncoding.EncodeToString(private.PublicKey().Bytes())
}

// configToUAPI is #387's test adapter for the wg-quick fields emitted by
// Nexus (copied from router_interop_test.go, which anchors a different
// package). It translates syntax, never changes the saved configuration's
// values; Address, DNS and MTU are host-interface settings the in-memory
// test TUN supplies.
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

// engineUpstreamClient is one real amneziawg-go engine bound to an
// in-memory TUN, configured from the Nexus-rendered config.
type engineUpstreamClient struct {
	dev *device.Device
	vt  *virtualtun.VirtualTUN
}

// startEngineUpstreamClient builds the real upstream engine for one issued
// config; the first send initiates the handshake with the portal.
func startEngineUpstreamClient(t *testing.T, saved, name string) *engineUpstreamClient {
	t.Helper()
	vt, err := virtualtun.New(virtualtun.Config{Name: name, MTU: 1280})
	if err != nil {
		t.Fatal(err)
	}
	dev := device.NewDevice(vt, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, name))
	t.Cleanup(dev.Close)
	if err := dev.IpcSet(configToUAPI(t, saved)); err != nil {
		t.Fatal("upstream rejected saved generated configuration")
	}
	_ = dev.IpcSet("rekey_timeout=1\n")
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}
	return &engineUpstreamClient{dev: dev, vt: vt}
}

// inject pushes one application packet into the upstream engine's TUN; the
// engine encrypts and sends it, initiating the handshake if needed.
func (uc *engineUpstreamClient) inject(t *testing.T, pkt []byte) {
	t.Helper()
	if err := uc.vt.InjectInbound(pkt); err != nil {
		t.Fatalf("upstream inject: %v", err)
	}
}

// engineUDPPacket is a valid UDP/IPv4 datagram with a marker payload (the
// interop helper, repeated for this package).
func engineUDPPacket(src, dst netip.Addr, marker uint32) []byte {
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

// startEngine attaches the service forwarder's backend queues for the
// pool's tunnels (nil devices — see the file-level compromise note),
// syncs the pool, and constructs + starts the production ingress engine.
func startEngine(t *testing.T, svc *Service, name string, peers []clientawg.Peer) *IngressEngine {
	t.Helper()
	ctx := t.Context()
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	for _, tun := range svc.pool.ListTunnels() {
		svc.forwarder.AttachBackendDevice(tun.ID, nil)
	}
	engine, err := svc.NewIngressEngine(ctx, name, peers)
	if err != nil {
		t.Fatalf("engine construction: %v", err)
	}
	t.Cleanup(func() { _ = engine.Stop() })
	if err := engine.Start(); err != nil {
		t.Fatalf("engine start: %v", err)
	}
	if !engine.Running() {
		t.Fatal("engine reports not running after Start")
	}
	return engine
}

// awaitEngineBackendPacket drains the backend queue until a byte-exact copy
// of want surfaces, failing at the deadline.
func awaitEngineBackendPacket(t *testing.T, queue <-chan []byte, want []byte) {
	t.Helper()
	deadline := time.NewTimer(engineHandshakeTimeout)
	defer deadline.Stop()
	for {
		select {
		case pkt := <-queue:
			if bytes.Equal(pkt, want) {
				return
			}
		case <-deadline.C:
			t.Fatalf("expected packet (src %s) missing at backend queue within %s",
				netip.AddrFrom4([4]byte{want[12], want[13], want[14], want[15]}), engineHandshakeTimeout)
		}
	}
}

// pumpEnginePacketUntil re-injects pkt into uc every 100ms until done
// reports that the condition being waited for has been observed, or until the
// returned stop function is called.
//
// A single injection with no retry is not sufficient here: the upstream
// engine may still be retransmitting its handshake initiation when the first
// datagram is handed to the TUN, so the plaintext can be dropped while the
// session is still settling (issue #391 round 4b, finding 3). That surfaced as
// load-dependent flakiness rather than a deterministic failure. Pumping the
// packet until the admission/delivery condition is actually observed is the
// same pattern TestIngressEngineRoutesEachPeerToOwnBackend uses, and it makes
// the wait independent of handshake retransmission timing.
//
// A nil done means "never satisfied, pump until stopped": that is the mode
// used when the caller pumps across BOTH the admission wait and the backend
// delivery wait, since the drop can land in either phase. The caller's own
// deadline remains the only thing that ends the wait — the pump never sleeps
// unconditionally and never shortens a bound.
//
// The returned stop function is safe to call more than once, and a cleanup
// guard releases the pump even if the caller fails before stopping it.
func pumpEnginePacketUntil(t *testing.T, uc *engineUpstreamClient, pkt []byte, done func() bool) func() {
	t.Helper()
	stop := make(chan struct{})
	stopped := make(chan struct{})
	stopPump := func() {
		select {
		case <-stop:
		default:
			close(stop)
		}
		<-stopped
	}
	t.Cleanup(stopPump)
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if done != nil && done() {
					return
				}
				// A transient inject failure (a session tearing down) is
				// not the condition under test; the next tick retries.
				_ = uc.vt.InjectInbound(pkt)
			}
		}
	}()
	return stopPump
}

// TestIngressEngineEndToEndThroughService is the Rework B deliverable: one
// REAL upstream engine, one REAL portal built from the durable identity,
// the production receive loop, Service admission, and the service's REAL
// forwarder. One injected plaintext datagram must surface on the selected
// backend's queue, admitted with the durable lease IP and exactly one
// fresh session registration.
func TestIngressEngineEndToEndThroughService(t *testing.T) {
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)

	peer, saved := newEnginePeer(t, svc, db, "engine-alice")
	ip := netip.MustParseAddr(peer.assignedIP)
	engine := startEngine(t, svc, "engine-e2e-portal", []clientawg.Peer{
		{PublicKey: peer.publicKey, AllowedIP: netip.PrefixFrom(ip, 32)},
	})

	dst := netip.MustParseAddr("198.51.100.1")
	want := engineUDPPacket(ip, dst, 0x38800001)

	uc := startEngineUpstreamClient(t, saved, "engine-e2e-client")
	uc.inject(t, want)
	// Keep re-injecting until the packet has actually been admitted AND
	// delivered: one injection with no retry can be dropped while the
	// upstream handshake initiation is still being retransmitted, which is a
	// load-dependent flake rather than a real failure (issue #391 round 4b,
	// finding 3). The condition is re-checked every 100ms; the waits below
	// keep their own deadlines and all original assertions.
	stopPump := pumpEnginePacketUntil(t, uc, want, nil)
	defer stopPump()

	// The packet picks its backend through the REAL admission path; wait
	// for the admitted session, then observe its backend queue.
	sessionDeadline := time.NewTimer(engineHandshakeTimeout)
	defer sessionDeadline.Stop()
	var sess models.VPNSession
	for {
		got, ok := svc.sessionMgr.GetSessionSnapshotByPeer(peer.publicKey)
		if ok && got.Status == "connected" {
			sess = got
			break
		}
		select {
		case <-sessionDeadline.C:
			t.Fatalf("admission never ran for the injected packet (sessions=%d)",
				len(svc.sessionMgr.ListActiveSessions()))
		case <-time.After(25 * time.Millisecond):
		}
	}

	queue, ok := svc.forwarder.GetBackendPacketChannel(sess.BackendTunnelID)
	if !ok {
		t.Fatalf("backend %d queue missing after AttachBackendDevice", sess.BackendTunnelID)
	}
	awaitEngineBackendPacket(t, queue, want)
	stopPump()

	// Admission identity: durable lease IP verbatim, correct user/peer
	// identity, and the full production chain produced exactly one fresh
	// route registration.
	if sess.AssignedIP != peer.assignedIP {
		t.Fatalf("admitted session IP %q, want durable lease %q", sess.AssignedIP, peer.assignedIP)
	}
	if sess.PeerPublicKey != peer.publicKey {
		t.Fatalf("admitted session peer %s, want %s", sess.PeerPublicKey, peer.publicKey)
	}
	if gen := svc.PeerGeneration(peer.publicKey); gen != 0 {
		t.Fatalf("ingress admission advanced peerGenerations to %d, want 0", gen)
	}
	if got := svc.freshSessionRegistrations.Load(); got != 1 {
		t.Fatalf("fresh session registrations = %d, want exactly 1", got)
	}
	if got := svc.forwarder.RouteSessionID(peer.publicKey); got != sess.ID {
		t.Fatalf("route session %q, want admitted session %q", got, sess.ID)
	}

	// The router saw exactly one admission and zero ownership drops.
	stats := engine.Router().StatsSnapshot()
	if stats.AdmittedSessions != 1 {
		t.Fatalf("AdmittedSessions = %d, want 1", stats.AdmittedSessions)
	}
	if stats.OwnershipMismatchDrops != 0 || stats.UnmappedSourceIPDrops != 0 ||
		stats.MalformedPacketDrops != 0 || stats.AdmissionRejectedDrops != 0 {
		t.Fatalf("unexpected drops on the engine happy path: %+v", stats)
	}
}

// TestIngressEngineRekeyStableThroughServiceHandshake pins the rekey
// contract at the production boundary: a second REAL engine with the SAME
// identity (same private key, same lease, NEW transport session) completes
// a fresh handshake and keeps sending — the Nexus session, backend, route,
// and admission count must not change.
func TestIngressEngineRekeyStableThroughServiceHandshake(t *testing.T) {
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)

	peer, saved := newEnginePeer(t, svc, db, "engine-rekey")
	ip := netip.MustParseAddr(peer.assignedIP)
	engine := startEngine(t, svc, "engine-rekey-portal", []clientawg.Peer{
		{PublicKey: peer.publicKey, AllowedIP: netip.PrefixFrom(ip, 32)},
	})

	dst := netip.MustParseAddr("198.51.100.1")
	first := engineUDPPacket(ip, dst, 0x388000A1)
	rekey := engineUDPPacket(ip, dst, 0x388000A2)

	uc1 := startEngineUpstreamClient(t, saved, "engine-rekey-client-1")
	uc1.inject(t, first)
	// The first packet is pumped until it is observed at the backend queue:
	// a single injection with no retry can be dropped while the upstream
	// handshake initiation is still being retransmitted, which is a
	// load-dependent flake, not a real failure (issue #391 round 4b,
	// finding 3).
	stopFirst := pumpEnginePacketUntil(t, uc1, first, nil)
	defer stopFirst()

	sessionDeadline := time.NewTimer(engineHandshakeTimeout)
	defer sessionDeadline.Stop()
	var sess models.VPNSession
	for {
		got, ok := svc.sessionMgr.GetSessionSnapshotByPeer(peer.publicKey)
		if ok && got.Status == "connected" {
			sess = got
			break
		}
		select {
		case <-sessionDeadline.C:
			t.Fatal("first admission never ran")
		case <-time.After(25 * time.Millisecond):
		}
	}
	queue, ok := svc.forwarder.GetBackendPacketChannel(sess.BackendTunnelID)
	if !ok {
		t.Fatalf("backend %d queue missing", sess.BackendTunnelID)
	}
	awaitEngineBackendPacket(t, queue, first)
	stopFirst()
	registrationsBefore := svc.freshSessionRegistrations.Load()

	// Upstream rekey: the first engine disappears and an identical one —
	// same private key, same leased IP, NEW transport session — completes
	// a fresh handshake. Nexus never sees any of it.
	uc1.dev.Close()
	uc2 := startEngineUpstreamClient(t, saved, "engine-rekey-client-2")
	uc2.inject(t, rekey)
	// Same pumping discipline for the post-rekey handshake: the new transport
	// session has not completed its handshake when the first rekey packet is
	// handed to the TUN.
	stopRekey := pumpEnginePacketUntil(t, uc2, rekey, nil)
	defer stopRekey()
	awaitEngineBackendPacket(t, queue, rekey)
	stopRekey()

	sessAfter, ok := svc.sessionMgr.GetSessionSnapshotByPeer(peer.publicKey)
	if !ok {
		t.Fatal("session vanished across the rekey")
	}
	if sessAfter.ID != sess.ID {
		t.Fatalf("Nexus session changed across the rekey: %s -> %s", sess.ID, sessAfter.ID)
	}
	if sessAfter.BackendTunnelID != sess.BackendTunnelID {
		t.Fatalf("backend changed across the rekey: %d -> %d", sess.BackendTunnelID, sessAfter.BackendTunnelID)
	}
	if got := svc.forwarder.RouteSessionID(peer.publicKey); got != sess.ID {
		t.Fatalf("route session changed across the rekey: %q, want %q", got, sess.ID)
	}
	if got := svc.freshSessionRegistrations.Load(); got != registrationsBefore {
		t.Fatalf("fresh session registrations changed across the rekey: %d -> %d", registrationsBefore, got)
	}
	if stats := engine.Router().StatsSnapshot(); stats.AdmittedSessions != 1 {
		t.Fatalf("AdmittedSessions = %d after the rekey, want 1", stats.AdmittedSessions)
	}
	if gen := svc.PeerGeneration(peer.publicKey); gen != 0 {
		t.Fatalf("rekey path advanced peerGenerations to %d, want 0", gen)
	}
}

// TestIngressEngineRoutesEachPeerToOwnBackend covers backend isolation
// through the REAL path: two clients, two distinct leases, each packet
// surfaces ONLY on the backend its admission selected (least-connections
// may co-locate them; isolation, not placement, is the assertion).
func TestIngressEngineRoutesEachPeerToOwnBackend(t *testing.T) {
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)

	peerA, savedA := newEnginePeer(t, svc, db, "engine-bea")
	peerB, savedB := newEnginePeer(t, svc, db, "engine-beb")
	ipA := netip.MustParseAddr(peerA.assignedIP)
	ipB := netip.MustParseAddr(peerB.assignedIP)
	engine := startEngine(t, svc, "engine-isolation-portal", []clientawg.Peer{
		{PublicKey: peerA.publicKey, AllowedIP: netip.PrefixFrom(ipA, 32)},
		{PublicKey: peerB.publicKey, AllowedIP: netip.PrefixFrom(ipB, 32)},
	})

	dst := netip.MustParseAddr("198.51.100.1")
	pktA := engineUDPPacket(ipA, dst, 0x38800BA1)
	pktB := engineUDPPacket(ipB, dst, 0x38800BB2)

	ucA := startEngineUpstreamClient(t, savedA, "engine-be-client-a")
	ucB := startEngineUpstreamClient(t, savedB, "engine-be-client-b")
	injectDone := make(chan struct{})
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		ucA.inject(t, pktA)
		ucB.inject(t, pktB)
		for {
			select {
			case <-injectDone:
				return
			case <-ticker.C:
				if _, ok := svc.sessionMgr.GetSessionSnapshotByPeer(peerA.publicKey); !ok {
					_ = ucA.vt.InjectInbound(pktA)
				}
				if _, ok := svc.sessionMgr.GetSessionSnapshotByPeer(peerB.publicKey); !ok {
					_ = ucB.vt.InjectInbound(pktB)
				}
			}
		}
	}()

	sessA, okA := waitForSession(t, svc, peerA.publicKey)
	sessB, okB := waitForSession(t, svc, peerB.publicKey)
	close(injectDone)
	if !okA || !okB {
		t.Fatal("admission never ran for both peers")
	}
	queueA, ok := svc.forwarder.GetBackendPacketChannel(sessA.BackendTunnelID)
	if !ok {
		t.Fatalf("backend %d queue missing", sessA.BackendTunnelID)
	}
	queueB, ok := svc.forwarder.GetBackendPacketChannel(sessB.BackendTunnelID)
	if !ok {
		t.Fatalf("backend %d queue missing", sessB.BackendTunnelID)
	}
	awaitEngineBackendPacket(t, queueA, pktA)
	awaitEngineBackendPacket(t, queueB, pktB)

	if sessA.ID == sessB.ID {
		t.Fatal("two distinct peers shared one session")
	}
	if got := svc.forwarder.RouteSessionID(peerA.publicKey); got != sessA.ID {
		t.Fatalf("peer A route session %q, want %q", got, sessA.ID)
	}
	if got := svc.forwarder.RouteSessionID(peerB.publicKey); got != sessB.ID {
		t.Fatalf("peer B route session %q, want %q", got, sessB.ID)
	}
	stats := engine.Router().StatsSnapshot()
	if stats.AdmittedSessions != 2 {
		t.Fatalf("AdmittedSessions = %d, want 2", stats.AdmittedSessions)
	}
	if stats.OwnershipMismatchDrops != 0 || stats.UnmappedSourceIPDrops != 0 {
		t.Fatalf("unexpected drops: %+v", stats)
	}
}

// waitForSession polls for a connected session snapshot for the peer.
func waitForSession(t *testing.T, svc *Service, peerKey string) (models.VPNSession, bool) {
	t.Helper()
	deadline := time.NewTimer(engineHandshakeTimeout)
	defer deadline.Stop()
	for {
		if sess, ok := svc.sessionMgr.GetSessionSnapshotByPeer(peerKey); ok && sess.Status == "connected" {
			return sess, true
		}
		select {
		case <-deadline.C:
			return models.VPNSession{}, false
		case <-time.After(25 * time.Millisecond):
		}
	}
}

// TestIngressEngineDoubleStartRejected pins the engine lifecycle contract
// on the production wiring: double Start is ErrIngressEngineStarted, Stop
// ends the loop cleanly, and a second Stop reports ErrIngressEngineNotStarted.
func TestIngressEngineDoubleStartRejected(t *testing.T) {
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)

	engine := startEngine(t, svc, "engine-lifecycle-portal", nil)
	if err := engine.Start(); err == nil {
		t.Fatal("double Start accepted")
	} else if !strings.Contains(err.Error(), "already started") {
		t.Fatalf("double Start = %v, want the already-started sentinel", err)
	}
	if err := engine.Stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if engine.Running() {
		t.Fatal("engine reports running after Stop")
	}
	if err := engine.Stop(); err == nil {
		t.Fatal("second Stop accepted")
	}
}
