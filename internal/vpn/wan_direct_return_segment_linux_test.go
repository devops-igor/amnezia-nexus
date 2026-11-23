//go:build linux

package vpn

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"golang.org/x/sys/unix"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/clientawg"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/virtualtun"
)

// This file is the real-path qualification for the direct WAN return
// normalization repair: a reply the production reader returns oversized must
// still reach the client whole, in pieces the client device accepts.
//
// What is real here, and what is not:
//   - The WAN device is created by NewProductionWANDevice (real TUN, real
//     AF_PACKET capture on the WAN interface, real reset suppression), and the
//     dispatcher is the one ConfigurePBR installs, with the real policy matcher
//     and the real direct-NAT allocator.
//   - The remote endpoint is a real kernel TCP sender in a nested network
//     namespace reached over a veth pair, so the frames the production reader
//     returns are produced by the kernel's own segmentation/aggregation paths,
//     not by a crafted buffer.
//   - The client is a real userspace TCP stack (netstack) whose MTU is the
//     deployment's plaintext MTU, and every reply piece is first offered to a
//     real clientawg.ClientAWGDevice.InjectInbound — the production gate that
//     refused the oversized frame — before it is handed to that stack.
//   - The only instrumentation is a pass-through wrapper that records the length
//     of each frame the production Read returns. It never rewrites, splits or
//     drops a frame, so the behaviour under test is production behaviour.
//
// Everything runs inside a user+network namespace this run owns (the same
// launcher, ownership proof and teardown the S4 qualification uses), so no host
// interface, route, firewall rule or sysctl is read or written.

const (
	// returnSegChildEnv selects the in-namespace qualification body.
	returnSegChildEnv = "NEXUS_RETURNSEG_CHILD"
	// returnSegPeerEnv selects the nested bulk-sender participant.
	returnSegPeerEnv = "NEXUS_RETURNSEG_PEER"
	// returnSegPeerRole is the participant role value.
	returnSegPeerRole = "bulk"
	// returnSegResultPrefix marks one machine-readable case result.
	returnSegResultPrefix = "RETURNSEG_RESULT "

	// returnSegClientMTU is the plaintext MTU this fixture builds its client
	// device with. TestReturnSegClientMTUAuthorityIsSingleDefinition pins it to
	// the deployment's single definition, so the fixture cannot drift from the
	// gate it is measuring.
	returnSegClientMTU = 1420
)

// returnSegCaseResult is the measured outcome of one qualification case.
type returnSegCaseResult struct {
	Case             string  `json:"case"`
	WantBytes        int64   `json:"want_bytes"`
	GotBytes         int64   `json:"got_bytes"`
	PayloadOK        bool    `json:"payload_sha_matches"`
	TimedOut         bool    `json:"timed_out"`
	Secs             float64 `json:"secs"`
	Mbps             float64 `json:"mbps"`
	WANFrames        uint64  `json:"wan_frames"`
	WANMaxFrame      uint64  `json:"wan_max_frame"`
	WANFramesOverMTU uint64  `json:"wan_frames_over_client_mtu"`
	WANFeatures      string  `json:"wan_features"`
	PeerFeatures     string  `json:"peer_features"`
	PeerRTTMS        int     `json:"peer_rtt_ms"`
	GateAccepted     uint64  `json:"client_gate_accepted"`
	GateRejected     uint64  `json:"client_gate_rejected"`
	SinkErrors       uint64  `json:"return_path_write_errors"`
	FirstSinkError   string  `json:"first_return_path_error,omitempty"`
	MaxDelivered     uint64  `json:"max_delivered_packet"`
	AFPacketSeen     uint32  `json:"afpacket_seen"`
	AFPacketDrops    uint32  `json:"afpacket_kernel_drops"`
	GuardDrops       uint64  `json:"fwd_drops_packet_too_large"`
	QueueFullDrops   uint64  `json:"fwd_drops_queue_full"`
	DirectDrops      uint64  `json:"direct_drops"`
	DirectBytes      int64   `json:"direct_bytes"`
	Err              string  `json:"err,omitempty"`
}

// returnSegCase describes one measurement.
type returnSegCase struct {
	name      string
	mib       int64
	limit     time.Duration
	wireSized bool // sender TSO/GSO off: every frame the sender emits is MTU sized
	rttMS     int  // netem delay on the peer end of the link
	// wantOversized says the case must actually produce frames above the client
	// MTU, otherwise it would not exercise the defect at all.
	wantOversized bool
}

// returnSegCases are run in order. The first two are the defect and its positive
// control; the third is the high-RTT case that timed out before the repair.
func returnSegCases() []returnSegCase {
	return []returnSegCase{
		{name: "aggregated_reply", mib: 8, limit: 40 * time.Second, wantOversized: true},
		{name: "wire_sized_control", mib: 8, limit: 40 * time.Second, wireSized: true},
		{name: "aggregated_reply_20ms_rtt", mib: 16, limit: 30 * time.Second, rttMS: 20, wantOversized: true},
	}
}

// TestWANReturnSegmentationDeliversOversizedRepliesInMTUPieces is the real-path
// acceptance gate for the repair.
func TestWANReturnSegmentationDeliversOversizedRepliesInMTUPieces(t *testing.T) {
	if os.Getenv(returnSegChildEnv) == "1" {
		runReturnSegQualification(t)
		return
	}
	out, err := s4LaunchInOwnedNamespace("^"+t.Name()+"$", []string{returnSegChildEnv + "=1"})
	t.Logf("return-segmentation qualification output:\n%s", out)
	// The child's per-test lines are the verdict. Both halves matter: a passing
	// SUBTEST line also starts with this name, so a bare "contains" check would
	// accept a run whose outer test failed.
	childPassed := strings.Contains(out, "\n--- PASS: "+t.Name()+" (") &&
		!strings.Contains(out, "\n--- FAIL: "+t.Name()+" (")
	if !childPassed {
		if err != nil && !strings.Contains(out, "=== RUN") {
			if s4RequiredEnvironment() {
				t.Fatalf("the return-segmentation qualification could not execute in required CI: %v", err)
			}
			t.Skipf("cannot create an isolated user+network namespace in this environment: %v", err)
		}
		t.Fatalf("the in-namespace qualification did not pass:\n%s", out)
	}
}

// runReturnSegQualification is the body that runs inside the owned namespace.
// Each case builds its own topology, measures, tears down, and reports one result
// line; a failing assertion fails the test with the measured evidence attached.
func runReturnSegQualification(t *testing.T) {
	if err := s4RequireOwnedNamespace(); err != nil {
		t.Fatalf("qualification refuses to run outside a run-owned namespace: %v", err)
	}
	if err := configurePrivateNamespaceSetup(); err != nil {
		t.Fatalf("configure private namespace: %v", err)
	}
	for _, tc := range returnSegCases() {
		t.Run(tc.name, func(t *testing.T) {
			res, err := runReturnSegCase(t, tc)
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			encoded, _ := json.Marshal(res)
			fmt.Printf("%s%s\n", returnSegResultPrefix, encoded)
			requireReturnSegAcceptance(t, tc, res)
		})
	}
}

// requireReturnSegAcceptance applies the acceptance rule that distinguishes a real
// repair from a coincidence: the whole requested byte range arrives, its SHA-256
// equals the deterministic stream the remote endpoint sent, the exchange did not
// time out, and no reply packet was refused by either the admission guard or the
// client device gate.
func requireReturnSegAcceptance(t *testing.T, tc returnSegCase, res *returnSegCaseResult) {
	t.Helper()
	if res.Err != "" {
		t.Fatalf("transfer reported an error: %s", res.Err)
	}
	if res.TimedOut {
		t.Fatalf("transfer timed out after %.1fs with %d of %d bytes delivered", res.Secs, res.GotBytes, res.WantBytes)
	}
	if res.GotBytes != res.WantBytes {
		t.Fatalf("delivered %d of %d bytes (%.1fs, %.1f Mbit/s)", res.GotBytes, res.WantBytes, res.Secs, res.Mbps)
	}
	if !res.PayloadOK {
		t.Fatalf("delivered bytes do not match the deterministic stream the remote endpoint sent")
	}
	if res.GuardDrops != 0 {
		t.Fatalf("%d reply packet(s) were refused as too large; the delivered pieces do not fit the admission guard", res.GuardDrops)
	}
	if res.GateRejected != 0 {
		t.Fatalf("%d reply packet(s) were refused by the client device MTU gate; the repair did not fit the real client boundary", res.GateRejected)
	}
	if res.SinkErrors != 0 {
		t.Fatalf("%d reply packet(s) failed delivery to the client (first: %s)", res.SinkErrors, res.FirstSinkError)
	}
	if res.MaxDelivered > returnSegClientMTU {
		t.Fatalf("a delivered packet was %d bytes, above the %d byte client MTU", res.MaxDelivered, returnSegClientMTU)
	}
	if tc.wantOversized && res.WANFramesOverMTU == 0 {
		t.Fatalf("this case never produced a frame above the client MTU (max %d bytes), so it did not exercise the defect", res.WANMaxFrame)
	}
	if !tc.wantOversized && res.WANFramesOverMTU != 0 {
		t.Fatalf("the wire-sized control produced %d frame(s) above the client MTU, so it is not a positive control", res.WANFramesOverMTU)
	}
}

// returnSegPayloadStream is the deterministic byte stream the remote endpoint
// sends and the client verifies. One fixed pseudo-random block repeats, so the
// expected digest is derivable without storing the transfer.
var returnSegPayloadBlock = func() []byte {
	r := rand.New(rand.NewPCG(2026, 857))
	b := make([]byte, 1<<20)
	for i := range b {
		b[i] = byte(r.Uint32())
	}
	return b
}()

func returnSegStream(n int64) io.Reader { return &returnSegReader{left: n} }

type returnSegReader struct {
	left int64
	off  int
}

func (r *returnSegReader) Read(p []byte) (int, error) {
	if r.left <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > r.left {
		p = p[:r.left]
	}
	n := copy(p, returnSegPayloadBlock[r.off:])
	r.off = (r.off + n) % len(returnSegPayloadBlock)
	r.left -= int64(n)
	return n, nil
}

func returnSegExpectedSHA(n int64) string {
	h := sha256.New()
	_, _ = io.Copy(h, returnSegStream(n))
	return hex.EncodeToString(h.Sum(nil))
}

// returnSegWAN records the size of every frame the production reader returns and
// forwards every call unchanged. It is the same interface the production reader
// uses, so nothing about the delivery path changes.
type returnSegWAN struct {
	inner   forwarder.PacketDevice
	frames  atomic.Uint64
	maxLen  atomic.Uint64
	overMTU atomic.Uint64
}

func (w *returnSegWAN) Read(p []byte) (int, error) {
	n, err := w.inner.Read(p)
	if n > 0 {
		w.frames.Add(1)
		if uint64(n) > w.maxLen.Load() {
			w.maxLen.Store(uint64(n))
		}
		if n > returnSegClientMTU {
			w.overMTU.Add(1)
		}
	}
	return n, err
}

func (w *returnSegWAN) Write(p []byte) (int, error) { return w.inner.Write(p) }
func (w *returnSegWAN) Close() error                { return w.inner.Close() }

func (w *returnSegWAN) SetHostWANIP(ip netip.Addr) error {
	if setter, ok := w.inner.(interface{ SetHostWANIP(netip.Addr) error }); ok {
		return setter.SetHostWANIP(ip)
	}
	return nil
}

// returnSegClient is one simulated VPN client: a real userspace TCP stack behind
// the real client device gate.
type returnSegClient struct {
	peerKey, clientIP string
	stack             *netstack.Net
	sink              *returnStackDevice
	portal            *clientawg.ClientAWGDevice
	accepted          atomic.Uint64
	rejected          atomic.Uint64
	sinkErrors        atomic.Uint64
	maxAcceptedLen    atomic.Uint64
	errMu             sync.Mutex
	firstErr          string
}

// returnSink is the production ReturnPath write callback. Every packet is first
// offered to the production client device, so the MTU gate that refused the
// oversized frame decides whether it is acceptable; only an accepted packet is
// then handed to the client stack so the transfer can complete and be verified.
func (c *returnSegClient) returnSink(_, _ string, packet []byte) (int, error) {
	if err := c.portal.InjectInbound(packet); err != nil {
		c.rejected.Add(1)
		c.errMu.Lock()
		if c.firstErr == "" {
			c.firstErr = "client device gate: " + err.Error()
		}
		c.errMu.Unlock()
		return 0, err
	}
	c.accepted.Add(1)
	if uint64(len(packet)) > c.maxAcceptedLen.Load() {
		c.maxAcceptedLen.Store(uint64(len(packet)))
	}
	n, err := c.sink.Write(packet)
	if err != nil {
		c.sinkErrors.Add(1)
		c.errMu.Lock()
		if c.firstErr == "" {
			c.firstErr = err.Error()
		}
		c.errMu.Unlock()
	}
	return n, err
}

func newReturnSegClient(t *testing.T, peerKey, clientIP string) *returnSegClient {
	t.Helper()
	vt, stack, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(clientIP)}, nil, returnSegClientMTU)
	if err != nil {
		t.Fatalf("client stack: %v", err)
	}
	privateKey, publicKey := engineKeys(t)
	portal, err := clientawg.NewDevice(clientawg.Config{
		PrivateKey: privateKey, PublicKey: publicKey,
		// The inbound queue only has to hand plaintext to this fixture's own
		// reader; it never carries production traffic. It is generous so a
		// measurement is never distorted by fixture queue pressure.
		TUN: virtualtun.Config{Name: "returnseg-gate", MTU: returnSegClientMTU, InboundCapacity: 8192},
	})
	if err != nil {
		t.Fatalf("client device gate: %v", err)
	}
	return &returnSegClient{peerKey: peerKey, clientIP: clientIP, stack: stack, sink: &returnStackDevice{tun: vt}, portal: portal}
}

func (c *returnSegClient) close() {
	if c.portal != nil {
		_ = c.portal.Close()
	}
	if c.sink != nil {
		_ = c.sink.Close()
	}
}

// returnSegRig wires the production dispatcher over the production WAN device.
type returnSegRig struct {
	svc     *Service
	dem     *forwarder.DirectEgressManager
	fwd     *forwarder.Forwarder
	clients []*returnSegClient
	stop    func()
}

// buildReturnSegRig installs the production dispatcher and starts its pumps. Direct
// decisions are seeded for the remote endpoint exactly as the S4 fixture seeds
// them from observed DNS evidence.
func buildReturnSegRig(t *testing.T, wan forwarder.PacketDevice, server netip.Addr, clients []*returnSegClient) *returnSegRig {
	t.Helper()
	rules, _, err := policy.Parse(context.Background(), strings.NewReader("203.0.113.0/24\n"), policy.DefaultParseLimits())
	if err != nil {
		t.Fatalf("policy rules: %v", err)
	}
	src := policy.NewMemorySource("returnseg", rules)
	matcher := policy.NewMatcher()
	snap, err := policy.CompileSnapshot(1, "gen-returnseg", []policy.SourceParsedRules{src.ToSourceParsedRules()})
	if err != nil {
		t.Fatalf("policy snapshot: %v", err)
	}
	matcher.Publish(snap)
	fwd := forwarder.NewForwarder(nil, "10.100.0.0/16", 100)
	for _, c := range clients {
		path := forwarder.NewReturnPath(c.returnSink)
		fwd.RegisterSessionWithReturnPath("sess-"+c.peerKey, "conn-"+c.peerKey, c.peerKey, c.clientIP, 301, path)
	}
	svc := &Service{forwarder: fwd}
	if err := svc.ConfigurePBR(PBRConfig{
		Enabled:       true,
		HostWANIP:     netip.MustParseAddr(s4HostWAN),
		WANDevice:     wan,
		PolicyMatcher: matcher,
	}); err != nil {
		t.Fatalf("ConfigurePBR: %v", err)
	}
	// The remote endpoint is classified as an allocation member, so every flow to
	// it takes the DIRECT path by address.
	installDirectDestinations(fwd, server)

	dem := fwd.DirectEgress()
	if dem == nil {
		t.Fatal("ConfigurePBR installed no DirectEgressManager")
	}
	fwd.StartPumps(context.Background())
	done := make(chan struct{}, len(clients))
	for _, c := range clients {
		go func(c *returnSegClient) {
			defer func() { done <- struct{}{} }()
			buf := make([]byte, 65535)
			for {
				n, err := c.sink.Read(buf)
				if err != nil {
					return
				}
				if n < 20 {
					continue
				}
				pkt := make([]byte, n)
				copy(pkt, buf[:n])
				_ = fwd.RouteClientToBackend(c.peerKey, pkt)
			}
		}(c)
	}
	return &returnSegRig{
		svc: svc, dem: dem, fwd: fwd, clients: clients,
		stop: func() {
			fwd.StopPumps()
			_ = svc.TeardownPBR()
			for _, c := range clients {
				c.close()
			}
			for range clients {
				<-done
			}
		},
	}
}

// returnSegResetLinks removes the fixture's own link and tunnel devices from this
// namespace, so a case never inherits the previous case's topology. Everything it
// touches was created by this run inside this namespace.
func returnSegResetLinks(t *testing.T) {
	t.Helper()
	if err := s4RequireOwnedNamespace(); err != nil {
		t.Fatalf("refusing to reset fixture links: %v", err)
	}
	for _, name := range []string{s4WANIface, s4WANPeerIface, s4WANDeviceName} {
		_, _ = s4Command("ip", "link", "del", name)
	}
}

// returnSegPeer is the nested namespace running the real bulk TCP sender.
type returnSegPeer struct {
	peerIP netip.Addr
	cmd    *exec.Cmd
	mu     sync.Mutex
	lines  []string
	ready  chan struct{}
}

func (p *returnSegPeer) add(line string) {
	p.mu.Lock()
	p.lines = append(p.lines, line)
	p.mu.Unlock()
}

func (p *returnSegPeer) grep(prefix string) []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []string
	for _, line := range p.lines {
		if strings.HasPrefix(line, prefix) {
			out = append(out, strings.TrimPrefix(line, prefix))
		}
	}
	return out
}

func (p *returnSegPeer) Close() {
	if p != nil && p.cmd != nil && p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
		_ = p.cmd.Wait()
	}
}

// newReturnSegPeer builds the veth pair, starts the sender namespace with this
// case's link settings, and waits for its readiness line.
func newReturnSegPeer(t *testing.T, tc returnSegCase) *returnSegPeer {
	t.Helper()
	if out, err := s4Command("ip", "link", "add", s4WANIface, "type", "veth", "peer", "name", s4WANPeerIface); err != nil {
		t.Fatalf("create wan veth pair: %v: %s", err, out)
	}
	p := &returnSegPeer{peerIP: netip.MustParseAddr(s4RemotePeer), ready: make(chan struct{})}
	recordPath := filepath.Join(os.TempDir(), fmt.Sprintf("nexus-returnseg-peer-%d-%s.json", os.Getpid(), mustShortToken()))
	recordEnv, err := s4WriteLaunchRecord(recordPath)
	if err != nil {
		t.Fatalf("peer launch record: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(recordPath); _ = os.Remove(recordPath + ".claimed") })

	// #nosec G204 -- os.Args[0] is this test binary; "unshare -n" takes no input
	p.cmd = exec.Command("unshare", "-n", os.Args[0], "-test.run=^$")
	p.cmd.Env = append(append(os.Environ(), recordEnv...),
		returnSegPeerEnv+"="+returnSegPeerRole,
		"NEXUS_RETURNSEG_WIRE="+boolFlag(tc.wireSized),
		"NEXUS_RETURNSEG_RTT_MS="+strconv.Itoa(tc.rttMS),
	)
	p.cmd.Stderr = os.Stderr
	stdout, err := p.cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("peer stdout: %v", err)
	}
	if err := p.cmd.Start(); err != nil {
		t.Fatalf("start sender namespace: %v", err)
	}
	reader := bufio.NewReader(stdout)
	line, err := reader.ReadString('\n')
	if err != nil {
		p.Close()
		t.Fatalf("sender namespace pid handshake: %v", err)
	}
	pid, convErr := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "PID ")))
	if convErr != nil || pid <= 0 {
		p.Close()
		t.Fatalf("unexpected sender handshake %q", line)
	}
	go func() {
		sc := bufio.NewScanner(reader)
		sc.Buffer(make([]byte, 64*1024), 1<<20)
		for sc.Scan() {
			p.add(sc.Text())
			if sc.Text() == "READY" {
				close(p.ready)
			}
		}
	}()
	if out, err := s4Command("ip", "link", "set", s4WANPeerIface, "netns", strconv.Itoa(pid)); err != nil {
		p.Close()
		t.Fatalf("move peer link into sender namespace: %v: %s", err, out)
	}
	for _, args := range [][]string{
		{"addr", "add", s4HostWAN + "/24", "dev", s4WANIface},
		{"link", "set", s4WANIface, "up"},
		{"link", "set", "lo", "up"},
	} {
		if out, err := s4Command("ip", args...); err != nil {
			p.Close()
			t.Fatalf("ip %v: %v: %s", args, err, out)
		}
	}
	select {
	case <-p.ready:
	case <-time.After(20 * time.Second):
		p.Close()
		t.Fatalf("sender namespace never reported READY")
	}
	return p
}

func boolFlag(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

// runReturnSegCase measures one case end to end: real sender, real kernel
// forwarding and NAT, real production capture and delivery, real client stack.
func runReturnSegCase(t *testing.T, tc returnSegCase) (*returnSegCaseResult, error) {
	t.Helper()
	res := &returnSegCaseResult{Case: tc.name, WantBytes: tc.mib << 20, PeerRTTMS: tc.rttMS}

	returnSegResetLinks(t)
	peer := newReturnSegPeer(t, tc)
	defer peer.Close()

	features := peer.grep("FEAT ")
	if len(features) > 0 {
		res.PeerFeatures = features[0]
	} else {
		res.PeerFeatures = "unreported"
	}
	if wanFeatures, err := returnSegFeatures(s4WANIface); err == nil {
		res.WANFeatures = wanFeatures
	}

	inner, err := NewProductionWANDevice(s4WANDeviceName)
	if err != nil {
		return nil, fmt.Errorf("NewProductionWANDevice: %w", err)
	}
	wan := &returnSegWAN{inner: inner}
	defer func() { _ = wan.Close() }()
	if err := s4ForwardingRules(s4WANIface, s4WANDeviceName); err != nil {
		return nil, err
	}
	if err := s4AwaitPeerReachable(peer.peerIP); err != nil {
		return nil, fmt.Errorf("sender unreachable: %w", err)
	}

	client := newReturnSegClient(t, "peer-returnseg", "10.100.0.10")
	rig := buildReturnSegRig(t, wan, peer.peerIP, []*returnSegClient{client})
	defer rig.stop()

	res.Err, res.GotBytes, res.PayloadOK, res.Secs, res.TimedOut = returnSegDownload(client, peer.peerIP, res.WantBytes, tc.limit)
	if res.Secs > 0 {
		res.Mbps = float64(res.GotBytes) * 8 / res.Secs / 1e6
	}
	res.WANFrames = wan.frames.Load()
	res.WANMaxFrame = wan.maxLen.Load()
	res.WANFramesOverMTU = wan.overMTU.Load()
	res.GateAccepted = client.accepted.Load()
	res.GateRejected = client.rejected.Load()
	res.SinkErrors = client.sinkErrors.Load()
	client.errMu.Lock()
	res.FirstSinkError = client.firstErr
	client.errMu.Unlock()
	res.MaxDelivered = maxReturnSegPacket(client)
	res.AFPacketSeen, res.AFPacketDrops, _ = returnSegPacketDrops(inner)
	res.GuardDrops = rig.fwd.DropsPacketTooLarge()
	res.QueueFullDrops = rig.fwd.DropsQueueFull()
	res.DirectDrops = rig.dem.DirectDrops()
	res.DirectBytes = rig.dem.DirectBytes()
	return res, nil
}

// returnSegDownload requests n bytes over a real TCP connection in the client stack
// and verifies that exactly those bytes arrived, in order.
func returnSegDownload(c *returnSegClient, server netip.Addr, n int64, limit time.Duration) (errText string, got int64, payloadOK bool, secs float64, timedOut bool) {
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	start := time.Now()
	conn, err := c.stack.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(server, s4RemotePort))
	if err != nil {
		return err.Error(), 0, false, time.Since(start).Seconds(), ctx.Err() != nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(start.Add(limit))
	var hdr [8]byte
	binary.BigEndian.PutUint64(hdr[:], uint64(n))
	if _, err := conn.Write(hdr[:]); err != nil {
		return err.Error(), 0, false, time.Since(start).Seconds(), ctx.Err() != nil
	}
	h := sha256.New()
	got, readErr := io.Copy(h, io.LimitReader(conn, n))
	secs = time.Since(start).Seconds()
	if readErr != nil {
		timedOut = ctx.Err() != nil || time.Since(start) >= limit
		return readErr.Error(), got, false, secs, timedOut
	}
	return "", got, hex.EncodeToString(h.Sum(nil)) == returnSegExpectedSHA(got) && got == n, secs, false
}

// maxReturnSegPacket reports the largest packet the production client device
// accepted during the transfer.
func maxReturnSegPacket(c *returnSegClient) uint64 { return c.maxAcceptedLen.Load() }

// returnSegFeatures reports the offload features of one link in this namespace.
func returnSegFeatures(iface string) (string, error) {
	out, err := s4Command("ethtool", "-k", iface)
	if err != nil {
		return "", err
	}
	keep := map[string]bool{
		"tcp-segmentation-offload":     true,
		"generic-segmentation-offload": true,
		"generic-receive-offload":      true,
	}
	var parts []string
	for _, line := range strings.Split(out, "\n") {
		if key, value, ok := strings.Cut(line, ":"); ok && keep[strings.TrimSpace(key)] {
			parts = append(parts, strings.TrimSpace(key)+"="+strings.Fields(value)[0])
		}
	}
	return strings.Join(parts, ","), nil
}

// returnSegPacketDrops reads PACKET_STATISTICS from the production capture socket.
func returnSegPacketDrops(dev forwarder.PacketDevice) (seen, dropped uint32, ok bool) {
	linux, isLinux := dev.(*linuxWANDevice)
	if !isLinux || linux.rawFile == nil {
		return 0, 0, false
	}
	rc, err := linux.rawFile.SyscallConn()
	if err != nil {
		return 0, 0, false
	}
	_ = rc.Control(func(fd uintptr) {
		if stats, err := unix.GetsockoptTpacketStats(int(fd), unix.SOL_PACKET, unix.PACKET_STATISTICS); err == nil {
			seen, dropped, ok = stats.Packets, stats.Drops, true
		}
	})
	return seen, dropped, ok
}

// returnSegSenderParticipant is the nested namespace body: a real kernel TCP
// sender with this case's link settings.
func runReturnSegSenderParticipant() int {
	fmt.Printf("PID %d\n", os.Getpid())
	_ = os.Stdout.Sync()
	if err := s4RequireOwnedNamespace(); err != nil {
		fmt.Fprintf(os.Stderr, "RETURNSEG FAIL: sender without an owned namespace: %v\n", err)
		return 1
	}
	if err := s4WaitForLink(s4WANPeerIface, 10*time.Second); err != nil {
		fmt.Fprintf(os.Stderr, "RETURNSEG FAIL: %v\n", err)
		return 1
	}
	for _, args := range [][]string{
		{"addr", "add", s4RemotePeer + "/24", "dev", s4WANPeerIface},
		{"link", "set", s4WANPeerIface, "up"},
		{"link", "set", "lo", "up"},
	} {
		if out, err := s4Command("ip", args...); err != nil {
			fmt.Fprintf(os.Stderr, "RETURNSEG FAIL: ip %v: %v %s\n", args, err, out)
			return 1
		}
	}
	_, _ = s4Command("sysctl", "-w", "net.ipv4.conf.all.rp_filter=2")
	if os.Getenv("NEXUS_RETURNSEG_WIRE") == "1" {
		// A wire-sized sender emits MTU-sized segments, which is what a physical
		// sender without segmentation offload does.
		if out, err := s4Command("ethtool", "-K", s4WANPeerIface, "tso", "off", "gso", "off"); err != nil {
			fmt.Fprintf(os.Stderr, "RETURNSEG FAIL: cannot disable sender offloads: %v %s\n", err, out)
			return 1
		}
	}
	if ms := os.Getenv("NEXUS_RETURNSEG_RTT_MS"); ms != "" && ms != "0" {
		if out, err := s4Command("tc", "qdisc", "add", "dev", s4WANPeerIface, "root", "netem", "delay", ms+"ms", "limit", "20000"); err != nil {
			fmt.Fprintf(os.Stderr, "RETURNSEG FAIL: cannot add netem delay: %v %s\n", err, out)
			return 1
		}
	}
	ln, err := net.Listen("tcp4", fmt.Sprintf("%s:%d", s4RemotePeer, s4RemotePort))
	if err != nil {
		fmt.Fprintf(os.Stderr, "RETURNSEG FAIL: listen: %v\n", err)
		return 1
	}
	go returnSegServe(ln)
	if features, err := returnSegFeatures(s4WANPeerIface); err == nil {
		fmt.Printf("FEAT %s\n", features)
	} else {
		fmt.Printf("FEAT unreported\n")
	}
	fmt.Println("READY")
	_ = os.Stdout.Sync()
	time.Sleep(150 * time.Second)
	return 0
}

// returnSegServe accepts connections and streams the deterministic payload.
func returnSegServe(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(75 * time.Second))
			var hdr [8]byte
			if _, err := io.ReadFull(c, hdr[:]); err != nil {
				return
			}
			n := int64(binary.BigEndian.Uint64(hdr[:]))
			if n <= 0 || n > 256<<20 {
				return
			}
			sent, _ := io.Copy(c, returnSegStream(n))
			info := map[string]any{"want": n, "sent": sent}
			if tcp, ok := c.(*net.TCPConn); ok {
				_ = tcp.CloseWrite()
				_, _ = io.Copy(io.Discard, c)
				if rc, err := tcp.SyscallConn(); err == nil {
					_ = rc.Control(func(fd uintptr) {
						if i, err := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO); err == nil {
							info["total_retrans"], info["segs_out"] = i.Total_retrans, i.Segs_out
							info["snd_mss"], info["snd_cwnd"] = i.Snd_mss, i.Snd_cwnd
						}
					})
				}
			}
			b, _ := json.Marshal(info)
			fmt.Printf("SRV %s\n", b)
		}(conn)
	}
}

func init() {
	if os.Getenv(returnSegPeerEnv) != returnSegPeerRole {
		return
	}
	// This entry point is reachable from an inherited environment, so it proves it
	// was launched into a run-owned namespace before touching any kernel setting.
	if err := s4RequireOwnedNamespace(); err != nil {
		fmt.Fprintf(os.Stderr, "RETURNSEG FAIL: peer refuses to run without a run-owned namespace: %v\n", err)
		os.Exit(1)
	}
	os.Exit(runReturnSegSenderParticipant())
}
