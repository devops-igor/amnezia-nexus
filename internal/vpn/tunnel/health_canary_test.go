package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/virtualtun"
)

type mockPacketDevice struct {
	mu          sync.Mutex
	writeErr    error
	readErr     error
	written     [][]byte
	replyData   []byte
	delay       time.Duration
	closed      bool
	canaryHooks map[uint64]CanaryResponseHook
	nextHookID  uint64
}

var _ CanaryResponseDemuxer = (*mockPacketDevice)(nil)

func (m *mockPacketDevice) RegisterCanaryResponseHook(hook CanaryResponseHook) func() {
	m.mu.Lock()
	if m.canaryHooks == nil {
		m.canaryHooks = make(map[uint64]CanaryResponseHook)
	}
	m.nextHookID++
	id := m.nextHookID
	m.canaryHooks[id] = hook
	m.mu.Unlock()
	return func() {
		m.mu.Lock()
		delete(m.canaryHooks, id)
		m.mu.Unlock()
	}
}

func (m *mockPacketDevice) Write(p []byte) (int, error) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return 0, errors.New("mock device closed")
	}
	if m.writeErr != nil {
		m.mu.Unlock()
		return 0, m.writeErr
	}
	cp := make([]byte, len(p))
	copy(cp, p)
	m.written = append(m.written, cp)

	if len(m.replyData) > 0 {
		reply := make([]byte, len(m.replyData))
		copy(reply, m.replyData)
		hooks := make([]CanaryResponseHook, 0, len(m.canaryHooks))
		for _, h := range m.canaryHooks {
			if h != nil {
				hooks = append(hooks, h)
			}
		}
		delay := m.delay
		m.mu.Unlock()

		go func() {
			if delay > 0 {
				time.Sleep(delay)
			}
			for _, h := range hooks {
				h(reply)
			}
		}()
		return len(p), nil
	}
	m.mu.Unlock()
	return len(p), nil
}

func (m *mockPacketDevice) setReplyData(data []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.replyData = data
}

func (m *mockPacketDevice) Read(p []byte) (int, error) {
	m.mu.Lock()
	delay := m.delay
	m.mu.Unlock()
	if delay > 0 {
		time.Sleep(delay)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return 0, errors.New("mock device closed")
	}
	if m.readErr != nil {
		return 0, m.readErr
	}
	if len(m.replyData) > 0 {
		n := copy(p, m.replyData)
		return n, nil
	}
	return 0, errors.New("no reply data")
}

func (m *mockPacketDevice) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

type mockCustomCanaryDevice struct {
	mockPacketDevice
	probed bool
	err    error
}

func (m *mockCustomCanaryDevice) ProbeCanary(ctx context.Context, timeout time.Duration) error {
	m.probed = true
	return m.err
}

func TestCanaryPacket_ICMP(t *testing.T) {
	pkt := DefaultCanaryPingPacket()
	if len(pkt) != 28 {
		t.Fatalf("expected 28 bytes, got %d", len(pkt))
	}
	// Verify IPv4 header
	if pkt[0] != 0x45 {
		t.Errorf("expected version 4 IHL 5, got 0x%x", pkt[0])
	}
	if pkt[9] != 1 {
		t.Errorf("expected protocol 1 (ICMP), got %d", pkt[9])
	}
	// F3: Source IP must be within authorized portal subnet (default 10.100.0.1)
	srcIP := net.IPv4(pkt[12], pkt[13], pkt[14], pkt[15])
	if !srcIP.Equal(net.IPv4(10, 100, 0, 1)) {
		t.Errorf("expected source IP 10.100.0.1 from authorized portal subnet, got %s", srcIP)
	}
	ipCsum := internetChecksum(pkt[0:20])
	if ipCsum != 0 {
		t.Errorf("expected IP checksum verification to yield 0, got 0x%x", ipCsum)
	}
	// Verify ICMP header
	if pkt[20] != 8 {
		t.Errorf("expected ICMP type 8 (Echo Request), got %d", pkt[20])
	}
	icmpCsum := internetChecksum(pkt[20:28])
	if icmpCsum != 0 {
		t.Errorf("expected ICMP checksum verification to yield 0, got 0x%x", icmpCsum)
	}
}

func TestCanaryPacket_DNS(t *testing.T) {
	pkt := DefaultCanaryDNSPacket()
	if len(pkt) < 28 {
		t.Fatalf("expected packet >= 28 bytes, got %d", len(pkt))
	}
	if pkt[0] != 0x45 {
		t.Errorf("expected IPv4 version 4, got 0x%x", pkt[0])
	}
	if pkt[9] != 17 {
		t.Errorf("expected protocol 17 (UDP), got %d", pkt[9])
	}
	// F3: Source IP must be within authorized portal subnet (default 10.100.0.1)
	srcIP := net.IPv4(pkt[12], pkt[13], pkt[14], pkt[15])
	if !srcIP.Equal(net.IPv4(10, 100, 0, 1)) {
		t.Errorf("expected source IP 10.100.0.1 from authorized portal subnet, got %s", srcIP)
	}
	ipCsum := internetChecksum(pkt[0:20])
	if ipCsum != 0 {
		t.Errorf("expected IP checksum verification 0, got 0x%x", ipCsum)
	}
	dstPort := binary.BigEndian.Uint16(pkt[22:24])
	if dstPort != 53 {
		t.Errorf("expected DNS destination port 53, got %d", dstPort)
	}
}

func TestCanarySourceIP_AuthorizedSubnetDerivation(t *testing.T) {
	tests := []struct {
		cidr    string
		wantSrc string
		wantDst string
	}{
		{"10.100.0.0/16", "10.100.0.1", "10.100.0.2"},
		{"10.200.0.0/16", "10.200.0.1", "10.200.0.2"},
		{"172.16.0.0/12", "172.16.0.1", "172.16.0.2"},
		{"192.168.1.0/24", "192.168.1.1", "192.168.1.2"},
		{"", "10.100.0.1", "10.100.0.2"},
		{"invalid", "10.100.0.1", "10.100.0.2"},
	}

	for _, tt := range tests {
		src := CanarySourceIPFromCIDR(tt.cidr)
		if src.String() != tt.wantSrc {
			t.Errorf("CanarySourceIPFromCIDR(%q) = %s, want %s", tt.cidr, src, tt.wantSrc)
		}
		dst := CanaryDestinationIPFromCIDR(tt.cidr)
		if dst.String() != tt.wantDst {
			t.Errorf("CanaryDestinationIPFromCIDR(%q) = %s, want %s", tt.cidr, dst, tt.wantDst)
		}
		if tt.cidr != "" && tt.cidr != "invalid" {
			_, ipNet, err := net.ParseCIDR(tt.cidr)
			if err == nil && !ipNet.Contains(src) {
				t.Errorf("derived source IP %s is outside authorized subnet %s", src, tt.cidr)
			}
		}

		// Verify constructed packet carries the derived source IP
		pkt := CanaryPingPacketForSubnet(tt.cidr)
		pktSrc := net.IPv4(pkt[12], pkt[13], pkt[14], pkt[15])
		if pktSrc.String() != tt.wantSrc {
			t.Errorf("CanaryPingPacketForSubnet(%q) src = %s, want %s", tt.cidr, pktSrc, tt.wantSrc)
		}
	}
}

func TestHealthProber_SubnetCIDR_Resolution(t *testing.T) {
	hp := NewHealthProber(nil, nil, DefaultHealthConfig())
	// Default before configuration
	if got := hp.GetSubnetCIDR(); got != "10.100.0.0/16" {
		t.Fatalf("expected default 10.100.0.0/16, got %s", got)
	}

	// Direct configuration
	hp.SetSubnetCIDR("10.200.0.0/16")
	if got := hp.GetSubnetCIDR(); got != "10.200.0.0/16" {
		t.Fatalf("expected configured 10.200.0.0/16, got %s", got)
	}

	// Reset direct configuration
	hp.SetSubnetCIDR("")

	// Provider fallback
	type dummySubnetProvider struct{}
	mockProv := &struct {
		dummySubnetProvider
	}{}
	_ = mockProv
	hp.SetDeviceProvider(dummyProviderWithSubnet("172.16.0.0/12"))
	if got := hp.GetSubnetCIDR(); got != "172.16.0.0/12" {
		t.Fatalf("expected provider subnet 172.16.0.0/12, got %s", got)
	}
}

type dummyProviderWithSubnet string

func (d dummyProviderWithSubnet) SubnetCIDR() string {
	return string(d)
}

func TestProbePacketDevice_Success(t *testing.T) {
	echoReply := BuildCanaryICMPEchoReply(net.IPv4(10, 100, 0, 2), net.IPv4(10, 100, 0, 1), 0x0713, 1)
	dev := &mockPacketDevice{
		replyData: echoReply,
	}
	ctx := context.Background()
	err := ProbePacketDevice(ctx, dev, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("ProbePacketDevice failed: %v", err)
	}
	if len(dev.written) != 1 {
		t.Errorf("expected 1 written packet, got %d", len(dev.written))
	}
}

func TestProbePacketDevice_WriteError(t *testing.T) {
	dev := &mockPacketDevice{
		writeErr: errors.New("network down"),
	}
	ctx := context.Background()
	err := ProbePacketDevice(ctx, dev, 500*time.Millisecond)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestProbePacketDevice_UnsupportedDevice(t *testing.T) {
	dev := &bareTestPacketDevice{}
	ctx := context.Background()
	err := ProbePacketDevice(ctx, dev, 500*time.Millisecond)
	if err == nil {
		t.Fatal("expected unsupported device error, got nil")
	}
}

type bareTestPacketDevice struct{}

func (b *bareTestPacketDevice) Read([]byte) (int, error)    { return 0, errors.New("eof") }
func (b *bareTestPacketDevice) Write(p []byte) (int, error) { return len(p), nil }
func (b *bareTestPacketDevice) Close() error                { return nil }

func TestProbePacketDevice_Timeout(t *testing.T) {
	dev := &mockPacketDevice{
		delay:     500 * time.Millisecond,
		replyData: BuildCanaryICMPEchoReply(net.IPv4(10, 100, 0, 2), net.IPv4(10, 100, 0, 1), 0x0713, 1),
	}
	ctx := context.Background()
	err := ProbePacketDevice(ctx, dev, 50*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	// Verify hook was cleanly unregistered on timeout
	dev.mu.Lock()
	hookCount := len(dev.canaryHooks)
	dev.mu.Unlock()
	if hookCount != 0 {
		t.Fatalf("expected 0 hooks remaining after timeout, got %d", hookCount)
	}
}

func TestProbePacketDevice_DemuxerSingleReaderConcurrent(t *testing.T) {
	// Verify that with a single reader loop running (simulating pumpBackendReturns),
	// client traffic is NOT stolen and canary responses are cleanly consumed by the hook.
	dev := &mockPacketDevice{}
	clientPacketsReceived := make([][]byte, 0)
	var clientMu sync.Mutex

	// Background return pump reading continuously (single reader)
	stopPump := make(chan struct{})
	pumpDone := make(chan struct{})
	go func() {
		defer close(pumpDone)
		buf := make([]byte, 1500)
		for {
			select {
			case <-stopPump:
				return
			default:
			}
			n, err := dev.Read(buf)
			if err == nil && n > 0 {
				pkt := make([]byte, n)
				copy(pkt, buf[:n])
				clientMu.Lock()
				clientPacketsReceived = append(clientPacketsReceived, pkt)
				clientMu.Unlock()
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()

	// Simulate backend replying to canary probes by dispatching Echo Reply to registered hook
	echoReply := BuildCanaryICMPEchoReply(net.IPv4(10, 100, 0, 2), net.IPv4(10, 100, 0, 1), 0x0713, 1)
	dev.setReplyData(echoReply)

	// Run canary probe concurrently with active return pump
	ctx := context.Background()
	if err := ProbePacketDevice(ctx, dev, 1*time.Second); err != nil {
		t.Fatalf("ProbePacketDevice failed under concurrent pump: %v", err)
	}

	// Verify that no hooks remain registered after completion
	dev.mu.Lock()
	hooksLeft := len(dev.canaryHooks)
	dev.mu.Unlock()
	if hooksLeft != 0 {
		t.Errorf("expected 0 hooks left after probe completion, got %d", hooksLeft)
	}

	close(stopPump)
	<-pumpDone
}

func TestProbePacketDevice_DemuxerIgnoresNonCanaryTraffic(t *testing.T) {
	// A packet with wrong sequence or ID must not satisfy the canary listener
	wrongReply := BuildCanaryICMPEchoReply(net.IPv4(10, 100, 0, 2), net.IPv4(10, 100, 0, 1), 0x9999, 99)
	dev := &mockPacketDevice{
		replyData: wrongReply,
	}

	ctx := context.Background()
	err := ProbePacketDevice(ctx, dev, 100*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout when only non-matching packet arrives, got nil")
	}
}

func TestProbePacketDevice_CustomInterface(t *testing.T) {
	dev := &mockCustomCanaryDevice{
		err: nil,
	}
	ctx := context.Background()
	err := ProbePacketDevice(ctx, dev, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if !dev.probed {
		t.Fatal("expected ProbeCanary on custom device to be invoked")
	}
}

func TestProbeVirtualTUN(t *testing.T) {
	vt, err := virtualtun.New(virtualtun.Config{
		Name:            "canary-vt0",
		MTU:             1420,
		InboundCapacity: 16,
	})
	if err != nil {
		t.Fatalf("virtualtun.New failed: %v", err)
	}
	defer func() { _ = vt.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// In background, act as the WireGuard engine: read from tun, echo to tun
	go func() {
		buf := make([][]byte, 1)
		buf[0] = make([]byte, 1500)
		sizes := make([]int, 1)
		n, rErr := vt.Read(buf, sizes, 0)
		if rErr == nil && n > 0 {
			// Write response back to engine -> outbound
			_, _ = vt.Write(buf, 0)
		}
	}()

	probeErr := ProbeVirtualTUN(ctx, vt, 1*time.Second)
	if probeErr != nil {
		t.Fatalf("ProbeVirtualTUN failed: %v", probeErr)
	}
}

func TestHealthProber_DeviceManagement(t *testing.T) {
	hp := NewHealthProber(nil, nil, DefaultHealthConfig())
	tunID := int64(42)
	dev := &mockPacketDevice{replyData: []byte("pong")}

	if got := hp.GetDevice(tunID); got != nil {
		t.Fatalf("expected nil device before registration, got %v", got)
	}

	hp.RegisterDevice(tunID, dev)
	if got := hp.GetDevice(tunID); got != dev {
		t.Fatalf("expected registered device, got %v", got)
	}

	hp.UnregisterDevice(tunID)
	if got := hp.GetDevice(tunID); got != nil {
		t.Fatalf("expected nil device after unregistration, got %v", got)
	}

	// Test SetDeviceProvider
	hp.SetDeviceProvider(func(id int64) PacketDevice {
		if id == 99 {
			return dev
		}
		return nil
	})
	if got := hp.GetDevice(99); got != dev {
		t.Fatalf("expected device from provider for 99, got %v", got)
	}
	if got := hp.GetDevice(100); got != nil {
		t.Fatalf("expected nil for 100, got %v", got)
	}
}

func TestHealthProber_CanaryProbe_NoDevice(t *testing.T) {
	hp := NewHealthProber(nil, nil, DefaultHealthConfig())
	tunnel := &models.BackendTunnel{ID: 10, ServerID: 1}
	err := hp.ProbeCanary(context.Background(), tunnel)
	if err == nil || !errors.Is(err, ErrNoActiveDevice) {
		t.Fatalf("expected ErrNoActiveDevice, got %v", err)
	}
}

func TestHealthProber_DualTier_HandshakeBlocked(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	pool := NewPool(db)
	sID, _ := db.CreateServer(ctx, &models.Server{Name: "Host 1", Host: "10.0.0.1"})
	tun, err := pool.AddTunnel(ctx, sID, "10.0.0.1:51820", "pubkey1")
	if err != nil {
		t.Fatalf("failed to add tunnel: %v", err)
	}
	_ = pool.SetTunnelStatus(ctx, sID, "active", 50)

	cfg := DefaultHealthConfig()
	cfg.FailureThreshold = 3

	// Outer handshake probe always fails (e.g. DPI blocks handshake IK)
	failOuterProbe := func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 0, errors.New("DPI handshake packet drop")
	}

	hp := NewHealthProber(pool, db, cfg, failOuterProbe)

	// Inner canary probe succeeds (payload data plane is passing traffic)
	canaryCalled := 0
	hp.SetCanaryProbeFunc(func(ctx context.Context, tunnel *models.BackendTunnel) error {
		canaryCalled++
		return nil
	})

	// Probes 1 and 2: outer fails, failures < threshold -> becomes degraded
	for i := 1; i < cfg.FailureThreshold; i++ {
		_, pErr := hp.ProbeTunnel(ctx, tun)
		if pErr == nil {
			t.Fatalf("expected probe error on failure %d", i)
		}
	}

	current, err := pool.GetTunnel(sID)
	if err != nil || current.Status != "degraded" {
		t.Fatalf("expected status degraded before threshold, got %q", current.Status)
	}

	// Probe 3: outer fails, reaches FailureThreshold.
	// Tier 2 canary probe runs and succeeds! Status MUST become handshake_blocked (NOT disabled).
	_, pErr := hp.ProbeTunnel(ctx, tun)
	if pErr == nil {
		t.Fatal("expected probe error from ProbeTunnel")
	}

	if canaryCalled == 0 {
		t.Fatal("expected canary probe to be called when reaching FailureThreshold")
	}

	current, err = pool.GetTunnel(sID)
	if err != nil {
		t.Fatalf("failed to get tunnel: %v", err)
	}
	if current.Status != models.TunnelStatusHandshakeBlocked {
		t.Fatalf("expected status %q, got %q", models.TunnelStatusHandshakeBlocked, current.Status)
	}
	if current.DisableReason != models.DisableReasonNone {
		t.Fatalf("expected DisableReason none, got %q", current.DisableReason)
	}
	if hp.IsAutoDisabled(sID) {
		t.Fatal("tunnel in handshake_blocked must NOT be autoDisabled")
	}
}

func TestHealthProber_DualTier_BothProbesFail_Disabled(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	pool := NewPool(db)
	sID, _ := db.CreateServer(ctx, &models.Server{Name: "Host 2", Host: "10.0.0.2"})
	tun, err := pool.AddTunnel(ctx, sID, "10.0.0.2:51820", "pubkey2")
	if err != nil {
		t.Fatalf("failed to add tunnel: %v", err)
	}
	_ = pool.SetTunnelStatus(ctx, sID, "active", 50)

	cfg := DefaultHealthConfig()
	cfg.FailureThreshold = 2

	failOuterProbe := func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 0, errors.New("network failure")
	}

	hp := NewHealthProber(pool, db, cfg, failOuterProbe)

	// Inner canary probe ALSO fails
	hp.SetCanaryProbeFunc(func(ctx context.Context, tunnel *models.BackendTunnel) error {
		return errors.New("canary data plane failed")
	})

	// Probe 1: failures=1
	_, _ = hp.ProbeTunnel(ctx, tun)
	// Probe 2: failures=2 >= FailureThreshold. Both outer and inner fail -> disabled
	_, _ = hp.ProbeTunnel(ctx, tun)

	current, err := pool.GetTunnel(sID)
	if err != nil {
		t.Fatalf("failed to get tunnel: %v", err)
	}
	if current.Status != models.TunnelStatusDisabled {
		t.Fatalf("expected status %q, got %q", models.TunnelStatusDisabled, current.Status)
	}
	if current.DisableReason != models.DisableReasonHealth {
		t.Fatalf("expected DisableReason %q, got %q", models.DisableReasonHealth, current.DisableReason)
	}
	if !hp.IsAutoDisabled(sID) {
		t.Fatal("expected tunnel to be autoDisabled")
	}
}

func TestHealthProber_DualTier_RecoveryToActive(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	pool := NewPool(db)
	sID, _ := db.CreateServer(ctx, &models.Server{Name: "Host 3", Host: "10.0.0.3"})
	tun, err := pool.AddTunnel(ctx, sID, "10.0.0.3:51820", "pubkey3")
	if err != nil {
		t.Fatalf("failed to add tunnel: %v", err)
	}

	cfg := DefaultHealthConfig()
	cfg.FailureThreshold = 2

	outerSuccess := false
	outerProbe := func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		if !outerSuccess {
			return 0, errors.New("outer handshake failed")
		}
		return 35 * time.Millisecond, nil
	}

	hp := NewHealthProber(pool, db, cfg, outerProbe)

	canarySuccess := true
	hp.SetCanaryProbeFunc(func(ctx context.Context, tunnel *models.BackendTunnel) error {
		if !canarySuccess {
			return errors.New("inner canary probe failed")
		}
		return nil
	})

	// Put tunnel into handshake_blocked
	_, _ = hp.ProbeTunnel(ctx, tun)
	_, _ = hp.ProbeTunnel(ctx, tun)

	current, _ := pool.GetTunnel(sID)
	if current.Status != models.TunnelStatusHandshakeBlocked {
		t.Fatalf("expected handshake_blocked, got %q", current.Status)
	}

	// Case 1: Outer probe succeeds, BUT inner canary probe fails!
	outerSuccess = true
	canarySuccess = false

	_, err = hp.ProbeTunnel(ctx, tun)
	if err == nil {
		t.Fatal("expected error when canary fails during recovery")
	}
	current, _ = pool.GetTunnel(sID)
	if current.Status != models.TunnelStatusHandshakeBlocked {
		t.Fatalf("tunnel MUST stay in handshake_blocked when canary fails, got %q", current.Status)
	}

	// Case 2: BOTH outer probe AND inner canary probe succeed!
	canarySuccess = true

	_, err = hp.ProbeTunnel(ctx, tun)
	if err != nil {
		t.Fatalf("expected ProbeTunnel success on full recovery, got %v", err)
	}

	current, _ = pool.GetTunnel(sID)
	if current.Status != models.TunnelStatusActive {
		t.Fatalf("expected status active after both succeed, got %q", current.Status)
	}
	if hp.GetFailCount(sID) != 0 {
		t.Errorf("expected failCount 0, got %d", hp.GetFailCount(sID))
	}
}
