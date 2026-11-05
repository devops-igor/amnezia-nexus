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
	}
}

func TestProbePacketDevice_Success(t *testing.T) {
	dev := &mockPacketDevice{}
	ctx := context.Background()
	go func() {
		time.Sleep(10 * time.Millisecond)
		dev.mu.Lock()
		hooks := make([]CanaryResponseHook, 0, len(dev.canaryHooks))
		for _, h := range dev.canaryHooks {
			if h != nil {
				hooks = append(hooks, h)
			}
		}
		dev.mu.Unlock()
		if len(dev.written) > 0 {
			req := dev.written[0]
			id := binary.BigEndian.Uint16(req[24:26])
			seq := binary.BigEndian.Uint16(req[26:28])
			reply := BuildCanaryICMPEchoReply(net.IPv4(1, 1, 1, 1), net.IPv4(10, 100, 0, 1), id, seq)
			for _, h := range hooks {
				h(reply)
			}
		}
	}()

	err := ProbePacketDevice(ctx, dev, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("ProbePacketDevice failed: %v", err)
	}
	if len(dev.written) == 0 {
		t.Fatal("expected at least 1 written packet")
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

func TestProbePacketDevice_Timeout(t *testing.T) {
	dev := &mockPacketDevice{}
	ctx := context.Background()
	err := ProbePacketDevice(ctx, dev, 50*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
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

	go func() {
		buf := make([][]byte, 1)
		buf[0] = make([]byte, 1500)
		sizes := make([]int, 1)
		n, rErr := vt.Read(buf, sizes, 0)
		if rErr == nil && n > 0 {
			_, _ = vt.Write(buf, 0)
		}
	}()

	probeErr := ProbeVirtualTUN(ctx, vt, 1*time.Second)
	if probeErr != nil {
		t.Fatalf("ProbeVirtualTUN failed: %v", probeErr)
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

func TestHealthProber_CanaryProbe_CustomFunc(t *testing.T) {
	hp := NewHealthProber(nil, nil, DefaultHealthConfig())
	tunnel := &models.BackendTunnel{ID: 10, ServerID: 1}
	called := false
	hp.SetCanaryProbeFunc(func(ctx context.Context, t *models.BackendTunnel) error {
		called = true
		return nil
	})
	if err := hp.ProbeCanary(context.Background(), tunnel); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("expected custom canary probe function to be invoked")
	}
}

func TestHealthProber_CanaryManagement(t *testing.T) {
	hp := NewHealthProber(nil, nil, DefaultHealthConfig())
	if hp.GetCanaryProbeFunc() != nil {
		t.Fatal("expected nil canary probe func initially")
	}
	if hp.GetSubnetCIDR() != "10.100.0.0/16" {
		t.Fatalf("expected default subnet, got %s", hp.GetSubnetCIDR())
	}
	hp.SetSubnetCIDR("10.200.0.0/16")
	if hp.GetSubnetCIDR() != "10.200.0.0/16" {
		t.Fatalf("expected 10.200.0.0/16, got %s", hp.GetSubnetCIDR())
	}

	dev := &mockPacketDevice{}
	hp.RegisterDevice(101, dev)
	if hp.GetDevice(101) != dev {
		t.Fatal("expected registered device")
	}
	hp.UnregisterDevice(101)
	if hp.GetDevice(101) != nil {
		t.Fatal("expected nil device after unregister")
	}

	hp.SetDeviceProvider(func(id int64) PacketDevice {
		if id == 202 {
			return dev
		}
		return nil
	})
	if hp.GetDevice(202) != dev {
		t.Fatal("expected device from provider")
	}

	tun := &models.BackendTunnel{ID: 202, ServerID: 2}
	calledCustom := false
	hp.SetCanaryProbeFunc(func(ctx context.Context, t *models.BackendTunnel) error {
		calledCustom = true
		return nil
	})
	if hp.GetCanaryProbeFunc() == nil {
		t.Fatal("expected non-nil canary probe func")
	}
	if err := hp.ProbeCanaryWithDevice(context.Background(), tun, dev); err != nil {
		t.Fatal(err)
	}
	if !calledCustom {
		t.Fatal("expected custom probe canary with device to be called")
	}
}

func TestCanary_DNS_And_EchoMatching(t *testing.T) {
	src := net.IPv4(10, 100, 0, 1)
	dst := net.IPv4(8, 8, 8, 8)
	dnsResp := BuildCanaryDNSResponse(dst, src, 0x1234)
	if !IsCanaryDNSResponseMatching(dnsResp, dst, src, 0x1234) {
		t.Fatal("expected DNS response to match")
	}
	if IsCanaryDNSResponseMatching(dnsResp, dst, src, 0x9999) {
		t.Fatal("expected mismatching transaction ID to fail")
	}
	if IsCanaryDNSResponseMatching([]byte{1, 2, 3}, dst, src, 0x1234) {
		t.Fatal("expected truncated packet to fail")
	}

	echoReply := BuildCanaryICMPEchoReply(dst, src, 0x0713, 1)
	if !IsCanaryEchoReply(echoReply, 0x0713, 1) {
		t.Fatal("expected Echo reply to match")
	}
	if IsCanaryEchoReply(echoReply, 0x0713, 2) {
		t.Fatal("expected mismatching seq to fail")
	}
	if IsCanaryEchoReply([]byte{1, 2, 3}, 0x0713, 1) {
		t.Fatal("expected truncated echo reply to fail")
	}
}
