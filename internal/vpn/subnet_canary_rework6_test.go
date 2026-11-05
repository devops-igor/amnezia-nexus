package vpn

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

// This fixture models the remote AWG data peer's source AllowedIPs: only packets
// originating in the configured portal subnet can produce authenticated replies.
type auditR5SubnetDevice struct {
	testCanaryDevice
	subnet   *net.IPNet
	mu       sync.Mutex
	hook     tunnel.CanaryResponseHook
	sources  []string
	accepted int
}

func (d *auditR5SubnetDevice) RegisterCanaryResponseHook(h tunnel.CanaryResponseHook) func() {
	d.mu.Lock()
	d.hook = h
	d.mu.Unlock()
	return func() {
		d.mu.Lock()
		d.hook = nil
		d.mu.Unlock()
	}
}

func (d *auditR5SubnetDevice) Write(p []byte) (int, error) {
	if len(p) < 28 {
		return len(p), nil
	}
	src := net.IP(p[12:16])
	dst := net.IP(p[16:20])
	d.mu.Lock()
	d.sources = append(d.sources, src.String())
	h := d.hook
	allowed := d.subnet.Contains(src)
	if allowed {
		d.accepted++
	}
	d.mu.Unlock()
	if allowed && h != nil && p[9] == 1 {
		h(tunnel.BuildCanaryICMPEchoReply(dst, src, binary.BigEndian.Uint16(p[24:26]), binary.BigEndian.Uint16(p[26:28])))
	}
	return len(p), nil
}

// Do not promote the success-only CanaryDevice method from testCanaryDevice.
type auditR5RealSubnetDevice struct {
	inner *auditR5SubnetDevice
}

func (d *auditR5RealSubnetDevice) Read(p []byte) (int, error) {
	return d.inner.Read(p)
}

func (d *auditR5RealSubnetDevice) Write(p []byte) (int, error) {
	return d.inner.Write(p)
}

func (d *auditR5RealSubnetDevice) Close() error {
	return nil
}

func (d *auditR5RealSubnetDevice) CreatedAt() time.Time {
	return time.Now()
}

func (d *auditR5RealSubnetDevice) LastHandshakeTime() time.Time {
	return time.Now()
}

func (d *auditR5RealSubnetDevice) IsClosed() bool {
	return false
}

func (d *auditR5RealSubnetDevice) DroppedPackets() uint64 {
	return 0
}

func (d *auditR5RealSubnetDevice) RegisterCanaryResponseHook(h tunnel.CanaryResponseHook) func() {
	return d.inner.RegisterCanaryResponseHook(h)
}

// TestAuditR5_CustomSubnetReachesCanary verifies Finding F9 fix:
// A configured custom portal subnet (e.g. 10.200.0.0/16) is propagated cleanly to the canary prober,
// allowing canary packets to match the remote data peer's AllowedIPs.
func TestAuditR5_CustomSubnetReachesCanary(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, _, _ := setupTestVPNService(t, db, func(cfg *models.VPNConfig) {
		cfg.SubnetCIDR = "10.200.0.0/16"
	})
	_, subnet, _ := net.ParseCIDR(svc.cfg.SubnetCIDR)
	inner := &auditR5SubnetDevice{subnet: subnet}
	dev := &auditR5RealSubnetDevice{inner: inner}
	svc.backendDevices = map[int64]BackendDevice{9001: dev}
	svc.SetCanaryProbeFunc(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	err := svc.ProbeCanary(ctx, &models.BackendTunnel{ID: 9001, ServerID: 9002})
	t.Logf("configured=%s prober=%s source_packets=%v accepted=%d error=%v", svc.SubnetCIDR(), svc.prober.GetSubnetCIDR(), inner.sources, inner.accepted, err)

	// Control: same actual canary/device succeeds with the configured CIDR.
	control := tunnel.ProbePacketDevice(ctx, dev, 100*time.Millisecond, svc.SubnetCIDR())
	t.Logf("configured-CIDR control result=%v accepted=%d", control, inner.accepted)
	if control != nil {
		t.Fatalf("invalid fixture control: %v", control)
	}
	if err != nil {
		t.Fatalf("working custom-subnet data peer rejected by Service.ProbeCanary: %v", err)
	}
}
