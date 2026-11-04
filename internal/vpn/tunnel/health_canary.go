package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/virtualtun"
)

// ErrNoActiveDevice is returned when an in-tunnel canary probe is attempted on a backend
// without a registered or active data-plane device (PacketDevice/VirtualTUN).
var ErrNoActiveDevice = errors.New("no active data-plane device for backend tunnel")

// CanaryProbeFunc defines the function signature for probing the in-tunnel data plane
// of an active backend tunnel.
type CanaryProbeFunc func(ctx context.Context, tunnel *models.BackendTunnel) error

// CanaryDevice is an optional interface that a custom PacketDevice can implement to handle
// canary probing directly.
type CanaryDevice interface {
	ProbeCanary(ctx context.Context, timeout time.Duration) error
}

type outboundChannelHolder interface {
	Outbound() <-chan []byte
}

// SetCanaryProbeFunc overrides the canary probe function (useful for deterministic tests).
func (hp *HealthProber) SetCanaryProbeFunc(fn CanaryProbeFunc) {
	if hp == nil {
		return
	}
	hp.mu.Lock()
	defer hp.mu.Unlock()
	hp.probeCanaryFn = fn
}

// DeviceProvider provides access to active backend PacketDevices by tunnel or server ID.
type DeviceProvider interface {
	GetDevice(id int64) (PacketDevice, bool)
}

// SetDeviceProvider registers a DeviceProvider or lookup callback for retrieving active backend devices by tunnel ID.
func (hp *HealthProber) SetDeviceProvider(provider any) {
	if hp == nil {
		return
	}
	hp.mu.Lock()
	defer hp.mu.Unlock()
	switch p := provider.(type) {
	case DeviceProvider:
		hp.deviceProvider = func(tunnelID int64) PacketDevice {
			dev, ok := p.GetDevice(tunnelID)
			if !ok {
				return nil
			}
			return dev
		}
	case func(tunnelID int64) PacketDevice:
		hp.deviceProvider = p
	case func(tunnelID int64) (PacketDevice, bool):
		hp.deviceProvider = func(tunnelID int64) PacketDevice {
			dev, _ := p(tunnelID)
			return dev
		}
	case nil:
		hp.deviceProvider = nil
	}
}

// RegisterDevice registers an active PacketDevice for a backend tunnel.
func (hp *HealthProber) RegisterDevice(tunnelID int64, dev PacketDevice) {
	if hp == nil {
		return
	}
	hp.mu.Lock()
	defer hp.mu.Unlock()
	if hp.devices == nil {
		hp.devices = make(map[int64]PacketDevice)
	}
	hp.devices[tunnelID] = dev
}

// UnregisterDevice removes a registered PacketDevice for a backend tunnel.
func (hp *HealthProber) UnregisterDevice(tunnelID int64) {
	if hp == nil {
		return
	}
	hp.mu.Lock()
	defer hp.mu.Unlock()
	if hp.devices != nil {
		delete(hp.devices, tunnelID)
	}
}

// GetDevice returns the active PacketDevice for a backend tunnel, if any.
func (hp *HealthProber) GetDevice(tunnelID int64) PacketDevice {
	if hp == nil {
		return nil
	}
	hp.mu.RLock()
	provider := hp.deviceProvider
	hp.mu.RUnlock()

	if provider != nil {
		if dev := provider(tunnelID); dev != nil {
			return dev
		}
	}

	hp.mu.RLock()
	defer hp.mu.RUnlock()
	if hp.devices != nil {
		return hp.devices[tunnelID]
	}
	return nil
}

// ProbeCanary executes an in-tunnel canary probe against the given backend tunnel.
// If a custom CanaryProbeFunc is configured, it is invoked; otherwise defaultCanaryProbe is used.
func (hp *HealthProber) ProbeCanary(ctx context.Context, tunnel *models.BackendTunnel) error {
	return hp.probeCanary(ctx, tunnel)
}

func (hp *HealthProber) probeCanary(ctx context.Context, tunnel *models.BackendTunnel) error {
	if hp == nil {
		return errors.New("health prober is nil")
	}
	if tunnel == nil {
		return errors.New("tunnel is nil")
	}

	hp.mu.RLock()
	fn := hp.probeCanaryFn
	hp.mu.RUnlock()

	if fn != nil {
		return fn(ctx, tunnel)
	}

	return hp.defaultCanaryProbe(ctx, tunnel)
}

func (hp *HealthProber) defaultCanaryProbe(ctx context.Context, tunnel *models.BackendTunnel) error {
	dev := hp.GetDevice(tunnel.ID)
	if dev == nil {
		return fmt.Errorf("%w: tunnel %d", ErrNoActiveDevice, tunnel.ID)
	}

	timeout := hp.cfg.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	return ProbePacketDevice(ctx, dev, timeout)
}

// ProbePacketDevice sends an in-tunnel canary packet and waits for response or data-plane loopback.
func ProbePacketDevice(ctx context.Context, dev PacketDevice, timeout time.Duration) error {
	if dev == nil {
		return errors.New("packet device is nil")
	}

	if cd, ok := dev.(CanaryDevice); ok {
		return cd.ProbeCanary(ctx, timeout)
	}

	pkt := DefaultCanaryPingPacket()
	if _, err := dev.Write(pkt); err != nil {
		return fmt.Errorf("canary packet write failed: %w", err)
	}

	ctxTimeout, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// If device exposes an Outbound channel (like VirtualTUN), read directly without leaking a goroutine
	if chDev, ok := dev.(outboundChannelHolder); ok {
		select {
		case <-ctxTimeout.Done():
			return fmt.Errorf("canary probe timed out: %w", ctxTimeout.Err())
		case out, ok := <-chDev.Outbound():
			if !ok {
				return errors.New("device outbound channel closed")
			}
			if len(out) == 0 {
				return errors.New("empty packet received from device outbound channel")
			}
			return nil
		}
	}

	readCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 1500)
		n, err := dev.Read(buf)
		if err != nil {
			readCh <- fmt.Errorf("canary packet read failed: %w", err)
			return
		}
		if n <= 0 {
			readCh <- errors.New("canary packet read returned 0 bytes")
			return
		}
		readCh <- nil
	}()

	select {
	case <-ctxTimeout.Done():
		return fmt.Errorf("canary probe timed out: %w", ctxTimeout.Err())
	case err := <-readCh:
		return err
	}
}

// ProbeVirtualTUN probes an in-memory VirtualTUN directly using InjectInbound and Outbound.
func ProbeVirtualTUN(ctx context.Context, vt *virtualtun.VirtualTUN, timeout time.Duration) error {
	if vt == nil {
		return errors.New("virtual tun is nil")
	}

	pkt := DefaultCanaryPingPacket()
	if err := vt.InjectInbound(pkt); err != nil {
		return fmt.Errorf("virtual tun inject inbound failed: %w", err)
	}

	ctxTimeout, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	select {
	case <-ctxTimeout.Done():
		return fmt.Errorf("canary probe timed out: %w", ctxTimeout.Err())
	case out, ok := <-vt.Outbound():
		if !ok {
			return errors.New("virtual tun closed")
		}
		if len(out) == 0 {
			return errors.New("empty packet from virtual tun")
		}
		return nil
	}
}

// DefaultCanaryPingPacket returns a minimal valid IPv4 ICMP Echo Request packet.
func DefaultCanaryPingPacket() []byte {
	return BuildCanaryICMPEchoRequest(net.IPv4(10, 0, 0, 2), net.IPv4(10, 0, 0, 1), 0x0713, 1)
}

// BuildCanaryICMPEchoRequest builds a complete IPv4 packet containing an ICMP Echo Request.
func BuildCanaryICMPEchoRequest(srcIP, dstIP net.IP, id, seq uint16) []byte {
	src := srcIP.To4()
	if src == nil {
		src = net.IPv4(10, 0, 0, 2).To4()
	}
	dst := dstIP.To4()
	if dst == nil {
		dst = net.IPv4(10, 0, 0, 1).To4()
	}

	pkt := make([]byte, 28) // 20 bytes IPv4 header + 8 bytes ICMP header
	// IPv4 Header
	pkt[0] = 0x45                            // Version 4, IHL 5
	pkt[1] = 0x00                            // DSCP / ECN
	binary.BigEndian.PutUint16(pkt[2:4], 28) // Total Length
	binary.BigEndian.PutUint16(pkt[4:6], id) // Identification
	pkt[6] = 0x40                            // Flags: Don't Fragment
	pkt[7] = 0x00                            // Fragment offset 0
	pkt[8] = 64                              // TTL
	pkt[9] = 1                               // Protocol: ICMP
	// Checksum placeholder at pkt[10:12]
	copy(pkt[12:16], src)
	copy(pkt[16:20], dst)
	ipCsum := internetChecksum(pkt[0:20])
	binary.BigEndian.PutUint16(pkt[10:12], ipCsum)

	// ICMP Echo Request
	pkt[20] = 8 // Type: Echo Request
	pkt[21] = 0 // Code: 0
	// Checksum placeholder at pkt[22:24]
	binary.BigEndian.PutUint16(pkt[24:26], id)
	binary.BigEndian.PutUint16(pkt[26:28], seq)
	icmpCsum := internetChecksum(pkt[20:28])
	binary.BigEndian.PutUint16(pkt[22:24], icmpCsum)

	return pkt
}

// DefaultCanaryDNSPacket returns a lightweight UDP DNS query packet for "canary.nexus.internal".
func DefaultCanaryDNSPacket() []byte {
	return BuildCanaryDNSQuery(net.IPv4(10, 0, 0, 2), net.IPv4(10, 0, 0, 1), "canary.nexus.internal")
}

// BuildCanaryDNSQuery constructs an IPv4 + UDP packet with a minimal DNS query for domain.
func BuildCanaryDNSQuery(srcIP, dstIP net.IP, domain string) []byte {
	src := srcIP.To4()
	if src == nil {
		src = net.IPv4(10, 0, 0, 2).To4()
	}
	dst := dstIP.To4()
	if dst == nil {
		dst = net.IPv4(10, 0, 0, 1).To4()
	}

	// Minimal DNS Query: ID(2), Flags(2), QDCOUNT(2), ANCOUNT(2), NSCOUNT(2), ARCOUNT(2) = 12 bytes
	var dnsPayload []byte
	dnsPayload = append(dnsPayload,
		0x07, 0x13, // ID
		0x01, 0x00, // Flags: Standard query, RD=1
		0x00, 0x01, // QDCOUNT: 1
		0x00, 0x00, // ANCOUNT: 0
		0x00, 0x00, // NSCOUNT: 0
		0x00, 0x00, // ARCOUNT: 0
	)
	// Encode domain labels
	labels := splitDomainLabels(domain)
	for _, l := range labels {
		labelLen := len(l)
		if labelLen > 63 {
			labelLen = 63
			l = l[:63]
		}
		dnsPayload = append(dnsPayload, byte(labelLen)) // #nosec G115 -- labelLen clamped to <= 63
		dnsPayload = append(dnsPayload, []byte(l)...)
	}
	dnsPayload = append(dnsPayload, 0x00)       // Root null label
	dnsPayload = append(dnsPayload, 0x00, 0x01) // QTYPE: A (1)
	dnsPayload = append(dnsPayload, 0x00, 0x01) // QCLASS: IN (1)

	udpLen := 8 + len(dnsPayload)
	totalLen := 20 + udpLen
	if totalLen > 65535 || udpLen > 65535 {
		return nil
	}

	pkt := make([]byte, totalLen)
	// IPv4 Header
	pkt[0] = 0x45
	pkt[1] = 0x00
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen)) // #nosec G115 -- totalLen verified <= 65535
	binary.BigEndian.PutUint16(pkt[4:6], 0x0713)
	pkt[6] = 0x40
	pkt[7] = 0x00
	pkt[8] = 64
	pkt[9] = 17 // UDP
	copy(pkt[12:16], src)
	copy(pkt[16:20], dst)
	ipCsum := internetChecksum(pkt[0:20])
	binary.BigEndian.PutUint16(pkt[10:12], ipCsum)

	// UDP Header: src port 53535, dst port 53
	binary.BigEndian.PutUint16(pkt[20:22], 53535)
	binary.BigEndian.PutUint16(pkt[22:24], 53)
	binary.BigEndian.PutUint16(pkt[24:26], uint16(udpLen)) // #nosec G115 -- udpLen verified <= 65535
	binary.BigEndian.PutUint16(pkt[26:28], 0)              // Checksum optional in IPv4 UDP
	copy(pkt[28:], dnsPayload)

	return pkt
}

func splitDomainLabels(domain string) []string {
	var labels []string
	curr := ""
	for i := 0; i < len(domain); i++ {
		if domain[i] == '.' {
			if len(curr) > 0 {
				labels = append(labels, curr)
				curr = ""
			}
		} else {
			curr += string(domain[i])
		}
	}
	if len(curr) > 0 {
		labels = append(labels, curr)
	}
	return labels
}

func internetChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i < len(b)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}
