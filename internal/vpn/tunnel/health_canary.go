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

// CanaryResponseHook defines the callback signature used by return listeners to inspect packets.
// It returns true if the packet was recognized and consumed as an in-tunnel canary response.
type CanaryResponseHook func(packet []byte) bool

// CanaryResponseDemuxer is implemented by PacketDevices or return paths that demultiplex
// in-tunnel canary responses from the single return reader loop (e.g. pumpBackendReturns).
type CanaryResponseDemuxer interface {
	RegisterCanaryResponseHook(hook CanaryResponseHook) (unregister func())
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

// GetSubnetCIDR returns the immutable configured portal subnet CIDR for canary probes.
// It is read directly from immutable prober configuration without acquiring hp.mu,
// eliminating cross-lock contention with Service.mu.
func (hp *HealthProber) GetSubnetCIDR() string {
	if hp == nil || hp.cfg.SubnetCIDR == "" {
		return "10.100.0.0/16"
	}
	return hp.cfg.SubnetCIDR
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

	return ProbePacketDevice(ctx, dev, timeout, hp.GetSubnetCIDR())
}

// ProbePacketDevice sends an in-tunnel canary packet and waits for response or data-plane loopback.
// Canary responses are demultiplexed via return listener hooks to ensure only ONE reader consumes
// backend packets, eliminating reader race conditions with the production return pump and avoiding
// orphaned goroutines on timeout.
func ProbePacketDevice(ctx context.Context, dev PacketDevice, timeout time.Duration, subnetCIDR ...string) error {
	if dev == nil {
		return errors.New("packet device is nil")
	}

	if cd, ok := dev.(CanaryDevice); ok {
		return cd.ProbeCanary(ctx, timeout)
	}

	cidr := "10.100.0.0/16"
	if len(subnetCIDR) > 0 && subnetCIDR[0] != "" {
		cidr = subnetCIDR[0]
	}

	canaryID := uint16(0x0713)
	canarySeq := uint16(1)
	pkt := CanaryPingPacketForSubnet(cidr)

	ctxTimeout, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// If device implements CanaryResponseDemuxer, register a response listener hook.
	// The single reader (e.g. pumpBackendReturns) will invoke the hook without reader contention.
	if demux, ok := dev.(CanaryResponseDemuxer); ok {
		respCh := make(chan struct{}, 1)
		unregister := demux.RegisterCanaryResponseHook(func(packet []byte) bool {
			if IsCanaryEchoReply(packet, canaryID, canarySeq) {
				select {
				case respCh <- struct{}{}:
				default:
				}
				return true
			}
			return false
		})
		defer unregister()

		if _, err := dev.Write(pkt); err != nil {
			return fmt.Errorf("canary packet write failed: %w", err)
		}

		select {
		case <-ctxTimeout.Done():
			return fmt.Errorf("canary probe timed out: %w", ctxTimeout.Err())
		case <-respCh:
			return nil
		}
	}

	// If device exposes an Outbound channel (like VirtualTUN in standalone tests),
	// read directly without leaking a goroutine.
	if chDev, ok := dev.(outboundChannelHolder); ok {
		if _, err := dev.Write(pkt); err != nil {
			return fmt.Errorf("canary packet write failed: %w", err)
		}
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

	return fmt.Errorf("packet device of type %T does not support canary response demultiplexing", dev)
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

// CanarySourceIPFromCIDR derives a valid source IP within the given CIDR subnet.
// It uses the gateway address (netInt + 1), which is within the authorized AllowedIPs
// of the portal data peer on the remote backend and reserved in IPAM.
func CanarySourceIPFromCIDR(cidr string) net.IP {
	if cidr == "" {
		cidr = "10.100.0.0/16"
	}
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil || ip.To4() == nil {
		return net.IPv4(10, 100, 0, 1)
	}
	ipv4 := ip.To4()
	netInt := binary.BigEndian.Uint32(ipv4.Mask(ipNet.Mask))
	gwInt := netInt + 1
	gwBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(gwBytes, gwInt)
	return net.IP(gwBytes)
}

// DefaultCanaryDestination is the reliable public responder IP (1.1.1.1) used as the
// canary probe destination. Packets targeting this address route through the backend tunnel
// to WAN, eliciting responses from the internet rather than local client leases.
var DefaultCanaryDestination = net.IPv4(1, 1, 1, 1)

// CanaryDestinationIP returns a reliable public canary responder IP (1.1.1.1) that routes
// through the backend tunnel to the internet WAN.
func CanaryDestinationIP() net.IP {
	return net.IPv4(1, 1, 1, 1)
}

// CanaryDestinationIPFromCIDR returns a reachable public responder IP (1.1.1.1) routed via WAN.
// To ensure the canary probe verifies WAN reachability and is answered by an active internet responder
// rather than being dropped or misrouted to a client lease, this targets a reliable public responder.
// The cidr parameter is preserved for API compatibility.
func CanaryDestinationIPFromCIDR(_ string) net.IP {
	return CanaryDestinationIP()
}

// CanaryPingPacketForSubnet builds a valid ICMP Echo Request packet with source address
// inside the specified portal client subnet and destination address targeting a reliable
// public canary responder (1.1.1.1) routed via WAN.
func CanaryPingPacketForSubnet(subnetCIDR string) []byte {
	src := CanarySourceIPFromCIDR(subnetCIDR)
	dst := CanaryDestinationIP()
	return BuildCanaryICMPEchoRequest(src, dst, 0x0713, 1)
}

// CanaryDNSPacketForSubnet builds a UDP DNS query with source address inside the specified portal client subnet
// and destination address targeting a reliable public DNS resolver (1.1.1.1).
func CanaryDNSPacketForSubnet(subnetCIDR string) []byte {
	src := CanarySourceIPFromCIDR(subnetCIDR)
	dst := CanaryDestinationIP()
	return BuildCanaryDNSQuery(src, dst, "canary.nexus.internal")
}

// DefaultCanaryPingPacket returns a minimal valid IPv4 ICMP Echo Request packet using the default portal subnet.
func DefaultCanaryPingPacket() []byte {
	return CanaryPingPacketForSubnet("10.100.0.0/16")
}

// BuildCanaryICMPEchoRequest builds a complete IPv4 packet containing an ICMP Echo Request.
func BuildCanaryICMPEchoRequest(srcIP, dstIP net.IP, id, seq uint16) []byte {
	src := srcIP.To4()
	if src == nil {
		src = net.IPv4(10, 100, 0, 1).To4()
	}
	dst := dstIP.To4()
	if dst == nil {
		dst = net.IPv4(1, 1, 1, 1).To4()
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

// BuildCanaryICMPEchoReply builds a complete IPv4 packet containing an ICMP Echo Reply matching a canary request.
func BuildCanaryICMPEchoReply(srcIP, dstIP net.IP, id, seq uint16) []byte {
	src := srcIP.To4()
	if src == nil {
		src = net.IPv4(1, 1, 1, 1).To4()
	}
	dst := dstIP.To4()
	if dst == nil {
		dst = net.IPv4(10, 100, 0, 1).To4()
	}

	pkt := make([]byte, 28)
	// IPv4 Header
	pkt[0] = 0x45
	pkt[1] = 0x00
	binary.BigEndian.PutUint16(pkt[2:4], 28)
	binary.BigEndian.PutUint16(pkt[4:6], id)
	pkt[6] = 0x40
	pkt[7] = 0x00
	pkt[8] = 64
	pkt[9] = 1 // Protocol: ICMP
	copy(pkt[12:16], src)
	copy(pkt[16:20], dst)
	ipCsum := internetChecksum(pkt[0:20])
	binary.BigEndian.PutUint16(pkt[10:12], ipCsum)

	// ICMP Echo Reply
	pkt[20] = 0 // Type: Echo Reply
	pkt[21] = 0 // Code: 0
	binary.BigEndian.PutUint16(pkt[24:26], id)
	binary.BigEndian.PutUint16(pkt[26:28], seq)
	icmpCsum := internetChecksum(pkt[20:28])
	binary.BigEndian.PutUint16(pkt[22:24], icmpCsum)

	return pkt
}

// IsCanaryEchoReply verifies whether an incoming IPv4 datagram is an ICMP Echo Reply
// corresponding to the canary probe with the given identifier and sequence number.
func IsCanaryEchoReply(pkt []byte, expectedID, expectedSeq uint16) bool {
	if len(pkt) < 28 {
		return false
	}
	if pkt[0]>>4 != 4 {
		return false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || ihl+8 > len(pkt) {
		return false
	}
	if pkt[9] != 1 { // Protocol: ICMP
		return false
	}
	if pkt[ihl] != 0 || pkt[ihl+1] != 0 { // ICMP Type 0 (Echo Reply), Code 0
		return false
	}
	id := binary.BigEndian.Uint16(pkt[ihl+4 : ihl+6])
	seq := binary.BigEndian.Uint16(pkt[ihl+6 : ihl+8])
	return id == expectedID && seq == expectedSeq
}

// DefaultCanaryDNSPacket returns a lightweight UDP DNS query packet with source IP inside the default portal subnet.
func DefaultCanaryDNSPacket() []byte {
	return CanaryDNSPacketForSubnet("10.100.0.0/16")
}

// BuildCanaryDNSQuery constructs an IPv4 + UDP packet with a minimal DNS query for domain.
func BuildCanaryDNSQuery(srcIP, dstIP net.IP, domain string) []byte {
	src := srcIP.To4()
	if src == nil {
		src = net.IPv4(10, 100, 0, 1).To4()
	}
	dst := dstIP.To4()
	if dst == nil {
		dst = net.IPv4(1, 1, 1, 1).To4()
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
