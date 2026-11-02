package gatewaydns

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync/atomic"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
	mdns "github.com/miekg/dns"
)

// ReplyWriter sends packet frames back towards the authenticated VPN client.
type ReplyWriter interface {
	WritePacket(scope policy.Scope, packet []byte) error
}

// ScopeHandle represents an active authenticated DNS session capability.
type ScopeHandle struct {
	Scope        policy.Scope
	SessionCache *policy.SessionCache
	ReplyWriter  ReplyWriter
	ctx          context.Context
	cancel       context.CancelFunc
	retired      atomic.Bool
}

// NewScopeHandle constructs a new ScopeHandle tied to the parent context.
func NewScopeHandle(parent context.Context, scope policy.Scope, sc *policy.SessionCache, writer ReplyWriter) *ScopeHandle {
	ctx, cancel := context.WithCancel(parent)
	return &ScopeHandle{
		Scope:        scope,
		SessionCache: sc,
		ReplyWriter:  writer,
		ctx:          ctx,
		cancel:       cancel,
	}
}

// IsRetired returns true if the scope handle has been retired.
func (h *ScopeHandle) IsRetired() bool {
	if h == nil {
		return true
	}
	return h.retired.Load()
}

// Context returns the context for this scope handle.
func (h *ScopeHandle) Context() context.Context {
	if h == nil {
		return context.Background()
	}
	return h.ctx
}

// Retirement tracks synchronous invalidation of an expired or revoked scope.
type Retirement struct {
	Scope policy.Scope
}

// GatewayConfig configures the Gateway transport adapter.
type GatewayConfig struct {
	Gateway netip.AddrPort
}

// Gateway intercepts and processes DNS queries addressed to the gateway on port 53.
type Gateway struct {
	cfg    GatewayConfig
	server *Server
}

// NewGateway constructs a new Gateway transport adapter.
func NewGateway(cfg GatewayConfig, server *Server) (*Gateway, error) {
	if !cfg.Gateway.IsValid() || !cfg.Gateway.Addr().Is4() || cfg.Gateway.Port() != 53 {
		return nil, errors.New("gateway must have valid IPv4 and port 53")
	}
	if server == nil {
		return nil, errors.New("server cannot be nil")
	}
	return &Gateway{
		cfg:    cfg,
		server: server,
	}, nil
}

// TrySubmit inspects incoming IPv4 packets from authenticated ingress.
// If addressed to the gateway IPv4 on port 53 (UDP or TCP), the packet is handled by the DNS service.
func (g *Gateway) TrySubmit(scope *ScopeHandle, ipv4Packet []byte) (handled bool, err error) {
	if scope == nil || scope.IsRetired() {
		return false, nil
	}
	if len(ipv4Packet) < 20 {
		return false, nil
	}

	// Verify IPv4 version.
	if (ipv4Packet[0] >> 4) != 4 {
		return false, nil
	}
	ihl := int(ipv4Packet[0]&0x0f) * 4
	if len(ipv4Packet) < ihl {
		return false, nil
	}

	// Verify destination IP matches gateway IP.
	dstIP := netip.AddrFrom4([4]byte{ipv4Packet[16], ipv4Packet[17], ipv4Packet[18], ipv4Packet[19]})
	if dstIP != g.cfg.Gateway.Addr() {
		return false, nil
	}

	proto := ipv4Packet[9]
	switch proto {
	case 17: // UDP
		if len(ipv4Packet) < ihl+8 {
			return false, nil
		}
		dstPort := binary.BigEndian.Uint16(ipv4Packet[ihl+2 : ihl+4])
		if dstPort != 53 {
			return false, nil
		}

		// Exact gateway:53 UDP destination - packet is handled by DNS gateway.
		fragOffset := binary.BigEndian.Uint16(ipv4Packet[6:8]) & 0x1fff
		moreFrags := (ipv4Packet[6] & 0x20) != 0
		if fragOffset != 0 || moreFrags {
			// Drop fragmented UDP packets.
			return true, nil
		}

		srcIP := netip.AddrFrom4([4]byte{ipv4Packet[12], ipv4Packet[13], ipv4Packet[14], ipv4Packet[15]})
		srcPort := binary.BigEndian.Uint16(ipv4Packet[ihl : ihl+2])
		udpLen := int(binary.BigEndian.Uint16(ipv4Packet[ihl+4 : ihl+6]))
		if udpLen < 8 || ihl+udpLen > len(ipv4Packet) {
			return true, nil
		}

		udpPayload := ipv4Packet[ihl+8 : ihl+udpLen]
		reqMsg := new(mdns.Msg)
		if err := reqMsg.Unpack(udpPayload); err != nil {
			return true, nil // Malformed DNS query dropped.
		}

		respMsg, err := g.server.ServeDNSMessage(scope.ctx, scope.SessionCache, scope.Scope.SessionID, reqMsg, false)
		if err != nil || respMsg == nil {
			return true, nil
		}

		respBytes, err := respMsg.Pack()
		if err != nil {
			return true, nil
		}

		// Enqueue reply back to authenticated client if scope remains active.
		if !scope.IsRetired() && scope.ReplyWriter != nil {
			replyPkt := buildIPv4UDPPacket(dstIP, 53, srcIP, srcPort, respBytes)
			if replyPkt != nil {
				_ = scope.ReplyWriter.WritePacket(scope.Scope, replyPkt)
			}
		}
		return true, nil

	case 6: // TCP
		if len(ipv4Packet) < ihl+20 {
			return false, nil
		}
		dstPort := binary.BigEndian.Uint16(ipv4Packet[ihl+2 : ihl+4])
		if dstPort != 53 {
			return false, nil
		}
		// Exact gateway:53 TCP destination - handled.
		return true, nil

	default:
		return false, nil
	}
}

// BeginRetire permanently retires scope handle, cancels query contexts, and invalidates session cache.
// Synchronous, memory-only, and idempotent.
func (g *Gateway) BeginRetire(scope *ScopeHandle) Retirement {
	if scope != nil {
		scope.retired.Store(true)
		scope.cancel()
		if scope.SessionCache != nil {
			scope.SessionCache.Invalidate()
		}
		return Retirement{Scope: scope.Scope}
	}
	return Retirement{}
}

func buildIPv4UDPPacket(srcIP netip.Addr, srcPort uint16, dstIP netip.Addr, dstPort uint16, payload []byte) []byte {
	if len(payload) > 65507 {
		return nil
	}
	totalLen := 20 + 8 + len(payload)
	pkt := make([]byte, totalLen)

	// IPv4 Header
	pkt[0] = 0x45
	pkt[1] = 0x00
	// #nosec G115 -- totalLen is bounded by 20+8+65507 <= 65535
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(pkt[4:6], 0)
	binary.BigEndian.PutUint16(pkt[6:8], 0x4000) // DF flag
	pkt[8] = 64                                 // TTL
	pkt[9] = 17                                 // Protocol UDP
	srcBytes := srcIP.As4()
	dstBytes := dstIP.As4()
	copy(pkt[12:16], srcBytes[:])
	copy(pkt[16:20], dstBytes[:])
	ipChecksum := calculateChecksum(pkt[0:20])
	binary.BigEndian.PutUint16(pkt[10:12], ipChecksum)

	// UDP Header
	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	// #nosec G115 -- 8+len(payload) is bounded by 8+65507 <= 65535
	binary.BigEndian.PutUint16(pkt[24:26], uint16(8+len(payload)))
	binary.BigEndian.PutUint16(pkt[26:28], 0) // Checksum optional
	copy(pkt[28:], payload)

	return pkt
}

func calculateChecksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i < len(header)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	if len(header)%2 != 0 {
		sum += uint32(header[len(header)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
