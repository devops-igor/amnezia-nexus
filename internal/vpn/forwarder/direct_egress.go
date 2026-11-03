package forwarder

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

var (
	// ErrProhibitedDestination is returned when traffic targets private, loopback, or metadata addresses.
	ErrProhibitedDestination = errors.New("forwarder: prohibited destination address")
	// ErrDirectEgressUnavailable is returned when direct WAN egress is unconfigured or unavailable.
	ErrDirectEgressUnavailable = errors.New("forwarder: direct egress unavailable")
	// ErrNATPortExhaustion is returned when no unused NAT port is available.
	ErrNATPortExhaustion = errors.New("forwarder: direct egress nat port exhaustion")
	// ErrFlowTableFull is returned when flow tracking capacity is reached.
	ErrFlowTableFull = errors.New("forwarder: flow table capacity reached")
)

// EgressChoice represents the routing choice (DIRECT or PROXY) for an active 5-tuple flow.
type EgressChoice uint8

const (
	EgressChoiceNone   EgressChoice = 0
	EgressChoiceDirect EgressChoice = 1
	EgressChoiceProxy  EgressChoice = 2
)

func (c EgressChoice) String() string {
	switch c {
	case EgressChoiceDirect:
		return "DIRECT"
	case EgressChoiceProxy:
		return "PROXY"
	default:
		return "NONE"
	}
}

// FlowKey represents a 5-tuple flow scoped to a specific authenticated peer session.
type FlowKey struct {
	PeerKey  string
	Protocol uint8
	SrcIP    [4]byte
	DstIP    [4]byte
	SrcPort  uint16
	DstPort  uint16
}

type flowEntry struct {
	choice     EgressChoice
	natPort    uint16
	lastSeen   time.Time
	peerKey    string
	sessionID  string
	generation uint64
	closeSeen  bool
}

type inboundKey struct {
	protocol uint8
	natPort  uint16
}

type natEntry struct {
	peerKey    string
	sessionID  string
	generation uint64
	flowKey    FlowKey
	clientIP   netip.Addr
	clientPort uint16
	remoteIP   netip.Addr
	remotePort uint16
	protocol   uint8
	natPort    uint16
	returnPath *ReturnPath
	lastSeen   time.Time
	closeSeen  bool
}

// DirectEgressConfig configures DirectEgressManager.
type DirectEgressConfig struct {
	HostWANIP    netip.Addr
	GatewayDNSIP netip.Addr
	WANDevice    PacketDevice
	TCPTimeout   time.Duration
	UDPTimeout   time.Duration
	MinPort      uint16
	MaxPort      uint16
	MaxFlows     int
}

const (
	defaultDirectTCPTimeout = 300 * time.Second
	defaultDirectUDPTimeout = 30 * time.Second
	defaultMinNATPort       = 40000
	defaultMaxNATPort       = 65000
	defaultMaxFlows         = 65536
)

var cloudMetadataIP = netip.MustParseAddr("169.254.169.254")

// DirectEgressManager manages direct host WAN forwarding, SNAT, response demultiplexing,
// and 5-tuple flow stickiness.
type DirectEgressManager struct {
	mu          sync.RWMutex
	cfg         DirectEgressConfig
	fwd         *Forwarder
	wanDevice   PacketDevice
	flows       map[FlowKey]*flowEntry
	inboundNAT  map[inboundKey]*natEntry
	usedPorts   map[uint16]bool
	nextPort    uint16
	stopCh      chan struct{}
	closed      bool
	directDrops atomic.Uint64
	directBytes atomic.Int64
}

// DirectDrops returns the total number of packets dropped by direct egress.
func (m *DirectEgressManager) DirectDrops() uint64 {
	return m.directDrops.Load()
}

// DirectBytes returns the total number of bytes successfully egressed via direct WAN.
func (m *DirectEgressManager) DirectBytes() int64 {
	return m.directBytes.Load()
}

// NewDirectEgressManager constructs a new DirectEgressManager.
func NewDirectEgressManager(cfg DirectEgressConfig, fwd *Forwarder) *DirectEgressManager {
	if !cfg.HostWANIP.IsValid() || !cfg.HostWANIP.Is4() {
		cfg.HostWANIP = netip.MustParseAddr("203.0.113.1")
	}
	if cfg.TCPTimeout <= 0 {
		cfg.TCPTimeout = defaultDirectTCPTimeout
	}
	if cfg.UDPTimeout <= 0 {
		cfg.UDPTimeout = defaultDirectUDPTimeout
	}
	if cfg.MinPort == 0 {
		cfg.MinPort = defaultMinNATPort
	}
	if cfg.MaxPort == 0 || cfg.MaxPort <= cfg.MinPort {
		cfg.MaxPort = defaultMaxNATPort
	}
	if cfg.MaxFlows <= 0 {
		cfg.MaxFlows = defaultMaxFlows
	}

	dem := &DirectEgressManager{
		cfg:        cfg,
		fwd:        fwd,
		wanDevice:  cfg.WANDevice,
		flows:      make(map[FlowKey]*flowEntry),
		inboundNAT: make(map[inboundKey]*natEntry),
		usedPorts:  make(map[uint16]bool),
		nextPort:   cfg.MinPort,
	}

	if cfg.WANDevice != nil {
		dem.stopCh = make(chan struct{})
		go dem.readWANLoop(cfg.WANDevice, dem.stopCh)
	}

	return dem
}

// WritePacket sends a return packet for an authenticated peer directly to its ReturnPath.
func (p *ReturnPath) WritePacket(peerKey, assignedIP string, packet []byte) error {
	_, err := p.Write(peerKey, assignedIP, packet)
	return err
}

// AttachWANDevice attaches or replaces the WAN egress packet device.
func (m *DirectEgressManager) AttachWANDevice(dev PacketDevice) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.stopCh != nil {
		close(m.stopCh)
		m.stopCh = nil
	}

	m.wanDevice = dev
	if dev != nil && !m.closed {
		m.stopCh = make(chan struct{})
		go m.readWANLoop(dev, m.stopCh)
	}
}

func (m *DirectEgressManager) readWANLoop(dev PacketDevice, stopCh chan struct{}) {
	buf := make([]byte, 65535)
	for {
		select {
		case <-stopCh:
			return
		default:
		}
		n, err := dev.Read(buf)
		if err != nil {
			return
		}
		if n > 0 {
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			_ = m.HandleWANReply(pkt)
		}
	}
}

// IsProhibitedDestination tests whether dst is a restricted network address:
// Loopback (127/8), link-local (169.254/16), RFC1918 private (10/8, 172.16/12, 192.168/16),
// multicast (224/4), or cloud metadata (169.254.169.254).
// Traffic to the designated gateway DNS address is explicitly permitted.
func (m *DirectEgressManager) IsProhibitedDestination(dst netip.Addr) bool {
	if m != nil && m.cfg.GatewayDNSIP.IsValid() && dst == m.cfg.GatewayDNSIP {
		return false
	}

	if !dst.IsValid() || !dst.Is4() {
		return true
	}
	if dst.IsLoopback() || dst.IsLinkLocalUnicast() || dst.IsPrivate() || dst.IsMulticast() || dst.IsUnspecified() {
		return true
	}
	if dst == cloudMetadataIP {
		return true
	}
	if dst.As4()[0] == 0 {
		return true
	}
	if dst == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return true
	}
	return false
}

func (m *DirectEgressManager) isFlowExpiredLocked(f *flowEntry, proto uint8, now time.Time) bool {
	timeout := m.cfg.UDPTimeout
	if proto == 6 {
		if f.closeSeen {
			timeout = 5 * time.Second
		} else {
			timeout = m.cfg.TCPTimeout
		}
	}
	return now.Sub(f.lastSeen) > timeout
}

// LookupFlow checks if an existing sticky flow decision is recorded for this packet's 5-tuple.
func (m *DirectEgressManager) LookupFlow(peerKey string, packet []byte) (EgressChoice, bool) {
	if m == nil || len(packet) < 20 || (packet[0]>>4) != 4 {
		return EgressChoiceNone, false
	}
	ihl := int(packet[0]&0x0f) * 4
	if len(packet) < ihl+4 {
		return EgressChoiceNone, false
	}
	proto := packet[9]
	if proto != 6 && proto != 17 {
		return EgressChoiceNone, false
	}

	key := FlowKey{
		PeerKey:  peerKey,
		Protocol: proto,
		SrcIP:    [4]byte{packet[12], packet[13], packet[14], packet[15]},
		DstIP:    [4]byte{packet[16], packet[17], packet[18], packet[19]},
		SrcPort:  binary.BigEndian.Uint16(packet[ihl : ihl+2]),
		DstPort:  binary.BigEndian.Uint16(packet[ihl+2 : ihl+4]),
	}

	var activeGen uint64
	var activeSID string
	var hasActive bool
	if m.fwd != nil {
		activeGen, activeSID, hasActive = m.fwd.ActivePeerGeneration(peerKey)
	}

	m.mu.Lock()
	entry, ok := m.flows[key]
	if !ok {
		m.mu.Unlock()
		return EgressChoiceNone, false
	}

	// Verify cached flow belongs to calling session's active generation
	if m.fwd != nil {
		if !hasActive || (entry.generation != 0 && entry.generation != activeGen) || (entry.sessionID != "" && entry.sessionID != activeSID) {
			delete(m.flows, key)
			if entry.choice == EgressChoiceDirect && entry.natPort > 0 {
				delete(m.usedPorts, entry.natPort)
				delete(m.inboundNAT, inboundKey{protocol: proto, natPort: entry.natPort})
			}
			m.mu.Unlock()
			return EgressChoiceNone, false
		}
	}

	now := time.Now()
	if m.isFlowExpiredLocked(entry, proto, now) {
		delete(m.flows, key)
		if entry.choice == EgressChoiceDirect && entry.natPort > 0 {
			delete(m.usedPorts, entry.natPort)
			delete(m.inboundNAT, inboundKey{protocol: proto, natPort: entry.natPort})
		}
		m.mu.Unlock()
		return EgressChoiceNone, false
	}

	entry.lastSeen = now
	choice := entry.choice
	m.mu.Unlock()

	return choice, true
}

func parseGenerationArg(v any) (uint64, bool) {
	switch g := v.(type) {
	case uint64:
		return g, true
	case int:
		if g >= 0 {
			return uint64(g), true // #nosec G115
		}
	case uint:
		return uint64(g), true
	case int64:
		if g >= 0 {
			return uint64(g), true // #nosec G115
		}
	}
	return 0, false
}

// RecordFlow records the initial routing decision for a 5-tuple flow to maintain stickiness.
// Supported invocations:
//
//	RecordFlow(peerKey string, packet []byte, choice EgressChoice)
//	RecordFlow(peerKey, sessionID string, generation uint64, packet []byte, choice EgressChoice)
func (m *DirectEgressManager) RecordFlow(peerKey string, args ...any) {
	if m == nil {
		return
	}
	var sessionID string
	var generation uint64
	var packet []byte
	var choice EgressChoice

	switch len(args) {
	case 2:
		var ok, ok2 bool
		packet, ok = args[0].([]byte)
		choice, ok2 = args[1].(EgressChoice)
		if !ok || !ok2 {
			return
		}
	case 4:
		var ok, ok2, okGen bool
		sessionID, ok = args[0].(string)
		generation, okGen = parseGenerationArg(args[1])
		if !ok || !okGen {
			return
		}
		packet, ok = args[2].([]byte)
		choice, ok2 = args[3].(EgressChoice)
		if !ok || !ok2 {
			return
		}
	default:
		return
	}

	if len(packet) < 20 || (packet[0]>>4) != 4 {
		return
	}
	ihl := int(packet[0]&0x0f) * 4
	if len(packet) < ihl+4 {
		return
	}
	proto := packet[9]
	if proto != 6 && proto != 17 {
		return
	}

	key := FlowKey{
		PeerKey:  peerKey,
		Protocol: proto,
		SrcIP:    [4]byte{packet[12], packet[13], packet[14], packet[15]},
		DstIP:    [4]byte{packet[16], packet[17], packet[18], packet[19]},
		SrcPort:  binary.BigEndian.Uint16(packet[ihl : ihl+2]),
		DstPort:  binary.BigEndian.Uint16(packet[ihl+2 : ihl+4]),
	}

	if m.fwd != nil {
		m.fwd.mu.RLock()
		defer m.fwd.mu.RUnlock()
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	var activeGen uint64
	var activeSID string
	if m.fwd != nil {
		route, ok := m.fwd.routesByPeer[peerKey]
		if !ok || route == nil || route.retired.Load() || route.sessionID != sessionID || route.generation != generation {
			return
		}
		activeGen = route.generation
		activeSID = route.sessionID
	} else {
		activeGen = generation
		activeSID = sessionID
	}

	if entry, ok := m.flows[key]; ok {
		entry.choice = choice
		entry.lastSeen = time.Now()
		entry.generation = activeGen
		entry.sessionID = activeSID
		return
	}

	if len(m.flows) >= m.cfg.MaxFlows {
		m.sweepLocked(time.Now())
		if len(m.flows) >= m.cfg.MaxFlows {
			return
		}
	}

	m.flows[key] = &flowEntry{
		choice:     choice,
		lastSeen:   time.Now(),
		peerKey:    peerKey,
		sessionID:  activeSID,
		generation: activeGen,
	}
}

// RouteDirect forwards an authenticated client packet directly to host WAN with SNAT.
// It accepts either:
//
//	RouteDirect(peerKey, assignedIP string, packet []byte, path *ReturnPath) error
//	RouteDirect(peerKey, assignedIP, sessionID string, generation uint64, packet []byte, path *ReturnPath) error
func (m *DirectEgressManager) RouteDirect(peerKey, assignedIP string, args ...any) error {
	var sessionID string
	var generation uint64
	var packet []byte
	var path *ReturnPath

	switch len(args) {
	case 2:
		var ok bool
		packet, ok = args[0].([]byte)
		if !ok {
			return errors.New("invalid packet")
		}
		path, ok = args[1].(*ReturnPath)
		if !ok {
			return errors.New("invalid return path")
		}
	case 4:
		var ok bool
		sessionID, ok = args[0].(string)
		if !ok {
			return errors.New("invalid sessionID")
		}
		var okGen bool
		generation, okGen = parseGenerationArg(args[1])
		if !okGen {
			return errors.New("invalid generation")
		}
		packet, ok = args[2].([]byte)
		if !ok {
			return errors.New("invalid packet")
		}
		path, ok = args[3].(*ReturnPath)
		if !ok {
			return errors.New("invalid return path")
		}
	default:
		return errors.New("invalid number of arguments to RouteDirect")
	}

	if path == nil || path.Closed() {
		return ErrReturnPathClosed
	}
	if len(packet) < 20 || (packet[0]>>4) != 4 {
		return errors.New("invalid ipv4 packet")
	}
	ihl := int(packet[0]&0x0f) * 4
	if len(packet) < ihl+4 {
		return errors.New("truncated l4 packet")
	}
	proto := packet[9]
	if proto != 6 && proto != 17 {
		return errors.New("unsupported protocol for direct egress")
	}

	dstIP := netip.AddrFrom4([4]byte{packet[16], packet[17], packet[18], packet[19]})
	if m.IsProhibitedDestination(dstIP) {
		m.directDrops.Add(1)
		return ErrProhibitedDestination
	}

	return m.routeDirectProtocol(peerKey, assignedIP, sessionID, generation, packet, path, proto, ihl)
}

// RouteTCPDirect forwards an IPv4 TCP packet directly to host WAN.
func (m *DirectEgressManager) RouteTCPDirect(peerKey string, packet []byte, path *ReturnPath) error {
	if len(packet) < 20 {
		return errors.New("packet too short")
	}
	assignedIP := netip.AddrFrom4([4]byte{packet[12], packet[13], packet[14], packet[15]}).String()
	var sID string
	var gen uint64
	if m.fwd != nil {
		g, s, ok := m.fwd.ActivePeerGeneration(peerKey)
		if ok {
			gen = g
			sID = s
		}
	}
	return m.RouteDirect(peerKey, assignedIP, sID, gen, packet, path)
}

// RouteUDPDirect forwards an IPv4 UDP packet directly to host WAN.
func (m *DirectEgressManager) RouteUDPDirect(peerKey string, packet []byte, path *ReturnPath) error {
	if len(packet) < 20 {
		return errors.New("packet too short")
	}
	assignedIP := netip.AddrFrom4([4]byte{packet[12], packet[13], packet[14], packet[15]}).String()
	var sID string
	var gen uint64
	if m.fwd != nil {
		g, s, ok := m.fwd.ActivePeerGeneration(peerKey)
		if ok {
			gen = g
			sID = s
		}
	}
	return m.RouteDirect(peerKey, assignedIP, sID, gen, packet, path)
}

func (m *DirectEgressManager) ensureDirectNATLocked(
	flowKey FlowKey, proto uint8,
	srcIP, dstIP [4]byte, srcPort, dstPort uint16,
	peerKey, sessionID string, generation uint64,
	path *ReturnPath, now time.Time,
) (uint16, *flowEntry, error) {
	flow, exists := m.flows[flowKey]
	var natPort uint16
	if exists && flow.natPort > 0 {
		if m.isFlowExpiredLocked(flow, proto, now) {
			delete(m.usedPorts, flow.natPort)
			delete(m.inboundNAT, inboundKey{protocol: proto, natPort: flow.natPort})
			delete(m.flows, flowKey)
			flow = nil
			exists = false
		} else {
			natPort = flow.natPort
			flow.lastSeen = now
		}
	}

	if !exists || flow == nil || flow.natPort == 0 {
		if flow == nil && len(m.flows) >= m.cfg.MaxFlows {
			m.sweepLocked(now)
			if len(m.flows) >= m.cfg.MaxFlows {
				return 0, nil, ErrFlowTableFull
			}
		}

		var err error
		natPort, err = m.allocatePortLocked()
		if err != nil {
			return 0, nil, err
		}
		if flow == nil {
			flow = &flowEntry{
				choice:     EgressChoiceDirect,
				natPort:    natPort,
				lastSeen:   now,
				peerKey:    peerKey,
				sessionID:  sessionID,
				generation: generation,
			}
			m.flows[flowKey] = flow
		} else {
			flow.natPort = natPort
			flow.choice = EgressChoiceDirect
			flow.lastSeen = now
			flow.sessionID = sessionID
			flow.generation = generation
		}

		inKey := inboundKey{protocol: proto, natPort: natPort}
		m.inboundNAT[inKey] = &natEntry{
			peerKey:    peerKey,
			sessionID:  sessionID,
			generation: generation,
			flowKey:    flowKey,
			clientIP:   netip.AddrFrom4(srcIP),
			clientPort: srcPort,
			remoteIP:   netip.AddrFrom4(dstIP),
			remotePort: dstPort,
			protocol:   proto,
			natPort:    natPort,
			returnPath: path,
			lastSeen:   now,
		}
	}

	return natPort, flow, nil
}

func applySNAT(packet []byte, ihl int, proto uint8, hostWAN netip.Addr, dstIP [4]byte, natPort uint16) []byte {
	out := make([]byte, len(packet))
	copy(out, packet)
	wanBytes := hostWAN.As4()
	copy(out[12:16], wanBytes[:])
	binary.BigEndian.PutUint16(out[ihl:ihl+2], natPort)

	// Recalculate IPv4 Header Checksum
	binary.BigEndian.PutUint16(out[10:12], 0)
	ipCS := computeIPv4Checksum(out[:ihl])
	binary.BigEndian.PutUint16(out[10:12], ipCS)

	// Recalculate L4 Checksum
	if proto == 6 {
		if len(out) >= ihl+20 {
			binary.BigEndian.PutUint16(out[ihl+16:ihl+18], 0)
			tcpCS := computeL4Checksum(wanBytes, dstIP, 6, out[ihl:])
			binary.BigEndian.PutUint16(out[ihl+16:ihl+18], tcpCS)
		}
	} else if proto == 17 {
		if len(out) >= ihl+8 {
			binary.BigEndian.PutUint16(out[ihl+6:ihl+8], 0)
			udpCS := computeL4Checksum(wanBytes, dstIP, 17, out[ihl:])
			binary.BigEndian.PutUint16(out[ihl+6:ihl+8], udpCS)
		}
	}
	return out
}

func (m *DirectEgressManager) routeDirectProtocol(peerKey, assignedIP, sessionID string, generation uint64, packet []byte, path *ReturnPath, proto uint8, ihl int) error {
	srcIP := [4]byte{packet[12], packet[13], packet[14], packet[15]}
	dstIP := [4]byte{packet[16], packet[17], packet[18], packet[19]}
	srcPort := binary.BigEndian.Uint16(packet[ihl : ihl+2])
	dstPort := binary.BigEndian.Uint16(packet[ihl+2 : ihl+4])

	flowKey := FlowKey{
		PeerKey:  peerKey,
		Protocol: proto,
		SrcIP:    srcIP,
		DstIP:    dstIP,
		SrcPort:  srcPort,
		DstPort:  dstPort,
	}

	if m.fwd != nil {
		m.fwd.mu.RLock()
	}
	m.mu.Lock()
	if m.fwd != nil && (sessionID != "" || generation != 0) {
		route, ok := m.fwd.routesByPeer[peerKey]
		if !ok || route == nil || route.retired.Load() || (generation != 0 && route.generation != generation) || (sessionID != "" && route.sessionID != sessionID) {
			m.mu.Unlock()
			m.fwd.mu.RUnlock()
			m.directDrops.Add(1)
			return ErrSessionNotRegistered
		}
	}

	now := time.Now()
	natPort, flow, err := m.ensureDirectNATLocked(flowKey, proto, srcIP, dstIP, srcPort, dstPort, peerKey, sessionID, generation, path, now)
	if err != nil {
		m.mu.Unlock()
		if m.fwd != nil {
			m.fwd.mu.RUnlock()
		}
		m.directDrops.Add(1)
		return err
	}

	if proto == 6 && len(packet) >= ihl+14 && packet[ihl+13]&(0x01|0x04) != 0 {
		flow.closeSeen = true
	}

	wanDev := m.wanDevice
	hostWAN := m.cfg.HostWANIP
	m.mu.Unlock()
	if m.fwd != nil {
		m.fwd.mu.RUnlock()
	}

	if wanDev == nil {
		m.directDrops.Add(1)
		return ErrDirectEgressUnavailable
	}

	out := applySNAT(packet, ihl, proto, hostWAN, dstIP, natPort)
	if _, err := wanDev.Write(out); err != nil {
		m.directDrops.Add(1)
		return err
	}
	m.directBytes.Add(int64(len(out)))
	return nil
}

func (m *DirectEgressManager) validateWANReplyHeader(packet []byte) (ihl int, proto uint8, natPort uint16, srcIP netip.Addr, srcPort uint16, err error) {
	if len(packet) < 20 || (packet[0]>>4) != 4 {
		return 0, 0, 0, netip.Addr{}, 0, errors.New("invalid ipv4 reply packet")
	}
	ihl = int(packet[0]&0x0f) * 4
	if len(packet) < ihl+4 {
		return 0, 0, 0, netip.Addr{}, 0, errors.New("truncated reply packet")
	}
	proto = packet[9]
	if proto != 6 && proto != 17 {
		return 0, 0, 0, netip.Addr{}, 0, errors.New("unsupported protocol in wan reply")
	}
	dstIP := netip.AddrFrom4([4]byte{packet[16], packet[17], packet[18], packet[19]})
	if m.cfg.HostWANIP.IsValid() && dstIP != m.cfg.HostWANIP {
		return 0, 0, 0, netip.Addr{}, 0, errors.New("destination ip does not match host wan ip")
	}
	natPort = binary.BigEndian.Uint16(packet[ihl+2 : ihl+4])
	srcIP = netip.AddrFrom4([4]byte{packet[12], packet[13], packet[14], packet[15]})
	srcPort = binary.BigEndian.Uint16(packet[ihl : ihl+2])
	return ihl, proto, natPort, srcIP, srcPort, nil
}

func (m *DirectEgressManager) lookupAndRefreshNATReply(proto uint8, natPort uint16, srcIP netip.Addr, srcPort uint16, isClose bool) (natEntry, error) {
	inKey := inboundKey{protocol: proto, natPort: natPort}
	m.mu.Lock()
	defer m.mu.Unlock()

	entry, ok := m.inboundNAT[inKey]
	if !ok {
		return natEntry{}, errors.New("no nat entry for reply")
	}
	if srcIP != entry.remoteIP || srcPort != entry.remotePort {
		return natEntry{}, errors.New("remote endpoint does not match nat entry")
	}

	now := time.Now()
	entry.lastSeen = now
	if flow, ok := m.flows[entry.flowKey]; ok {
		flow.lastSeen = now
		if isClose {
			flow.closeSeen = true
		}
	}
	if isClose {
		entry.closeSeen = true
	}
	return *entry, nil
}

func applyDNAT(packet []byte, ihl int, proto uint8, clientIP netip.Addr, clientPort uint16) []byte {
	reply := make([]byte, len(packet))
	copy(reply, packet)
	clientIPBytes := clientIP.As4()
	copy(reply[16:20], clientIPBytes[:])
	binary.BigEndian.PutUint16(reply[ihl+2:ihl+4], clientPort)

	// Recalculate IPv4 Header Checksum
	binary.BigEndian.PutUint16(reply[10:12], 0)
	ipCS := computeIPv4Checksum(reply[:ihl])
	binary.BigEndian.PutUint16(reply[10:12], ipCS)

	// Recalculate L4 Checksum
	srcIPBytes := [4]byte{reply[12], reply[13], reply[14], reply[15]}
	if proto == 6 && len(reply) >= ihl+20 {
		binary.BigEndian.PutUint16(reply[ihl+16:ihl+18], 0)
		tcpCS := computeL4Checksum(srcIPBytes, clientIPBytes, 6, reply[ihl:])
		binary.BigEndian.PutUint16(reply[ihl+16:ihl+18], tcpCS)
	} else if proto == 17 && len(reply) >= ihl+8 {
		binary.BigEndian.PutUint16(reply[ihl+6:ihl+8], 0)
		udpCS := computeL4Checksum(srcIPBytes, clientIPBytes, 17, reply[ihl:])
		binary.BigEndian.PutUint16(reply[ihl+6:ihl+8], udpCS)
	}
	return reply
}

// HandleWANReply demultiplexes an inbound response packet from the WAN and forwards it to the client.
func (m *DirectEgressManager) HandleWANReply(packet []byte) error {
	ihl, proto, natPort, srcIP, srcPort, err := m.validateWANReplyHeader(packet)
	if err != nil {
		m.directDrops.Add(1)
		return err
	}

	isClose := proto == 6 && len(packet) >= ihl+14 && (packet[ihl+13]&(0x01|0x04) != 0)
	entry, err := m.lookupAndRefreshNATReply(proto, natPort, srcIP, srcPort, isClose)
	if err != nil {
		m.directDrops.Add(1)
		return err
	}

	if entry.returnPath == nil || entry.returnPath.Closed() {
		m.directDrops.Add(1)
		return ErrReturnPathClosed
	}

	pktLen := int64(len(packet))
	reply := applyDNAT(packet, ihl, proto, entry.clientIP, entry.clientPort)

	if m.fwd != nil {
		if err := m.fwd.DeliverDirectWANReply(entry.peerKey, entry.sessionID, entry.generation, entry.returnPath, reply); err != nil {
			m.directDrops.Add(1)
			return err
		}
	} else {
		if err := entry.returnPath.WritePacket(entry.peerKey, entry.clientIP.String(), reply); err != nil {
			m.directDrops.Add(1)
			return err
		}
	}

	m.directBytes.Add(pktLen)
	return nil
}

func (m *DirectEgressManager) allocatePortLocked() (uint16, error) {
	totalPorts := int(m.cfg.MaxPort - m.cfg.MinPort + 1)
	for attempt := 0; attempt < 2; attempt++ {
		for i := 0; i < totalPorts; i++ {
			port := m.nextPort
			m.nextPort++
			if m.nextPort > m.cfg.MaxPort || m.nextPort < m.cfg.MinPort {
				m.nextPort = m.cfg.MinPort
			}
			if !m.usedPorts[port] {
				m.usedPorts[port] = true
				return port, nil
			}
		}
		if attempt == 0 {
			m.sweepLocked(time.Now())
		}
	}
	return 0, ErrNATPortExhaustion
}

// Sweep removes expired idle flows and releases unused NAT ports.
func (m *DirectEgressManager) Sweep(now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sweepLocked(now)
}

func (m *DirectEgressManager) sweepLocked(now time.Time) {
	for k, f := range m.flows {
		if m.isFlowExpiredLocked(f, k.Protocol, now) {
			if f.choice == EgressChoiceDirect && f.natPort > 0 {
				delete(m.usedPorts, f.natPort)
				delete(m.inboundNAT, inboundKey{protocol: k.Protocol, natPort: f.natPort})
			}
			delete(m.flows, k)
		}
	}
}

// PurgePeer purges all active flows and NAT state belonging to peerKey.
func (m *DirectEgressManager) PurgePeer(peerKey string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for k, f := range m.flows {
		if f.peerKey == peerKey {
			if f.choice == EgressChoiceDirect && f.natPort > 0 {
				delete(m.usedPorts, f.natPort)
				delete(m.inboundNAT, inboundKey{protocol: k.Protocol, natPort: f.natPort})
			}
			delete(m.flows, k)
		}
	}
	for inK, entry := range m.inboundNAT {
		if entry.peerKey == peerKey {
			delete(m.usedPorts, entry.natPort)
			delete(m.inboundNAT, inK)
		}
	}
}

// PurgeSession purges all active flows and NAT state belonging to sessionID.
func (m *DirectEgressManager) PurgeSession(sessionID string) {
	if sessionID == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	for k, f := range m.flows {
		if f.sessionID == sessionID {
			if f.choice == EgressChoiceDirect && f.natPort > 0 {
				delete(m.usedPorts, f.natPort)
				delete(m.inboundNAT, inboundKey{protocol: k.Protocol, natPort: f.natPort})
			}
			delete(m.flows, k)
		}
	}
	for inK, entry := range m.inboundNAT {
		if entry.sessionID == sessionID {
			delete(m.usedPorts, entry.natPort)
			delete(m.inboundNAT, inK)
		}
	}
}

// PurgeAll purges all flows and NAT state.
func (m *DirectEgressManager) PurgeAll() {
	m.mu.Lock()
	defer m.mu.Unlock()

	clear(m.flows)
	clear(m.inboundNAT)
	clear(m.usedPorts)
}

// Close terminates direct egress background routines and closes resources.
func (m *DirectEgressManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil
	}
	m.closed = true
	if m.stopCh != nil {
		close(m.stopCh)
		m.stopCh = nil
	}
	if m.wanDevice != nil {
		_ = m.wanDevice.Close()
	}
	return nil
}

func computeIPv4Checksum(header []byte) uint16 {
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

func computeL4Checksum(srcIP, dstIP [4]byte, protocol uint8, l4Data []byte) uint16 {
	var sum uint32
	// Pseudo-header
	sum += uint32(binary.BigEndian.Uint16(srcIP[0:2]))
	sum += uint32(binary.BigEndian.Uint16(srcIP[2:4]))
	sum += uint32(binary.BigEndian.Uint16(dstIP[0:2]))
	sum += uint32(binary.BigEndian.Uint16(dstIP[2:4]))
	sum += uint32(protocol)
	length := uint16(len(l4Data)) // #nosec G115 -- l4Data bounded by IP MTU <= 65535
	sum += uint32(length)

	// L4 Data
	for i := 0; i < len(l4Data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(l4Data[i : i+2]))
	}
	if len(l4Data)%2 != 0 {
		sum += uint32(l4Data[len(l4Data)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	c := ^uint16(sum)
	if protocol == 17 && c == 0 {
		return 0xffff
	}
	return c
}
