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
	epoch      uint64
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
	HostWANIP     netip.Addr
	GatewayDNSIP  netip.Addr
	WANDevice     PacketDevice
	TCPTimeout    time.Duration
	UDPTimeout    time.Duration
	MinPort       uint16
	MaxPort       uint16
	MaxFlows      int
	TCPQuarantine time.Duration
	UDPQuarantine time.Duration
}

const (
	defaultDirectTCPTimeout = 300 * time.Second
	defaultDirectUDPTimeout = 30 * time.Second
	defaultMinNATPort       = 40000
	defaultMaxNATPort       = 65000
	defaultMaxFlows         = 65536
)

// DirectEgressManager manages direct host WAN forwarding, SNAT, response demultiplexing,
// and 5-tuple flow stickiness.
type DirectEgressManager struct {
	mu               sync.RWMutex
	cfg              DirectEgressConfig
	fwd              *Forwarder
	wanDevice        PacketDevice
	flows            map[FlowKey]*flowEntry
	inboundNAT       map[inboundKey]*natEntry
	usedPorts        map[uint16]bool
	nextPort         uint16
	stopCh           chan struct{}
	closed           bool
	readerWG         sync.WaitGroup
	readerRunning    bool
	directDrops      atomic.Uint64
	directBytes      atomic.Int64
	gwDNSMu          sync.RWMutex
	gwDNSIP          netip.Addr
	portEpoch        map[uint16]uint64
	quarantinedPorts map[uint16]time.Time
	portCooldown     time.Duration
	tcpQuarantine    time.Duration
	udpQuarantine    time.Duration
	remoteBindings   map[remoteBindingKey]*remoteBindingEntry
	portOwners       map[uint16]string
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
	if cfg.TCPTimeout <= 0 {
		cfg.TCPTimeout = defaultDirectTCPTimeout
	}
	if cfg.UDPTimeout <= 0 {
		cfg.UDPTimeout = defaultDirectUDPTimeout
	}
	if cfg.MinPort == 0 {
		cfg.MinPort = defaultMinNATPort
	}
	if cfg.MaxPort == 0 || cfg.MaxPort < cfg.MinPort {
		cfg.MaxPort = defaultMaxNATPort
	}
	if cfg.MaxFlows <= 0 {
		cfg.MaxFlows = defaultMaxFlows
	}

	dem := &DirectEgressManager{
		cfg:              cfg,
		fwd:              fwd,
		wanDevice:        cfg.WANDevice,
		flows:            make(map[FlowKey]*flowEntry),
		inboundNAT:       make(map[inboundKey]*natEntry),
		usedPorts:        make(map[uint16]bool),
		nextPort:         cfg.MinPort,
		portEpoch:        make(map[uint16]uint64),
		quarantinedPorts: make(map[uint16]time.Time),
		portCooldown:     5 * time.Second,
		tcpQuarantine:    cfg.TCPQuarantine,
		udpQuarantine:    cfg.UDPQuarantine,
		remoteBindings:   make(map[remoteBindingKey]*remoteBindingEntry),
		portOwners:       make(map[uint16]string),
		gwDNSIP:          cfg.GatewayDNSIP,
	}

	if cfg.WANDevice != nil {
		dem.stopCh = make(chan struct{})
		dem.readerRunning = true
		dem.readerWG.Add(1)
		go dem.readWANLoop(cfg.WANDevice, dem.stopCh)
	}

	return dem
}

// SetGatewayDNSIP updates the designated gateway DNS IPv4 address safely under a lock.
func (m *DirectEgressManager) SetGatewayDNSIP(ip netip.Addr) {
	if m == nil {
		return
	}
	m.gwDNSMu.Lock()
	m.gwDNSIP = ip
	m.cfg.GatewayDNSIP = ip
	m.gwDNSMu.Unlock()
}

// GatewayDNSIP returns the configured gateway DNS address safely.
func (m *DirectEgressManager) GatewayDNSIP() netip.Addr {
	if m == nil {
		return netip.Addr{}
	}
	m.gwDNSMu.RLock()
	defer m.gwDNSMu.RUnlock()
	if m.gwDNSIP.IsValid() {
		return m.gwDNSIP
	}
	return m.cfg.GatewayDNSIP
}

// SetPortCooldown configures the quarantine cooldown for recycled NAT ports.
func (m *DirectEgressManager) SetPortCooldown(d time.Duration) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.portCooldown = d
	m.mu.Unlock()
}

// WritePacket sends a return packet for an authenticated peer directly to its ReturnPath.
func (p *ReturnPath) WritePacket(peerKey, assignedIP string, packet []byte) error {
	_, err := p.Write(peerKey, assignedIP, packet)
	return err
}

// AttachWANDevice attaches or replaces the WAN egress packet device.
// Exactly one reader goroutine runs per device; any running reader is stopped and joined before replacement.
func (m *DirectEgressManager) AttachWANDevice(dev PacketDevice) {
	m.mu.Lock()
	if m.wanDevice == dev && m.readerRunning {
		m.mu.Unlock()
		return
	}
	oldStopCh := m.stopCh
	m.stopCh = nil
	oldDev := m.wanDevice
	m.wanDevice = nil
	m.readerRunning = false
	m.mu.Unlock()

	if oldStopCh != nil {
		close(oldStopCh)
		if oldDev != nil && oldDev != dev {
			_ = oldDev.Close()
		}
		m.readerWG.Wait()
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	m.wanDevice = dev
	if dev != nil {
		m.stopCh = make(chan struct{})
		m.readerRunning = true
		m.readerWG.Add(1)
		go m.readWANLoop(dev, m.stopCh)
	}
}

func (m *DirectEgressManager) readWANLoop(dev PacketDevice, stopCh chan struct{}) {
	defer m.readerWG.Done()
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
		select {
		case <-stopCh:
			return
		default:
		}
		if n > 0 {
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			_ = m.HandleWANReply(pkt)
		}
	}
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
			m.retireFlowLocked(key, entry, proto, time.Now())
			m.mu.Unlock()
			return EgressChoiceNone, false
		}
	}

	now := time.Now()
	if m.isFlowExpiredLocked(entry, proto, now) {
		m.retireFlowLocked(key, entry, proto, now)
		m.mu.Unlock()
		return EgressChoiceNone, false
	}

	entry.lastSeen = now
	choice := entry.choice
	m.mu.Unlock()

	return choice, true
}

// RecordFlow records the initial routing decision for a 5-tuple flow to maintain stickiness.
// Supported invocations:
//
//	RecordFlow(peerKey string, packet []byte, choice EgressChoice) error
//	RecordFlow(peerKey, sessionID string, generation uint64, packet []byte, choice EgressChoice) error
func (m *DirectEgressManager) RecordFlow(peerKey string, args ...any) error {
	if m == nil {
		return nil
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
			return errors.New("invalid arguments to RecordFlow")
		}
	case 4:
		var ok, ok2, okGen bool
		sessionID, ok = args[0].(string)
		generation, okGen = parseGenerationArg(args[1])
		if !ok || !okGen {
			return errors.New("invalid arguments to RecordFlow")
		}
		packet, ok = args[2].([]byte)
		choice, ok2 = args[3].(EgressChoice)
		if !ok || !ok2 {
			return errors.New("invalid arguments to RecordFlow")
		}
	default:
		return errors.New("invalid argument count to RecordFlow")
	}

	if len(packet) < 20 || (packet[0]>>4) != 4 {
		return ErrInvalidIPv4Packet
	}
	ihl := int(packet[0]&0x0f) * 4
	if len(packet) < ihl+4 {
		return ErrInvalidTransportHdr
	}
	proto := packet[9]
	if proto != 6 && proto != 17 {
		return errors.New("unsupported protocol for direct egress")
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
			return ErrSessionNotRegistered
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
		return nil
	}

	if len(m.flows) >= m.cfg.MaxFlows {
		m.sweepLocked(time.Now())
		if len(m.flows) >= m.cfg.MaxFlows {
			return ErrFlowTableFull
		}
	}

	m.flows[key] = &flowEntry{
		choice:     choice,
		lastSeen:   time.Now(),
		peerKey:    peerKey,
		sessionID:  activeSID,
		generation: activeGen,
	}
	return nil
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

	parsed, err := ParseAndValidateClientIPv4(packet, assignedIP)
	if err != nil {
		m.directDrops.Add(1)
		return err
	}
	proto := parsed.Protocol
	ihl := parsed.IHL

	var gw netip.Addr
	if m != nil {
		gw = m.GatewayDNSIP()
	}
	if err := ValidateDirectDestination(parsed.DstIP, parsed.DstPort, gw); err != nil {
		m.directDrops.Add(1)
		return err
	}

	return m.routeDirectProtocol(peerKey, assignedIP, sessionID, generation, packet, path, proto, ihl)
}

// RouteTCPDirect forwards an IPv4 TCP packet directly to host WAN.
func (m *DirectEgressManager) RouteTCPDirect(peerKey string, packet []byte, path *ReturnPath) error {
	var sID string
	var gen uint64
	var assignedIP string
	if m.fwd != nil {
		g, s, ok := m.fwd.ActivePeerGeneration(peerKey)
		if ok {
			gen = g
			sID = s
		}
	}
	if len(packet) >= 16 {
		assignedIP = netip.AddrFrom4([4]byte{packet[12], packet[13], packet[14], packet[15]}).String()
	}
	return m.RouteDirect(peerKey, assignedIP, sID, gen, packet, path)
}

// RouteUDPDirect forwards an IPv4 UDP packet directly to host WAN.
func (m *DirectEgressManager) RouteUDPDirect(peerKey string, packet []byte, path *ReturnPath) error {
	var sID string
	var gen uint64
	var assignedIP string
	if m.fwd != nil {
		g, s, ok := m.fwd.ActivePeerGeneration(peerKey)
		if ok {
			gen = g
			sID = s
		}
	}
	if len(packet) >= 16 {
		assignedIP = netip.AddrFrom4([4]byte{packet[12], packet[13], packet[14], packet[15]}).String()
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
			m.retireFlowLocked(flowKey, flow, proto, now)
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
		natPort, err = m.allocatePortLocked(peerKey, proto, netip.AddrFrom4(dstIP), dstPort)
		if err != nil {
			delete(m.flows, flowKey)
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
			epoch:      m.portEpoch[natPort],
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
		bKey := remoteBindingKey{protocol: proto, natPort: natPort, remoteIP: netip.AddrFrom4(dstIP), remotePort: dstPort}
		m.recordRemoteBindingLocked(bKey, peerKey, sessionID, generation, m.portEpoch[natPort], now)
	}

	return natPort, flow, nil
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
	return ValidateWANReplyIPv4(packet, m.cfg.HostWANIP)
}

func (m *DirectEgressManager) lookupAndRefreshNATReply(proto uint8, natPort uint16, srcIP netip.Addr, srcPort uint16, isClose bool) (natEntry, error) {
	inKey := inboundKey{protocol: proto, natPort: natPort}
	m.mu.Lock()
	defer m.mu.Unlock()

	bKey := remoteBindingKey{protocol: proto, natPort: natPort, remoteIP: srcIP, remotePort: srcPort}

	entry, ok := m.inboundNAT[inKey]
	if !ok {
		if _, exists := m.remoteBindings[bKey]; exists {
			return natEntry{}, ErrStaleSessionReply
		}
		return natEntry{}, errors.New("no nat entry for reply")
	}
	if srcIP != entry.remoteIP || srcPort != entry.remotePort {
		if _, exists := m.remoteBindings[bKey]; exists {
			return natEntry{}, ErrStaleSessionReply
		}
		return natEntry{}, errors.New("remote endpoint does not match nat entry")
	}
	if entry.epoch != m.portEpoch[natPort] {
		return natEntry{}, ErrStaleSessionReply
	}
	if b, exists := m.remoteBindings[bKey]; exists {
		if !b.active || b.peerKey != entry.peerKey || b.sessionID != entry.sessionID || b.epoch != entry.epoch {
			return natEntry{}, ErrStaleSessionReply
		}
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

// Close terminates direct egress background routines and closes resources.
func (m *DirectEgressManager) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	m.readerRunning = false
	oldStopCh := m.stopCh
	m.stopCh = nil
	dev := m.wanDevice
	m.wanDevice = nil
	m.mu.Unlock()

	if oldStopCh != nil {
		close(oldStopCh)
	}
	var err error
	if dev != nil {
		err = dev.Close()
	}
	m.readerWG.Wait()
	return err
}
