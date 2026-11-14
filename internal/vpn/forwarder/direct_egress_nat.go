package forwarder

import (
	"errors"
	"net/netip"
	"time"
)

const (
	defaultTCPQuarantine     = 30 * time.Second
	defaultUDPQuarantine     = 30 * time.Second
	defaultMaxRemoteBindings = 65536
)

type remoteBindingKey struct {
	protocol   uint8
	natPort    uint16
	remoteIP   netip.Addr
	remotePort uint16
}

type remoteBindingEntry struct {
	peerKey    string
	sessionID  string
	generation uint64
	epoch      uint64
	releasedAt time.Time
	active     bool
}

// SetQuarantineDurations configures explicit quarantine expiration for TCP and UDP flows.
func (m *DirectEgressManager) SetQuarantineDurations(tcp, udp time.Duration) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.tcpQuarantine = tcp
	m.udpQuarantine = udp
	m.mu.Unlock()
}

// SetMaxBindings configures explicit remote binding capacity.
func (m *DirectEgressManager) SetMaxBindings(max int) {
	if m == nil {
		return
	}
	m.mu.Lock()
	if max <= 0 {
		m.maxBindings = defaultMaxRemoteBindings
	} else {
		m.maxBindings = max
	}
	m.mu.Unlock()
}

func (m *DirectEgressManager) bindingQuarantineDuration(proto uint8) time.Duration {
	if proto == 6 { // TCP
		if m.tcpQuarantine > 0 {
			return m.tcpQuarantine
		}
		return defaultTCPQuarantine
	}
	// UDP and others
	if m.udpQuarantine > 0 {
		return m.udpQuarantine
	}
	return defaultUDPQuarantine
}

func (m *DirectEgressManager) isPortQuarantinedLocked(port uint16, now time.Time) bool {
	if m.portCooldown <= 0 {
		return false
	}
	rel, ok := m.quarantinedPorts[port]
	if !ok {
		return false
	}
	if now.Sub(rel) >= m.portCooldown {
		delete(m.quarantinedPorts, port)
		delete(m.portOwners, port)
		// Quarantine ownership ends with the cooldown: nothing can be routing a
		// reply to the port any more, so the kernel tuple is released for the
		// host to use again.
		m.releaseHostPortLocked(port)
		return false
	}
	return true
}

func (m *DirectEgressManager) isBindingQuarantinedLocked(b *remoteBindingEntry, proto uint8, now time.Time) bool {
	if b == nil {
		return false
	}
	if b.active {
		return true
	}
	quarantine := m.bindingQuarantineDuration(proto)
	if now.Sub(b.releasedAt) < quarantine {
		return true
	}
	return false
}

func (m *DirectEgressManager) releasePortLocked(port uint16, proto uint8, remoteIP netip.Addr, remotePort uint16, now time.Time) {
	if port == 0 {
		return
	}
	delete(m.usedPorts, port)
	if m.portCooldown > 0 {
		// Delayed replies for the retired flow stay attributable to this manager
		// while the port is quarantined, so kernel ownership is held for exactly
		// the same window and a host socket can never inherit the tuple in
		// between.
		m.quarantinedPorts[port] = now
	} else {
		delete(m.portOwners, port)
		m.releaseHostPortLocked(port)
	}
	bKey := remoteBindingKey{protocol: proto, natPort: port, remoteIP: remoteIP, remotePort: remotePort}
	if b := m.remoteBindings[bKey]; b != nil && b.active {
		b.active = false
		b.releasedAt = now
	}
}

func (m *DirectEgressManager) retireFlowLocked(key FlowKey, entry *flowEntry, proto uint8, now time.Time) {
	if entry.choice == EgressChoiceDirect && entry.natPort > 0 {
		remoteIP := netip.AddrFrom4(key.DstIP)
		m.releasePortLocked(entry.natPort, proto, remoteIP, key.DstPort, now)
		delete(m.inboundNAT, inboundKey{protocol: proto, natPort: entry.natPort})
	}
	delete(m.flows, key)
}

func (m *DirectEgressManager) advanceNextPortLocked() uint16 {
	port := m.nextPort
	m.nextPort++
	if m.nextPort > m.cfg.MaxPort || m.nextPort < m.cfg.MinPort {
		m.nextPort = m.cfg.MinPort
	}
	return port
}

func (m *DirectEgressManager) isPortAvailableLocked(port uint16, peerKey string, now time.Time) bool {
	if m.usedPorts[port] || m.isPortQuarantinedLocked(port, now) {
		return false
	}
	if owner, ok := m.portOwners[port]; ok && owner != "" && owner != peerKey {
		return false
	}
	return true
}

func (m *DirectEgressManager) canBindRemoteLocked(port uint16, peerKey string, proto uint8, remoteIP netip.Addr, remotePort uint16, tableFull bool, now time.Time) bool {
	bKey := remoteBindingKey{protocol: proto, natPort: port, remoteIP: remoteIP, remotePort: remotePort}
	b, exists := m.remoteBindings[bKey]
	if !exists {
		return !tableFull
	}
	// A binding that was retired for this exact tuple keeps the port for its
	// quarantine window and must refuse every rebinder. The check has to come
	// before the same-peer shortcut: a replacement session of the same peer is
	// a different authenticated session, so rebinding its tuple would relabel
	// the retired flow's in-flight replies with the new session instead of
	// refusing them. When no other safe port exists the flow fails closed.
	if m.isBindingQuarantinedLocked(b, proto, now) {
		return false
	}
	if b.peerKey == peerKey {
		return true
	}
	delete(m.remoteBindings, bKey)
	return true
}

func (m *DirectEgressManager) allocatePortLocked(peerKey string, proto uint8, remoteIP netip.Addr, remotePort uint16) (uint16, error) {
	totalPorts := int(m.cfg.MaxPort - m.cfg.MinPort + 1)
	now := time.Now()
	m.pruneOldestBindingsLocked(now)

	// Every held reservation keeps its kernel tuple for the whole binding
	// lifetime, including the port-cooldown window after the flow retires, so a
	// cap reached by flows that already expired can only be relieved by the
	// ordinary sweep. Nothing else in this path runs after a reservation
	// refusal, so reclaim here before deciding the cap is exhausted: retire
	// expired flows and release the tuples whose quarantine window has elapsed.
	// An all-live cap reclaims nothing and stays refused by the checks below.
	if m.atReservationCapLocked() {
		m.sweepLocked(now)
	}

	maxB := m.maxBindings
	if maxB <= 0 {
		maxB = defaultMaxRemoteBindings
	}
	tableFull := len(m.remoteBindings) >= maxB

	for attempt := 0; attempt < 2; attempt++ {
		for i := 0; i < totalPorts; i++ {
			port := m.advanceNextPortLocked()
			if m.isPortAvailableLocked(port, peerKey, now) {
				if m.canBindRemoteLocked(port, peerKey, proto, remoteIP, remotePort, tableFull, now) {
					if err := m.reserveHostPortLocked(proto, port); err != nil {
						if errors.Is(err, errHostTupleInUse) {
							// Another local socket owns this exact host tuple. It is
							// not ours to take over: try the next candidate.
							continue
						}
						// Ownership could not be established (resource or platform
						// failure). Refuse direct egress rather than fall back to
						// an unverified mapping.
						return 0, err
					}
					m.usedPorts[port] = true
					m.portOwners[port] = peerKey
					m.portEpoch[port]++
					return port, nil
				}
			}
		}
		if attempt == 0 {
			m.sweepLocked(now)
			tableFull = len(m.remoteBindings) >= maxB
		}
	}

	// Under extreme port pressure where all unquarantined ports are exhausted,
	// check if an unused port can be recycled without evicting or violating any active quarantine.
	for i := 0; i < totalPorts; i++ {
		port := m.advanceNextPortLocked()
		if !m.usedPorts[port] {
			if m.canBindRemoteLocked(port, peerKey, proto, remoteIP, remotePort, tableFull, now) {
				// A quarantined port still holds its kernel reservation, so reuse
				// keeps the tuple exclusively ours; a released port is re-acquired
				// here under the same ownership rule as the primary path.
				if err := m.reserveHostPortLocked(proto, port); err != nil {
					if errors.Is(err, errHostTupleInUse) {
						continue
					}
					return 0, err
				}
				delete(m.quarantinedPorts, port)
				m.usedPorts[port] = true
				m.portOwners[port] = peerKey
				m.portEpoch[port]++
				return port, nil
			}
		}
	}

	if tableFull {
		return 0, ErrNATTableFull
	}
	return 0, ErrNATPortExhaustion
}

func (m *DirectEgressManager) recordRemoteBindingLocked(bKey remoteBindingKey, peerKey, sessionID string, generation, epoch uint64, now time.Time) {
	maxB := m.maxBindings
	if maxB <= 0 {
		maxB = defaultMaxRemoteBindings
	}
	if len(m.remoteBindings) >= maxB {
		m.pruneOldestBindingsLocked(now)
	}
	if existing, exists := m.remoteBindings[bKey]; exists {
		if existing.peerKey == peerKey {
			existing.sessionID = sessionID
			existing.generation = generation
			existing.epoch = epoch
			existing.active = true
			existing.releasedAt = time.Time{}
		}
		return
	}
	if len(m.remoteBindings) >= maxB {
		return
	}
	m.remoteBindings[bKey] = &remoteBindingEntry{
		peerKey:    peerKey,
		sessionID:  sessionID,
		generation: generation,
		epoch:      epoch,
		active:     true,
	}
}

func (m *DirectEgressManager) sweepRemoteBindingsLocked(now time.Time) {
	for k, b := range m.remoteBindings {
		if b == nil || (!b.active && now.Sub(b.releasedAt) >= m.bindingQuarantineDuration(k.protocol)) {
			delete(m.remoteBindings, k)
		}
	}
}

func (m *DirectEgressManager) pruneOldestBindingsLocked(now time.Time) {
	m.sweepRemoteBindingsLocked(now)
}

// RemoteBindingCount returns the current count of tracked remote bindings (useful for tests).
func (m *DirectEgressManager) RemoteBindingCount() int {
	if m == nil {
		return 0
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.remoteBindings)
}

// Sweep removes expired idle flows and releases unused NAT ports and expired bindings.
func (m *DirectEgressManager) Sweep(now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sweepLocked(now)
}

func (m *DirectEgressManager) sweepLocked(now time.Time) {
	for k, f := range m.flows {
		if m.isFlowExpiredLocked(f, k.Protocol, now) {
			m.retireFlowLocked(k, f, k.Protocol, now)
		}
	}
	m.sweepRemoteBindingsLocked(now)
	m.sweepQuarantinedPortsLocked(now)
}

// sweepQuarantinedPortsLocked releases kernel ownership of ports whose
// quarantine window has elapsed, so an idle manager never keeps host tuples
// reserved longer than its own delayed-reply protection requires.
func (m *DirectEgressManager) sweepQuarantinedPortsLocked(now time.Time) {
	if m.portCooldown <= 0 || len(m.quarantinedPorts) == 0 {
		return
	}
	for port, releasedAt := range m.quarantinedPorts {
		if now.Sub(releasedAt) < m.portCooldown {
			continue
		}
		delete(m.quarantinedPorts, port)
		delete(m.portOwners, port)
		m.releaseHostPortLocked(port)
	}
}

// PurgePeer purges all active flows and NAT state belonging to peerKey.
func (m *DirectEgressManager) PurgePeer(peerKey string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for k, f := range m.flows {
		if f.peerKey == peerKey {
			m.retireFlowLocked(k, f, k.Protocol, now)
		}
	}
	for inK, entry := range m.inboundNAT {
		if entry.peerKey == peerKey {
			m.releasePortLocked(entry.natPort, entry.protocol, entry.remoteIP, entry.remotePort, now)
			delete(m.inboundNAT, inK)
		}
	}
	m.sweepRemoteBindingsLocked(now)
}

// PurgeSession purges all active flows and NAT state belonging to sessionID.
func (m *DirectEgressManager) PurgeSession(sessionID string) {
	if sessionID == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for k, f := range m.flows {
		if f.sessionID == sessionID {
			m.retireFlowLocked(k, f, k.Protocol, now)
		}
	}
	for inK, entry := range m.inboundNAT {
		if entry.sessionID == sessionID {
			m.releasePortLocked(entry.natPort, entry.protocol, entry.remoteIP, entry.remotePort, now)
			delete(m.inboundNAT, inK)
		}
	}
	m.sweepRemoteBindingsLocked(now)
}

// PurgeAll purges all flows and NAT state.
func (m *DirectEgressManager) PurgeAll() {
	m.mu.Lock()
	defer m.mu.Unlock()

	clear(m.flows)
	clear(m.inboundNAT)
	clear(m.usedPorts)
	clear(m.quarantinedPorts)
	clear(m.remoteBindings)
	clear(m.portOwners)
	m.releaseAllHostPortsLocked()
}
