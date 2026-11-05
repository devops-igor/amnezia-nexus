package forwarder

import (
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

func (m *DirectEgressManager) releasePortLocked(port uint16, now time.Time) {
	if port == 0 {
		return
	}
	delete(m.usedPorts, port)
	if m.portCooldown > 0 {
		m.quarantinedPorts[port] = now
	} else {
		delete(m.portOwners, port)
	}
	for k, b := range m.remoteBindings {
		if k.natPort == port {
			b.active = false
			b.releasedAt = now
		}
	}
}

func (m *DirectEgressManager) retireFlowLocked(key FlowKey, entry *flowEntry, proto uint8, now time.Time) {
	if entry.choice == EgressChoiceDirect && entry.natPort > 0 {
		m.releasePortLocked(entry.natPort, now)
		delete(m.inboundNAT, inboundKey{protocol: proto, natPort: entry.natPort})
	}
	delete(m.flows, key)
}

func (m *DirectEgressManager) allocatePortLocked(peerKey string, proto uint8, remoteIP netip.Addr, remotePort uint16) (uint16, error) {
	totalPorts := int(m.cfg.MaxPort - m.cfg.MinPort + 1)
	now := time.Now()
	for attempt := 0; attempt < 2; attempt++ {
		for i := 0; i < totalPorts; i++ {
			port := m.nextPort
			m.nextPort++
			if m.nextPort > m.cfg.MaxPort || m.nextPort < m.cfg.MinPort {
				m.nextPort = m.cfg.MinPort
			}
			if !m.usedPorts[port] && !m.isPortQuarantinedLocked(port, now) {
				if owner, ok := m.portOwners[port]; ok && owner != "" && owner != peerKey {
					continue
				}
				bKey := remoteBindingKey{protocol: proto, natPort: port, remoteIP: remoteIP, remotePort: remotePort}
				if b, exists := m.remoteBindings[bKey]; exists {
					if b.peerKey != peerKey {
						if m.isBindingQuarantinedLocked(b, proto, now) {
							continue
						}
						// Expired retired remote binding: safe to evict
						delete(m.remoteBindings, bKey)
					}
				}
				m.usedPorts[port] = true
				m.portOwners[port] = peerKey
				m.portEpoch[port]++
				return port, nil
			}
		}
		if attempt == 0 {
			m.sweepLocked(now)
		}
	}

	// Under extreme port pressure where all other available ports are exhausted,
	// recycle the oldest unused port while bumping its generation epoch to fence delayed replies.
	for i := 0; i < totalPorts; i++ {
		port := m.nextPort
		m.nextPort++
		if m.nextPort > m.cfg.MaxPort || m.nextPort < m.cfg.MinPort {
			m.nextPort = m.cfg.MinPort
		}
		if !m.usedPorts[port] {
			bKey := remoteBindingKey{protocol: proto, natPort: port, remoteIP: remoteIP, remotePort: remotePort}
			if b, exists := m.remoteBindings[bKey]; exists {
				if b.peerKey != peerKey {
					if m.isBindingQuarantinedLocked(b, proto, now) {
						continue
					}
					delete(m.remoteBindings, bKey)
				}
			}
			delete(m.quarantinedPorts, port)
			m.usedPorts[port] = true
			m.portOwners[port] = peerKey
			m.portEpoch[port]++
			return port, nil
		}
	}

	return 0, ErrNATPortExhaustion
}

func (m *DirectEgressManager) recordRemoteBindingLocked(bKey remoteBindingKey, peerKey, sessionID string, generation, epoch uint64, now time.Time) {
	if len(m.remoteBindings) >= defaultMaxRemoteBindings {
		m.pruneOldestBindingsLocked(now)
	}
	if existing, exists := m.remoteBindings[bKey]; !exists || existing.peerKey == peerKey {
		m.remoteBindings[bKey] = &remoteBindingEntry{
			peerKey:    peerKey,
			sessionID:  sessionID,
			generation: generation,
			epoch:      epoch,
			active:     true,
		}
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
	if len(m.remoteBindings) < defaultMaxRemoteBindings {
		return
	}
	var oldestKey remoteBindingKey
	var oldestTime time.Time
	found := false
	for k, b := range m.remoteBindings {
		if b != nil && !b.active {
			if !found || b.releasedAt.Before(oldestTime) {
				oldestKey = k
				oldestTime = b.releasedAt
				found = true
			}
		}
	}
	if found {
		delete(m.remoteBindings, oldestKey)
	}
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
			m.releasePortLocked(entry.natPort, now)
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
			m.releasePortLocked(entry.natPort, now)
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
}
