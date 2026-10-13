package vpn

import (
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/session"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

// diagnosticsInputs owns Service lifecycle storage for one observation.
// Shared collaborators synchronize their own methods and remain valid after
// retirement. Call them only after releasing Service.mu.
//
// generation is the dataplane incarnation this snapshot belongs to (issue
// #429 review round 4, blocker 1): it is captured atomically together with
// the rest of the snapshot and must be passed to EVERY sampling entry point
// fed from it, so a snapshot can never be sampled against the trackers'
// current generation after a lifecycle reset. The trackers' reset(gen)
// lifecycle is unchanged.
type diagnosticsInputs struct {
	generation                diagGeneration
	sessions                  []Session
	tunnels                   []*models.BackendTunnel
	forwarder                 *forwarder.Forwarder
	ingressEngine             *IngressEngine
	sessionMgr                *session.SessionManager
	pool                      *tunnel.Pool
	rollingHistory            *RollingHistory
	backendDevices            map[int64]BackendDevice
	retiredBackendDeviceDrops backendDeviceDropStats
	retiredIngressLosses      ingressLossTotals
}

func (s *Service) captureDiagnosticsInputs() diagnosticsInputs {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.diagnosticsInputsLocked()
}

// diagnosticsInputsLocked requires Service.mu. Map storage, retired prefixes
// and the diagnostics generation are captured together so an observation
// belongs to exactly one population AND one dataplane incarnation: the
// atomic load cannot straddle a lifecycle transition that the rest of the
// snapshot already crossed, because resetDiagnosticsGeneration bumps the
// generation under diagRatesMu before Service.Start repopulates the
// snapshot's collaborators (and their writers hold s.mu).
func (s *Service) diagnosticsInputsLocked() diagnosticsInputs {
	devices := make(map[int64]BackendDevice, len(s.backendDevices))
	for id, dev := range s.backendDevices {
		devices[id] = dev
	}
	var sessions []Session
	if s.sessionMgr != nil {
		sessions = s.sessionMgr.ListActiveSessionsSnapshot()
	}
	var tunnels []*models.BackendTunnel
	if s.pool != nil {
		tunnels = s.pool.ListTunnels()
	}
	return diagnosticsInputs{
		generation: s.currentDiagGeneration(),
		sessions:   sessions, tunnels: tunnels,
		forwarder: s.forwarder, ingressEngine: s.ingressEngine,
		sessionMgr: s.sessionMgr, pool: s.pool, rollingHistory: s.rollingHistory,
		backendDevices:            devices,
		retiredBackendDeviceDrops: s.retiredBackendDeviceDrops,
		retiredIngressLosses:      s.retiredIngressLosses,
	}
}

// currentDiagGeneration reports the live diagnostics generation. Lock-free on
// purpose (atomic): capture paths hold s.mu, while resetDiagnosticsGeneration
// holds diagRatesMu and takes s.mu for its priming capture — a diagRatesMu
// read here would invert the established lock order and deadlock.
func (s *Service) currentDiagGeneration() diagGeneration {
	return diagGeneration(s.diagGeneration.Load())
}
