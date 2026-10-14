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

func (s *Service) collectDropCategories() DropCategoryBreakdown {
	return s.captureDiagnosticsInputs().collectDropCategories()
}

func (inputs diagnosticsInputs) collectDropCategories() DropCategoryBreakdown {
	losses := addIngressLosses(inputs.retiredIngressLosses, engineLossTotals(inputs.ingressEngine))
	routerMalformed := losses.router.MalformedPacketDrops
	routerUnmapped := losses.router.UnmappedSourceIPDrops
	routerMismatch := losses.router.OwnershipMismatchDrops
	routerNoBackend := losses.router.NoActiveBackendDrops
	routerRejected := losses.router.AdmissionRejectedDrops - routerNoBackend + losses.router.RouteRegistrationErrors
	var fwdClientQueueFull, fwdClientRateLimited, fwdClientNoBackend uint64
	if inputs.forwarder != nil {
		fwdClientQueueFull, fwdClientRateLimited, fwdClientNoBackend, _ = inputs.forwarder.ClientDropStats()
	}

	retStats := losses.returns
	// Use live engine queue gauges; retained state contains counters only.
	if inputs.ingressEngine != nil {
		current := inputs.ingressEngine.ReturnStats().TUN
		current.InboundDrops = retStats.TUN.InboundDrops
		current.OutboundDrops = retStats.TUN.OutboundDrops
		retStats.TUN = current
	}

	// Backend-device VirtualTUN loss is attributed per direction AND per reason
	// (issue #424 round 3, finding 1). Inbound loss is client-originating
	// traffic that never reached the backend; outbound loss is backend->Nexus
	// RETURN traffic that never reached the client. Neither is a whole-tunnel
	// total, so nothing here can overlap forwarder admission or backend-queue
	// refusal, which own their own reasons above.
	deviceDrops := inputs.collectBackendDeviceDropStats()
	var returnQueueFull, returnOversized uint64
	if inputs.forwarder != nil {
		returnQueueFull = inputs.forwarder.DropsQueueFull()
		returnOversized = inputs.forwarder.DropsPacketTooLarge()
	}
	fwdClientNoBackend += routerNoBackend

	// Upstream -> Nexus: VirtualTUN.Write feeds the OUTBOUND queue. The upstream
	// AWG engine emits authenticated plaintext it received from the client, so
	// an outbound drop is lost client traffic and belongs in the client bucket
	// (issue #424 round 2, finding 2).
	clientVirtualTUNDrops := retStats.TUN.OutboundDrops
	clientTotal := routerMalformed +
		routerUnmapped +
		routerMismatch +
		routerRejected +
		fwdClientQueueFull +
		fwdClientRateLimited +
		fwdClientNoBackend +
		clientVirtualTUNDrops +
		deviceDrops.ClientQueueFull +
		deviceDrops.ClientOversized +
		deviceDrops.ClientShutdown +
		deviceDrops.ClientExternal

	// Nexus -> Upstream: VirtualTUN.InjectInbound feeds the INBOUND queue, so
	// its drop bucket is the return path's own loss accounting.
	returnTunDrops := retStats.TUN.InboundDrops

	// The overlap between injection errors and inbound VirtualTUN drops is
	// owned by the injection site (returnCounters.injectionTunDrops), not
	// inferred here. InboundDrops also rises on oversized reads and on
	// shutdown drain with no injection error at all, so subtracting the
	// aggregate masked real non-TUN injection failures (issue #424 round 2,
	// finding 3).
	nonTunInjectionErrors := uint64(0)
	if retStats.InjectionErrors > retStats.InjectionTunDrops {
		nonTunInjectionErrors = retStats.InjectionErrors - retStats.InjectionTunDrops
	}
	returnTotal := retStats.MalformedDrops +
		retStats.UnmappedDrops +
		retStats.OwnershipMismatchDrops +
		nonTunInjectionErrors +
		returnTunDrops + returnQueueFull + returnOversized +
		deviceDrops.ReturnQueueFull + deviceDrops.ReturnShutdown

	// The direction-neutral backend-device population is real measured loss,
	// so loss conservation keeps it in the total; it belongs to NEITHER
	// directional total because its device reports no direction (issue #429
	// review round 3, blocker 3).
	totalDrops := clientTotal + returnTotal + deviceDrops.Unattributed

	return DropCategoryBreakdown{
		ClientMalformed:              routerMalformed,
		ClientUnmappedSource:         routerUnmapped,
		ClientMismatch:               routerMismatch,
		ClientRejected:               routerRejected,
		ClientBackendQueueFull:       fwdClientQueueFull,
		ClientRateLimited:            fwdClientRateLimited,
		ClientNoHealthyBackend:       fwdClientNoBackend,
		ClientVirtualTUNDrops:        clientVirtualTUNDrops,
		ClientBackendDeviceQueueFull: deviceDrops.ClientQueueFull,
		ClientBackendDeviceOversized: deviceDrops.ClientOversized,
		ClientBackendDeviceShutdown:  deviceDrops.ClientShutdown,
		ClientBackendDeviceExternal:  deviceDrops.ClientExternal,
		BackendDeviceUnattributed:    deviceDrops.Unattributed,
		ClientTotalDrops:             clientTotal,

		ReturnMalformed:         retStats.MalformedDrops,
		ReturnUnmapped:          retStats.UnmappedDrops,
		ReturnMismatch:          retStats.OwnershipMismatchDrops,
		ReturnInjectionErrors:   nonTunInjectionErrors,
		ReturnVirtualTUNDrops:   returnTunDrops,
		ReturnInjectionTUNDrops: retStats.InjectionTunDrops,
		ReturnTotalDrops:        returnTotal,
		ReturnQueueFull:         returnQueueFull,
		ReturnPacketTooLarge:    returnOversized,

		ReturnBackendDeviceQueueFull: deviceDrops.ReturnQueueFull,
		ReturnBackendDeviceShutdown:  deviceDrops.ReturnShutdown,

		TotalDrops: totalDrops,
	}
}

func (inputs diagnosticsInputs) collectVirtualTUNDiagnostics() VirtualTUNDiagnostics {
	losses := addIngressLosses(inputs.retiredIngressLosses, engineLossTotals(inputs.ingressEngine))
	retStats := losses.returns
	if inputs.ingressEngine != nil {
		current := inputs.ingressEngine.ReturnStats().TUN
		current.InboundDrops = retStats.TUN.InboundDrops
		current.OutboundDrops = retStats.TUN.OutboundDrops
		retStats.TUN = current
	}
	return VirtualTUNDiagnostics{
		UpstreamToNexus: VirtualTUNDirectionalHealth{
			Occupancy: retStats.TUN.OutboundDepth,
			Capacity:  retStats.TUN.OutboundCapacity,
			Peak:      retStats.TUN.OutboundPeak,
			Drops:     retStats.TUN.OutboundDrops,
		},
		NexusToUpstream: VirtualTUNDirectionalHealth{
			Occupancy: retStats.TUN.InboundDepth,
			Capacity:  retStats.TUN.InboundCapacity,
			Peak:      retStats.TUN.InboundPeak,
			Drops:     retStats.TUN.InboundDrops,
		},
	}
}
