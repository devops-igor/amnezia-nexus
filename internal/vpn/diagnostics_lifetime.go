package vpn

import "github.com/devops-igor/amnezia-nexus/internal/vpn/ingress"

// Fixed engine-owned loss populations survive engine shutdown/replacement.
// Gauge fields are never retained; cumulative counters preserve service lifetime.
type ingressLossTotals struct {
	router  ingress.Stats
	returns ReturnStatsSnapshot
}

func engineLossTotals(e *IngressEngine) ingressLossTotals {
	var totals ingressLossTotals
	if e != nil {
		if e.router != nil {
			totals.router = e.router.StatsSnapshot()
		}
		totals.returns = e.ReturnStats()
	}
	return totals
}

func addIngressLosses(a, b ingressLossTotals) ingressLossTotals {
	a.router.MalformedPacketDrops += b.router.MalformedPacketDrops
	a.router.UnmappedSourceIPDrops += b.router.UnmappedSourceIPDrops
	a.router.OwnershipMismatchDrops += b.router.OwnershipMismatchDrops
	a.router.AdmissionRejectedDrops += b.router.AdmissionRejectedDrops
	a.router.NoActiveBackendDrops += b.router.NoActiveBackendDrops
	a.router.RouteRegistrationErrors += b.router.RouteRegistrationErrors
	a.returns.MalformedDrops += b.returns.MalformedDrops
	a.returns.UnmappedDrops += b.returns.UnmappedDrops
	a.returns.OwnershipMismatchDrops += b.returns.OwnershipMismatchDrops
	a.returns.InjectionErrors += b.returns.InjectionErrors
	a.returns.InjectionTunDrops += b.returns.InjectionTunDrops
	a.returns.TUN.InboundDrops += b.returns.TUN.InboundDrops
	a.returns.TUN.OutboundDrops += b.returns.TUN.OutboundDrops
	return a
}

// Retirement initially publishes counters before detaching the engine, then
// adds only the remaining shutdown delta (not its entire final snapshot).
func ingressLossDelta(after, before ingressLossTotals) ingressLossTotals {
	after.router.MalformedPacketDrops -= before.router.MalformedPacketDrops
	after.router.UnmappedSourceIPDrops -= before.router.UnmappedSourceIPDrops
	after.router.OwnershipMismatchDrops -= before.router.OwnershipMismatchDrops
	after.router.AdmissionRejectedDrops -= before.router.AdmissionRejectedDrops
	after.router.NoActiveBackendDrops -= before.router.NoActiveBackendDrops
	after.router.RouteRegistrationErrors -= before.router.RouteRegistrationErrors
	after.returns.MalformedDrops -= before.returns.MalformedDrops
	after.returns.UnmappedDrops -= before.returns.UnmappedDrops
	after.returns.OwnershipMismatchDrops -= before.returns.OwnershipMismatchDrops
	after.returns.InjectionErrors -= before.returns.InjectionErrors
	after.returns.InjectionTunDrops -= before.returns.InjectionTunDrops
	after.returns.TUN.InboundDrops -= before.returns.TUN.InboundDrops
	after.returns.TUN.OutboundDrops -= before.returns.TUN.OutboundDrops
	return after
}
