package vpn

import (
	"github.com/devops-igor/amnezia-nexus/internal/vpn/virtualtun"
)

// Backend-device drop ownership (issue #424 round 3, finding 1).
//
// A backend device's VirtualTUN moves packets in two directions with opposite
// meanings:
//
//	client -> backend : AWGClientDevice.Write() -> VirtualTUN.Inbound
//	backend -> client : VirtualTUN.Outbound   -> AWGClientDevice.Read()
//
// Inbound loss is therefore client-originating traffic that never reached the
// backend; outbound loss is return (reply) traffic that never reached the
// client. BackendDevice.DroppedPackets() collapses both directions AND three
// distinct reasons (queue-full, oversized, shutdown drain) into one integer,
// so it cannot populate either axis. Every publication below is sourced from
// the direction x reason breakdown instead.

// backendDeviceStatsProvider is the OPTIONAL capability a BackendDevice
// implements when it can report directional, per-reason drop accounting.
//
// It is deliberately optional rather than an addition to BackendDevice: every
// implementer of that interface would have to grow a method it has no use for,
// and a device that genuinely cannot report the axes (a plain socket, a test
// double) must still be representable. Devices that do not implement it are
// accounted for, not ignored — see backendDeviceDropStats.Unattributed.
type backendDeviceStatsProvider interface {
	DeviceStats() virtualtun.StatsSnapshot
}

// backendDeviceDropStats is the fleet-wide, DISJOINT breakdown of loss inside
// backend devices. Every field is a distinct loss class, every packet is
// counted in exactly one of them, and Total is their sum: the struct is the
// single source the drop-category breakdown is built from.
//
// Direction attribution
//
//	Client*  <- inbound VirtualTUN drops (client -> backend population)
//	Return*  <- outbound VirtualTUN drops (backend -> client population)
//
// Reason attribution: one field per reason, never folded into "queue full".
type backendDeviceDropStats struct {
	// ClientQueueFull is inbound loss to a full VirtualTUN inbound queue
	// (InjectInbound, i.e. AWGClientDevice.Write).
	ClientQueueFull uint64
	// ClientOversized is inbound loss because the engine's Read destination
	// buffer could not hold the packet.
	ClientOversized uint64
	// ClientShutdown is inbound loss drained and discarded by Close.
	ClientShutdown uint64
	// ReturnQueueFull is outbound loss to a full VirtualTUN outbound queue
	// (VirtualTUN.Write, i.e. engine-written return traffic).
	ReturnQueueFull uint64
	// ReturnShutdown is outbound loss drained and discarded by Close.
	ReturnShutdown uint64

	// ClientExternal is the EXPLICIT attribution decision for drops recorded
	// through VirtualTUN.RecordDrop/RecordDropN.
	//
	// That API takes no direction and no reason: an external owner tells the
	// device "I dropped n packets" and nothing more. These drops are
	// therefore attributed to the client-originating population — the
	// conservative default, since every current external caller
	// (clientawg/device.go) observes packets the portal sent upstream on the
	// client's behalf — and are published under their OWN key so they are
	// never mistaken for measured queue-full loss. The alternative,
	// distributing them across the directional buckets, would fabricate a
	// direction the recorder never supplied.
	ClientExternal uint64

	// ClientUnattributed is LIVE loss observed on a device that does not
	// implement backendDeviceStatsProvider, so neither axis exists for it.
	// It is reported rather than dropped so TotalDrops stays truthful.
	ClientUnattributed uint64

	// ClientRetired is RETIRED loss that carries no direction and no reason:
	// the lifetime accumulator's own ClientUnattributed bucket, published
	// under its own key.
	//
	// Retirement is a transfer of the device's real breakdown (issue #424
	// round 5, finding 1), so retired loss that HAS a direction and a reason
	// is published in the reason keys above exactly as a live loss is — a
	// retired inbound queue-full loss appears in ClientQueueFull, a retired
	// outbound one in ReturnQueueFull, and neither changes key at retirement.
	// What remains here is the one retired population with no direction to
	// carry: loss on a device that never reported its axes. It is attributed
	// to the client population, the same conservative default the live path
	// uses, and it is the CLIENT-direction half of the retired total — the
	// retired TOTAL is Total(), the sum of every direction.
	ClientRetired uint64
}

// Total is the sum of every disjoint population above: for the retired
// accumulator this is the retired lifetime loss across every direction.
func (d backendDeviceDropStats) Total() uint64 {
	return d.ClientQueueFull + d.ClientOversized + d.ClientShutdown +
		d.ReturnQueueFull + d.ReturnShutdown +
		d.ClientExternal + d.ClientUnattributed + d.ClientRetired
}

// addInto folds other into d field by field.
//
// It is the RETIREMENT transfer primitive (issue #424 round 5, finding 1):
// the device's own direction x reason fields are added to the matching
// lifetime buckets, so a retired loss keeps the direction and reason it was
// measured with. Adding the device's aggregate scalar instead is what
// reclassified return loss as client loss at the instant of retirement.
func (d *backendDeviceDropStats) addInto(other backendDeviceDropStats) {
	d.ClientQueueFull += other.ClientQueueFull
	d.ClientOversized += other.ClientOversized
	d.ClientShutdown += other.ClientShutdown
	d.ReturnQueueFull += other.ReturnQueueFull
	d.ReturnShutdown += other.ReturnShutdown
	d.ClientExternal += other.ClientExternal
	d.ClientUnattributed += other.ClientUnattributed
}

// snapshotBackendDeviceDrops reads one device's real direction x reason
// breakdown into a single-device accumulator.
//
// It is the one place that answers "what did THIS device lose, in which
// direction, for which reason", and both the live-collection loop and every
// retirement site go through it, so a device is attributed identically while
// it is live and once it has been retired. A device that cannot report the
// axes contributes its aggregate as ClientUnattributed rather than being
// spread across buckets we cannot verify.
//
// It must be called AFTER the device has been closed, so shutdown drains are
// included in the snapshot and are not lost between the transfer and the
// deletion.
func snapshotBackendDeviceDrops(dev BackendDevice) backendDeviceDropStats {
	var out backendDeviceDropStats
	if dev == nil {
		return out
	}
	provider, ok := dev.(backendDeviceStatsProvider)
	if !ok {
		out.ClientUnattributed = dev.DroppedPackets()
		return out
	}
	snap := provider.DeviceStats()
	out.ClientQueueFull = snap.InboundQueueFullDrops
	out.ClientOversized = snap.InboundOversizedDrops
	out.ClientShutdown = snap.InboundShutdownDrops
	out.ReturnQueueFull = snap.OutboundQueueFullDrops
	out.ReturnShutdown = snap.OutboundShutdownDrops
	out.ClientExternal = snap.ExternalDrops()
	return out
}

// collectBackendDeviceDropStats folds every live backend device's
// direction x reason breakdown onto the retired lifetime accumulator.
//
// nil map entries are skipped exactly as the original inline loops did. The
// device map and the retired accumulator are read without the Service mutex,
// matching every other diagnostics reader of this state: the values are
// monotonic per-device counters sampled for a report, never used for a
// decision.
//
// A retired device contributes to the SAME key a live one does, so a loss
// never changes published key across a retirement. That is what keeps the
// per-reason rate trackers honest: they take deltas against a baseline, so a
// loss that migrated between keys at retirement would be published as fresh
// activity on the destination key while TotalDrops never moved.
func collectBackendDeviceDropStats(s *Service) backendDeviceDropStats {
	// Retired loss is published under the same keys as live loss; only the
	// directionless retired bucket keeps its own key.
	out := s.retiredBackendDeviceDrops
	out.ClientRetired = out.ClientUnattributed
	out.ClientUnattributed = 0
	for _, dev := range s.backendDevices {
		if dev == nil {
			continue
		}
		snap := snapshotBackendDeviceDrops(dev)
		out.ClientQueueFull += snap.ClientQueueFull
		out.ClientOversized += snap.ClientOversized
		out.ClientShutdown += snap.ClientShutdown
		out.ReturnQueueFull += snap.ReturnQueueFull
		out.ReturnShutdown += snap.ReturnShutdown
		out.ClientExternal += snap.ClientExternal
		out.ClientUnattributed += snap.ClientUnattributed
	}
	return out
}

// The direction- and reason-agnostic lifetime total across live and retired
// backend devices is totalBackendDeviceDrops in diagnostics.go. It is the
// figure the fleet summary publishes (BackendsDiagnostics.TotalDrops), which
// must keep matching the sum of BackendDevice.DroppedPackets() — the only
// quantity that survives a device that cannot report its breakdown. It is
// deliberately not re-wrapped here: a thin alias would only add an
// indirection with no behavior of its own.
