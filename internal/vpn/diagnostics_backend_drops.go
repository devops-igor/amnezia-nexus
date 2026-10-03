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

	// ClientUnattributed is live-device loss observed on a device that does
	// not implement backendDeviceStatsProvider, so neither axis exists for it.
	// It is reported rather than dropped so TotalDrops stays truthful.
	ClientUnattributed uint64

	// ClientRetired is s.retiredBackendDeviceDrops, the lifetime accumulator
	// for devices that have left the map.
	//
	// Retirement destroys the object that held the breakdown, so a retired
	// device's direction and reason are unrecoverable by construction — not a
	// measurement gap that more instrumentation could close. It is attributed
	// to the client population, which is where it was attributed before this
	// change, so the lifetime total is preserved across a retirement, and it
	// is published under its OWN key rather than being folded into
	// ClientQueueFull: reporting it as queue-full would reinstate exactly the
	// mislabelling this rework removes, on the one population where no better
	// answer exists.
	ClientRetired uint64
}

// Total is the sum of every disjoint population above.
func (d backendDeviceDropStats) Total() uint64 {
	return d.ClientQueueFull + d.ClientOversized + d.ClientShutdown +
		d.ReturnQueueFull + d.ReturnShutdown +
		d.ClientExternal + d.ClientUnattributed + d.ClientRetired
}

// collectBackendDeviceDropStats folds every live backend device's
// direction x reason breakdown onto the retired lifetime accumulator.
//
// nil map entries are skipped exactly as the original inline loops did. The
// device map and the retired accumulator are read without the Service mutex,
// matching every other diagnostics reader of this state: the values are
// monotonic per-device counters sampled for a report, never used for a
// decision.
func collectBackendDeviceDropStats(s *Service) backendDeviceDropStats {
	var out backendDeviceDropStats
	out.ClientRetired = s.retiredBackendDeviceDrops
	for _, dev := range s.backendDevices {
		if dev == nil {
			continue
		}
		provider, ok := dev.(backendDeviceStatsProvider)
		if !ok {
			// No directional or reason data exists for this device. Its
			// aggregate is still real loss, so it is published under its own
			// key instead of being spread across buckets we cannot verify.
			out.ClientUnattributed += dev.DroppedPackets()
			continue
		}
		snap := provider.DeviceStats()
		out.ClientQueueFull += snap.InboundQueueFullDrops
		out.ClientOversized += snap.InboundOversizedDrops
		out.ClientShutdown += snap.InboundShutdownDrops
		out.ReturnQueueFull += snap.OutboundQueueFullDrops
		out.ReturnShutdown += snap.OutboundShutdownDrops
		out.ClientExternal += snap.ExternalDrops()
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
