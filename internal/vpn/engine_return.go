package vpn

import (
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/ingress"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/virtualtun"
)

var errReturnDestination = errors.New("ingress engine: invalid return destination")

type returnCounters struct {
	injectionMu     sync.Mutex // keeps total/subset snapshot coherent
	accepted        atomic.Uint64
	malformed       atomic.Uint64
	unmapped        atomic.Uint64
	mismatch        atomic.Uint64
	injectionErrors atomic.Uint64
	// injectionTunDrops counts the subset of injectionErrors whose loss was
	// already accounted by the VirtualTUN inbound drop bucket. Only the
	// queue-full rejection of InjectInbound does that: ErrClosed drops
	// nothing, and ErrPacketTooLarge is recorded as an external device drop
	// outside the per-reason inbound buckets. Owning the overlap here is what
	// makes the diagnostics-side subtraction exact, instead of an unsound
	// subtraction of two unrelated aggregates.
	injectionTunDrops atomic.Uint64
}

// ReturnStatsSnapshot describes plaintext submission to the client engine.
// Accepted counts queue admissions, not wire delivery. TUN includes bounded
// queue depths and reason-specific losses; forwarder route queues retain their
// existing separate queue/write counters. Do not sum these overlapping losses.
type ReturnStatsSnapshot struct {
	AcceptedPackets        uint64
	MalformedDrops         uint64
	UnmappedDrops          uint64
	OwnershipMismatchDrops uint64
	InjectionErrors        uint64
	// InjectionTunDrops is the subset of InjectionErrors already counted by
	// TUN.InboundDrops, owned at the injection site. NonTunInjectionErrors is
	// therefore InjectionErrors - InjectionTunDrops: exact rather than
	// approximated from unrelated inbound drop reasons.
	InjectionTunDrops uint64
	TUN               virtualtun.StatsSnapshot
}

func (e *IngressEngine) ReturnStats() ReturnStatsSnapshot {
	e.returnCounters.injectionMu.Lock()
	defer e.returnCounters.injectionMu.Unlock()
	var tun virtualtun.StatsSnapshot
	if e.portal != nil {
		tun = e.portal.Stats()
	}
	return ReturnStatsSnapshot{
		AcceptedPackets: e.returnCounters.accepted.Load(), MalformedDrops: e.returnCounters.malformed.Load(),
		UnmappedDrops: e.returnCounters.unmapped.Load(), OwnershipMismatchDrops: e.returnCounters.mismatch.Load(),
		InjectionErrors:   e.returnCounters.injectionErrors.Load(),
		InjectionTunDrops: e.returnCounters.injectionTunDrops.Load(), TUN: tun,
	}
}

// classifyForwarderReject folds the forwarder's production-filter rejections
// into the engine counters. The forwarder calls this for every packet it
// rejects BEFORE per-route handling; the mapping follows the single-owner
// rule documented on Forwarder.returnRejectClassifier — the forwarder's
// filter and this engine's write callback each own disjoint packet
// populations, so a packet is never counted twice:
//   - ReturnRejectedUnrouted -> UnmappedDrops (no route/writer existed);
//   - ReturnRejectedMalformed -> MalformedDrops (shape filter rejected it
//     before the write callback ran);
//   - ReturnRejectedMismatch -> OwnershipMismatchDrops (reply arrived on a
//     backend the route does not own).
func (e *IngressEngine) classifyForwarderReject(reason forwarder.ReturnRejectReason) {
	switch reason {
	case forwarder.ReturnRejectedUnrouted:
		e.returnCounters.unmapped.Add(1)
	case forwarder.ReturnRejectedMalformed:
		e.returnCounters.malformed.Add(1)
	case forwarder.ReturnRejectedMismatch:
		e.returnCounters.mismatch.Add(1)
	}
}

// writeReturnPacket sees only plaintext and durable ownership. The upstream
// engine alone chooses AllowedIPs, roaming endpoint, keys, indices and nonce.
//
// Classification contract (issue #389 rework 2): on the production return
// path the forwarder's filters reject unrouted/malformed/mismatched replies
// before invoking this callback and classify them via
// classifyForwarderReject, so the branches below are the direct-call
// fallback (and future non-forwarder callers), never a second count of a
// forwarder-rejected packet.
func (e *IngressEngine) writeReturnPacket(peerKey, assignedIP string, packet []byte) (int, error) {
	if _, ok := ingress.ParseIPv4Source(packet); !ok {
		e.returnCounters.malformed.Add(1)
		return 0, errReturnDestination
	}
	destination := netip.AddrFrom4([4]byte{packet[16], packet[17], packet[18], packet[19]})
	owner, ok := e.resolver.Lookup(destination)
	if !ok {
		e.returnCounters.unmapped.Add(1)
		return 0, errReturnDestination
	}
	if destination.String() != assignedIP || owner.PeerPublicKey != peerKey {
		e.returnCounters.mismatch.Add(1)
		return 0, errReturnDestination
	}
	err := e.portal.InjectInbound(packet)
	if err != nil {
		e.returnCounters.injectionMu.Lock()
		e.returnCounters.injectionErrors.Add(1)
		// ErrQueueFull is the only rejection the VirtualTUN already counted
		// in its inbound drop bucket, so it is the only overlap to own here.
		if errors.Is(err, virtualtun.ErrQueueFull) {
			e.returnCounters.injectionTunDrops.Add(1)
		}
		e.returnCounters.injectionMu.Unlock()
		return 0, err
	}
	e.returnCounters.accepted.Add(1)
	return len(packet), nil
}
