package vpn

import (
	"errors"
	"net/netip"
	"sync/atomic"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/ingress"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/virtualtun"
)

var errReturnDestination = errors.New("ingress engine: invalid return destination")

type returnCounters struct {
	accepted        atomic.Uint64
	malformed       atomic.Uint64
	unmapped        atomic.Uint64
	mismatch        atomic.Uint64
	injectionErrors atomic.Uint64
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
	TUN                    virtualtun.StatsSnapshot
}

func (e *IngressEngine) ReturnStats() ReturnStatsSnapshot {
	return ReturnStatsSnapshot{
		AcceptedPackets: e.returnCounters.accepted.Load(), MalformedDrops: e.returnCounters.malformed.Load(),
		UnmappedDrops: e.returnCounters.unmapped.Load(), OwnershipMismatchDrops: e.returnCounters.mismatch.Load(),
		InjectionErrors: e.returnCounters.injectionErrors.Load(), TUN: e.portal.Stats(),
	}
}

// writeReturnPacket sees only plaintext and durable ownership. The upstream
// engine alone chooses AllowedIPs, roaming endpoint, keys, indices and nonce.
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
	if err := e.portal.InjectInbound(packet); err != nil {
		e.returnCounters.injectionErrors.Add(1)
		return 0, err
	}
	e.returnCounters.accepted.Add(1)
	return len(packet), nil
}
