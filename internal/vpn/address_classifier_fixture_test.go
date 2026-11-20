package vpn

import (
	"net/netip"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

// directDestinationSet is the address classifier a fixture installs when a flow
// must be decided DIRECT. It answers the way the production classifier does for
// an address inside the Russian allocation with no CDN exclusion.
//
// The packet path decides by destination address, so a fixture that needs the
// direct data path states the address input. Seeding retained DNS evidence no
// longer routes anything: that evidence is still recorded, never consulted.
type directDestinationSet map[netip.Addr]struct{}

func (d directDestinationSet) Classify(addr netip.Addr) policy.DestinationClassification {
	if _, ok := d[addr]; ok {
		return policy.DestinationClassification{
			InAllocation: true,
			Source:       policy.InventorySourceShipped,
			ASN:          64999,
		}
	}
	return policy.DestinationClassification{}
}

// installDirectDestinations replaces the forwarder's address classifier so the
// supplied destinations take the contract's DIRECT row and every other
// destination stays uncovered.
func installDirectDestinations(fwd *forwarder.Forwarder, addrs ...netip.Addr) {
	set := make(directDestinationSet, len(addrs))
	for _, addr := range addrs {
		set[addr] = struct{}{}
	}
	fwd.SetDestinationClassifier(set)
}

// direct keeps the accumulated direct destinations of this fixture, so a test
// can add one destination per call without unclassifying the ones it added
// before.
func (f *clientDiagFixture) direct(t *testing.T, addrs ...netip.Addr) {
	t.Helper()
	if f.directAddrs == nil {
		f.directAddrs = make(map[netip.Addr]struct{}, len(addrs))
	}
	for _, addr := range addrs {
		f.directAddrs[addr] = struct{}{}
	}
	set := make(directDestinationSet, len(f.directAddrs))
	for addr := range f.directAddrs {
		set[addr] = struct{}{}
	}
	f.fwd.SetDestinationClassifier(set)
}
