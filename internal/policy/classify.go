package policy

import (
	"errors"
	"net"
	"net/netip"

	"github.com/devops-igor/amnezia-nexus/internal/geodb"
)

// This file owns the destination-address classifier of issue #918.
//
// It joins the two committed inputs and answers two questions about one IPv4
// destination, and nothing else:
//
//   - is the address inside the Russian allocation, from the committed
//     inventory (issue #919), which follows RIR delegation; and
//   - does the covering range belong to a known multi-region CDN, from the
//     embedded ASN table (issue #922), which is the question ASN answers
//     correctly here.
//
// The inputs are complementary rather than interchangeable. The inventory is
// what decides "inside the Russian allocation": Yandex prefixes are originated
// by a Serbian-registered network, so the ASN table reports `RS` for them. The
// ASN table is what decides "multi-region CDN": an allocation-based zone cannot
// express that, and an Amazon or Cloudflare range inside the zone would
// otherwise be routed direct.
//
// This is deliberately NOT a routing decision. Membership is an approximation of
// allocation, not proof of where a service runs, and it says nothing about
// reachability: a direct path still egresses through this host's own WAN
// address. Prohibited and internal destinations, the operator's proxy rules and
// the fail-safe proxy default all outrank this answer, so the packet path
// applies those around it instead of reading any classification as "go direct".

// DestinationClassification is what the classifier knows about one destination
// address. The zero value means "not classified": outside the allocation, or no
// classifier installed.
type DestinationClassification struct {
	// InAllocation reports membership of the Russian IPv4 allocation.
	InAllocation bool
	// Source names the set that placed the address inside the allocation: the
	// committed inventory or an operator override.
	Source InventorySource
	// ASN is the origin ASN the embedded table reports for the address. It is
	// zero when the address is outside the allocation (the table is consulted
	// for members only) or the table does not cover it.
	ASN uint32
	// CDNProvider names the multi-region CDN whose ASN covers the address, and
	// is empty when the ASN is not on the conservative exclusion list.
	CDNProvider string
}

// AllocationRoutesDirect reports whether allocation membership, with no CDN
// exclusion, makes the destination a DIRECT candidate. It is not a decision:
// the packet path applies the prohibited-destination guard and the operator's
// proxy rules before this can route anything, and every caller must say
// "allocation-matched" rather than claim the service is hosted in Russia.
func (c DestinationClassification) AllocationRoutesDirect() bool {
	return c.InAllocation && c.CDNProvider == ""
}

// AddressClassifier answers the allocation question from the committed
// inventory and the embedded ASN table. It holds no mutable state, takes no
// locks and performs no I/O, so it is safe to share between goroutines.
type AddressClassifier struct {
	inventory *Inventory
	geo       *geodb.GeoDB
}

// NewAddressClassifier joins the two committed inputs. Both are required: a
// classifier built from one of them would answer a different question than the
// accepted contract, so a missing input is an error rather than a partially
// capable classifier. Callers that cannot supply both install no classifier,
// and the packet path then keeps its fail-safe proxy default.
func NewAddressClassifier(inventory *Inventory, geo *geodb.GeoDB) (*AddressClassifier, error) {
	if inventory == nil {
		return nil, errors.New("policy: address classifier requires the allocation inventory")
	}
	if geo == nil {
		return nil, errors.New("policy: address classifier requires the ASN table")
	}
	return &AddressClassifier{inventory: inventory, geo: geo}, nil
}

// Classify reports what the two inputs say about addr.
//
// An address outside the allocation is reported as not classified and the ASN
// table is not consulted for it: CDN exclusion exists to keep allocation
// members on the proxy, so it has nothing to add for a destination the
// allocation already leaves uncovered.
func (c *AddressClassifier) Classify(addr netip.Addr) DestinationClassification {
	if c == nil || c.inventory == nil || c.geo == nil {
		return DestinationClassification{}
	}
	addr = addr.Unmap()
	if !addr.IsValid() || !addr.Is4() {
		// IPv6 is out of scope for this epic; an unclassifiable family must not
		// be reported as a member.
		return DestinationClassification{}
	}
	source, member := c.inventory.Match(addr)
	if !member {
		return DestinationClassification{}
	}
	out := DestinationClassification{InAllocation: true, Source: source}
	asn, _, found := c.geo.Lookup(net.IP(addr.AsSlice()))
	if !found {
		return out
	}
	out.ASN = asn
	if geodb.IsMultiRegionCDNASN(asn) {
		out.CDNProvider = geodb.KnownCDNASNs[asn]
	}
	return out
}
