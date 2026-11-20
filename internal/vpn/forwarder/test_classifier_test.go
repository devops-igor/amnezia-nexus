package forwarder

import (
	"net/netip"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// testDirectClassifier is the address classifier a test installs when it needs the
// DIRECT path. It answers the way the production classifier does for an address
// inside the Russian allocation with no CDN exclusion, which is the contract's
// DIRECT row.
//
// Before this slice the same fixtures obtained a DIRECT route by seeding retained
// DNS evidence. The decision no longer reads that evidence, so a test that wants a
// direct flow now supplies the address input, exactly as production does.
type testDirectClassifier struct {
	// addrs is the set of destinations classified as allocation members. A nil
	// set means every destination, which the catch-all constructor builds.
	addrs map[netip.Addr]struct{}
}

// allocationDirectClassification is the classifier's answer for an allocation
// member with no CDN exclusion.
var allocationDirectClassification = policy.DestinationClassification{
	InAllocation: true,
	Source:       policy.InventorySourceShipped,
	ASN:          64999,
}

// newTestDirectClassifier classifies exactly the supplied destinations as
// allocation members; every other destination stays uncovered and therefore
// proxies.
func newTestDirectClassifier(addrs ...netip.Addr) *testDirectClassifier {
	set := make(map[netip.Addr]struct{}, len(addrs))
	for _, addr := range addrs {
		set[addr] = struct{}{}
	}
	return &testDirectClassifier{addrs: set}
}

// newAllDirectTestClassifier classifies every destination as an allocation
// member. Fixtures whose subject is the direct dataplane rather than the
// classification use it so each flow they dispatch takes the DIRECT path.
func newAllDirectTestClassifier() *testDirectClassifier {
	return &testDirectClassifier{}
}

func (c *testDirectClassifier) Classify(addr netip.Addr) policy.DestinationClassification {
	if c.addrs == nil {
		return allocationDirectClassification
	}
	if _, ok := c.addrs[addr]; ok {
		return allocationDirectClassification
	}
	return policy.DestinationClassification{}
}
