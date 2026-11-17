package forwarder

import (
	"testing"
	"time"
)

// Logical-age helpers for the reply-refresh fixture (issue #861).
//
// The refresh case used to sleep 40ms of real time inside a 60ms lifetime, which left a 20ms
// margin: a scheduler overshoot turned a correct refresh into a stale reply and reported it as
// a product failure. These helpers place a flow at a known logical age instead, through the
// same table access the manager uses, and read it back without going through the lookup path
// (which refreshes).

// flowAgeSample is one observation of a flow's stored age.
type flowAgeSample struct {
	Present   bool
	NATPort   uint16
	LastSeen  time.Time
	Age       time.Duration
	SampledAt time.Time
}

// sampleFlowAge reads one flow's stored age without touching it.
func sampleFlowAge(dem *DirectEgressManager, key FlowKey) flowAgeSample {
	now := time.Now()
	dem.mu.RLock()
	defer dem.mu.RUnlock()
	entry := dem.flows[key]
	if entry == nil {
		return flowAgeSample{SampledAt: now}
	}
	return flowAgeSample{
		Present:   true,
		NATPort:   entry.natPort,
		LastSeen:  entry.lastSeen,
		Age:       now.Sub(entry.lastSeen),
		SampledAt: now,
	}
}

// positionFlowAge sets one flow's lastSeen so its logical age is exactly age, under the same
// lock the manager uses. It replaces a real sleep inside a timing budget: the flow is placed at
// a known age instead of the test hoping a sleep landed there.
func positionFlowAge(t *testing.T, dem *DirectEgressManager, key FlowKey, age time.Duration) {
	t.Helper()
	dem.mu.Lock()
	defer dem.mu.Unlock()
	entry := dem.flows[key]
	if entry == nil {
		t.Fatalf("cannot position a flow that does not exist: %+v", key)
	}
	entry.lastSeen = time.Now().Add(-age)
}

// flowKeyForTest builds the tuple key this package uses for the given packet.
func flowKeyForTest(t *testing.T, peerKey string, packet []byte) FlowKey {
	t.Helper()
	key, err := flowKeyForPacket(peerKey, packet)
	if err != nil {
		t.Fatalf("flow key: %v", err)
	}
	return key
}
