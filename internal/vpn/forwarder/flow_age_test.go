package forwarder

import (
	"testing"
	"time"
)

// Logical-age helpers for the reply-refresh fixture (issue #861).
//
// The refresh case used to sleep 40ms of real time inside a 60ms lifetime, so any delay of
// more than 20ms between the two sleeps and the reply would have made a correct refresh look
// like a stale reply. Whether that is what failed in CI is not known. These helpers place a
// flow at a known logical age instead, through the same lock the manager uses, and read it
// back without going through the lookup path (which refreshes).

// flowAgeSample is one observation of a flow's stored age.
type flowAgeSample struct {
	Present   bool
	NATPort   uint16
	LastSeen  time.Time
	Age       time.Duration
	SampledAt time.Time
}

// sampleFlowAge reads one flow's stored age without touching it. The sample instant is taken
// after the lock is held, so a writer that refreshed the flow while this call waited for the
// lock cannot leave a lastSeen later than the instant it is measured against.
func sampleFlowAge(dem *DirectEgressManager, key FlowKey) flowAgeSample {
	dem.mu.RLock()
	defer dem.mu.RUnlock()
	now := time.Now()
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
