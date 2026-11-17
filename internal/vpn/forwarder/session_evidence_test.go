package forwarder

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// Behavioural coverage for the read-only session view (issue #861).
//
// The two properties under test are identity and non-mutation: a listing must
// return only the records one session incarnation owns, and reading must leave
// the flow table exactly as it found it. The second property is asserted against
// the record itself (lastSeen, presence, table size) and contrasted with
// LookupFlow, which does refresh and retire — so "the read did not mutate" is a
// measured difference rather than a comment.

func newSessionEvidenceFixture(t testing.TB, maxFlows int) (*Forwarder, *DirectEgressManager, *mockPacketDev) {
	t.Helper()
	fwd := NewForwarder(nil, "10.100.0.0/16", 16)
	wan := newMockPacketDev()
	dem := NewDirectEgressManager(DirectEgressConfig{
		HostWANIP:    netip.MustParseAddr("203.0.113.1"),
		GatewayDNSIP: netip.MustParseAddr("10.100.0.1"),
		WANDevice:    wan,
		MaxFlows:     maxFlows,
	}, fwd)
	fwd.SetDirectEgress(dem)
	return fwd, dem, wan
}

func clientPacket(src string, srcPort uint16, dst string, dstPort uint16) []byte {
	return buildTestIPv4TCPPacket(netip.MustParseAddr(src), netip.MustParseAddr(dst), srcPort, dstPort, 0x02, nil)
}

func TestSessionRouteStatesReportsTheRegisteredGenerations(t *testing.T) {
	fwd := NewForwarder(nil, "10.100.0.0/16", 16)
	fwd.RegisterSession("sess-a", "conn-a", "peer-a", "10.100.0.5", 11)
	fwd.RegisterSession("sess-b", "conn-b", "peer-b", "10.100.0.6", 12)

	states := fwd.SessionRouteStates()
	if len(states) != 2 {
		t.Fatalf("states = %d, want 2", len(states))
	}
	if states[0].SessionID != "sess-a" || states[1].SessionID != "sess-b" {
		t.Errorf("states are not sorted by session id: %+v", states)
	}
	for _, state := range states {
		if state.Generation == 0 {
			t.Errorf("session %s reports generation 0; the registration count is the incarnation", state.SessionID)
		}
		if state.ConnectionID == "" || state.AssignedIP == "" {
			t.Errorf("session %s is missing its route identity: %+v", state.SessionID, state)
		}
	}
	firstGen := states[0].Generation

	// A same-session rekey keeps the session id and bumps the generation, so the
	// listing has to follow the route, not the id.
	fwd.RegisterSession("sess-a", "conn-a", "peer-a", "10.100.0.5", 11)
	states = fwd.SessionRouteStates()
	if len(states) != 2 {
		t.Fatalf("states after rekey = %d, want 2", len(states))
	}
	if states[0].SessionID != "sess-a" || states[0].Generation <= firstGen {
		t.Fatalf("rekey generation = %d, want greater than %d", states[0].Generation, firstGen)
	}
	if got := fwd.ActiveRoutesCount(); got != 2 {
		t.Errorf("ActiveRoutesCount after listing = %d, want 2 (a listing must not change the route set)", got)
	}
	// The listing is a copy: mutating it must not reach the forwarder.
	states[0].AssignedIP = "203.0.113.99"
	if again := fwd.SessionRouteStates(); again[0].AssignedIP == "203.0.113.99" {
		t.Error("SessionRouteStates returned a view into live route state")
	}
}

// TestSessionRouteGenerationReportsOnlyRegisteredRoutes pins the read-only
// incarnation lookup the DNS recorder uses: it reports the registered generation
// for an exact session and nothing for an unknown or empty one.
func TestSessionRouteGenerationReportsOnlyRegisteredRoutes(t *testing.T) {
	fwd := NewForwarder(nil, "10.100.0.0/16", 16)
	fwd.RegisterSession("sess-a", "conn-a", "peer-a", "10.100.0.5", 11)
	first := fwd.PeerRegistration("peer-a")

	generation, ok := fwd.SessionRouteGeneration("sess-a")
	if !ok || generation != first {
		t.Fatalf("generation = %d/%v, want the registered %d", generation, ok, first)
	}
	if _, ok := fwd.SessionRouteGeneration("sess-unknown"); ok {
		t.Error("an unregistered session reported a generation")
	}
	if _, ok := fwd.SessionRouteGeneration(""); ok {
		t.Error("an empty session id reported a generation")
	}
	var nilForwarder *Forwarder
	if _, ok := nilForwarder.SessionRouteGeneration("sess-a"); ok {
		t.Error("a nil forwarder reported a generation")
	}

	// A rekey of the same session moves the incarnation.
	fwd.RegisterSession("sess-a", "conn-a", "peer-a", "10.100.0.5", 11)
	second, ok := fwd.SessionRouteGeneration("sess-a")
	if !ok || second <= first {
		t.Errorf("generation after rekey = %d/%v, want greater than %d", second, ok, first)
	}
}

func TestSnapshotSessionFlowsFiltersBySessionAndGeneration(t *testing.T) {
	fwd, dem, _ := newSessionEvidenceFixture(t, 64)
	fwd.RegisterSession("sess-a", "conn-a", "peer-a", "10.100.0.5", 11)
	fwd.RegisterSession("sess-b", "conn-b", "peer-b", "10.100.0.6", 12)
	genA := fwd.PeerRegistration("peer-a")

	if err := dem.RecordFlow("peer-a", "sess-a", genA, clientPacket("10.100.0.5", 40001, "93.184.216.34", 443), EgressChoiceProxy); err != nil {
		t.Fatalf("RecordFlow sess-a: %v", err)
	}
	if err := dem.RecordFlow("peer-b", "sess-b", fwd.PeerRegistration("peer-b"), clientPacket("10.100.0.6", 40002, "1.1.1.1", 53), EgressChoiceDirect); err != nil {
		t.Fatalf("RecordFlow sess-b: %v", err)
	}

	list := dem.SnapshotSessionFlows("sess-a", genA, time.Now(), 0)
	if list.Total != 1 || len(list.Flows) != 1 {
		t.Fatalf("sess-a flows = %d, want exactly its own record", list.Total)
	}
	flow := list.Flows[0]
	if flow.Choice != EgressChoiceProxy || flow.DstIP.String() != "93.184.216.34" || flow.DstPort != 443 || flow.SrcPort != 40001 {
		t.Errorf("flow = %+v, want the PROXY record for 93.184.216.34:443", flow)
	}
	if flow.Generation != genA {
		t.Errorf("generation = %d, want %d", flow.Generation, genA)
	}
	// Scanned is this selection's own visit count through the session index, not a count of
	// table records walked: sess-a owns exactly one flow, so exactly one record is visited
	// even though the table holds sess-b's as well.
	if list.Scanned != 1 {
		t.Errorf("scanned = %d, want the selection's own single record", list.Scanned)
	}
	if !list.ScanComplete {
		t.Error("a one-record selection must report its visit as complete")
	}

	// The isolation property that used to be implicit in a global scan count: adding more
	// records for another client must not change this client's visit or total.
	for i := range 8 {
		port := uint16(41000 + i)
		if err := dem.RecordFlow("peer-b", "sess-b", fwd.PeerRegistration("peer-b"),
			clientPacket("10.100.0.6", port, "1.1.1.1", 53), EgressChoiceDirect); err != nil {
			t.Fatalf("RecordFlow sess-b %d: %v", i, err)
		}
	}
	after := dem.SnapshotSessionFlows("sess-a", genA, time.Now(), 0)
	if after.Scanned != list.Scanned || after.Total != list.Total || len(after.Flows) != len(list.Flows) {
		t.Errorf("another client's records changed this selection: scanned %d->%d total %d->%d rows %d->%d",
			list.Scanned, after.Scanned, list.Total, after.Total, len(list.Flows), len(after.Flows))
	}

	// Another session's records are never returned for this selection.
	for _, other := range dem.SnapshotSessionFlows("sess-b", 0, time.Now(), 0).Flows {
		if other.DstIP.String() == "93.184.216.34" {
			t.Error("sess-b's listing contains sess-a's record")
		}
	}

	// After a same-session rekey the previous generation's records are purged
	// with the peer (the DNS ledger survives a rekey, the flow table does not),
	// so neither generation can present the other incarnation's flow.
	fwd.RegisterSession("sess-a", "conn-a", "peer-a", "10.100.0.5", 11)
	genA2 := fwd.PeerRegistration("peer-a")
	if genA2 == genA {
		t.Fatal("rekey did not advance the generation")
	}
	if got := dem.SnapshotSessionFlows("sess-a", genA2, time.Now(), 0); got.Total != 0 {
		t.Errorf("new generation listing = %d flows, want 0", got.Total)
	}
	if got := dem.SnapshotSessionFlows("sess-a", genA, time.Now(), 0); got.Total != 0 {
		t.Errorf("replaced generation listing = %d flows, want 0 (the rekey purged them)", got.Total)
	}
}

func TestSnapshotSessionFlowsDoesNotRefreshOrRetire(t *testing.T) {
	fwd, dem, _ := newSessionEvidenceFixture(t, 64)
	fwd.RegisterSession("sess-a", "conn-a", "peer-a", "10.100.0.5", 11)
	gen := fwd.PeerRegistration("peer-a")
	pkt := clientPacket("10.100.0.5", 41000, "93.184.216.34", 443)
	if err := dem.RecordFlow("peer-a", "sess-a", gen, pkt, EgressChoiceProxy); err != nil {
		t.Fatalf("RecordFlow: %v", err)
	}

	// Age the record past its idle allowance, which is what makes the packet
	// path retire it on the next lookup.
	stale := time.Now().Add(-2 * time.Hour)
	dem.mu.Lock()
	var key FlowKey
	for k := range dem.flows {
		key = k
	}
	dem.flows[key].lastSeen = stale
	dem.mu.Unlock()

	before := time.Now()
	list := dem.SnapshotSessionFlows("sess-a", gen, before, 0)
	if len(list.Flows) != 1 {
		t.Fatalf("flows = %d, want the expired record reported", len(list.Flows))
	}
	if !list.Flows[0].Expired {
		t.Error("record past its idle allowance must be reported as expired")
	}
	if !list.Flows[0].LastSeen.Equal(stale) {
		t.Errorf("lastSeen = %v, want the stored instant %v (a read must not refresh it)", list.Flows[0].LastSeen, stale)
	}

	dem.mu.RLock()
	present := len(dem.flows)
	dem.mu.RUnlock()
	if present != 1 {
		t.Fatalf("flow table holds %d records after the listing, want 1 (a read must not retire)", present)
	}
	if list.Flows[0].LastSeen.After(stale) {
		t.Error("listing advanced lastSeen")
	}

	// Negative control: the packet-path reader does retire the record, which is
	// why the listing must not use it.
	if choice, ok := dem.LookupFlow("peer-a", pkt); ok || choice != EgressChoiceNone {
		t.Fatalf("LookupFlow on an expired record = %v/%v, want none", choice, ok)
	}
	dem.mu.RLock()
	present = len(dem.flows)
	dem.mu.RUnlock()
	if present != 0 {
		t.Errorf("flow table holds %d records after LookupFlow, want 0", present)
	}
}

func TestSnapshotSessionFlowsTruncatesAndKeepsTheTotal(t *testing.T) {
	fwd, dem, _ := newSessionEvidenceFixture(t, 64)
	fwd.RegisterSession("sess-a", "conn-a", "peer-a", "10.100.0.5", 11)
	gen := fwd.PeerRegistration("peer-a")
	for i := 0; i < 5; i++ {
		pkt := clientPacket("10.100.0.5", uint16(42000+i), "93.184.216.34", uint16(443+i))
		if err := dem.RecordFlow("peer-a", "sess-a", gen, pkt, EgressChoiceProxy); err != nil {
			t.Fatalf("RecordFlow %d: %v", i, err)
		}
	}

	list := dem.SnapshotSessionFlows("sess-a", gen, time.Now(), 2)
	if list.Total != 5 {
		t.Errorf("total = %d, want 5", list.Total)
	}
	if !list.Truncated {
		t.Error("a page smaller than the record set must report truncation")
	}
	if len(list.Flows) != 2 {
		t.Errorf("flows = %d, want the requested page size 2", len(list.Flows))
	}

	// The maximum page is the documented bound, not an error.
	full := dem.SnapshotSessionFlows("sess-a", gen, time.Now(), SessionFlowSnapshotMaxLimit*4)
	if full.Truncated || len(full.Flows) != 5 {
		t.Errorf("page above the maximum = %d flows truncated=%v, want all 5", len(full.Flows), full.Truncated)
	}
}

func TestSnapshotSessionFlowsExposesNoPeerIdentity(t *testing.T) {
	fwd, dem, _ := newSessionEvidenceFixture(t, 64)
	const peerKey = "peer-secret-fingerprint"
	fwd.RegisterSession("sess-a", "conn-a", peerKey, "10.100.0.5", 11)
	gen := fwd.PeerRegistration(peerKey)
	if err := dem.RecordFlow(peerKey, "sess-a", gen, clientPacket("10.100.0.5", 43000, "93.184.216.34", 443), EgressChoiceProxy); err != nil {
		t.Fatalf("RecordFlow: %v", err)
	}

	list := dem.SnapshotSessionFlows("sess-a", gen, time.Now(), 0)
	raw, err := json.Marshal(list)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), peerKey) {
		t.Errorf("the listing carries the peer key: %s", raw)
	}
	// The client address is also absent: a diagnosis is about the selected
	// session, and the response does not need to repeat it per flow.
	if strings.Contains(string(raw), "10.100.0.5") {
		t.Errorf("the listing carries the client address: %s", raw)
	}
}

// TestCompareSessionFlowRanksDeterministically pins the page ordering rule,
// including every tie-break. Without it a page would be an arbitrary map slice
// and two identical reads could return different records.
func TestCompareSessionFlowRanksDeterministically(t *testing.T) {
	base := time.Date(2026, 11, 17, 9, 0, 0, 0, time.UTC)
	newer := SessionFlow{LastSeen: base.Add(time.Second), DstPort: 443, Protocol: 6, SrcPort: 1, DstIP: netip.MustParseAddr("1.1.1.1")}
	older := SessionFlow{LastSeen: base, DstPort: 443, Protocol: 6, SrcPort: 1, DstIP: netip.MustParseAddr("1.1.1.1")}
	if compareSessionFlow(newer, older) >= 0 {
		t.Error("the newer record must rank first")
	}
	if compareSessionFlow(older, newer) <= 0 {
		t.Error("the older record must rank last")
	}

	// Same instant: address, then destination port, then protocol, then source
	// port decide, in that order.
	low := SessionFlow{LastSeen: base, DstIP: netip.MustParseAddr("1.1.1.1"), DstPort: 443, Protocol: 6, SrcPort: 1}
	for name, other := range map[string]SessionFlow{
		"address":  {LastSeen: base, DstIP: netip.MustParseAddr("1.1.1.2"), DstPort: 443, Protocol: 6, SrcPort: 1},
		"dstPort":  {LastSeen: base, DstIP: netip.MustParseAddr("1.1.1.1"), DstPort: 8443, Protocol: 6, SrcPort: 1},
		"protocol": {LastSeen: base, DstIP: netip.MustParseAddr("1.1.1.1"), DstPort: 443, Protocol: 17, SrcPort: 1},
		"srcPort":  {LastSeen: base, DstIP: netip.MustParseAddr("1.1.1.1"), DstPort: 443, Protocol: 6, SrcPort: 2},
	} {
		if compareSessionFlow(low, other) >= 0 {
			t.Errorf("%s tie-break: the lower value must rank first", name)
		}
		if compareSessionFlow(other, low) <= 0 {
			t.Errorf("%s tie-break: the higher value must rank last", name)
		}
	}
	if compareSessionFlow(low, low) != 0 {
		t.Error("identical records must compare equal")
	}
}

// TestSessionFlowPageKeepsTheNewestRecords proves the bounded page keeps the
// best-ranked records rather than the first ones the map happened to yield.
func TestSessionFlowPageKeepsTheNewestRecords(t *testing.T) {
	base := time.Date(2026, 11, 17, 9, 0, 0, 0, time.UTC)
	page := &sessionFlowPage{limit: 2}
	for i := 0; i < 5; i++ {
		page.add(SessionFlow{
			LastSeen: base.Add(time.Duration(i) * time.Second),
			DstIP:    netip.MustParseAddr("1.1.1.1"),
			DstPort:  uint16(443 + i),
			Protocol: 6,
		})
	}
	if page.matched != 5 {
		t.Fatalf("matched = %d, want 5", page.matched)
	}
	kept := page.sorted()
	if len(kept) != 2 {
		t.Fatalf("page holds %d records, want the limit 2", len(kept))
	}
	if kept[0].DstPort != 447 || kept[1].DstPort != 446 {
		t.Errorf("page = %d,%d, want the two newest (447,446)", kept[0].DstPort, kept[1].DstPort)
	}
}

func TestSessionFlowMatchesPinsTheGeneration(t *testing.T) {
	entry := &flowEntry{sessionID: "sess-a", generation: 3}
	cases := []struct {
		name       string
		entry      *flowEntry
		sessionID  string
		generation uint64
		want       bool
	}{
		{"OwnRecord", entry, "sess-a", 3, true},
		{"AnyGeneration", entry, "sess-a", 0, true},
		{"OtherSession", entry, "sess-b", 0, false},
		{"OtherGeneration", entry, "sess-a", 4, false},
		{"NilRecord", nil, "sess-a", 0, false},
	}
	for _, tc := range cases {
		if got := sessionFlowMatches(tc.entry, tc.sessionID, tc.generation); got != tc.want {
			t.Errorf("%s = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestSnapshotSessionFlowsWithoutAManagerIsEmpty(t *testing.T) {
	var dem *DirectEgressManager
	if list := dem.SnapshotSessionFlows("sess-a", 1, time.Now(), 0); list.Total != 0 || list.Flows == nil {
		t.Fatalf("nil manager listing = %+v, want an empty non-nil list", list)
	}
	var fwd *Forwarder
	if states := fwd.SessionRouteStates(); len(states) != 0 {
		t.Fatalf("nil forwarder states = %v, want none", states)
	}
}
