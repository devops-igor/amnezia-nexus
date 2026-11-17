package vpn

import (
	"context"
	"net/netip"
	"testing"
)

// Producer→API controls for pre-flow DROP evidence (issue #861, R20).
//
// A prohibited destination is refused inside routeClientPBR before any flow record exists.
// The global counters can only say that something was dropped; these controls prove the
// per-client ledger attributes the refusal to the client that sent it, through the real
// diagnosis service.

func TestClientDiagnosisReportsPreFlowDrop(t *testing.T) {
	f := newClientDiagFixture(t)
	sessionID := f.sessionID(t)

	// Metadata address: prohibited by ValidateDirectDestination, so no flow is created.
	prohibited := netip.MustParseAddr("169.254.169.254")
	packet := buildTestPBRTCPPacket(f.clientIP, prohibited, 41400, 80, []byte("blocked"))
	if err := f.fwd.RouteClientToBackend(f.peerKey, packet); err == nil {
		t.Fatal("a prohibited destination was accepted; the control needs the real refusal")
	}

	// The refusal produced no flow, which is exactly why it needs its own record.
	answer, err := f.svc.ClientDiagnosis(context.Background(), ClientDiagnosisRequest{SessionID: sessionID})
	if err != nil {
		t.Fatalf("ClientDiagnosis: %v", err)
	}
	if len(answer.Flows.Entries) != 0 {
		t.Fatalf("a pre-flow refusal created %d flow records", len(answer.Flows.Entries))
	}

	if !answer.Drops.Available || answer.Drops.State != "observed" {
		t.Fatalf("drops section = available %v state %q, want an observed section",
			answer.Drops.Available, answer.Drops.State)
	}
	if answer.Drops.Total != 1 || len(answer.Drops.Entries) != 1 {
		t.Fatalf("drops = total %d entries %d, want the one refusal", answer.Drops.Total, len(answer.Drops.Entries))
	}
	row := answer.Drops.Entries[0]
	if row.Reason != "prohibited_destination" {
		t.Errorf("reason = %q, want prohibited_destination", row.Reason)
	}
	if !row.HasTuple {
		t.Error("a well-formed refused packet lost its tuple metadata")
	}
	if row.DestinationIP != prohibited.String() || row.DestinationPort != 80 {
		t.Errorf("destination = %s:%d, want %s:80", row.DestinationIP, row.DestinationPort, prohibited)
	}
	if row.Protocol != "tcp" {
		t.Errorf("protocol = %q, want tcp", row.Protocol)
	}
	if row.Count != 1 || row.Bytes == 0 {
		t.Errorf("count/bytes = %d/%d, want 1 and a non-zero packet size", row.Count, row.Bytes)
	}
	if row.FirstSeen == "" || row.LastSeen == "" {
		t.Error("the refusal has no first/last instant")
	}
	if answer.Drops.Coverage.KeyLimit == 0 || answer.Drops.Coverage.AgeLimitSeconds == 0 {
		t.Errorf("coverage does not state its bounds: %+v", answer.Drops.Coverage)
	}
}

// TestClientDiagnosisDropCountsAggregateAndStayPerClient proves repeated refusals collapse
// into one row and that a different client cannot see them.
func TestClientDiagnosisDropCountsAggregateAndStayPerClient(t *testing.T) {
	f := newClientDiagFixture(t)
	sessionID := f.sessionID(t)
	prohibited := netip.MustParseAddr("127.0.0.1")

	for range 3 {
		packet := buildTestPBRTCPPacket(f.clientIP, prohibited, 41401, 8080, []byte("blocked"))
		if err := f.fwd.RouteClientToBackend(f.peerKey, packet); err == nil {
			t.Fatal("a prohibited destination was accepted")
		}
	}

	answer, err := f.svc.ClientDiagnosis(context.Background(), ClientDiagnosisRequest{SessionID: sessionID})
	if err != nil {
		t.Fatalf("ClientDiagnosis: %v", err)
	}
	if answer.Drops.Total != 1 || answer.Drops.Entries[0].Count != 3 {
		t.Fatalf("drops = total %d count %d, want one row of 3", answer.Drops.Total, answer.Drops.Entries[0].Count)
	}

	// Another session reads as empty rather than seeing this client's refusals.
	other := f.fwd.ClientDropSnapshot("some-other-session", 1, 0)
	if other.Total != 0 {
		t.Errorf("a different session read %d of this client's refusals", other.Total)
	}

	// Retirement removes them: a read after the session ends cannot resurrect evidence.
	f.fwd.UnregisterSession(f.peerKey)
	if after := f.fwd.ClientDropSnapshot(sessionID, 1, 0); after.Total != 0 {
		t.Errorf("retired session still reports %d refusals", after.Total)
	}
}

// TestClientDiagnosisMalformedPacketDropHasNoInventedDestination proves a packet too
// malformed to parse is recorded without metadata it never carried.
func TestClientDiagnosisMalformedPacketDropHasNoInventedDestination(t *testing.T) {
	f := newClientDiagFixture(t)
	sessionID := f.sessionID(t)

	if err := f.fwd.RouteClientToBackend(f.peerKey, []byte{0x45, 0x00, 0x00}); err == nil {
		t.Fatal("a truncated packet was accepted")
	}

	answer, err := f.svc.ClientDiagnosis(context.Background(), ClientDiagnosisRequest{SessionID: sessionID})
	if err != nil {
		t.Fatalf("ClientDiagnosis: %v", err)
	}
	if answer.Drops.Total != 1 {
		t.Fatalf("drops = %d, want the malformed refusal", answer.Drops.Total)
	}
	row := answer.Drops.Entries[0]
	if row.Reason != "invalid_client_packet" {
		t.Errorf("reason = %q, want invalid_client_packet", row.Reason)
	}
	if row.HasTuple {
		t.Error("a malformed packet was reported with a tuple")
	}
	if row.DestinationIP != "" || row.DestinationPort != 0 || row.Protocol != "" {
		t.Errorf("malformed row invented metadata: %+v", row)
	}
}

// TestClientDiagnosisDropSnapshotIsPure proves reading the answer does not change it.
func TestClientDiagnosisDropSnapshotIsPure(t *testing.T) {
	f := newClientDiagFixture(t)
	sessionID := f.sessionID(t)
	if err := f.fwd.RouteClientToBackend(f.peerKey,
		buildTestPBRTCPPacket(f.clientIP, netip.MustParseAddr("169.254.169.254"), 41402, 80, nil)); err == nil {
		t.Fatal("a prohibited destination was accepted")
	}

	first, err := f.svc.ClientDiagnosis(context.Background(), ClientDiagnosisRequest{SessionID: sessionID})
	if err != nil {
		t.Fatalf("ClientDiagnosis: %v", err)
	}
	for range 3 {
		if _, err := f.svc.ClientDiagnosis(context.Background(), ClientDiagnosisRequest{SessionID: sessionID}); err != nil {
			t.Fatalf("ClientDiagnosis: %v", err)
		}
	}
	last, err := f.svc.ClientDiagnosis(context.Background(), ClientDiagnosisRequest{SessionID: sessionID})
	if err != nil {
		t.Fatalf("ClientDiagnosis: %v", err)
	}
	if first.Drops.Total != last.Drops.Total || first.Drops.Entries[0].Count != last.Drops.Entries[0].Count {
		t.Errorf("reads changed the ledger: %d/%d then %d/%d",
			first.Drops.Total, first.Drops.Entries[0].Count, last.Drops.Total, last.Drops.Entries[0].Count)
	}
	if first.Drops.Entries[0].LastSeen != last.Drops.Entries[0].LastSeen {
		t.Error("a read refreshed the refusal's recency")
	}
}
