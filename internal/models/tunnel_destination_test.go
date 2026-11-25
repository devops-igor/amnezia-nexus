package models

// The destination decision, exercised at its own boundary.
//
// Callers in other packages also cover this (the ingress, migration and rebalance tests each
// drive it through a real route assertion), but the decision is a fact about the model, so it
// is pinned here too: the same set of facts must produce the same answer no matter which
// consumer asks, and a caller that has no absence information must get the pre-existing
// answer rather than a refusal.

import "testing"

func TestTunnelDestinationAllowedTable(t *testing.T) {
	absent := NewAbsentServerSet([]int64{2})

	cases := []struct {
		name    string
		tunnel  *BackendTunnel
		absent  AbsentServerSet
		want    bool
		because string
	}{
		{
			name:   "enabled and active, provider confirms it exists",
			tunnel: &BackendTunnel{ServerID: 1, Enabled: true, Status: TunnelStatusActive},
			absent: absent,
			want:   true,
		},
		{
			name:    "enabled and active, provider confirms it deleted",
			tunnel:  &BackendTunnel{ServerID: 2, Enabled: true, Status: TunnelStatusActive},
			absent:  absent,
			want:    false,
			because: "a last health sample is not an existence answer",
		},
		{
			name:    "administratively disabled",
			tunnel:  &BackendTunnel{ServerID: 1, Enabled: false, Status: TunnelStatusActive},
			absent:  absent,
			want:    false,
			because: "operator intent outranks any health or inventory observation",
		},
		{
			name:    "runtime status degraded",
			tunnel:  &BackendTunnel{ServerID: 1, Enabled: true, Status: TunnelStatusDegraded},
			absent:  absent,
			want:    false,
			because: "the status itself is not adoptable",
		},
		{
			name:    "runtime status disabled",
			tunnel:  &BackendTunnel{ServerID: 1, Enabled: true, Status: TunnelStatusDisabled},
			absent:  absent,
			want:    false,
			because: "the status itself is not adoptable",
		},
		{
			name:   "handshake-blocked carries its own canary admission elsewhere",
			tunnel: &BackendTunnel{ServerID: 1, Enabled: true, Status: TunnelStatusHandshakeBlocked},
			absent: absent,
			want:   true,
		},
		{
			name:    "absent backend that is also disabled",
			tunnel:  &BackendTunnel{ServerID: 2, Enabled: false, Status: TunnelStatusActive},
			absent:  absent,
			want:    false,
			because: "either fact refuses on its own",
		},
		{
			name:    "nil tunnel",
			tunnel:  nil,
			absent:  absent,
			want:    false,
			because: "a nil destination is not a destination",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := TunnelDestinationAllowed(tc.tunnel, tc.absent); got != tc.want {
				t.Fatalf("allowed = %v, want %v (%s)", got, tc.want, tc.because)
			}
		})
	}
}

// An unknown absence fact must not become a refusal: every consumer reads the marks
// best-effort, and a momentarily unreadable store must leave selection as it was.
func TestTunnelDestinationAllowedWithoutAbsenceInformation(t *testing.T) {
	tunnel := &BackendTunnel{ServerID: 2, Enabled: true, Status: TunnelStatusActive}
	if !TunnelDestinationAllowed(tunnel, nil) {
		t.Fatal("a nil absence set refused a healthy backend")
	}
	if !TunnelDestinationAllowed(tunnel, AbsentServerSet{}) {
		t.Fatal("an empty absence set refused a healthy backend")
	}
	// And a set that names other servers says nothing about this one.
	if !TunnelDestinationAllowed(tunnel, NewAbsentServerSet([]int64{7, 8})) {
		t.Fatal("an unrelated mark refused a healthy backend")
	}
}

func TestAbsentServerSetContains(t *testing.T) {
	set := NewAbsentServerSet([]int64{3, 5})
	if !set.Contains(3) || !set.Contains(5) {
		t.Fatal("a marked server was not found in the set")
	}
	if set.Contains(4) {
		t.Fatal("an unmarked server was reported absent")
	}
	if NewAbsentServerSet(nil).Contains(3) {
		t.Fatal("an empty set reported a server absent")
	}
}

func TestEligibleTunnelDestinations(t *testing.T) {
	absent := NewAbsentServerSet([]int64{20})
	list := []*BackendTunnel{
		{ID: 1, ServerID: 10, Enabled: true, Status: TunnelStatusActive},
		{ID: 2, ServerID: 20, Enabled: true, Status: TunnelStatusActive},
		{ID: 3, ServerID: 30, Enabled: false, Status: TunnelStatusActive},
		{ID: 4, ServerID: 40, Enabled: true, Status: TunnelStatusActive},
	}

	kept := EligibleTunnelDestinations(list, absent)
	if len(kept) != 2 || kept[0].ID != 1 || kept[1].ID != 4 {
		t.Fatalf("eligible = %d entries (%v), want tunnel ids 1 and 4 in order", len(kept), tunnelDestinationIDs(kept))
	}

	// Nothing absent and nothing disabled: the very same list comes back, so a caller cannot
	// mistake an empty result for "no candidates".
	if got := EligibleTunnelDestinations(list[:1], nil); len(got) != 1 || got[0].ID != 1 {
		t.Fatalf("an empty absence set changed an eligible list: %v", tunnelDestinationIDs(got))
	}
	if got := EligibleTunnelDestinations(nil, absent); got != nil {
		t.Fatalf("nil input produced %v", got)
	}

	// The value form used by the durable rebalance query applies the identical rule.
	values := []BackendTunnel{
		{ID: 1, ServerID: 10, Enabled: true, Status: TunnelStatusActive},
		{ID: 2, ServerID: 20, Enabled: true, Status: TunnelStatusActive},
	}
	keptValues := EligibleTunnelDestinationValues(values, absent)
	if len(keptValues) != 1 || keptValues[0].ServerID != 10 {
		t.Fatalf("value form kept %v, want only server 10", keptValues)
	}
}

func TestTunnelStatusAdmitsNewWork(t *testing.T) {
	cases := map[string]bool{
		TunnelStatusActive:           true,
		" ACTIVE ":                   true,
		TunnelStatusHandshakeBlocked: true,
		TunnelStatusDegraded:         false,
		TunnelStatusDisabled:         false,
		"":                           false,
		"unknown":                    false,
	}
	for status, want := range cases {
		if got := TunnelStatusAdmitsNewWork(status); got != want {
			t.Fatalf("status %q admits new work = %v, want %v", status, got, want)
		}
	}
	if got := NormalizeStatus(" Active "); got != TunnelStatusActive {
		t.Fatalf("NormalizeStatus = %q", got)
	}
}

func tunnelDestinationIDs(tunnels []*BackendTunnel) []int64 {
	ids := make([]int64, 0, len(tunnels))
	for _, tunnel := range tunnels {
		ids = append(ids, tunnel.ID)
	}
	return ids
}
