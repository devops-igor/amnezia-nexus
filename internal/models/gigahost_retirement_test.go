package models

// The retirement decision, exercised at its own boundary.
//
// Every consumer of an order's life asks this one predicate: the grid card, the history
// stage, the saved setup approvals and both background workers. Callers in other packages
// cover it through their own surfaces, but the vocabulary itself is a fact about the model,
// so it is pinned here too - a spelling nobody listed, or a provenance combination nobody
// expected, must answer the same way no matter which consumer is asking.
//
// The cases that matter are the ones that look identical in the ledger's status column: a
// provider that ended provisioning and an install this panel ran and failed both record
// `failed`. Only the onboarding journal separates them, and getting that wrong in either
// direction is a real defect - one hides a recoverable job, the other offers work that
// cannot succeed.

import "testing"

func TestGigahostOrderEndedStatusVocabulary(t *testing.T) {
	cases := []struct {
		status string
		want   bool
	}{
		// The provider spells a cancellation both ways in different fields, and its
		// deletion vocabulary has two words for one fact.
		{"cancelled", true},
		{"canceled", true},
		{"deleted", true},
		{"terminated", true},
		// Case and surrounding whitespace come from the ledger, not from a claim.
		{"  CANCELLED  ", true},
		{"Terminated", true},
		// `failed` is deliberately NOT an ending here: it is only final when nothing local
		// records an install attempt, which is a separate question (see the table below).
		{"failed", false},
		{"error", false},
		// Ordinary live and in-flight states.
		{"ready", false},
		{"active", false},
		{"deploying", false},
		{"pending", false},
		{"installing_protocol", false},
		{"", false},
		// An unrecognised spelling is not an ending: the panel reports what it does not
		// know as unknown rather than inventing a deletion.
		{"something_new", false},
	}
	for _, tc := range cases {
		t.Run(tc.status, func(t *testing.T) {
			if got := IsGigahostOrderEndedStatus(tc.status); got != tc.want {
				t.Errorf("IsGigahostOrderEndedStatus(%q) = %v, want %v", tc.status, got, tc.want)
			}
		})
	}
}

func TestGigahostOrderFailedStatusVocabulary(t *testing.T) {
	cases := map[string]bool{
		"failed":          true,
		"error":           true,
		" FAILED ":        true,
		"failed_provider": false,
		"ready":           false,
		"cancelled":       false,
		"":                false,
	}
	for status, want := range cases {
		if got := IsGigahostOrderFailedStatus(status); got != want {
			t.Errorf("IsGigahostOrderFailedStatus(%q) = %v, want %v", status, got, want)
		}
	}
}

// TestGigahostOrderRetired is the whole decision, over the combinations that occur.
//
// The two failure rows are the point of the table: same status, same absence record, and
// opposite answers, because the panel's own journal says whether an install was attempted.
func TestGigahostOrderRetired(t *testing.T) {
	const step = "installing_protocol"
	const absentAt = "2026-11-28T10:00:00Z"
	const panelServerID = int64(7301)

	cases := []struct {
		name  string
		order GigahostOrder
		want  bool
	}{
		{
			name:  "a live order is not retired",
			order: GigahostOrder{Status: "ready"},
			want:  false,
		},
		{
			name:  "a recorded absence retires it whatever the status says",
			order: GigahostOrder{Status: "ready", ProviderAbsentAt: absentAt},
			want:  true,
		},
		{
			name:  "a recorded ending retires it",
			order: GigahostOrder{Status: "cancelled"},
			want:  true,
		},
		{
			// The defect this round exists to correct: no journal, so nothing can be
			// retried onto a deployment the provider never provisioned.
			name:  "a provider-final failure retires it",
			order: GigahostOrder{Status: "failed"},
			want:  true,
		},
		{
			// The paired direction: this panel ran the install and it failed, so the
			// operator has real work they can retry.
			name:  "a journal-backed failure does not",
			order: GigahostOrder{Status: "failed", Step: step},
			want:  false,
		},
		{
			// The second form of journal evidence: the registration the journal mirrors
			// onto the ledger when an install completes.
			name:  "a mirrored panel server is journal evidence too",
			order: GigahostOrder{Status: "failed", NexusServerID: panelServerID},
			want:  false,
		},
		{
			// Absence and a journal can both be true; the ending still wins, because the
			// deployment is gone regardless of what the panel attempted against it.
			name:  "an absence outranks a journal-backed failure",
			order: GigahostOrder{Status: "failed", Step: step, ProviderAbsentAt: absentAt},
			want:  true,
		},
		{
			// A step alone does not make a live order retired.
			name:  "a completed install with a step is still live",
			order: GigahostOrder{Status: "ready", Step: "ready"},
			want:  false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.order.Retired(); got != tc.want {
				t.Errorf("Retired() = %v, want %v for %+v", got, tc.want, tc.order)
			}
			// The two halves the decision is built from must agree with it, so a consumer
			// that asks a narrower question cannot contradict the wide one.
			if tc.order.FailureIsProviderFinal() && !tc.order.Retired() {
				t.Errorf("FailureIsProviderFinal() = true but Retired() = false for %+v", tc.order)
			}
		})
	}
}

// TestGigahostOrderProviderAbsenceRequiresATimestamp pins the zero-value reading: an empty
// record is "not observed", never "observed as absent".
func TestGigahostOrderProviderAbsenceRequiresATimestamp(t *testing.T) {
	for _, value := range []string{"", "   "} {
		order := GigahostOrder{Status: "ready", ProviderAbsentAt: value}
		if order.ProviderAbsent() {
			t.Errorf("ProviderAbsent() = true for %q; an empty record is no observation", value)
		}
		if order.Retired() {
			t.Errorf("Retired() = true for %q; no observation must not retire an order", value)
		}
	}
}
