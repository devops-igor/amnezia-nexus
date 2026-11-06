package vless

import "testing"

// TestDialer_isModernPQ_ProfileSelection pins the profile classification that drives
// configureKeyShares: a misclassified modern_pq engine silently downgrades the ClientHello
// instead of failing, so every version-string alias must classify correctly.
//
// The pinned modern version moves when upstream retracts a release (26.10.29 -> 26.10.31), so
// the 26.10.* family is matched by prefix. This guards against reintroducing an exact-literal
// list that would drop the current pin.
func TestDialer_isModernPQ_ProfileSelection(t *testing.T) {
	tests := []struct {
		name          string
		engineProfile string
		want          bool
	}{
		{name: "canonical profile name", engineProfile: "modern_pq", want: true},
		{name: "modern alias", engineProfile: "modern", want: true},
		{name: "pq alias", engineProfile: "pq", want: true},
		{name: "modern pq with space", engineProfile: "modern pq", want: true},
		{name: "post_quantum alias", engineProfile: "post_quantum", want: true},
		{name: "post-quantum alias", engineProfile: "post-quantum", want: true},
		{name: "current pinned version", engineProfile: "26.10.31", want: true},
		{name: "current pinned version with v prefix", engineProfile: "v26.10.31", want: true},
		{name: "retracted version alias still in saved config", engineProfile: "26.10.29", want: true},
		{name: "retracted version alias with v prefix", engineProfile: "v26.10.29", want: true},
		{name: "future 26.10 pin", engineProfile: "26.10.45", want: true},
		{name: "uppercase and surrounding spaces", engineProfile: "  Modern_PQ  ", want: true},

		{name: "empty profile is not modern", engineProfile: "", want: false},
		{name: "legacy name is not modern", engineProfile: "legacy", want: false},
		{name: "legacy version is not modern", engineProfile: "1.8.24", want: false},
		{name: "legacy version with v prefix is not modern", engineProfile: "v1.8.24", want: false},
		{name: "unknown profile is not modern", engineProfile: "custom_unknown", want: false},
		{name: "other calver month is not modern", engineProfile: "26.9.30", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// New() stores the normalized profile; isModernPQ() also normalizes defensively.
			d := &Dialer{engineProfile: tc.engineProfile}
			if got := d.isModernPQ(); got != tc.want {
				t.Errorf("isModernPQ() = %v for profile %q, want %v", got, tc.engineProfile, tc.want)
			}
		})
	}
}
