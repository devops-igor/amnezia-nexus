package awg

import (
	"strings"
	"testing"
)

// TestValidateAWGParams_JunkSizeOrdering pins the upstream ordering rule added
// in amneziawg-go v3.1.20261116: the UAPI commit refuses jmin > jmax, so Nexus
// must refuse the same pair at its own validation boundary instead of writing a
// configuration the backend engine will reject at bring-up.
func TestValidateAWGParams_JunkSizeOrdering(t *testing.T) {
	valid := []struct {
		name   string
		params map[string]string
	}{
		{
			name:   "min_below_max",
			params: map[string]string{"junk_packet_min_size": "10", "junk_packet_max_size": "30"},
		},
		{
			name:   "min_equals_max",
			params: map[string]string{"junk_packet_min_size": "30", "junk_packet_max_size": "30"},
		},
		{
			name:   "aliases_min_below_max",
			params: map[string]string{"jmin": "5", "jmax": "9"},
		},
		{
			name:   "mixed_spelling_min_below_max",
			params: map[string]string{"junk_packet_min_size": "5", "jmax": "9"},
		},
		{
			name:   "only_max_present",
			params: map[string]string{"jmax": "30"},
		},
		{
			name:   "neither_present",
			params: map[string]string{"mtu": "1280"},
		},
	}

	for _, tc := range valid {
		t.Run("valid_"+tc.name, func(t *testing.T) {
			if err := ValidateAWGParams(tc.params); err != nil {
				t.Errorf("expected params %+v to pass validation, got: %v", tc.params, err)
			}
		})
	}

	inverted := []struct {
		name   string
		params map[string]string
	}{
		{
			name:   "canonical_inverted",
			params: map[string]string{"junk_packet_min_size": "100", "junk_packet_max_size": "30"},
		},
		{
			name:   "aliases_inverted",
			params: map[string]string{"jmin": "100", "jmax": "30"},
		},
		{
			name:   "case_variants_inverted",
			params: map[string]string{"JMIN": "100", "JMAX": "30"},
		},
		{
			name:   "mixed_spelling_inverted",
			params: map[string]string{"junk_packet_min_size": "100", "jmax": "30"},
		},
		{
			name:   "only_min_present",
			params: map[string]string{"junk_packet_min_size": "100"},
		},
		{
			name:   "only_min_alias_present",
			params: map[string]string{"jmin": "1"},
		},
	}

	for _, tc := range inverted {
		t.Run("inverted_"+tc.name, func(t *testing.T) {
			err := ValidateAWGParams(tc.params)
			if err == nil {
				t.Fatalf("expected ordering error for params %+v, got nil", tc.params)
			}
			msg := err.Error()
			if !strings.Contains(msg, "junk_packet_min_size") || !strings.Contains(msg, "junk_packet_max_size") {
				t.Errorf("expected error to name both junk-size params, got: %v", err)
			}
		})
	}

	t.Run("inverted_canonical_reports_values", func(t *testing.T) {
		err := ValidateAWGParams(map[string]string{
			"junk_packet_min_size": "100",
			"junk_packet_max_size": "30",
		})
		if err == nil {
			t.Fatal("expected ordering error, got nil")
		}
		if !strings.Contains(err.Error(), "100") || !strings.Contains(err.Error(), "30") {
			t.Errorf("expected error to report the configured values 100 and 30, got: %v", err)
		}
	})
}
