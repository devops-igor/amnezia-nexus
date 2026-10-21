package orchestrator

import (
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestNextMimicryProfile_RotationOrder(t *testing.T) {
	tests := []struct {
		name    string
		current models.AWGMimicryProfile
		want    models.AWGMimicryProfile
	}{
		{name: "auto_rotates_to_sip", current: models.AWGMimicryAuto, want: models.AWGMimicrySIP},
		{name: "empty_rotates_to_sip", current: "", want: models.AWGMimicrySIP},
		{name: "sip_rotates_to_dns", current: models.AWGMimicrySIP, want: models.AWGMimicryDNS},
		{name: "dns_rotates_to_quic", current: models.AWGMimicryDNS, want: models.AWGMimicryQUIC},
		{name: "quic_rotates_to_tls", current: models.AWGMimicryQUIC, want: models.AWGMimicryTLS},
		{name: "tls_rotates_to_sip", current: models.AWGMimicryTLS, want: models.AWGMimicrySIP},
		{name: "unknown_rotates_to_sip", current: "unknown", want: models.AWGMimicrySIP},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NextMimicryProfile(tt.current)
			if got != tt.want {
				t.Errorf("NextMimicryProfile(%q) = %q, want %q", tt.current, got, tt.want)
			}
		})
	}
}

func TestNextMimicryProfile_FullCycle(t *testing.T) {
	// Verify continuous cycle starting from Auto returns to SIP and cycles indefinitely:
	// auto -> sip -> dns -> quic -> tls -> sip -> dns ...
	cycle := []models.AWGMimicryProfile{
		models.AWGMimicryAuto,
		models.AWGMimicrySIP,
		models.AWGMimicryDNS,
		models.AWGMimicryQUIC,
		models.AWGMimicryTLS,
		models.AWGMimicrySIP,
		models.AWGMimicryDNS,
	}

	curr := cycle[0]
	for i := 1; i < len(cycle); i++ {
		next := NextMimicryProfile(curr)
		if next != cycle[i] {
			t.Fatalf("step %d from %q: expected %q, got %q", i, curr, cycle[i], next)
		}
		curr = next
	}
}
