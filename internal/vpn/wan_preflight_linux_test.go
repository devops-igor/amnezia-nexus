//go:build linux

package vpn

import (
	"os"
	"strings"
	"testing"
)

// TestRunStandaloneWANChecks_ReportsBothCapabilities pins the operator-facing
// capability report: every probe is listed with a status, and failures carry the
// actionable error text rather than an empty line.
func TestRunStandaloneWANChecks_ReportsBothCapabilities(t *testing.T) {
	var sb strings.Builder
	results := RunStandaloneWANChecks(&sb)

	if len(results) != 2 {
		t.Fatalf("expected 2 capability probes, got %d", len(results))
	}
	for _, want := range []string{"TUN device access", "AF_PACKET WAN capture socket"} {
		if !strings.Contains(sb.String(), want) {
			t.Fatalf("report missing probe %q:\n%s", want, sb.String())
		}
	}
	for _, r := range results {
		if r.Err != nil && !strings.Contains(sb.String(), r.Err.Error()) {
			t.Fatalf("report omitted error detail for %q:\n%s", r.Name, sb.String())
		}
	}
}

// TestEffectiveCapabilityNames_MatchesCapEff proves the diagnostic capability list is
// derived from the process's real effective set rather than a static guess.
func TestEffectiveCapabilityNames_MatchesCapEff(t *testing.T) {
	mask, err := effectiveCapabilities()
	if err != nil {
		t.Fatalf("read effective capabilities: %v", err)
	}
	names := EffectiveCapabilityNames()

	joined := strings.Join(names, " ")
	wantNetRaw := mask&(1<<capNetRawBit) != 0
	if gotNetRaw := strings.Contains(joined, "CAP_NET_RAW"); gotNetRaw != wantNetRaw {
		t.Fatalf("CAP_NET_RAW reported=%v but CapEff says %v (names: %v)", gotNetRaw, wantNetRaw, names)
	}
	const capNetAdminBit = 12
	wantNetAdmin := mask&(1<<capNetAdminBit) != 0
	if gotNetAdmin := strings.Contains(joined, "CAP_NET_ADMIN"); gotNetAdmin != wantNetAdmin {
		t.Fatalf("CAP_NET_ADMIN reported=%v but CapEff says %v (names: %v)", gotNetAdmin, wantNetAdmin, names)
	}
	if mask == 0 && len(names) != 0 {
		t.Fatalf("expected no capability names for empty CapEff, got %v", names)
	}
}

// TestStandaloneResult_Label pins the status vocabulary operators and CI match on.
func TestStandaloneResult_Label(t *testing.T) {
	if got := (StandaloneResult{}).Label(); got != "OK" {
		t.Fatalf("expected OK, got %q", got)
	}
	if got := (StandaloneResult{Err: os.ErrPermission}).Label(); got != "FAIL" {
		t.Fatalf("expected FAIL, got %q", got)
	}
	if (StandaloneResult{}).OK() != true || (StandaloneResult{Err: os.ErrPermission}).OK() != false {
		t.Fatal("OK() does not agree with Label()")
	}
}
