package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/geodb"
)

// The CDN exclusion set on the policy settings surface (issue #934).
//
// The allocation half of the classifier's decision was already reported. This
// asserts the other half through the API the settings page reads: the entries an
// operator sees are the table the classifier matches against, in a form that
// names where they come from.
//
// The comparison is structural rather than textual: every reported entry is
// looked up in geodb itself and re-checked with the classifier's own predicate,
// so a second list maintained beside the table fails here as well.

type policyCDNAnswerForTest struct {
	Status struct {
		CDN *struct {
			Source  string               `json:"source"`
			Entries []geodb.CDNExclusion `json:"entries"`
			Error   string               `json:"error"`
		} `json:"cdn"`
	} `json:"status"`
}

func getPolicyCDNStatus(t *testing.T, h *Handlers) policyCDNAnswerForTest {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/vpn/policy", nil)
	rec := httptest.NewRecorder()
	h.GetPolicyHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/vpn/policy answered %d: %s", rec.Code, rec.Body.String())
	}
	var answer policyCDNAnswerForTest
	if err := json.Unmarshal(rec.Body.Bytes(), &answer); err != nil {
		t.Fatalf("decode GET answer: %v", err)
	}
	if answer.Status.CDN == nil {
		t.Fatal("the policy status carries no CDN exclusion block, so the classifier's second input is still invisible")
	}
	return answer
}

func TestPolicyStatusReportsTheCDNExclusionSet(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	answer := getPolicyCDNStatus(t, h)
	cdn := answer.Status.CDN

	// Policy routing is disabled in this fixture, which is exactly when an
	// operator reads the status: the set that will decide direct traffic is a
	// fact about the build, not about the running sync.
	if cdn.Error != "" {
		t.Fatalf("the compiled-in CDN exclusion set is reported as unusable: %s", cdn.Error)
	}
	if cdn.Source != geodb.CDNExclusionSource {
		t.Fatalf("CDN exclusion source = %q, want %q", cdn.Source, geodb.CDNExclusionSource)
	}
	if len(cdn.Entries) != len(geodb.KnownCDNASNs) {
		t.Fatalf("%d CDN exclusion entries reported, the classifier table holds %d", len(cdn.Entries), len(geodb.KnownCDNASNs))
	}
	for i, entry := range cdn.Entries {
		provider, known := geodb.KnownCDNASNs[entry.ASN]
		if !known {
			t.Errorf("entry %d reports AS%d, which is not in the classifier's table", i, entry.ASN)
			continue
		}
		if provider != entry.Provider {
			t.Errorf("entry %d reports AS%d as %q, the classifier knows it as %q", i, entry.ASN, entry.Provider, provider)
		}
		if !geodb.IsMultiRegionCDNASN(entry.ASN) {
			t.Errorf("entry %d reports AS%d as excluded, but the classifier does not exclude it", i, entry.ASN)
		}
	}
}

// TestPolicyStatusCDNSetIsReadFromGeodb proves the block is a projection of the
// live table rather than a literal in the status builder: an ASN the table gains
// must appear without touching the projection.
func TestPolicyStatusCDNSetIsReadFromGeodb(t *testing.T) {
	const probeASN = 64513
	const probeProvider = "Test Provider"
	geodb.KnownCDNASNs[probeASN] = probeProvider
	defer delete(geodb.KnownCDNASNs, probeASN)

	h, _, _ := setupTestHandlers(t)
	answer := getPolicyCDNStatus(t, h)
	for _, entry := range answer.Status.CDN.Entries {
		if entry.ASN == probeASN && entry.Provider == probeProvider {
			return
		}
	}
	t.Fatalf("AS%d added to geodb.KnownCDNASNs is missing from the status; the surface is not reading the classifier's table", probeASN)
}
