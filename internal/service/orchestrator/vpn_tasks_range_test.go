package orchestrator

import (
	"context"
	"testing"

	"github.com/devops-igor/amnezia-web-ui-go/internal/models"
)

// Issue #49: resolveTunnelProbeParams must preserve AWG 3.1 H1/H2 RANGES for
// the orchestrator probe; the previous ExtractAWGExplicitParams path
// truncated them to hr.Lo, so range-configured backends (e.g. Server 6 with
// H2 = "718486018-718530126") failed handshake response verification.
func TestResolveTunnelProbeParams_PreservesHeaderRanges(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	srvID, err := db.CreateServer(ctx, &models.Server{
		Name: "Server 6 AWG 3.1",
		Host: "10.0.0.60",
		Protocols: map[string]any{
			"awg": map[string]any{
				"awg_params": map[string]any{
					"init_packet_magic_header":     "196955274-196979834",
					"response_packet_magic_header": "718486018-718530126",
					"init_packet_junk_size":        12,
					"response_packet_junk_size":    12,
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	tunID, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:  srvID,
		PublicKey: "pub-awg31",
		Endpoint:  "127.0.0.1:55440",
		Status:    "active",
	})
	if err != nil {
		t.Fatalf("CreateBackendTunnel failed: %v", err)
	}

	orch := New(db, nil)
	got := orch.resolveTunnelProbeParams(ctx, []models.BackendTunnel{{ID: tunID, ServerID: srvID}})

	res, ok := got[tunID]
	if !ok {
		t.Fatal("expected tunnel params to be resolved for range-configured server")
	}

	wantH1 := models.HeaderRange{Lo: 196955274, Hi: 196979834}
	wantH2 := models.HeaderRange{Lo: 718486018, Hi: 718530126}
	if res.h1 != wantH1 {
		t.Errorf("resolved h1 = %v (%T), want full range %s (Lo-truncated?)", res.h1, res.h1, wantH1)
	}
	if res.h2 != wantH2 {
		t.Errorf("resolved h2 = %v (%T), want full range %s (Lo-truncated?)", res.h2, res.h2, wantH2)
	}
	if res.s1 != 12 || res.s2 != 12 {
		t.Errorf("resolved s1/s2 = (%d, %d), want (12, 12)", res.s1, res.s2)
	}
}
