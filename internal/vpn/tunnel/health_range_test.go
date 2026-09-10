package tunnel

import (
	"context"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-web-ui-go/internal/models"
)

// Issue #49: a backend provisioned with AWG 3.1 carries H1/H2 header RANGES
// (e.g. "196955274-196979834"). resolveTunnelParams must return the FULL
// ranges — the previous uint32 plumbing truncated them to hr.Lo, producing a
// degenerate [Lo, Lo] range that rejected ~99.998% of real backend responses.
func TestResolveTunnelParams_PreservesHeaderRanges(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	pool := NewPool(db)

	sID, err := db.CreateServer(ctx, &models.Server{
		Name: "AWG 3.1 range backend",
		Host: "192.0.2.10",
		Protocols: map[string]any{
			"awg": map[string]any{
				"installed": true,
				"awg_params": map[string]any{
					"init_packet_magic_header":     "196955274-196979834",
					"response_packet_magic_header": "718486018-718530126",
					"init_packet_junk_size":        40,
					"response_packet_junk_size":    50,
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	prober := NewHealthProber(pool, db, DefaultHealthConfig())

	h1, h2, s1, s2, hpKey := prober.resolveTunnelParams(ctx, sID)

	h1Range, ok := h1.(models.HeaderRange)
	if !ok {
		t.Fatalf("resolveTunnelParams h1 is %T (%v), want models.HeaderRange", h1, h1)
	}
	h2Range, ok := h2.(models.HeaderRange)
	if !ok {
		t.Fatalf("resolveTunnelParams h2 is %T (%v), want models.HeaderRange", h2, h2)
	}

	wantH1 := models.HeaderRange{Lo: 196955274, Hi: 196979834}
	wantH2 := models.HeaderRange{Lo: 718486018, Hi: 718530126}
	if h1Range != wantH1 {
		t.Errorf("H1 range mismatch: got %s, want %s (Lo-truncated?)", h1Range, wantH1)
	}
	if h2Range != wantH2 {
		t.Errorf("H2 range mismatch: got %s, want %s (Lo-truncated?)", h2Range, wantH2)
	}
	if s1 != 40 || s2 != 50 {
		t.Errorf("S1/S2 mismatch: got (%d, %d), want (40, 50)", s1, s2)
	}
	if hpKey != "" {
		t.Errorf("hpKey mismatch: got %q, want empty", hpKey)
	}
}

// Issue #49: ProbeTunnel must forward the resolved ranges to the probe
// function verbatim, so range verification happens against the full span,
// and resolution must fall through to range-valued VPNConfig entries.
func TestProbeTunnel_ForwardsFullHeaderRanges(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	pool := NewPool(db)

	// No awg_params on the server: resolution falls through to the stored
	// VPNConfig, which itself carries true AWG 3.1 ranges.
	sID, err := db.CreateServer(ctx, &models.Server{
		Name:      "Plain backend",
		Host:      "192.0.2.20",
		Protocols: map[string]any{},
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	wantH1 := models.HeaderRange{Lo: 196955274, Hi: 196979834}
	wantH2 := models.HeaderRange{Lo: 718486018, Hi: 718530126}
	if err := db.SaveVPNConfig(ctx, &models.VPNConfig{
		H1: wantH1,
		H2: wantH2,
		S1: 35,
		S2: 45,
	}); err != nil {
		t.Fatalf("SaveVPNConfig failed: %v", err)
	}

	var gotH1, gotH2 any
	var gotS1, gotS2 int
	mockProbe := func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		gotH1, gotH2, gotS1, gotS2 = h1, h2, s1, s2
		return 25 * time.Millisecond, nil
	}

	prober := NewHealthProber(pool, db, DefaultHealthConfig(), mockProbe)

	t1, err := pool.AddTunnel(ctx, sID, "192.0.2.20:51820", "pub-range")
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}
	if _, err := prober.ProbeTunnel(ctx, t1); err != nil {
		t.Fatalf("ProbeTunnel failed: %v", err)
	}

	if gotH1 != wantH1 {
		t.Errorf("probeFn h1 = %v (%T), want full range %s", gotH1, gotH1, wantH1)
	}
	if gotH2 != wantH2 {
		t.Errorf("probeFn h2 = %v (%T), want full range %s", gotH2, gotH2, wantH2)
	}
	if gotS1 != 35 || gotS2 != 45 {
		t.Errorf("probeFn s1/s2 = (%d, %d), want (35, 45)", gotS1, gotS2)
	}
}
