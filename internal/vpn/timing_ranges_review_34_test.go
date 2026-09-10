package vpn

import (
	"context"
	"testing"

	"github.com/devops-igor/amnezia-web-ui-go/internal/manager/awg"
	"github.com/devops-igor/amnezia-web-ui-go/internal/models"
)

// PROBE 1: single-backfill of rat while rt+rej are stored.
// Stored legacy-consistent data: rt=110, rej=125 (rt < rej, as old code guaranteed).
// Missing rat -> regenerated -> clamp raises rat.Lo above rt.Hi, but NOTHING
// re-checks rat.Hi < rej.Lo. Generated rat.Hi can be up to 140 >= rej.Lo=125.
func TestProbe_SingleBackfillViolatesRejInvariant(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	ctx := context.Background()

	uID, err := db.CreateUser(ctx, &models.User{Username: "probe_rej_violation", Enabled: true})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	conn := &models.UserConnection{
		UserID:   uID,
		ServerID: 0,
		Protocol: "awg",
		ClientID: "pubkey-probe-1",
		Name:     "probe_rej_violation-awg",
		ClientParams: map[string]any{
			"client_private_key": "privkey-probe-1",
			"rekey_timeout":      float64(110),
			"reject_after_time":  float64(125),
			// rekey_after_time missing
		},
	}
	if _, err := db.CreateConnection(ctx, conn); err != nil {
		t.Fatalf("CreateConnection failed: %v", err)
	}

	violations := 0
	for i := 0; i < 40; i++ {
		cfg, _, err := svc.GenerateClientConfig(ctx, uID)
		if err != nil {
			t.Fatalf("GenerateClientConfig failed: %v", err)
		}
		rat := parseDirectiveRange(t, cfg, "RekeyAfterTime")
		rej := parseDirectiveRange(t, cfg, "RejectAfterTime")
		rt := parseDirectiveRange(t, cfg, "RekeyTimeout")
		if rt.Hi >= rat.Lo {
			t.Fatalf("invariant 1 broken too: rt.Hi=%d rat.Lo=%d", rt.Hi, rat.Lo)
		}
		if rat.Hi >= rej.Lo {
			violations++
			t.Logf("VIOLATION iter %d: rat=%s rej=%s (rat.Hi >= rej.Lo)", i, rat.String(), rej.String())
		}
	}
	if violations > 0 {
		t.Fatalf("PROBE CONFIRMED: %d/40 renders violate rat.Hi < rej.Lo after single-backfill of rat", violations)
	}
}

func TestTimingRangeUnmarshalJSONRejectsOutOfRange(t *testing.T) {
	var tr awg.TimingRange
	if err := tr.UnmarshalJSON([]byte(`1e300`)); err == nil {
		t.Fatalf("1e300 must be rejected by UnmarshalJSON, got %s", tr.String())
	}
	if err := tr.UnmarshalJSON([]byte(`-5`)); err == nil {
		t.Fatalf("-5 must be rejected by UnmarshalJSON, got %s", tr.String())
	}
	if err := tr.UnmarshalJSON([]byte(`4294967296`)); err == nil {
		t.Fatalf("values above uint32 max must be rejected (upstream ParseUint 32), got %s", tr.String())
	}
	// Legitimate values still parse.
	for _, ok := range []string{`125`, `125.0`, `"100-140"`, `{"lo":100,"hi":140}`} {
		var r awg.TimingRange
		if err := r.UnmarshalJSON([]byte(ok)); err != nil {
			t.Fatalf("%s should parse: %v", ok, err)
		}
	}
}

// PROBE 2: both stored but invariant-violating combo -> does EnforceTimingOrdering
// mutate stored values and is the fix stable across renders?
func TestProbe_BothStoredBrokenCombo_MutationAndStability(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	ctx := context.Background()

	uID, err := db.CreateUser(ctx, &models.User{Username: "probe_broken_combo", Enabled: true})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	conn := &models.UserConnection{
		UserID:   uID,
		ServerID: 0,
		Protocol: "awg",
		ClientID: "pubkey-probe-2",
		Name:     "probe_broken_combo-awg",
		ClientParams: map[string]any{
			"client_private_key": "privkey-probe-2",
			"rekey_timeout":      float64(100),
			"rekey_after_time":   float64(100), // degenerate, rt.Hi == rat.Lo
			"reject_after_time":  float64(180),
		},
	}
	if _, err := db.CreateConnection(ctx, conn); err != nil {
		t.Fatalf("CreateConnection failed: %v", err)
	}

	cfg1, _, err := svc.GenerateClientConfig(ctx, uID)
	if err != nil {
		t.Fatalf("GenerateClientConfig 1: %v", err)
	}
	rt := parseDirectiveRange(t, cfg1, "RekeyTimeout")
	rat := parseDirectiveRange(t, cfg1, "RekeyAfterTime")
	t.Logf("render1: rt=%s rat=%s (stored was 100/100)", rt.String(), rat.String())

	// Check stored row was rewritten
	conns, _ := db.GetConnectionsByUserID(ctx, uID)
	if len(conns) == 1 {
		t.Logf("stored rekey_timeout now: %v", conns[0].ClientParams["rekey_timeout"])
	}

	cfg2, _, err := svc.GenerateClientConfig(ctx, uID)
	if err != nil {
		t.Fatalf("GenerateClientConfig 2: %v", err)
	}
	if cfg1 != cfg2 {
		t.Fatalf("NOT STABLE across renders:\n%s\n---\n%s", cfg1, cfg2)
	}
}

// PROBE 3: ParseTimingRange / UnmarshalJSON robustness on hostile values.
func TestProbe_ParseRobustness(t *testing.T) {
	cases := []struct {
		in        string
		wantPanic bool
	}{
		{"125-", false},
		{"-140", false},
		{"140-100", false},
		{"12 5", false},
		{"0", false},
		{"-5", false},
		{"18446744073709551615", false}, // uint64 max
		{"4294967296", false},           // uint32 max + 1: upstream rejects
		{"1e300", false},
		{"1-2-3", false},
		{"", false},
		{"  100 - 140  ", false},
	}
	for _, c := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("ParseTimingRange(%q) PANICKED: %v", c.in, r)
				}
			}()
			tr, err := awg.ParseTimingRange(c.in)
			if err != nil {
				t.Logf("%-24q -> err: %v", c.in, err)
				return
			}
			t.Logf("%-24q -> %s", c.in, tr.String())
		}()
	}

	// JSON unmarshal path: bare floats and negatives
	jsonCases := []string{
		`1e300`, `-5`, `125.7`, `{"lo":1,"hi":2}`, `{"lo":0,"hi":0}`, `"100-140"`, `null`, `"garbage"`,
	}
	for _, jc := range jsonCases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("UnmarshalJSON(%s) PANICKED: %v", jc, r)
				}
			}()
			var tr awg.TimingRange
			err := tr.UnmarshalJSON([]byte(jc))
			if err != nil {
				t.Logf("json %-18s -> err: %v", jc, err)
				return
			}
			t.Logf("json %-18s -> %s", jc, tr.String())
		}()
	}
}

// PROBE 4: does a single corrupt timing value in clientsTable JSON nuke the whole table?
func TestProbe_CorruptClientsTable(t *testing.T) {
	bad := `[
  {"ClientID":"aaa","UserData":{"ClientName":"u1","Enabled":true,"rekey_after_time":"garbage-value"}},
  {"ClientID":"bbb","UserData":{"ClientName":"u2","Enabled":true}}
]`
	clients, err := awg.ParseClientsTable(bad)
	t.Logf("corrupt single timing param -> clients=%d err=%v", len(clients), err)
	if err == nil && len(clients) == 2 {
		t.Logf("OK: corrupt param tolerated")
	}
}
