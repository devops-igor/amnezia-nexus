package models

import (
	"encoding/json"
	"math"
	"testing"
)

func TestHeaderRange_Basics(t *testing.T) {
	r := NewHeaderRange(100, 200)
	if r.Lo != 100 || r.Hi != 200 {
		t.Fatalf("expected 100-200, got %+v", r)
	}
	if r.IsDegenerate() {
		t.Errorf("expected true range not degenerate")
	}
	if r.IsZero() {
		t.Errorf("expected not zero")
	}
	if r.String() != "100-200" {
		t.Errorf("expected 100-200 string, got %s", r.String())
	}
	if !r.Contains(100) || !r.Contains(150) || !r.Contains(200) {
		t.Errorf("expected range to contain 100, 150, 200")
	}
	if r.Contains(99) || r.Contains(201) {
		t.Errorf("expected range to not contain 99, 201")
	}

	swapped := NewHeaderRange(200, 100)
	if swapped.Lo != 100 || swapped.Hi != 200 {
		t.Errorf("expected swapped to normalize to 100-200, got %+v", swapped)
	}

	deg := DegenerateHeaderRange(555)
	if !deg.IsDegenerate() {
		t.Errorf("expected degenerate")
	}
	if deg.String() != "555" {
		t.Errorf("expected 555, got %s", deg.String())
	}
	if !deg.Contains(555) || deg.Contains(554) || deg.Contains(556) {
		t.Errorf("degenerate range membership incorrect")
	}

	zero := HeaderRange{}
	if !zero.IsZero() {
		t.Errorf("expected zero range")
	}

	// Overlap tests
	r1 := NewHeaderRange(100, 200)
	r2 := NewHeaderRange(201, 300)
	r3 := NewHeaderRange(150, 250)
	if r1.Overlap(r2) {
		t.Errorf("r1 and r2 should not overlap")
	}
	if !r1.Overlap(r3) {
		t.Errorf("r1 and r3 should overlap")
	}

	// PickOne test
	for i := 0; i < 50; i++ {
		val := r1.PickOne()
		if !r1.Contains(val) {
			t.Fatalf("PickOne value %d out of range %+v", val, r1)
		}
	}
	if deg.PickOne() != 555 {
		t.Errorf("degenerate PickOne must return exact value")
	}
}

func TestHeaderRange_JSON(t *testing.T) {
	// 1. Quoted string range
	var r1 HeaderRange
	if err := json.Unmarshal([]byte(`"1000-2000"`), &r1); err != nil {
		t.Fatalf("unmarshal quoted range failed: %v", err)
	}
	if r1.Lo != 1000 || r1.Hi != 2000 {
		t.Errorf("expected 1000-2000, got %+v", r1)
	}

	// 2. Quoted string single
	var r2 HeaderRange
	if err := json.Unmarshal([]byte(`"12345"`), &r2); err != nil {
		t.Fatalf("unmarshal quoted single failed: %v", err)
	}
	if r2.Lo != 12345 || r2.Hi != 12345 || !r2.IsDegenerate() {
		t.Errorf("expected 12345, got %+v", r2)
	}

	// 3. Bare integer number
	var r3 HeaderRange
	if err := json.Unmarshal([]byte(`3288052141`), &r3); err != nil {
		t.Fatalf("unmarshal bare uint32 number failed: %v", err)
	}
	if r3.Lo != 3288052141 || r3.Hi != 3288052141 {
		t.Errorf("expected 3288052141, got %+v", r3)
	}

	// 4. Bare float number
	var r4 HeaderRange
	if err := json.Unmarshal([]byte(`100.0`), &r4); err != nil {
		t.Fatalf("unmarshal bare float failed: %v", err)
	}
	if r4.Lo != 100 || r4.Hi != 100 {
		t.Errorf("expected 100, got %+v", r4)
	}

	// 5. JSON Object
	var r5 HeaderRange
	if err := json.Unmarshal([]byte(`{"lo": 500, "hi": 600}`), &r5); err != nil {
		t.Fatalf("unmarshal object failed: %v", err)
	}
	if r5.Lo != 500 || r5.Hi != 600 {
		t.Errorf("expected 500-600, got %+v", r5)
	}

	// 6. Marshal
	b, err := json.Marshal(r1)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if string(b) != `"1000-2000"` {
		t.Errorf("expected %q, got %s", `"1000-2000"`, string(b))
	}
	bDeg, err := json.Marshal(r2)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if string(bDeg) != `"12345"` {
		t.Errorf("expected %q, got %s", `"12345"`, string(bDeg))
	}
}

func TestHeaderRange_BoundsValidation(t *testing.T) {
	invalidJSON := []string{
		`-1`,
		`-100`,
		`4294967296`,
		`1e300`,
		`"200-100"`,
		`"-5-10"`,
		`"10--20"`,
		`"10-20-30"`,
		`"abc"`,
		`"4294967296"`,
		`{"lo": 100, "hi": 50}`,
		`{"lo": -1, "hi": 50}`,
		`{"lo": 10, "hi": 5000000000}`,
	}

	for _, tc := range invalidJSON {
		var r HeaderRange
		if err := json.Unmarshal([]byte(tc), &r); err == nil {
			t.Errorf("expected JSON unmarshal error for %s, got nil (parsed %+v)", tc, r)
		}
	}
}

func TestParseHeaderRange(t *testing.T) {
	// Valid cases
	cases := []struct {
		in     any
		wantLo uint32
		wantHi uint32
		degen  bool
	}{
		{in: 125, wantLo: 125, wantHi: 125, degen: true},
		{in: int32(42), wantLo: 42, wantHi: 42, degen: true},
		{in: int64(1000), wantLo: 1000, wantHi: 1000, degen: true},
		{in: uint(999), wantLo: 999, wantHi: 999, degen: true},
		{in: uint32(3288052141), wantLo: 3288052141, wantHi: 3288052141, degen: true},
		{in: uint64(12345), wantLo: 12345, wantHi: 12345, degen: true},
		{in: float64(500), wantLo: 500, wantHi: 500, degen: true},
		{in: "100-200", wantLo: 100, wantHi: 200, degen: false},
		{in: "555", wantLo: 555, wantHi: 555, degen: true},
		{in: NewHeaderRange(10, 20), wantLo: 10, wantHi: 20, degen: false},
	}

	for _, c := range cases {
		got, err := ParseHeaderRange(c.in)
		if err != nil {
			t.Errorf("ParseHeaderRange(%v) unexpected error: %v", c.in, err)
			continue
		}
		if got.Lo != c.wantLo || got.Hi != c.wantHi {
			t.Errorf("ParseHeaderRange(%v) = %+v, want [%d, %d]", c.in, got, c.wantLo, c.wantHi)
		}
		if got.IsDegenerate() != c.degen {
			t.Errorf("ParseHeaderRange(%v).IsDegenerate() = %v, want %v", c.in, got.IsDegenerate(), c.degen)
		}
	}

	// Invalid cases
	invalidCases := []any{
		-1,
		int64(-50),
		int64(math.MaxUint32 + 1),
		uint64(math.MaxUint32 + 1),
		float64(-1.0),
		float64(math.MaxUint32 + 100),
		math.NaN(),
		math.Inf(1),
		"100-50",
		"bad",
		"1-2-3",
	}

	for _, c := range invalidCases {
		if _, err := ParseHeaderRange(c); err == nil {
			t.Errorf("ParseHeaderRange(%v) expected error, got nil", c)
		}
	}
}
