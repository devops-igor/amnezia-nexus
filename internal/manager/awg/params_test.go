package awg

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"testing"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/devops-igor/amnezia-web-ui-go/internal/models"
)

func TestGenerateWGKeypair(t *testing.T) {
	priv, pub, err := GenerateWGKeypair()
	if err != nil {
		t.Fatalf("GenerateWGKeypair failed: %v", err)
	}

	privBytes, err := base64.StdEncoding.DecodeString(priv)
	if err != nil || len(privBytes) != 32 {
		t.Errorf("invalid private key base64: %v", err)
	}

	pubBytes, err := base64.StdEncoding.DecodeString(pub)
	if err != nil || len(pubBytes) != 32 {
		t.Errorf("invalid public key base64: %v", err)
	}
}

func TestGeneratePSK(t *testing.T) {
	psk, err := GeneratePSK()
	if err != nil {
		t.Fatalf("GeneratePSK failed: %v", err)
	}

	pskBytes, err := base64.StdEncoding.DecodeString(psk)
	if err != nil || len(pskBytes) != 32 {
		t.Errorf("invalid PSK base64: %v", err)
	}
}

func TestGenerateQuadrantHeaders(t *testing.T) {
	for i := 0; i < 20; i++ {
		h1, h2, h3, h4, err := GenerateQuadrantHeaders()
		if err != nil {
			t.Fatalf("GenerateQuadrantHeaders failed: %v", err)
		}

		if err := ValidateQuadrantDisjointness(h1, h2, h3, h4); err != nil {
			t.Fatalf("disjointness failure: %v", err)
		}

		if h1.Lo < 5 || h2.Lo <= h1.Hi || h3.Lo <= h2.Hi || h4.Lo <= h3.Hi {
			t.Errorf("quadrant headers not strictly increasing: %s, %s, %s, %s", h1, h2, h3, h4)
		}

		for idx, h := range []HeaderRange{h1, h2, h3, h4} {
			if h.Hi-h.Lo < 1000 {
				t.Errorf("header %d span < 1000: %s (span=%d)", idx+1, h, h.Hi-h.Lo)
			}
			qLo, qHi := QuadrantBounds(idx)
			if h.Lo < qLo || h.Hi > qHi {
				t.Errorf("header %d out of quadrant bounds [%d, %d]: %s", idx+1, qLo, qHi, h)
			}
		}
	}
}

func TestGenerateAWGParams(t *testing.T) {
	profiles := []string{"lite", "standard", "pro"}

	for _, profile := range profiles {
		params, err := GenerateAWGParams(profile, false)
		if err != nil {
			t.Fatalf("GenerateAWGParams(%s) failed: %v", profile, err)
		}

		s1, _ := strconv.Atoi(params.InitPacketJunkSize)
		s2, _ := strconv.Atoi(params.ResponsePacketJunkSize)
		diff := s1 - s2
		if diff < 0 {
			diff = -diff
		}
		if diff < 10 {
			t.Errorf("profile %s: |S1 - S2| < 10 (S1=%d, S2=%d)", profile, s1, s2)
		}

		if profile == "pro" && params.MTU != "1320" {
			t.Errorf("pro profile expected MTU 1320, got %s", params.MTU)
		}
		if (profile == "lite" || profile == "standard") && params.MTU != "1280" {
			t.Errorf("%s profile expected MTU 1280, got %s", profile, params.MTU)
		}

		if err := ValidateAWGParams(params.ToMap()); err != nil {
			t.Errorf("ValidateAWGParams failed on generated %s params: %v", profile, err)
		}
	}
}

func TestValidateAWGParams_Errors(t *testing.T) {
	invalidNumeric := map[string]string{
		"junk_packet_count": "invalid",
	}
	if err := ValidateAWGParams(invalidNumeric); err == nil {
		t.Errorf("expected error for non-numeric param")
	}

	outOfBounds := map[string]string{
		"junk_packet_count": "500",
	}
	if err := ValidateAWGParams(outOfBounds); err == nil {
		t.Errorf("expected error for out of bounds param")
	}

	invalidCPS := map[string]string{
		"i1": "bad_cps_format",
	}
	if err := ValidateAWGParams(invalidCPS); err == nil {
		t.Errorf("expected error for invalid CPS format")
	}

	invalidMTU := map[string]string{
		"mtu": "999",
	}
	if err := ValidateAWGParams(invalidMTU); err == nil {
		t.Errorf("expected error for invalid MTU")
	}
}

func TestGenerateStandardObfuscationValues_Floor(t *testing.T) {
	for i := 0; i < 100; i++ {
		h1, h2, h3, h4, s1, s2, s3, s4, err := GenerateStandardObfuscationValues()
		if err != nil {
			t.Fatalf("iteration %d: GenerateStandardObfuscationValues failed: %v", i, err)
		}
		if s1 < 12 {
			t.Errorf("iteration %d: S1 = %d < 12", i, s1)
		}
		if s2 < 12 {
			t.Errorf("iteration %d: S2 = %d < 12", i, s2)
		}
		if s3 < 12 {
			t.Errorf("iteration %d: S3 = %d < 12", i, s3)
		}
		if s4 < 12 {
			t.Errorf("iteration %d: S4 = %d < 12", i, s4)
		}
		if h1.IsZero() || h2.IsZero() || h3.IsZero() || h4.IsZero() {
			t.Errorf("iteration %d: unexpected zero header value: h1=%s, h2=%s, h3=%s, h4=%s", i, h1, h2, h3, h4)
		}
		if err := ValidateQuadrantDisjointness(h1, h2, h3, h4); err != nil {
			t.Errorf("iteration %d: disjointness check failed: %v", i, err)
		}
	}
}

func TestAWGParamsFromVPNConfig_NoCPSPackets(t *testing.T) {
	cfg := &models.VPNConfig{
		H1: models.DegenerateHeaderRange(12345678),
		H2: models.DegenerateHeaderRange(23456789),
		H3: models.DegenerateHeaderRange(34567890),
		H4: models.DegenerateHeaderRange(45678901),
		S1: 45,
		S2: 60,
		S3: 25,
		S4: 15,
	}

	params := AWGParamsFromVPNConfig(cfg)
	if params == nil {
		t.Fatal("AWGParamsFromVPNConfig returned nil")
	}

	if params.I1 != "" || params.I2 != "" || params.I3 != "" || params.I4 != "" || params.I5 != "" {
		t.Errorf("AWGParamsFromVPNConfig must not contain CPS I1..I5 parameters: I1=%q, I2=%q, I3=%q, I4=%q, I5=%q",
			params.I1, params.I2, params.I3, params.I4, params.I5)
	}

	// Verify pure AWG 3+ parameters are properly mapped
	if params.InitPacketMagicHeader != "12345678" ||
		params.ResponsePacketMagicHeader != "23456789" ||
		params.UnderloadPacketMagicHeader != "34567890" ||
		params.TransportPacketMagicHeader != "45678901" {
		t.Errorf("unexpected magic headers in params: %+v", params)
	}

	if params.InitPacketJunkSize != "45" ||
		params.ResponsePacketJunkSize != "60" ||
		params.CookieReplyPacketJunkSize != "25" ||
		params.TransportPacketJunkSize != "15" {
		t.Errorf("unexpected junk sizes in params: %+v", params)
	}

	// Also verify nil cfg produces empty I1..I5
	nilParams := AWGParamsFromVPNConfig(nil)
	if nilParams.I1 != "" || nilParams.I2 != "" || nilParams.I3 != "" || nilParams.I4 != "" || nilParams.I5 != "" {
		t.Errorf("nil cfg must produce empty I1..I5: I1=%q, I2=%q, I3=%q, I4=%q, I5=%q",
			nilParams.I1, nilParams.I2, nilParams.I3, nilParams.I4, nilParams.I5)
	}

	// Verify RenderClientConfig with these params produces no I1-I5 lines
	rendered := RenderClientConfig("priv", "10.0.0.2", "pub", "", "1.2.3.4:51820", "1.1.1.1", "1.0.0.1", "1420", params, nil)
	for _, k := range []string{"I1", "I2", "I3", "I4", "I5"} {
		if strings.Contains(rendered, k+" =") || strings.Contains(rendered, k+"=") {
			t.Errorf("rendered config should not contain %s, got:\n%s", k, rendered)
		}
	}
}

func TestAWGParamsFromVPNConfig_HeaderProtectionKey(t *testing.T) {
	// Case 1: HeaderProtectionKey present with small S values (< 12) -> enforced to >= 12
	cfg := &models.VPNConfig{
		H1:                  models.DegenerateHeaderRange(1234),
		H2:                  models.DegenerateHeaderRange(5678),
		H3:                  models.DegenerateHeaderRange(9012),
		H4:                  models.DegenerateHeaderRange(3456),
		S1:                  4,
		S2:                  8,
		S3:                  6,
		S4:                  10,
		HeaderProtectionKey: "test-hp-key-base64",
	}

	params := AWGParamsFromVPNConfig(cfg)
	if params.HeaderProtectionKey != "test-hp-key-base64" {
		t.Errorf("expected HeaderProtectionKey %q, got %q", "test-hp-key-base64", params.HeaderProtectionKey)
	}
	if params.InitPacketJunkSize != "12" {
		t.Errorf("expected S1 enforced to 12, got %s", params.InitPacketJunkSize)
	}
	if params.ResponsePacketJunkSize != "12" {
		t.Errorf("expected S2 enforced to 12, got %s", params.ResponsePacketJunkSize)
	}
	if params.CookieReplyPacketJunkSize != "12" {
		t.Errorf("expected S3 enforced to 12, got %s", params.CookieReplyPacketJunkSize)
	}
	if params.TransportPacketJunkSize != "12" {
		t.Errorf("expected S4 enforced to 12, got %s", params.TransportPacketJunkSize)
	}

	// Case 2: S values already >= 12 -> preserved
	cfg2 := &models.VPNConfig{
		S1:                  20,
		S2:                  30,
		S3:                  40,
		S4:                  50,
		HeaderProtectionKey: "test-hp-key-2",
	}
	params2 := AWGParamsFromVPNConfig(cfg2)
	if params2.InitPacketJunkSize != "20" || params2.ResponsePacketJunkSize != "30" ||
		params2.CookieReplyPacketJunkSize != "40" || params2.TransportPacketJunkSize != "50" {
		t.Errorf("expected S1..S4 preserved when >= 12: %+v", params2)
	}
}

func TestTimingRange_ParseAndString(t *testing.T) {
	// 1. Bare ints and numeric types
	trInt, err := ParseTimingRange(125)
	if err != nil || trInt == nil || trInt.Lo != 125 || trInt.Hi != 125 || !trInt.IsDegenerate() || trInt.String() != "125" {
		t.Errorf("failed to parse int 125: %+v, err: %v", trInt, err)
	}

	trFloat, err := ParseTimingRange(float64(125))
	if err != nil || trFloat == nil || trFloat.Lo != 125 || trFloat.Hi != 125 || !trFloat.IsDegenerate() {
		t.Errorf("failed to parse float64 125: %+v, err: %v", trFloat, err)
	}

	trInt64, err := ParseTimingRange(int64(42))
	if err != nil || trInt64 == nil || trInt64.Lo != 42 || trInt64.Hi != 42 {
		t.Errorf("failed to parse int64 42: %+v, err: %v", trInt64, err)
	}

	// 2. Degenerate string
	trDegStr, err := ParseTimingRange("125")
	if err != nil || trDegStr == nil || trDegStr.Lo != 125 || trDegStr.Hi != 125 || trDegStr.String() != "125" {
		t.Errorf("failed to parse degenerate string \"125\": %+v, err: %v", trDegStr, err)
	}

	// 3. Range string
	trRangeStr, err := ParseTimingRange("100-140")
	if err != nil || trRangeStr == nil || trRangeStr.Lo != 100 || trRangeStr.Hi != 140 || trRangeStr.IsDegenerate() || trRangeStr.String() != "100-140" {
		t.Errorf("failed to parse range string \"100-140\": %+v, err: %v", trRangeStr, err)
	}

	// 4. TimingRange identity
	orig := NewTimingRange(10, 20)
	trCopy, err := ParseTimingRange(orig)
	if err != nil || trCopy.Lo != 10 || trCopy.Hi != 20 {
		t.Errorf("failed to parse TimingRange copy: %+v, err: %v", trCopy, err)
	}

	// 5. Nil / empty
	trNil, err := ParseTimingRange(nil)
	if err != nil || trNil != nil {
		t.Errorf("expected nil for nil input, got %+v, err: %v", trNil, err)
	}

	trEmpty, err := ParseTimingRange("")
	if err != nil || trEmpty != nil {
		t.Errorf("expected nil for empty string, got %+v, err: %v", trEmpty, err)
	}

	// 6. Inverted order in NewTimingRange should swap
	swapped := NewTimingRange(140, 100)
	if swapped.Lo != 100 || swapped.Hi != 140 {
		t.Errorf("NewTimingRange(140, 100) did not swap: %+v", swapped)
	}

	// 7. Error cases
	errorCases := []any{
		"140-100",   // hi < lo
		"abc",       // not numbers
		"-5",        // negative
		"-5-10",     // negative
		"10-20-30",  // too many parts
		[]int{1, 2}, // unsupported type
	}
	for _, tc := range errorCases {
		res, err := ParseTimingRange(tc)
		if err == nil {
			t.Errorf("expected error parsing %v, got %+v", tc, res)
		}
	}
}

func TestTimingRange_JSONMarshaling(t *testing.T) {
	type wrapper struct {
		Range *TimingRange `json:"timing,omitempty"`
	}

	// 1. Unmarshal bare int in JSON
	var wInt wrapper
	if err := json.Unmarshal([]byte(`{"timing": 125}`), &wInt); err != nil {
		t.Fatalf("Unmarshal bare int failed: %v", err)
	}
	if wInt.Range == nil || wInt.Range.Lo != 125 || wInt.Range.Hi != 125 {
		t.Errorf("expected Lo=125, Hi=125, got %+v", wInt.Range)
	}

	// 2. Unmarshal quoted single int string in JSON
	var wStrSingle wrapper
	if err := json.Unmarshal([]byte(`{"timing": "125"}`), &wStrSingle); err != nil {
		t.Fatalf("Unmarshal quoted single string failed: %v", err)
	}
	if wStrSingle.Range == nil || wStrSingle.Range.Lo != 125 || wStrSingle.Range.Hi != 125 {
		t.Errorf("expected Lo=125, Hi=125, got %+v", wStrSingle.Range)
	}

	// 3. Unmarshal quoted range string in JSON
	var wStrRange wrapper
	if err := json.Unmarshal([]byte(`{"timing": "100-140"}`), &wStrRange); err != nil {
		t.Fatalf("Unmarshal quoted range string failed: %v", err)
	}
	if wStrRange.Range == nil || wStrRange.Range.Lo != 100 || wStrRange.Range.Hi != 140 {
		t.Errorf("expected Lo=100, Hi=140, got %+v", wStrRange.Range)
	}

	// 4. Unmarshal object format in JSON
	var wObj wrapper
	if err := json.Unmarshal([]byte(`{"timing": {"lo": 10, "hi": 20}}`), &wObj); err != nil {
		t.Fatalf("Unmarshal object format failed: %v", err)
	}
	if wObj.Range == nil || wObj.Range.Lo != 10 || wObj.Range.Hi != 20 {
		t.Errorf("expected Lo=10, Hi=20, got %+v", wObj.Range)
	}

	// 5. Unmarshal null / empty in JSON
	var wNull wrapper
	if err := json.Unmarshal([]byte(`{"timing": null}`), &wNull); err != nil {
		t.Fatalf("Unmarshal null failed: %v", err)
	}
	if wNull.Range != nil {
		t.Errorf("expected nil range for null, got %+v", wNull.Range)
	}

	// 6. Marshal range
	wOut := wrapper{Range: NewTimingRange(100, 140)}
	b, err := json.Marshal(wOut)
	if err != nil {
		t.Fatalf("Marshal range failed: %v", err)
	}
	if string(b) != `{"timing":"100-140"}` {
		t.Errorf("expected {\"timing\":\"100-140\"}, got %s", string(b))
	}

	// 7. Marshal degenerate
	wOutDeg := wrapper{Range: DegenerateTimingRange(125)}
	bDeg, err := json.Marshal(wOutDeg)
	if err != nil {
		t.Fatalf("Marshal degenerate failed: %v", err)
	}
	if string(bDeg) != `{"timing":"125"}` {
		t.Errorf("expected {\"timing\":\"125\"}, got %s", string(bDeg))
	}
}

func TestGenerateClientTimingParams_RangesAndInvariants(t *testing.T) {
	for i := 0; i < 100; i++ {
		rat, rt, rej, kt, mha, pk := GenerateClientTimingParams()

		// Verify non-nil
		if rat == nil || rt == nil || rej == nil || kt == nil || mha == nil || pk == nil {
			t.Fatalf("iteration %d: unexpected nil param", i)
		}

		// Verify RekeyAfterTime in [100, 140] and true range (lo < hi)
		if rat.Lo < 100 || rat.Hi > 140 || rat.Lo >= rat.Hi {
			t.Errorf("iteration %d: invalid RekeyAfterTime: %+v", i, rat)
		}

		// Verify RekeyTimeout in [4, 6] and true range (lo < hi)
		if rt.Lo < 4 || rt.Hi > 6 || rt.Lo >= rt.Hi {
			t.Errorf("iteration %d: invalid RekeyTimeout: %+v", i, rt)
		}

		// Verify strict ordering invariant: rt entirely below rat (no overlap)
		if rt.Hi >= rat.Lo {
			t.Errorf("iteration %d: ordering invariant violated: rt.Hi (%d) >= rat.Lo (%d)", i, rt.Hi, rat.Lo)
		}

		// Verify RejectAfterTime in [160, 200] and true range (lo < hi)
		if rej.Lo < 160 || rej.Hi > 200 || rej.Lo >= rej.Hi {
			t.Errorf("iteration %d: invalid RejectAfterTime: %+v", i, rej)
		}

		// Verify rat strictly below rej
		if rat.Hi >= rej.Lo {
			t.Errorf("iteration %d: ordering invariant violated: rat.Hi (%d) >= rej.Lo (%d)", i, rat.Hi, rej.Lo)
		}

		// Verify KeepaliveTimeout in [8, 12] and true range
		if kt.Lo < 8 || kt.Hi > 12 || kt.Lo >= kt.Hi {
			t.Errorf("iteration %d: invalid KeepaliveTimeout: %+v", i, kt)
		}

		// Verify MaxHandshakeAttempts in [4, 8] and true range
		if mha.Lo < 4 || mha.Hi > 8 || mha.Lo >= mha.Hi {
			t.Errorf("iteration %d: invalid MaxHandshakeAttempts: %+v", i, mha)
		}

		// Verify PersistentKeepalive in [22, 30] and true range
		if pk.Lo < 22 || pk.Hi > 30 || pk.Lo >= pk.Hi {
			t.Errorf("iteration %d: invalid PersistentKeepalive: %+v", i, pk)
		}

		// String representation must be "lo-hi"
		for name, p := range map[string]*TimingRange{
			"rat": rat, "rt": rt, "rej": rej, "kt": kt, "mha": mha, "pk": pk,
		} {
			s := p.String()
			if !strings.Contains(s, "-") {
				t.Errorf("iteration %d: %s should be range 'lo-hi', got %q", i, name, s)
			}
			expected := fmt.Sprintf("%d-%d", p.Lo, p.Hi)
			if s != expected {
				t.Errorf("iteration %d: %s String() = %q, want %q", i, name, s, expected)
			}
		}
	}
}

func TestEnforceTimingOrdering_Clamping(t *testing.T) {
	// Case 1: rt overlaps or exceeds rat -> rt clamped below rat.Lo
	rt := NewTimingRange(10, 20)
	rat := NewTimingRange(15, 30)
	rej := NewTimingRange(35, 50)
	EnforceTimingOrdering(rt, rat, rej)

	if rt.Hi >= rat.Lo {
		t.Errorf("expected rt.Hi < rat.Lo, got rt=%+v, rat=%+v", rt, rat)
	}
	if rt.Hi != 14 {
		t.Errorf("expected rt.Hi clamped to 14, got %d", rt.Hi)
	}

	// Case 2: rej overlaps or is below rat -> rej.Lo clamped above rat.Hi
	rt2 := NewTimingRange(4, 6)
	rat2 := NewTimingRange(100, 140)
	rej2 := NewTimingRange(130, 150)
	EnforceTimingOrdering(rt2, rat2, rej2)

	if rej2.Lo <= rat2.Hi {
		t.Errorf("expected rej2.Lo > rat2.Hi, got rej2=%+v, rat2=%+v", rej2, rat2)
	}
	if rej2.Lo != 141 {
		t.Errorf("expected rej2.Lo clamped to 141, got %d", rej2.Lo)
	}
}

func TestTimingRange_UpstreamUintRangeRoundTrip(t *testing.T) {
	testRanges := []*TimingRange{
		NewTimingRange(100, 140),
		NewTimingRange(4, 6),
		NewTimingRange(160, 200),
		NewTimingRange(8, 12),
		NewTimingRange(4, 8),
		NewTimingRange(22, 30),
		DegenerateTimingRange(125),
		DegenerateTimingRange(5),
		DegenerateTimingRange(25),
	}

	for _, tr := range testRanges {
		str := tr.String()

		var ur device.UintRange
		if err := ur.FromString(str); err != nil {
			t.Fatalf("upstream device.UintRange failed to parse %q: %v", str, err)
		}

		if ur.Lo() != uint32(tr.Lo) {
			t.Errorf("Lo mismatch for %q: upstream %d != local %d", str, ur.Lo(), tr.Lo)
		}
		if ur.Hi() != uint32(tr.Hi) {
			t.Errorf("Hi mismatch for %q: upstream %d != local %d", str, ur.Hi(), tr.Hi)
		}
		if ur.ToString() != str {
			t.Errorf("ToString mismatch for %q: upstream %q != local %q", str, ur.ToString(), str)
		}
	}
}

func TestHeaderRange_UpstreamUintRangeRoundTrip(t *testing.T) {
	testRanges := []HeaderRange{
		NewHeaderRange(1000, 2000),
		NewHeaderRange(5, 536870911),
		NewHeaderRange(2000000000, math.MaxInt32),
		DegenerateHeaderRange(125),
		DegenerateHeaderRange(5),
		DegenerateHeaderRange(math.MaxUint32),
	}

	for _, hr := range testRanges {
		str := hr.String()

		var ur device.UintRange
		if err := ur.FromString(str); err != nil {
			t.Fatalf("upstream device.UintRange failed to parse %q: %v", str, err)
		}

		if ur.Lo() != hr.Lo {
			t.Errorf("Lo mismatch for %q: upstream %d != local %d", str, ur.Lo(), hr.Lo)
		}
		if ur.Hi() != hr.Hi {
			t.Errorf("Hi mismatch for %q: upstream %d != local %d", str, ur.Hi(), hr.Hi)
		}
		if ur.ToString() != str {
			t.Errorf("ToString mismatch for %q: upstream %q != local %q", str, ur.ToString(), str)
		}
	}
}

func TestHeaderRange_DegenerateBackCompat(t *testing.T) {
	singleVal := "12345678"
	hr, err := models.ParseHeaderRange(singleVal)
	if err != nil {
		t.Fatalf("failed to parse single value: %v", err)
	}
	if !hr.IsDegenerate() {
		t.Errorf("expected degenerate range, got lo=%d, hi=%d", hr.Lo, hr.Hi)
	}
	if hr.Lo != 12345678 || hr.Hi != 12345678 {
		t.Errorf("expected 12345678, got lo=%d, hi=%d", hr.Lo, hr.Hi)
	}
	if hr.String() != singleVal {
		t.Errorf("expected String() to return byte-identical %q, got %q", singleVal, hr.String())
	}
}

func TestQuadrantDisjointness_AndPartialBackfill(t *testing.T) {
	// 1. Verify disjointness holds on standard quadrant generation
	h1, h2, h3, h4, err := GenerateQuadrantHeaders()
	if err != nil {
		t.Fatalf("GenerateQuadrantHeaders failed: %v", err)
	}
	if err := ValidateQuadrantDisjointness(h1, h2, h3, h4); err != nil {
		t.Fatalf("expected disjoint ranges, got error: %v", err)
	}

	// 2. Overlap detection
	overlapH1 := NewHeaderRange(1000, 2000)
	overlapH2 := NewHeaderRange(1500, 3000)
	if err := ValidateQuadrantDisjointness(overlapH1, overlapH2, HeaderRange{}, HeaderRange{}); err == nil {
		t.Errorf("expected overlap error between %s and %s", overlapH1, overlapH2)
	}

	// 3. Partial backfill adjustment without mutating stored values
	storedH2 := DegenerateHeaderRange(5000)
	originalStored := storedH2
	newH1 := NewHeaderRange(4500, 5500) // overlaps storedH2

	AdjustGeneratedHeaderToAvoid(&newH1, storedH2)

	// Invariant: stored values must NEVER be mutated
	if storedH2 != originalStored {
		t.Fatalf("stored range was mutated! before: %v, after: %v", originalStored, storedH2)
	}

	// Invariant: adjusted newH1 must not overlap storedH2
	if newH1.Overlap(storedH2) {
		t.Errorf("adjusted range %s still overlaps %s", newH1, storedH2)
	}
	if newH1.Hi-newH1.Lo < 1000 {
		t.Errorf("adjusted range span < 1000: %s (span=%d)", newH1, newH1.Hi-newH1.Lo)
	}
}

func TestNeedsHeaderUpgrade(t *testing.T) {
	if !NeedsHeaderUpgrade(HeaderRange{}) {
		t.Error("expected zero HeaderRange to need upgrade")
	}
	if !NeedsHeaderUpgrade(DegenerateHeaderRange(12345)) {
		t.Error("expected degenerate HeaderRange to need upgrade")
	}
	if !NeedsHeaderUpgrade(NewHeaderRange(1000, 1500)) { // span 500 < 1000
		t.Error("expected sub-1000 span HeaderRange to need upgrade")
	}
	if NeedsHeaderUpgrade(NewHeaderRange(1000, 2000)) { // span 1000
		t.Error("expected span >= 1000 HeaderRange not to need upgrade")
	}
}

func TestExpandDegenerateHeader(t *testing.T) {
	// Zero range error
	if _, err := ExpandDegenerateHeader(HeaderRange{}, 0); err == nil {
		t.Error("expected error expanding zero HeaderRange")
	}

	// Out of quadrant bounds
	if _, err := ExpandDegenerateHeader(DegenerateHeaderRange(999999999), 0); err == nil {
		t.Error("expected error expanding value outside quadrant 0")
	}

	// DEV values in their respective quadrants:
	devVals := []struct {
		val uint32
		q   int
	}{
		{359398951, 0},
		{944086617, 1},
		{1418011628, 2},
		{1749149601, 3},
	}

	for _, tc := range devVals {
		expanded, err := ExpandDegenerateHeader(DegenerateHeaderRange(tc.val), tc.q)
		if err != nil {
			t.Fatalf("failed to expand %d in quadrant %d: %v", tc.val, tc.q, err)
		}
		if expanded.IsDegenerate() {
			t.Errorf("expanded range is still degenerate: %s", expanded)
		}
		if expanded.Hi-expanded.Lo < 1000 {
			t.Errorf("expanded range span < 1000: %s (span=%d)", expanded, expanded.Hi-expanded.Lo)
		}
		if !expanded.Contains(tc.val) {
			t.Errorf("expanded range %s does not contain legacy value %d", expanded, tc.val)
		}
		qLo, qHi := QuadrantBounds(tc.q)
		if expanded.Lo < qLo || expanded.Hi > qHi {
			t.Errorf("expanded range %s falls outside quadrant %d bounds [%d, %d]", expanded, tc.q, qLo, qHi)
		}
	}

	// Boundary condition: lowest value in quadrant 0
	low0, err := ExpandDegenerateHeader(DegenerateHeaderRange(5), 0)
	if err != nil {
		t.Fatalf("failed to expand low bound 5 in quadrant 0: %v", err)
	}
	if !low0.Contains(5) || low0.Lo < 5 || low0.Hi-low0.Lo < 1000 {
		t.Errorf("unexpected expansion for low bound 5: %s", low0)
	}

	// Boundary condition: highest value in quadrant 3
	_, q3Hi := QuadrantBounds(3)
	high3, err := ExpandDegenerateHeader(DegenerateHeaderRange(q3Hi), 3)
	if err != nil {
		t.Fatalf("failed to expand high bound in quadrant 3: %v", err)
	}
	if !high3.Contains(q3Hi) || high3.Hi > q3Hi || high3.Hi-high3.Lo < 1000 {
		t.Errorf("unexpected expansion for high bound %d: %s", q3Hi, high3)
	}
}

func TestUpgradeDegenerateHeaders(t *testing.T) {
	// 1. DEV environment degenerate headers
	h1 := DegenerateHeaderRange(359398951)
	h2 := DegenerateHeaderRange(944086617)
	h3 := DegenerateHeaderRange(1418011628)
	h4 := DegenerateHeaderRange(1749149601)

	up1, up2, up3, up4, upgraded, err := UpgradeDegenerateHeaders(h1, h2, h3, h4)
	if err != nil {
		t.Fatalf("UpgradeDegenerateHeaders failed: %v", err)
	}
	if !upgraded {
		t.Fatal("expected upgraded = true for degenerate headers")
	}

	for idx, tc := range []struct {
		rng HeaderRange
		val uint32
		q   int
	}{
		{up1, 359398951, 0},
		{up2, 944086617, 1},
		{up3, 1418011628, 2},
		{up4, 1749149601, 3},
	} {
		if tc.rng.IsDegenerate() {
			t.Errorf("H%d is still degenerate: %s", idx+1, tc.rng)
		}
		if tc.rng.Hi-tc.rng.Lo < 1000 {
			t.Errorf("H%d span < 1000: %s", idx+1, tc.rng)
		}
		if !tc.rng.Contains(tc.val) {
			t.Errorf("H%d %s does not contain legacy value %d", idx+1, tc.rng, tc.val)
		}
		qLo, qHi := QuadrantBounds(tc.q)
		if tc.rng.Lo < qLo || tc.rng.Hi > qHi {
			t.Errorf("H%d %s outside quadrant %d [%d, %d]", idx+1, tc.rng, tc.q, qLo, qHi)
		}
	}

	if err := ValidateQuadrantDisjointness(up1, up2, up3, up4); err != nil {
		t.Errorf("upgraded ranges are not pairwise disjoint: %v", err)
	}

	// 2. Already valid ranges are returned unmodified with upgraded = false
	same1, same2, same3, same4, upgraded2, err := UpgradeDegenerateHeaders(up1, up2, up3, up4)
	if err != nil {
		t.Fatalf("UpgradeDegenerateHeaders on valid ranges failed: %v", err)
	}
	if upgraded2 {
		t.Error("expected upgraded = false when ranges are already valid and disjoint")
	}
	if same1 != up1 || same2 != up2 || same3 != up3 || same4 != up4 {
		t.Errorf("ranges were unexpectedly mutated: got (%s, %s, %s, %s), want (%s, %s, %s, %s)",
			same1, same2, same3, same4, up1, up2, up3, up4)
	}

	// 3. Fallback when existing values cannot cleanly expand in quadrants (e.g. all in quadrant 0)
	badH1 := DegenerateHeaderRange(12345)
	badH2 := DegenerateHeaderRange(23456)
	badH3 := DegenerateHeaderRange(34567)
	badH4 := DegenerateHeaderRange(45678)

	fb1, fb2, fb3, fb4, fbUpgraded, err := UpgradeDegenerateHeaders(badH1, badH2, badH3, badH4)
	if err != nil {
		t.Fatalf("UpgradeDegenerateHeaders fallback failed: %v", err)
	}
	if !fbUpgraded {
		t.Error("expected upgraded = true on fallback")
	}
	if fb1.IsDegenerate() || fb2.IsDegenerate() || fb3.IsDegenerate() || fb4.IsDegenerate() {
		t.Error("fallback produced degenerate headers")
	}
	if err := ValidateQuadrantDisjointness(fb1, fb2, fb3, fb4); err != nil {
		t.Errorf("fallback headers are not pairwise disjoint: %v", err)
	}
}

func TestAWGParamsFromMap_HeaderProtectionKeyAndRandomTrailers(t *testing.T) {
	hpKeys := []string{
		"header_protection_key",
		"HeaderProtectionKey",
		"headerprotectionkey",
		"hpkey",
		"HPKEY",
	}

	for _, k := range hpKeys {
		p := AWGParamsFromMap(map[string]any{
			k: "dGVzdC1oZWFkZXItcHJvdGVjdGlvbi1rZXktMTIzNDU=",
		})
		if p.HeaderProtectionKey != "dGVzdC1oZWFkZXItcHJvdGVjdGlvbi1rZXktMTIzNDU=" {
			t.Errorf("key %q: expected HeaderProtectionKey to be set, got %q", k, p.HeaderProtectionKey)
		}
	}

	rtKeys := []string{
		"random_trailers",
		"RandomTrailers",
		"randomtrailers",
		"RANDOM_TRAILERS",
	}

	for _, k := range rtKeys {
		p := AWGParamsFromMap(map[string]any{
			k: "on",
		})
		if p.RandomTrailers != "on" {
			t.Errorf("key %q: expected RandomTrailers 'on', got %q", k, p.RandomTrailers)
		}

		pBool := AWGParamsFromMap(map[string]any{
			k: true,
		})
		if pBool.RandomTrailers != "true" {
			t.Errorf("key %q: expected RandomTrailers 'true' for bool, got %q", k, pBool.RandomTrailers)
		}
	}
}

func TestAWGParams_ToMap_RandomTrailers(t *testing.T) {
	p := &AWGParams{
		HeaderProtectionKey: "test-hpkey",
		RandomTrailers:      "on",
	}
	m := p.ToMap()
	if m["header_protection_key"] != "test-hpkey" {
		t.Errorf("expected header_protection_key 'test-hpkey', got %q", m["header_protection_key"])
	}
	if m["random_trailers"] != "on" {
		t.Errorf("expected random_trailers 'on', got %q", m["random_trailers"])
	}

	pEmpty := &AWGParams{}
	mEmpty := pEmpty.ToMap()
	if _, ok := mEmpty["random_trailers"]; ok {
		t.Errorf("expected random_trailers omitted when empty")
	}
	if _, ok := mEmpty["header_protection_key"]; ok {
		t.Errorf("expected header_protection_key omitted when empty")
	}
}
