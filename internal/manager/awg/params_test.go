package awg

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
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

		if h1 < 5 || h2 <= h1 || h3 <= h2 || h4 <= h3 {
			t.Errorf("quadrant headers not strictly increasing: %d, %d, %d, %d", h1, h2, h3, h4)
		}

		const qSize uint32 = 2147483647 / 4
		if h1 > qSize+1 {
			t.Errorf("h1 out of quadrant 1: %d", h1)
		}
		if h2 < qSize || h2 > 2*qSize+1 {
			t.Errorf("h2 out of quadrant 2: %d", h2)
		}
		if h3 < 2*qSize || h3 > 3*qSize+1 {
			t.Errorf("h3 out of quadrant 3: %d", h3)
		}
		if h4 < 3*qSize {
			t.Errorf("h4 out of quadrant 4: %d", h4)
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
		if h1 == 0 || h2 == 0 || h3 == 0 || h4 == 0 {
			t.Errorf("iteration %d: unexpected zero header value: h1=%d, h2=%d, h3=%d, h4=%d", i, h1, h2, h3, h4)
		}
	}
}

func TestAWGParamsFromVPNConfig_NoCPSPackets(t *testing.T) {
	cfg := &models.VPNConfig{
		H1: 12345678,
		H2: 23456789,
		H3: 34567890,
		H4: 45678901,
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
		H1:                  1234,
		H2:                  5678,
		H3:                  9012,
		H4:                  3456,
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
