package awg

import (
	"encoding/base64"
	"strconv"
	"strings"
	"testing"

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
