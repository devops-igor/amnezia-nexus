package tunnel

import (
	"strings"
	"testing"
)

// Regression test for issue-backend-awg-param-key-mismatch: NewAWGClientDevice
// used to look up obfuscation params under short rendered-config keys
// ("Jc", "S1", ...) while the stored server awg_params use snake_case keys.
// The exact live DEV values from the task report are used here.
func TestBuildAWGIPCConfig_SnakeCaseParams(t *testing.T) {
	params := map[string]any{
		"junk_packet_count":             6,
		"junk_packet_min_size":          10,
		"junk_packet_max_size":          50,
		"init_packet_junk_size":         12,
		"response_packet_junk_size":     12,
		"cookie_reply_packet_junk_size": 12,
		"transport_packet_junk_size":    12,
		"init_packet_magic_header":      1,
		"response_packet_magic_header":  2,
		"underload_packet_magic_header": 3,
		"transport_packet_magic_header": 4,
		"HeaderProtectionKey":           "BSX9FAKEKEYVALUE",
	}
	cfg := BuildAWGIPCConfigForTest("privkeyhex", "pubkeyhex", "91.226.221.253:33950", params)

	// amneziawg-go v3 UAPI: s1..s4 are per-packet padding sizes; cookie-reply
	// (s3) and transport (s4) junk sizes ARE rendered since the v3 upgrade.
	// h1..h4 accept UintRange "lo" or "lo-hi"; v1-style single magic headers
	// render as plain "lo".
	expected := []string{
		"jc=6", "jmin=10", "jmax=50",
		"s1=12", "s2=12", "s3=12", "s4=12",
		"h1=1", "h2=2", "h3=3", "h4=4",
	}
	for _, k := range expected {
		if !strings.Contains(cfg, k+"\n") {
			t.Errorf("expected IPC config to contain %q, got:\n%s", k, cfg)
		}
	}
}

// Short keys ("Jc", "S1", ...) are the rendered client-config style; some
// stored configs may still use them. They must keep working (backward compat),
// including the v3-only s3/s4 junk sizes.
func TestBuildAWGIPCConfig_ShortKeysBackwardCompat(t *testing.T) {
	params := map[string]any{
		"Jc":   3,
		"Jmin": 5,
		"Jmax": 20,
		"S1":   8,
		"S2":   9,
		"S3":   10,
		"S4":   11,
		"H1":   21,
		"H2":   22,
		"H3":   23,
		"H4":   24,
	}
	cfg := BuildAWGIPCConfigForTest("privkeyhex", "pubkeyhex", "10.0.0.1:51820", params)

	expected := []string{"jc=3", "jmin=5", "jmax=20", "s1=8", "s2=9", "s3=10", "s4=11", "h1=21", "h2=22", "h3=23", "h4=24"}
	for _, k := range expected {
		if !strings.Contains(cfg, k+"\n") {
			t.Errorf("expected IPC config to contain %q, got:\n%s", k, cfg)
		}
	}
}

// Snake_case wins when both styles are present; snake_case value types coming
// from JSON (float64) must parse via toInt.
func TestBuildAWGIPCConfig_SnakeCaseWinsAndHandlesJSONTypes(t *testing.T) {
	params := map[string]any{
		"junk_packet_count":        float64(7),
		"init_packet_junk_size":    float64(24),
		"init_packet_magic_header": float64(5),
		"Jc":                       1,
		"S1":                       0,
		"H1":                       1,
	}
	cfg := BuildAWGIPCConfigForTest("privkeyhex", "pubkeyhex", "10.0.0.1:51820", params)

	for _, k := range []string{"jc=7", "s1=24", "h1=5"} {
		if !strings.Contains(cfg, k+"\n") {
			t.Errorf("expected IPC config to contain %q (snake_case must win over short keys), got:\n%s", k, cfg)
		}
	}
}

// nil params keep the built-in defaults.
func TestBuildAWGIPCConfig_NilParamsDefaults(t *testing.T) {
	cfg := BuildAWGIPCConfigForTest("privkeyhex", "pubkeyhex", "10.0.0.1:51820", nil)

	expected := []string{"jc=1", "jmin=0", "jmax=0", "s1=0", "s2=0", "s3=0", "s4=0", "h1=1", "h2=2", "h3=3", "h4=4"}
	for _, k := range expected {
		if !strings.Contains(cfg, k+"\n") {
			t.Errorf("expected IPC config to contain default %q, got:\n%s", k, cfg)
		}
	}
}

// TestBuildAWGIPCConfig_HeaderProtectionAndAdvancedOptions verifies that
// HeaderProtectionKey, RandomTrailers, DisableCookies, ContentPaddingAddition,
// and PresharedKey are correctly parsed and rendered in the correct UAPI sections.
func TestBuildAWGIPCConfig_HeaderProtectionAndAdvancedOptions(t *testing.T) {
	hpKeyB64 := "BSX9ZtdoVp6sTwS+ziidJqp/aBjHrp1+xSOzc3+Z36Y="
	pskB64 := "WTatz4TICnqDwWAGsJCRuS8G4HDCyb9ZdUZQ3vGciUc="

	params := map[string]any{
		"HeaderProtectionKey":    hpKeyB64,
		"RandomTrailers":         "on",
		"DisableCookies":         "on",
		"ContentPaddingAddition": "50-100",
		"PresharedKey":           pskB64,
	}

	cfg := BuildAWGIPCConfigForTest("privkeyhex", "pubkeyhex", "10.0.0.1:51820", params)

	// Check device section contains header_protection_key, random_trailers, disable_cookies, content_padding_addition
	hpKeyHex, err := base64ToHex(hpKeyB64)
	if err != nil || hpKeyHex == "" {
		t.Fatalf("base64ToHex failed: %v", err)
	}
	pskHex, err := base64ToHex(pskB64)
	if err != nil || pskHex == "" {
		t.Fatalf("base64ToHex failed: %v", err)
	}

	expectedDevice := []string{
		"header_protection_key=" + hpKeyHex,
		"random_trailers=true",
		"disable_cookies=true",
		"content_padding_addition=50-100",
	}
	for _, line := range expectedDevice {
		if !strings.Contains(cfg, line+"\n") {
			t.Errorf("expected IPC config to contain %q, got:\n%s", line, cfg)
		}
	}

	// Peer section must contain public_key, preshared_key, endpoint, allowed_ip
	expectedPeer := []string{
		"public_key=pubkeyhex",
		"preshared_key=" + pskHex,
		"endpoint=10.0.0.1:51820",
		"allowed_ip=0.0.0.0/0",
	}
	for _, line := range expectedPeer {
		if !strings.Contains(cfg, line+"\n") {
			t.Errorf("expected IPC config to contain %q, got:\n%s", line, cfg)
		}
	}

	// Device properties MUST be before public_key line
	pubIdx := strings.Index(cfg, "public_key=")
	if pubIdx < 0 {
		t.Fatalf("missing public_key in config:\n%s", cfg)
	}
	hpIdx := strings.Index(cfg, "header_protection_key=")
	if hpIdx < 0 || hpIdx > pubIdx {
		t.Errorf("header_protection_key must appear before public_key (hpIdx=%d, pubIdx=%d)", hpIdx, pubIdx)
	}

	// preshared_key MUST appear after public_key line
	pskIdx := strings.Index(cfg, "preshared_key=")
	if pskIdx < 0 || pskIdx < pubIdx {
		t.Errorf("preshared_key must appear after public_key (pskIdx=%d, pubIdx=%d)", pskIdx, pubIdx)
	}
}

// TestBuildAWGIPCConfig_CaseAndUnderscoreInsensitive verifies that parameter names
// in any casing or style (snake_case, camelCase, PascalCase, hyphenated) are recognized.
func TestBuildAWGIPCConfig_CaseAndUnderscoreInsensitive(t *testing.T) {
	params := map[string]any{
		"header_protection_key": "BSX9ZtdoVp6sTwS+ziidJqp/aBjHrp1+xSOzc3+Z36Y=",
		"random_trailers":       "true",
		"disable_cookies":       "1",
		"psk":                   "WTatz4TICnqDwWAGsJCRuS8G4HDCyb9ZdUZQ3vGciUc=",
	}

	cfg := BuildAWGIPCConfigForTest("privkeyhex", "pubkeyhex", "10.0.0.1:51820", params)
	for _, expected := range []string{"header_protection_key=", "random_trailers=true", "disable_cookies=true", "preshared_key="} {
		if !strings.Contains(cfg, expected) {
			t.Errorf("expected IPC config to contain %q, got:\n%s", expected, cfg)
		}
	}
}

// TestBuildAWGIPCConfig_TimingRanges verifies that AWG 3.1 timing parameters
// (both ranges and single values) are correctly rendered into device and peer sections.
func TestBuildAWGIPCConfig_TimingRanges(t *testing.T) {
	params := map[string]any{
		"rekey_after_time":       "100-140",
		"rekey_timeout":          "4-6",
		"reject_after_time":      "160-200",
		"keepalive_timeout":      "8-12",
		"max_handshake_attempts": "4-8",
		"persistent_keepalive":   "22-30",
	}

	cfg := BuildAWGIPCConfigForTest("privkeyhex", "pubkeyhex", "10.0.0.1:51820", params)

	expectedDevice := []string{
		"rekey_after_time=100-140\n",
		"rekey_timeout=4-6\n",
		"reject_after_time=160-200\n",
		"keepalive_timeout=8-12\n",
		"max_handshake_attempts=4-8\n",
	}
	for _, exp := range expectedDevice {
		if !strings.Contains(cfg, exp) {
			t.Errorf("expected device section to contain %q, got:\n%s", exp, cfg)
		}
	}

	// Device options must appear before public_key
	pubIdx := strings.Index(cfg, "public_key=")
	for _, exp := range expectedDevice {
		idx := strings.Index(cfg, exp)
		if idx < 0 || idx > pubIdx {
			t.Errorf("%q must appear before public_key (idx=%d, pubIdx=%d)", exp, idx, pubIdx)
		}
	}

	// Peer section must contain persistent_keepalive_interval with range
	expPKA := "persistent_keepalive_interval=22-30\n"
	if !strings.Contains(cfg, expPKA) {
		t.Errorf("expected peer section to contain %q, got:\n%s", expPKA, cfg)
	}
	pkaIdx := strings.Index(cfg, expPKA)
	if pkaIdx < pubIdx {
		t.Errorf("%q must appear after public_key (pkaIdx=%d, pubIdx=%d)", expPKA, pkaIdx, pubIdx)
	}
}

// TestBuildAWGIPCConfig_TimingRangesDegenerateSingle verifies backward compatibility
// with single-value timing params.
func TestBuildAWGIPCConfig_TimingRangesDegenerateSingle(t *testing.T) {
	params := map[string]any{
		"rekey_after_time":              125,
		"rekey_timeout":                 5,
		"reject_after_time":             180,
		"keepalive_timeout":             10,
		"max_handshake_attempts":        6,
		"persistent_keepalive_interval": 27,
	}

	cfg := BuildAWGIPCConfigForTest("privkeyhex", "pubkeyhex", "10.0.0.1:51820", params)

	for _, exp := range []string{
		"rekey_after_time=125\n",
		"rekey_timeout=5\n",
		"reject_after_time=180\n",
		"keepalive_timeout=10\n",
		"max_handshake_attempts=6\n",
		"persistent_keepalive_interval=27\n",
	} {
		if !strings.Contains(cfg, exp) {
			t.Errorf("expected config to contain %q, got:\n%s", exp, cfg)
		}
	}
}
