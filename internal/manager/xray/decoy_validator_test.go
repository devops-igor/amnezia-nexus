package xray

import (
	"context"
	"encoding/hex"
	"net"
	"net/url"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/manager/xray/scanner"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestValidateDecoyDomain_BlacklistRejection(t *testing.T) {
	blacklisted := []string{
		"gateway.icloud.com",
		"mask.icloud.com",
		"mask-h2.icloud.com",
		"relay.icloud.com",
		"icloud.com",
		"apple-relay.apple.com",
		"sub.apple-relay.apple.com",
		"telegram.org",
		"web.telegram.org",
		"api.telegram.org",
		"t.me",
		"sub.t.me",
	}

	for _, domain := range blacklisted {
		t.Run(domain, func(t *testing.T) {
			err := ValidateDecoyDomain(domain, "", nil)
			if err == nil {
				t.Fatalf("expected error for blacklisted domain %q, got nil", domain)
			}
			if !strings.Contains(strings.ToLower(err.Error()), "blacklist") &&
				!strings.Contains(strings.ToLower(err.Error()), "censor") {
				t.Errorf("expected descriptive blacklist error for %q, got %v", domain, err)
			}
		})
	}

	// Test empty domain
	if err := ValidateDecoyDomain("", "", nil); err == nil {
		t.Errorf("expected error for empty decoy domain, got nil")
	}
}

func TestValidateDecoyDomain_ASNAndGeoAlignment(t *testing.T) {
	// Setup mock GeoDB
	// Server IP: 198.51.100.10 -> DE, AS12345
	// Target 1: 203.0.113.1 -> US, AS714 (Apple)
	// Target 2: 203.0.113.2 -> US, AS99999 (Non-CDN, different country)
	// Target 3: 203.0.113.3 -> US, AS8075 (Microsoft - multi-region CDN)
	// Target 4: 203.0.113.4 -> DE, AS54321 (Same country DE)

	ranges := []scanner.IPRange{
		{
			StartIP: binaryIP(net.ParseIP("198.51.100.10")),
			EndIP:   binaryIP(net.ParseIP("198.51.100.10")),
			ASN:     12345,
			Country: [2]byte{'D', 'E'},
		},
		{
			StartIP: binaryIP(net.ParseIP("203.0.113.1")),
			EndIP:   binaryIP(net.ParseIP("203.0.113.1")),
			ASN:     714, // Apple
			Country: [2]byte{'U', 'S'},
		},
		{
			StartIP: binaryIP(net.ParseIP("203.0.113.2")),
			EndIP:   binaryIP(net.ParseIP("203.0.113.2")),
			ASN:     99999, // Mismatched non-CDN
			Country: [2]byte{'U', 'S'},
		},
		{
			StartIP: binaryIP(net.ParseIP("203.0.113.3")),
			EndIP:   binaryIP(net.ParseIP("203.0.113.3")),
			ASN:     8075, // Microsoft Anycast CDN
			Country: [2]byte{'U', 'S'},
		},
		{
			StartIP: binaryIP(net.ParseIP("203.0.113.4")),
			EndIP:   binaryIP(net.ParseIP("203.0.113.4")),
			ASN:     54321,
			Country: [2]byte{'D', 'E'},
		},
	}
	mockGeoDB := scanner.NewGeoDBFromRanges(ranges)

	serverIP := "198.51.100.10"

	// 1. Apple AS714 should be rejected
	err := ValidateDecoyDomain("203.0.113.1", serverIP, mockGeoDB)
	if err == nil {
		t.Fatalf("expected error for Apple AS714 domain, got nil")
	}
	if !strings.Contains(err.Error(), "714") {
		t.Errorf("expected error mentioning AS714, got %v", err)
	}

	// 2. Mismatched non-CDN ASN/Country should be rejected
	err = ValidateDecoyDomain("203.0.113.2", serverIP, mockGeoDB)
	if err == nil {
		t.Fatalf("expected geo/ASN alignment error, got nil")
	}
	if !strings.Contains(err.Error(), "alignment") {
		t.Errorf("expected error mentioning alignment, got %v", err)
	}

	// 3. Allowed multi-region CDN (Microsoft AS8075) should pass
	err = ValidateDecoyDomain("203.0.113.3", serverIP, mockGeoDB)
	if err != nil {
		t.Errorf("expected multi-region CDN to pass, got: %v", err)
	}

	// 4. Same country match (DE) should pass
	err = ValidateDecoyDomain("203.0.113.4", serverIP, mockGeoDB)
	if err != nil {
		t.Errorf("expected same-country match to pass, got: %v", err)
	}
}

func binaryIP(ip net.IP) uint32 {
	ipv4 := ip.To4()
	if ipv4 == nil {
		return 0
	}
	return uint32(ipv4[0])<<24 | uint32(ipv4[1])<<16 | uint32(ipv4[2])<<8 | uint32(ipv4[3])
}

func TestGenerateShortIDPool(t *testing.T) {
	// Test clamping count < 4
	poolMin, err := GenerateShortIDPool(2)
	if err != nil {
		t.Fatalf("GenerateShortIDPool(2) failed: %v", err)
	}
	// Pool should have 4 hex IDs + 1 empty string = 5 items
	if len(poolMin) != 5 {
		t.Errorf("expected 5 items in poolMin, got %d", len(poolMin))
	}

	// Test clamping count > 8
	poolMax, err := GenerateShortIDPool(12)
	if err != nil {
		t.Fatalf("GenerateShortIDPool(12) failed: %v", err)
	}
	if len(poolMax) != 9 {
		t.Errorf("expected 9 items in poolMax, got %d", len(poolMax))
	}

	// Verify all hex IDs are distinct, 16 hex chars (8 bytes), and last item is ""
	seen := make(map[string]bool)
	for i, sid := range poolMax {
		if i == len(poolMax)-1 {
			if sid != "" {
				t.Errorf("expected last item in pool to be empty string, got %q", sid)
			}
			continue
		}
		if len(sid) != 16 {
			t.Errorf("expected 16 hex chars for sid, got %d (%s)", len(sid), sid)
		}
		if _, err := hex.DecodeString(sid); err != nil {
			t.Errorf("invalid hex in sid %q: %v", sid, err)
		}
		if seen[sid] {
			t.Errorf("duplicate sid %q in pool", sid)
		}
		seen[sid] = true
	}
}

func TestSelectClientShortID_Rotation(t *testing.T) {
	pool := []string{"0123456789abcdef", "fedcba9876543210", "1122334455667788", "8877665544332211", ""}

	// Deterministic selection for same client ID
	idA := "client-uuid-alpha"
	sidA1 := SelectClientShortID(pool, idA)
	sidA2 := SelectClientShortID(pool, idA)
	if sidA1 != sidA2 {
		t.Errorf("expected deterministic selection, got %q != %q", sidA1, sidA2)
	}
	if sidA1 == "" {
		t.Errorf("expected non-empty sid for client A")
	}

	// Test rotation across distinct client IDs
	distinctSelected := make(map[string]int)
	for i := 0; i < 20; i++ {
		clientID := strings.Repeat(string(rune('a'+i)), 16)
		sid := SelectClientShortID(pool, clientID)
		distinctSelected[sid]++
	}
	if len(distinctSelected) < 2 {
		t.Errorf("expected rotation across pool, got only %d distinct IDs: %+v", len(distinctSelected), distinctSelected)
	}

	// Test fallback on empty pool
	if sid := SelectClientShortID([]string{}, "client"); sid != "" {
		t.Errorf("expected empty string for empty pool, got %q", sid)
	}
	if sid := SelectClientShortID([]string{""}, "client"); sid != "" {
		t.Errorf("expected empty string for pool with only empty string, got %q", sid)
	}
}

func TestRenderXrayConfig_SinglePortStrictEnforcement(t *testing.T) {
	privB64, _, err := GenerateRealityKeypair()
	if err != nil {
		t.Fatalf("GenerateRealityKeypair: %v", err)
	}

	// 1. Rendering must only produce a single inbound on portPrimary (443)
	cfgBytes, err := RenderXrayConfig(443, 54321, "www.microsoft.com", "www.microsoft.com:443", privB64, nil, []XrayClient{})
	if err != nil {
		t.Fatalf("RenderXrayConfig: %v", err)
	}

	parsed, err := ParseXrayConfig(cfgBytes)
	if err != nil {
		t.Fatalf("ParseXrayConfig: %v", err)
	}

	if len(parsed.Inbounds) != 1 {
		t.Fatalf("expected exactly 1 inbound, got %d", len(parsed.Inbounds))
	}
	if parsed.Inbounds[0].Port != 443 {
		t.Errorf("expected port 443, got %d", parsed.Inbounds[0].Port)
	}

	// Verify port 54321 is not present
	for _, in := range parsed.Inbounds {
		if in.Port == 54321 {
			t.Errorf("auxiliary port 54321 must not be present in inbounds")
		}
	}

	// Verify shortID pool is generated when shortIDs slice is nil
	shortIDs := parsed.Inbounds[0].StreamSettings.RealitySettings.ShortIDs
	if len(shortIDs) < 4 {
		t.Errorf("expected at least 4 shortIDs in pool, got %d", len(shortIDs))
	}

	// 2. Reject blacklisted SNI
	_, err = RenderXrayConfig(443, 54321, "gateway.icloud.com", "", privB64, nil, nil)
	if err == nil {
		t.Fatalf("expected error when rendering config with blacklisted SNI, got nil")
	}

	// 3. Default SNI when empty must be www.microsoft.com
	cfgDefault, err := RenderXrayConfig(443, 54321, "", "", privB64, nil, nil)
	if err != nil {
		t.Fatalf("RenderXrayConfig with empty SNI: %v", err)
	}
	parsedDefault, err := ParseXrayConfig(cfgDefault)
	if err != nil {
		t.Fatalf("ParseXrayConfig: %v", err)
	}
	serverNames := parsedDefault.Inbounds[0].StreamSettings.RealitySettings.ServerNames
	if len(serverNames) == 0 || serverNames[0] != DefaultDecoyDomain {
		t.Errorf("expected default SNI %q, got %+v", DefaultDecoyDomain, serverNames)
	}
}

func TestBuildVLESSURI_Mux(t *testing.T) {
	// 1. Without mux
	uriNoMux, err := BuildVLESSURI("192.0.2.1", 443, "uuid-123", "alice", "www.microsoft.com", "pubkey", "sid123", "xtls-rprx-vision")
	if err != nil {
		t.Fatalf("BuildVLESSURI without mux: %v", err)
	}
	parsedNoMux, err := url.Parse(uriNoMux)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	if parsedNoMux.Query().Get("mux") != "" {
		t.Errorf("expected no mux query param, got %q", parsedNoMux.Query().Get("mux"))
	}

	// 2. With mux = true
	uriMux, err := BuildVLESSURI("192.0.2.1", 443, "uuid-123", "alice", "www.microsoft.com", "pubkey", "sid123", "xtls-rprx-vision", true)
	if err != nil {
		t.Fatalf("BuildVLESSURI with mux: %v", err)
	}
	parsedMux, err := url.Parse(uriMux)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	if parsedMux.Query().Get("mux") != "true" {
		t.Errorf("expected mux=true, got %q", parsedMux.Query().Get("mux"))
	}
}

func TestGetClientConfig_MuxAndRotation(t *testing.T) {
	mockSSH := newMockXraySSHClient()
	mgr := NewXrayManagerWithServerLocks(&mockXrayPool{client: mockSSH}, nil)

	server := &models.Server{
		ID:   42,
		Host: "192.0.2.1",
		Protocols: map[string]any{
			models.ProtocolVLESS: map[string]any{
				"installed": true,
				"mux":       true,
			},
		},
	}
	ctx := context.Background()

	privB64, pubB64, err := GenerateRealityKeypair()
	if err != nil {
		t.Fatalf("GenerateRealityKeypair: %v", err)
	}
	pool, err := GenerateShortIDPool(8)
	if err != nil {
		t.Fatalf("GenerateShortIDPool: %v", err)
	}

	cls := []XrayClient{
		{ID: "client-uuid-1", Email: "client-uuid-1", Flow: "xtls-rprx-vision"},
		{ID: "client-uuid-2", Email: "client-uuid-2", Flow: "xtls-rprx-vision"},
	}

	cfgBytes, err := RenderXrayConfig(443, 54321, "www.microsoft.com", "www.microsoft.com:443", privB64, pool, cls)
	if err != nil {
		t.Fatalf("RenderXrayConfig: %v", err)
	}
	mockSSH.files[XrayConfigPath] = cfgBytes

	// GetClientConfig for client 1
	uri1, err := mgr.GetClientConfig(ctx, server, "client-uuid-1")
	if err != nil {
		t.Fatalf("GetClientConfig(client-uuid-1): %v", err)
	}
	parsed1, err := url.Parse(uri1)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}

	// Verify mux=true was picked up from server.Protocols["vless"]["mux"]
	if parsed1.Query().Get("mux") != "true" {
		t.Errorf("expected mux=true in client URI, got %q", parsed1.Query().Get("mux"))
	}
	if parsed1.Query().Get("pbk") != pubB64 {
		t.Errorf("expected pubKey %q, got %q", pubB64, parsed1.Query().Get("pbk"))
	}

	// GetClientConfig for client 2
	uri2, err := mgr.GetClientConfig(ctx, server, "client-uuid-2")
	if err != nil {
		t.Fatalf("GetClientConfig(client-uuid-2): %v", err)
	}
	parsed2, err := url.Parse(uri2)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}

	sid1 := parsed1.Query().Get("sid")
	sid2 := parsed2.Query().Get("sid")
	if sid1 == "" || sid2 == "" {
		t.Errorf("expected non-empty shortIDs, got sid1=%q sid2=%q", sid1, sid2)
	}

	// Context override: disable mux
	ctxNoMux := WithMuxContext(ctx, false)
	uriNoMux, err := mgr.GetClientConfig(ctxNoMux, server, "client-uuid-1")
	if err != nil {
		t.Fatalf("GetClientConfig with ctxNoMux: %v", err)
	}
	parsedNoMux, err := url.Parse(uriNoMux)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	if parsedNoMux.Query().Get("mux") != "" {
		t.Errorf("expected no mux query param with false context, got %q", parsedNoMux.Query().Get("mux"))
	}
}
