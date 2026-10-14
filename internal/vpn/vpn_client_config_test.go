package vpn

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestGenerateClientConfig_PublicEndpoint(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	_, _, _, uID, _ := setupTestVPNService(t, db)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	// Ensure env vars are cleared initially
	t.Setenv("VPN_PUBLIC_ENDPOINT", "")
	t.Setenv("PUBLIC_ENDPOINT", "")
	t.Setenv("PUBLIC_IP", "")

	// Case 1: PublicEndpoint carries host:port — used verbatim.
	cfg1, err := svc.GetConfig(ctx)
	if err != nil {
		t.Fatalf("GetConfig failed: %v", err)
	}
	cfg1.PublicEndpoint = "vpn.example.com:51820"
	if err := svc.UpdateConfig(ctx, cfg1); err != nil {
		t.Fatalf("UpdateConfig failed: %v", err)
	}
	cfgStr1, _, err := svc.GenerateClientConfig(ctx, uID)
	if err != nil {
		t.Fatalf("GenerateClientConfig failed: %v", err)
	}
	if !strings.Contains(cfgStr1, "Endpoint = vpn.example.com:51820") {
		t.Errorf("expected Endpoint = vpn.example.com:51820, got: %s", cfgStr1)
	}

	// Case 2: bare host — configured ListenPort is appended.
	cfg2, _ := svc.GetConfig(ctx)
	cfg2.PublicEndpoint = "vpn.example.com"
	cfg2.ListenPort = 51821
	if err := svc.UpdateConfig(ctx, cfg2); err != nil {
		t.Fatalf("UpdateConfig failed: %v", err)
	}
	cfgStr2, _, err := svc.GenerateClientConfig(ctx, uID)
	if err != nil {
		t.Fatalf("GenerateClientConfig failed: %v", err)
	}
	if !strings.Contains(cfgStr2, "Endpoint = vpn.example.com:51821") {
		t.Errorf("expected Endpoint = vpn.example.com:51821, got: %s", cfgStr2)
	}

	// Case 3: PublicEndpoint empty, env vars set — resolution order respected.
	cfg3, _ := svc.GetConfig(ctx)
	cfg3.PublicEndpoint = ""
	cfg3.ListenPort = 51820
	if err := svc.UpdateConfig(ctx, cfg3); err != nil {
		t.Fatalf("UpdateConfig failed: %v", err)
	}

	// 3a: VPN_PUBLIC_ENDPOINT with host:port
	t.Setenv("VPN_PUBLIC_ENDPOINT", "env-vpn.example.com:51822")
	cfgStr3a, _, err := svc.GenerateClientConfig(ctx, uID)
	if err != nil {
		t.Fatalf("GenerateClientConfig failed: %v", err)
	}
	if !strings.Contains(cfgStr3a, "Endpoint = env-vpn.example.com:51822") {
		t.Errorf("expected Endpoint = env-vpn.example.com:51822 from VPN_PUBLIC_ENDPOINT, got: %s", cfgStr3a)
	}

	// 3b: PUBLIC_ENDPOINT bare host (VPN_PUBLIC_ENDPOINT unset)
	t.Setenv("VPN_PUBLIC_ENDPOINT", "")
	t.Setenv("PUBLIC_ENDPOINT", "env-portal.example.org")
	cfgStr3b, _, err := svc.GenerateClientConfig(ctx, uID)
	if err != nil {
		t.Fatalf("GenerateClientConfig failed: %v", err)
	}
	if !strings.Contains(cfgStr3b, "Endpoint = env-portal.example.org:51820") {
		t.Errorf("expected Endpoint = env-portal.example.org:51820 from PUBLIC_ENDPOINT, got: %s", cfgStr3b)
	}

	// 3c: PUBLIC_IP (VPN_PUBLIC_ENDPOINT and PUBLIC_ENDPOINT unset)
	t.Setenv("PUBLIC_ENDPOINT", "")
	t.Setenv("PUBLIC_IP", "198.18.0.99")
	cfgStr3c, _, err := svc.GenerateClientConfig(ctx, uID)
	if err != nil {
		t.Fatalf("GenerateClientConfig failed: %v", err)
	}
	if !strings.Contains(cfgStr3c, "Endpoint = 198.18.0.99:51820") {
		t.Errorf("expected Endpoint = 198.18.0.99:51820 from PUBLIC_IP, got: %s", cfgStr3c)
	}

	// Case 4: PublicEndpoint empty and no env var — auto-detected local/outbound IP,
	// and NEVER matches any backend server from db.GetAllServers().
	t.Setenv("PUBLIC_IP", "")
	cfgStr4, _, err := svc.GenerateClientConfig(ctx, uID)
	if err != nil {
		t.Fatalf("GenerateClientConfig failed: %v", err)
	}

	// Assert it never matches backend servers seeded in setupTestVPNService
	servers, err := db.GetAllServers(ctx)
	if err != nil {
		t.Fatalf("GetAllServers failed: %v", err)
	}
	if len(servers) == 0 {
		t.Fatal("expected test servers to exist in db")
	}
	for _, srv := range servers {
		if srv.Host != "" && strings.Contains(cfgStr4, "Endpoint = "+srv.Host) {
			t.Errorf("critical defect: client endpoint matched backend server host %s! Generated config:\n%s", srv.Host, cfgStr4)
		}
	}

	// Assert it resolved to a valid host:port format with listenPort 51820
	if !strings.Contains(cfgStr4, ":51820") {
		t.Errorf("expected config to contain listen port :51820, got: %s", cfgStr4)
	}
}

func TestGenerateClientConfig_AutoDetectFallbackAndCaching(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	_, _, _, uID, _ := setupTestVPNService(t, db)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	t.Setenv("VPN_PUBLIC_ENDPOINT", "")
	t.Setenv("PUBLIC_ENDPOINT", "")
	t.Setenv("PUBLIC_IP", "")

	// Mock external detector to fail and force the UDP-dial fallback onto a
	// private (container-local) address: per issue #71 the fallback must
	// reject non-public results and land on 127.0.0.1 instead of caching
	// the private IP for the process lifetime.
	origDetector := externalIPDetector
	origDial := outboundDial
	defer func() {
		externalIPDetector = origDetector
		outboundDial = origDial
	}()
	externalIPDetector = func(ctx context.Context) string {
		return ""
	}
	outboundDial = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return &fakeUDPConn{addr: &net.UDPAddr{IP: net.IPv4(172, 19, 0, 3), Port: 51820}}, nil
	}

	cfg, _ := svc.GetConfig(ctx)
	cfg.PublicEndpoint = ""
	cfg.ListenPort = 51820
	_ = svc.UpdateConfig(ctx, cfg)

	cfgStr, _, err := svc.GenerateClientConfig(ctx, uID)
	if err != nil {
		t.Fatalf("GenerateClientConfig failed: %v", err)
	}
	// Issue #71: the private UDP-dial result must be rejected, so the
	// endpoint falls back to the loopback default instead of the
	// container-local address.
	if !strings.Contains(cfgStr, "127.0.0.1:51820") {
		t.Errorf("expected fallback endpoint 127.0.0.1:51820, got: %s", cfgStr)
	}

	// Verify the non-public result is NOT cached on svc (issue #71: only
	// validated public IPs are cached, so the next resolve retries
	// detection instead of pinning 172.19.0.3 for the process lifetime).
	svc.publicIPMu.RLock()
	cached := svc.detectedPublicIP
	svc.publicIPMu.RUnlock()
	if cached != "" {
		t.Errorf("expected detectedPublicIP to remain empty for non-public detection, got: %q", cached)
	}
}

func TestGenerateClientConfig_NoCPSPackets(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	uID, err := db.CreateUser(ctx, &models.User{
		Username: "charlie",
		Enabled:  true,
	})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	cfgStr, filename, err := svc.GenerateClientConfig(ctx, uID)
	if err != nil {
		t.Fatalf("GenerateClientConfig failed: %v", err)
	}

	if filename != "amnezia-portal-charlie.conf" {
		t.Errorf("unexpected filename: %s", filename)
	}

	// Issue #15: Load balancer client configs must be pure AWG 3+ and must NEVER contain I1..I5
	for _, line := range strings.Split(cfgStr, "\n") {
		trimmed := strings.TrimSpace(line)
		for _, key := range []string{"I1", "I2", "I3", "I4", "I5"} {
			if strings.HasPrefix(trimmed, key+" =") || strings.HasPrefix(trimmed, key+"=") {
				t.Errorf("GenerateClientConfig must not output CPS param %s, config:\n%s", key, cfgStr)
			}
		}
	}

	// Ensure required AWG 3+ parameters are present
	for _, key := range []string{"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4"} {
		if !strings.Contains(cfgStr, key+" =") {
			t.Errorf("GenerateClientConfig missing required AWG parameter %s, config:\n%s", key, cfgStr)
		}
	}
}

func TestGenerateUserClientConfig_AWG3_Compliance(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	uID, err := db.CreateUser(ctx, &models.User{
		Username: "dave",
		Enabled:  true,
	})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	cfgStr, filename, err := svc.GenerateUserClientConfig(ctx, uID)
	if err != nil {
		t.Fatalf("GenerateUserClientConfig failed: %v", err)
	}

	if filename != "amnezia-portal-dave.conf" {
		t.Errorf("unexpected filename: %s, want amnezia-portal-dave.conf", filename)
	}

	// Verify required sections
	if !strings.Contains(cfgStr, "[Interface]") || !strings.Contains(cfgStr, "[Peer]") {
		t.Fatalf("missing required sections in generated config:\n%s", cfgStr)
	}

	// Verify AWG 3.1 timing parameters
	rat := parseDirectiveRange(t, cfgStr, "RekeyAfterTime")
	if rat.Lo < 100 || rat.Hi > 140 {
		t.Errorf("RekeyAfterTime %s not in required range [100, 140]", rat.String())
	}

	rt := parseDirectiveRange(t, cfgStr, "RekeyTimeout")
	if rt.Lo < 4 || rt.Hi > 6 {
		t.Errorf("RekeyTimeout %s not in required range [4, 6]", rt.String())
	}
	if rt.Hi >= rat.Lo {
		t.Errorf("RekeyTimeout %s must be strictly less than RekeyAfterTime %s", rt.String(), rat.String())
	}

	rej := parseDirectiveRange(t, cfgStr, "RejectAfterTime")
	if rej.Lo < 160 || rej.Hi > 200 {
		t.Errorf("RejectAfterTime %s not in required range [160, 200]", rej.String())
	}

	kt := parseDirectiveRange(t, cfgStr, "KeepaliveTimeout")
	if kt.Lo < 8 || kt.Hi > 12 {
		t.Errorf("KeepaliveTimeout %s not in required range [8, 12]", kt.String())
	}

	mha := parseDirectiveRange(t, cfgStr, "MaxHandshakeAttempts")
	if mha.Lo < 4 || mha.Hi > 8 {
		t.Errorf("MaxHandshakeAttempts %s not in required range [4, 8]", mha.String())
	}

	pk := parseDirectiveRange(t, cfgStr, "PersistentKeepalive")
	if pk.Lo < 22 || pk.Hi > 30 {
		t.Errorf("PersistentKeepalive %s not in required range [22, 30]", pk.String())
	}

	// Verify standard AWG obfuscation parameters
	for _, key := range []string{"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4"} {
		if !strings.Contains(cfgStr, key+" =") {
			t.Errorf("missing required AWG parameter %s in config:\n%s", key, cfgStr)
		}
	}

	// Verify NO CPS packets (Issue #15)
	for _, line := range strings.Split(cfgStr, "\n") {
		trimmed := strings.TrimSpace(line)
		for _, key := range []string{"I1", "I2", "I3", "I4", "I5"} {
			if strings.HasPrefix(trimmed, key+" =") || strings.HasPrefix(trimmed, key+"=") {
				t.Errorf("Load Balancer client config must not contain %s, got:\n%s", key, cfgStr)
			}
		}
	}
}

func TestGenerateUserClientConfig_StabilityAcrossRefetches(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	uID, err := db.CreateUser(ctx, &models.User{
		Username: "alice_stable",
		Enabled:  true,
	})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	cfg1, _, err := svc.GenerateUserClientConfig(ctx, uID)
	if err != nil {
		t.Fatalf("first GenerateUserClientConfig failed: %v", err)
	}

	cfg2, _, err := svc.GenerateUserClientConfig(ctx, uID)
	if err != nil {
		t.Fatalf("second GenerateUserClientConfig failed: %v", err)
	}

	cfg3, _, err := svc.GenerateClientConfig(ctx, uID)
	if err != nil {
		t.Fatalf("third GenerateClientConfig failed: %v", err)
	}

	// Verify stability across all 3 fetches
	directives := []string{
		"RekeyAfterTime",
		"RekeyTimeout",
		"RejectAfterTime",
		"KeepaliveTimeout",
		"MaxHandshakeAttempts",
		"PersistentKeepalive",
		"PrivateKey",
	}

	for _, d := range directives {
		val1 := parseDirectiveString(t, cfg1, d)
		val2 := parseDirectiveString(t, cfg2, d)
		val3 := parseDirectiveString(t, cfg3, d)

		if val1 != val2 {
			t.Errorf("directive %s differs between fetch 1 (%s) and fetch 2 (%s)", d, val1, val2)
		}
		if val1 != val3 {
			t.Errorf("directive %s differs between fetch 1 (%s) and fetch 3 (%s)", d, val1, val3)
		}
	}

	// Verify connection record in database has ClientParams persisted
	conns, err := db.GetConnectionsByUserID(ctx, uID)
	if err != nil || len(conns) == 0 {
		t.Fatalf("failed to retrieve connections from db: %v", err)
	}
	conn := conns[0]
	if len(conn.ClientParams) == 0 {
		t.Fatalf("expected ClientParams on user connection, got empty: %+v", conn)
	}

	ratDB := fmt.Sprint(conn.ClientParams["rekey_after_time"])
	ratCfg := parseDirectiveString(t, cfg1, "RekeyAfterTime")
	if ratDB != ratCfg {
		t.Errorf("persisted RekeyAfterTime in DB (%v) does not match config (%s)", ratDB, ratCfg)
	}
}

func TestGenerateUserClientConfig_FingerprintDiversity(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	uID1, err := db.CreateUser(ctx, &models.User{Username: "client_alice", Enabled: true})
	if err != nil {
		t.Fatalf("CreateUser alice failed: %v", err)
	}
	uID2, err := db.CreateUser(ctx, &models.User{Username: "client_bob", Enabled: true})
	if err != nil {
		t.Fatalf("CreateUser bob failed: %v", err)
	}

	cfgAlice, _, err := svc.GenerateUserClientConfig(ctx, uID1)
	if err != nil {
		t.Fatalf("GenerateUserClientConfig alice failed: %v", err)
	}
	cfgBob, _, err := svc.GenerateUserClientConfig(ctx, uID2)
	if err != nil {
		t.Fatalf("GenerateUserClientConfig bob failed: %v", err)
	}

	// Compare timing parameters
	paramsAlice := []string{
		parseDirectiveString(t, cfgAlice, "RekeyAfterTime"),
		parseDirectiveString(t, cfgAlice, "RekeyTimeout"),
		parseDirectiveString(t, cfgAlice, "RejectAfterTime"),
		parseDirectiveString(t, cfgAlice, "KeepaliveTimeout"),
		parseDirectiveString(t, cfgAlice, "MaxHandshakeAttempts"),
		parseDirectiveString(t, cfgAlice, "PersistentKeepalive"),
	}

	paramsBob := []string{
		parseDirectiveString(t, cfgBob, "RekeyAfterTime"),
		parseDirectiveString(t, cfgBob, "RekeyTimeout"),
		parseDirectiveString(t, cfgBob, "RejectAfterTime"),
		parseDirectiveString(t, cfgBob, "KeepaliveTimeout"),
		parseDirectiveString(t, cfgBob, "MaxHandshakeAttempts"),
		parseDirectiveString(t, cfgBob, "PersistentKeepalive"),
	}

	identicalParams := true
	for i := range paramsAlice {
		if paramsAlice[i] != paramsBob[i] {
			identicalParams = false
			break
		}
	}

	if identicalParams {
		t.Errorf("fingerprint diversity failure: Alice and Bob generated identical timing parameters: %+v", paramsAlice)
	}

	privAlice := parseDirectiveString(t, cfgAlice, "PrivateKey")
	privBob := parseDirectiveString(t, cfgBob, "PrivateKey")
	if privAlice == privBob {
		t.Errorf("Alice and Bob generated identical PrivateKey: %s", privAlice)
	}
}

func TestGenerateUserClientConfig_HeaderProtectionAndContentPadding(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	cfg, err := svc.GetConfig(ctx)
	if err != nil {
		t.Fatalf("GetConfig failed: %v", err)
	}

	cfg.HeaderProtectionKey = "dGVzdC1oZWFkZXItcHJvdGVjdGlvbi1rZXktMTIzNDU="
	cfg.ContentPaddingAddition = "16-64"
	cfg.S1 = 4
	cfg.S2 = 6
	cfg.S3 = 8
	cfg.S4 = 10
	if err := svc.UpdateConfig(ctx, cfg); err != nil {
		t.Fatalf("UpdateConfig failed: %v", err)
	}

	uID, err := db.CreateUser(ctx, &models.User{
		Username: "eve",
		Enabled:  true,
	})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	cfgStr, _, err := svc.GenerateUserClientConfig(ctx, uID)
	if err != nil {
		t.Fatalf("GenerateUserClientConfig failed: %v", err)
	}

	// Verify HeaderProtectionKey rendered in [Interface]
	hpk := parseDirectiveString(t, cfgStr, "HeaderProtectionKey")
	if hpk != "dGVzdC1oZWFkZXItcHJvdGVjdGlvbi1rZXktMTIzNDU=" {
		t.Errorf("unexpected HeaderProtectionKey: %s", hpk)
	}

	// Verify S1..S4 >= 12 enforced due to HeaderProtectionKey
	for _, sName := range []string{"S1", "S2", "S3", "S4"} {
		sVal := parseDirectiveInt(t, cfgStr, sName)
		if sVal < 12 {
			t.Errorf("%s = %d; expected >= 12 enforced when HeaderProtectionKey is active", sName, sVal)
		}
	}

	// Verify ContentPaddingAddition rendered in [Interface]
	cpAdd := parseDirectiveString(t, cfgStr, "ContentPaddingAddition")
	if cpAdd != "16-64" {
		t.Errorf("unexpected ContentPaddingAddition: %s, want 16-64", cpAdd)
	}

	// Refetch and ensure ContentPaddingAddition remains stable
	cfgStr2, _, err := svc.GenerateUserClientConfig(ctx, uID)
	if err != nil {
		t.Fatalf("second GenerateUserClientConfig failed: %v", err)
	}
	cpAdd2 := parseDirectiveString(t, cfgStr2, "ContentPaddingAddition")
	if cpAdd2 != "16-64" {
		t.Errorf("refetched ContentPaddingAddition: %s, want 16-64", cpAdd2)
	}
}

func TestGenerateClientConfig_PortalOwnHPKey_DoesNotBleedBackend(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	// Backend server has its own HeaderProtectionKey in DB.
	backendHPKey := "YmFja2VuZC1zZXJ2ZXItaGVhZGVyLXByb3RlY3Rpb24="
	sID, err := db.CreateServer(ctx, &models.Server{
		Name: "Backend-Server-1",
		Host: "192.168.1.50",
		Protocols: map[string]any{
			"awg": map[string]any{
				"awg_params": map[string]any{
					"HeaderProtectionKey": backendHPKey,
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	// Portal VPNConfig has its OWN HeaderProtectionKey.
	portalHPKey := "cG9ydGFsLW93bi1oZWFkZXItcHJvdGVjdGlvbi1rZXk="
	portalCfg := &models.VPNConfig{
		Algorithm:           models.LBLeastConnections,
		ListenPort:          31458,
		SubnetCIDR:          "10.100.0.0/16",
		HealthThresholdMS:   500,
		MaxTotalPeers:       1000,
		MaxPeersPerBackend:  250,
		Weights:             map[int64]int{sID: 100},
		H1:                  models.DegenerateHeaderRange(1000),
		H2:                  models.DegenerateHeaderRange(2000),
		H3:                  models.DegenerateHeaderRange(3000),
		H4:                  models.DegenerateHeaderRange(4000),
		S1:                  15,
		S2:                  25,
		S3:                  15,
		S4:                  15,
		HeaderProtectionKey: portalHPKey,
	}
	if err := db.SaveVPNConfig(ctx, portalCfg); err != nil {
		t.Fatalf("SaveVPNConfig failed: %v", err)
	}

	svc, err := NewVPNService(db, portalCfg)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	uID, err := db.CreateUser(ctx, &models.User{
		Username: "client_alice",
		Enabled:  true,
	})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	cfgStr, _, err := svc.GenerateClientConfig(ctx, uID)
	if err != nil {
		t.Fatalf("GenerateClientConfig failed: %v", err)
	}

	// Must render portal's HP key
	renderedHPKey := parseDirectiveString(t, cfgStr, "HeaderProtectionKey")
	if renderedHPKey != portalHPKey {
		t.Errorf("expected portal HP key %q, got %q", portalHPKey, renderedHPKey)
	}

	// Must NOT contain backend server's HP key
	if strings.Contains(cfgStr, backendHPKey) {
		t.Errorf("client config bled backend server's HeaderProtectionKey: %s", cfgStr)
	}
}

// TestGenerateClientConfig_DNSDefaults verifies Issue #42: GenerateClientConfig emits
// AdGuard DNS (94.140.14.14, 94.140.15.15) instead of Cloudflare DNS (1.1.1.1, 1.0.0.1).
func TestGenerateClientConfig_DNSDefaults(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	uID, err := db.CreateUser(ctx, &models.User{
		Username: "dns-test-user",
		Enabled:  true,
	})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	cfgStr, filename, err := svc.GenerateClientConfig(ctx, uID)
	if err != nil {
		t.Fatalf("GenerateClientConfig failed: %v", err)
	}

	if filename != "amnezia-portal-dns-test-user.conf" {
		t.Errorf("unexpected filename: %s", filename)
	}

	expectedDNS := "DNS = 94.140.14.14, 94.140.15.15"
	if !strings.Contains(cfgStr, expectedDNS) {
		t.Errorf("GenerateClientConfig must emit %q, got:\n%s", expectedDNS, cfgStr)
	}

	for _, badDNS := range []string{"1.1.1.1", "1.0.0.1"} {
		if strings.Contains(cfgStr, badDNS) {
			t.Errorf("GenerateClientConfig must not contain deprecated DNS %s, config:\n%s", badDNS, cfgStr)
		}
	}
}

func TestGenerateClientConfigForConnection(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	uID, err := db.CreateUser(ctx, &models.User{
		Username: "targeted-user",
		Enabled:  true,
	})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	otherUID, err := db.CreateUser(ctx, &models.User{
		Username: "other-user",
		Enabled:  true,
	})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	conn := &models.UserConnection{
		ID:         "conn-targeted-1",
		UserID:     uID,
		ServerID:   0,
		Protocol:   "awg",
		ClientID:   "",
		Name:       "Targeted Laptop",
		AWGMimicry: models.AWGMimicryAuto,
		CreatedAt:  time.Now(),
	}
	if _, err := db.CreateConnection(ctx, conn); err != nil {
		t.Fatalf("CreateConnection failed: %v", err)
	}

	// 1. Success on targeted connection
	cfgStr, filename, err := svc.GenerateClientConfigForConnection(ctx, uID, conn.ID)
	if err != nil {
		t.Fatalf("GenerateClientConfigForConnection failed: %v", err)
	}
	if filename != "Targeted Laptop.conf" {
		t.Errorf("expected filename 'Targeted Laptop.conf', got %q", filename)
	}
	if !strings.Contains(cfgStr, "[Interface]") {
		t.Errorf("expected config to contain [Interface], got:\n%s", cfgStr)
	}

	// Verify DB was updated with client_id and client_params
	updated, err := db.GetConnection(ctx, conn.ID)
	if err != nil || updated == nil {
		t.Fatalf("GetConnection failed: %v", err)
	}
	if updated.ClientID == "" {
		t.Errorf("expected ClientID to be populated")
	}
	if updated.ClientParams == nil || updated.ClientParams["client_private_key"] == nil {
		t.Errorf("expected ClientParams with client_private_key")
	}

	// Subsequent call returns identical config and preserves ClientID
	cfgStr2, filename2, err := svc.GenerateClientConfigForConnection(ctx, uID, conn.ID)
	if err != nil {
		t.Fatalf("second GenerateClientConfigForConnection failed: %v", err)
	}
	if cfgStr2 != cfgStr {
		t.Errorf("expected second call to generate identical config")
	}
	if filename2 != filename {
		t.Errorf("expected identical filename")
	}

	// Verify no phantom connection created
	conns, err := db.GetConnectionsByUserID(ctx, uID)
	if err != nil {
		t.Fatalf("GetConnectionsByUserID failed: %v", err)
	}
	if len(conns) != 1 {
		t.Fatalf("expected exactly 1 connection, got %d", len(conns))
	}

	// 2. Error on non-existent connection
	if _, _, err := svc.GenerateClientConfigForConnection(ctx, uID, "non-existent"); err == nil {
		t.Errorf("expected error for non-existent connection")
	}

	// 3. Error on connection belonging to another user
	if _, _, err := svc.GenerateClientConfigForConnection(ctx, otherUID, conn.ID); err == nil {
		t.Errorf("expected error for connection belonging to another user")
	}

	// 4. Error on ServerID != 0
	serverConn := &models.UserConnection{
		ID:        "conn-server-1",
		UserID:    uID,
		ServerID:  1,
		Protocol:  "awg",
		ClientID:  "server-client-pubkey",
		Name:      "Server Connection",
		CreatedAt: time.Now(),
	}
	if _, err := db.CreateConnection(ctx, serverConn); err != nil {
		t.Fatalf("CreateConnection serverConn failed: %v", err)
	}
	if _, _, err := svc.GenerateClientConfigForConnection(ctx, uID, serverConn.ID); err == nil {
		t.Errorf("expected error for connection with ServerID != 0")
	}

	// 5. Error on non-awg protocol
	vlessConn := &models.UserConnection{
		ID:        "conn-vless-1",
		UserID:    uID,
		ServerID:  0,
		Protocol:  "vless",
		ClientID:  "vless-key",
		Name:      "VLESS Connection",
		CreatedAt: time.Now(),
	}
	if _, err := db.CreateConnection(ctx, vlessConn); err != nil {
		t.Fatalf("CreateConnection vlessConn failed: %v", err)
	}
	if _, _, err := svc.GenerateClientConfigForConnection(ctx, uID, vlessConn.ID); err == nil {
		t.Errorf("expected error for non-awg protocol")
	}
}

func TestGenerateClientConfig_NoPhantomOnExistingConnections(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	uID, err := db.CreateUser(ctx, &models.User{
		Username: "custconn-user",
		Enabled:  true,
	})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	// Create custom-named connection
	conn := &models.UserConnection{
		ID:         "conn-custom-phone",
		UserID:     uID,
		ServerID:   0,
		Protocol:   "awg",
		ClientID:   "pubkey-phone",
		Name:       "My Phone",
		AWGMimicry: models.AWGMimicryAuto,
		CreatedAt:  time.Now(),
	}
	if _, err := db.CreateConnection(ctx, conn); err != nil {
		t.Fatalf("CreateConnection failed: %v", err)
	}

	// Call GenerateClientConfig(ctx, uID)
	cfgStr, filename, err := svc.GenerateClientConfig(ctx, uID)
	if err != nil {
		t.Fatalf("GenerateClientConfig failed: %v", err)
	}
	if !strings.Contains(cfgStr, "[Interface]") {
		t.Errorf("expected config to contain [Interface]")
	}
	if filename != "amnezia-portal-custconn-user.conf" {
		t.Errorf("expected filename 'amnezia-portal-custconn-user.conf', got %q", filename)
	}

	// Verify no phantom connection created
	conns, err := db.GetConnectionsByUserID(ctx, uID)
	if err != nil {
		t.Fatalf("GetConnectionsByUserID failed: %v", err)
	}
	if len(conns) != 1 {
		t.Fatalf("expected exactly 1 connection in DB, got %d", len(conns))
	}
	if conns[0].Name != "My Phone" {
		t.Errorf("expected connection Name 'My Phone', got %q", conns[0].Name)
	}
}

func TestGenerateClientConfigRejectsSingleRemoteAWGConnection(t *testing.T) {
	db := setupTestDB(t)
	ctx := t.Context()
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	userID, err := db.CreateUser(ctx, &models.User{Username: "single-remote-awg", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	serverID, err := db.CreateServer(ctx, &models.Server{Name: "remote-awg", Host: "192.0.2.7"})
	if err != nil {
		t.Fatal(err)
	}
	const remotePeer = "single-remote-peer"
	remoteParams := map[string]any{"remote_setting": "keep"}
	remoteID, err := db.CreateConnection(ctx, &models.UserConnection{
		UserID: userID, ServerID: serverID, Protocol: "awg", ClientID: remotePeer,
		ClientParams: remoteParams,
	})
	if err != nil {
		t.Fatal(err)
	}
	if config, filename, err := svc.GenerateClientConfig(ctx, userID); err == nil {
		t.Fatalf("generated unusable portal config for remote connection: filename=%q config=%q", filename, config)
	}
	conns, err := db.GetConnectionsByUserID(ctx, userID)
	if err != nil {
		t.Fatal(err)
	}
	if len(conns) != 1 || conns[0].ID != remoteID || conns[0].ServerID != serverID || conns[0].ClientID != remotePeer || !reflect.DeepEqual(conns[0].ClientParams, remoteParams) {
		t.Fatalf("remote connection changed or portal connection was created: %+v", conns)
	}
	if _, ok := svc.ipam.GetAssignedIP(remotePeer); ok {
		t.Fatal("remote peer reserved a portal IP")
	}
}

func TestGenerateClientConfig_NoPhantomWhenUserHasRemoteServerConnections(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	uID, err := db.CreateUser(ctx, &models.User{
		Username: "remote-only-user",
		Enabled:  true,
	})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	// User has 2 remote server connections (ServerID > 0).
	server1, err := db.CreateServer(ctx, &models.Server{Name: "remote-1", Host: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	server2, err := db.CreateServer(ctx, &models.Server{Name: "remote-2", Host: "192.0.2.2"})
	if err != nil {
		t.Fatal(err)
	}
	conn1 := &models.UserConnection{
		ID:        "conn-remote-1",
		UserID:    uID,
		ServerID:  server1,
		Protocol:  "awg",
		ClientID:  "pubkey-remote-1",
		Name:      "Server 1",
		CreatedAt: time.Now(),
	}
	conn2 := &models.UserConnection{
		ID:        "conn-remote-2",
		UserID:    uID,
		ServerID:  server2,
		Protocol:  "vless",
		ClientID:  "uuid-remote-2",
		Name:      "Server 2",
		CreatedAt: time.Now().Add(time.Second),
	}
	if _, err := db.CreateConnection(ctx, conn1); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateConnection(ctx, conn2); err != nil {
		t.Fatal(err)
	}

	// Call GenerateClientConfig(ctx, uID)
	_, _, err = svc.GenerateClientConfig(ctx, uID)
	if err == nil {
		t.Fatal("generated an unpersisted load balancer configuration for a user with only remote connections")
	}

	// Verify no phantom connection was created
	conns, err := db.GetConnectionsByUserID(ctx, uID)
	if err != nil {
		t.Fatalf("GetConnectionsByUserID failed: %v", err)
	}
	if len(conns) != 2 {
		t.Fatalf("expected exactly 2 connections in DB, got %d", len(conns))
	}
	for _, c := range conns {
		if c.Name == "remote-only-user-awg" {
			t.Errorf("phantom connection remote-only-user-awg was created in DB")
		}
	}
}
