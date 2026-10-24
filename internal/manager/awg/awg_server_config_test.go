package awg

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestAWGManager_SaveServerConfig_SyncconfFailure_ReturnsError(t *testing.T) {
	ctx := context.Background()
	mockClient := newMockAWGSSHClient()

	mockClient.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		if strings.Contains(cmd, "syncconf") {
			return "", "Line unrecognized: `DisableCookies = on`", 1, errors.New("exit status 1")
		}
		if strings.Contains(cmd, "cat") && strings.Contains(cmd, "awg0.conf") {
			return string(mockClient.files["/opt/amnezia/awg/awg0.conf"]), "", 0, nil
		}
		if strings.Contains(cmd, "cat") && strings.Contains(cmd, "clientsTable") {
			return string(mockClient.files["/opt/amnezia/awg/clientsTable"]), "", 0, nil
		}
		if strings.Contains(cmd, "wireguard_server_public_key.key") {
			return string(mockClient.files["/opt/amnezia/awg/wireguard_server_public_key.key"]), "", 0, nil
		}
		if strings.Contains(cmd, "wireguard_psk.key") {
			return string(mockClient.files["/opt/amnezia/awg/wireguard_psk.key"]), "", 0, nil
		}
		return "OK", "", 0, nil
	}

	mgr := NewAWGManager(&mockAWGSSHProvider{client: mockClient})
	server := &models.Server{ID: 1, Host: "1.2.3.4"}

	_, err := mgr.AddClient(ctx, server, map[string]any{"name": "SyncFailClient"})
	if err == nil {
		t.Fatal("expected AddClient to fail when syncconf fails, but got nil")
	}
	if !strings.Contains(err.Error(), "sync") {
		t.Errorf("expected error to mention sync, got: %v", err)
	}
}

func TestAWGManager_SaveServerConfig_DynamicConfigPath(t *testing.T) {
	ctx := context.Background()
	mockClient := newMockAWGSSHClient()

	var copiedTarget string
	var syncCmdExecuted string

	mockClient.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		if strings.Contains(cmd, "test -f") && strings.Contains(cmd, "awg0.conf") && strings.Contains(cmd, "opt/amnezia/awg") {
			return "", "No such file", 1, errors.New("exit status 1")
		}
		if strings.Contains(cmd, "test -f") && strings.Contains(cmd, "etc/amnezia/amneziawg") {
			return "", "", 0, nil
		}
		if strings.Contains(cmd, "docker cp") && strings.Contains(cmd, "_amnz_edit_config") {
			copiedTarget = cmd
			return "", "", 0, nil
		}
		if strings.Contains(cmd, "syncconf") || strings.Contains(cmd, "awg-quick") {
			syncCmdExecuted += cmd
			return "OK", "", 0, nil
		}
		if strings.Contains(cmd, "cat ") && strings.Contains(cmd, "etc/amnezia/amneziawg/awg0.conf") {
			return string(mockClient.files["/opt/amnezia/awg/awg0.conf"]), "", 0, nil
		}
		if strings.Contains(cmd, "cat ") && strings.Contains(cmd, "opt/amnezia/awg/awg0.conf") {
			return "", "No such file", 1, errors.New("exit status 1")
		}
		if strings.Contains(cmd, "cat ") && strings.Contains(cmd, "clientsTable") {
			return string(mockClient.files["/opt/amnezia/awg/clientsTable"]), "", 0, nil
		}
		if strings.Contains(cmd, "wireguard_server_public_key.key") {
			return string(mockClient.files["/opt/amnezia/awg/wireguard_server_public_key.key"]), "", 0, nil
		}
		if strings.Contains(cmd, "wireguard_psk.key") {
			return string(mockClient.files["/opt/amnezia/awg/wireguard_psk.key"]), "", 0, nil
		}
		return "OK", "", 0, nil
	}

	mgr := NewAWGManager(&mockAWGSSHProvider{client: mockClient})
	server := &models.Server{ID: 1, Host: "1.2.3.4"}

	_, err := mgr.AddClient(ctx, server, map[string]any{"name": "DynamicPathClient"})
	if err != nil {
		t.Fatalf("AddClient failed: %v", err)
	}

	if !strings.Contains(copiedTarget, "/etc/amnezia/amneziawg/awg0.conf") {
		t.Errorf("expected config to be copied to /etc/amnezia/amneziawg/awg0.conf, got: %s", copiedTarget)
	}
	if !strings.Contains(syncCmdExecuted, "/etc/amnezia/amneziawg/awg0.conf") || !strings.Contains(syncCmdExecuted, "/etc/amnezia/amneziawg/.awg-strip-") {
		t.Errorf("expected strip of awg0.conf and syncconf of the stripped file, got: %s", syncCmdExecuted)
	}
}

func TestSaveServerConfig_SelfHealing_Success(t *testing.T) {
	ctx := context.Background()
	client := newMockAWGSSHClient()
	mgr := NewAWGManager(&mockAWGSSHProvider{client: client})

	syncAttempts := 0
	awgQuickUpCalled := false
	ipLinkShowCalled := false

	client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		if strings.Contains(cmd, "docker ps") {
			return "amnezia-awg2", "", 0, nil
		}
		if strings.Contains(cmd, "docker cp") {
			return "", "", 0, nil
		}
		if strings.Contains(cmd, "rm -f") {
			return "", "", 0, nil
		}
		if strings.Contains(cmd, "test -d") && strings.Contains(cmd, "etc/amnezia/amneziawg") {
			return "", "", 1, nil
		}
		if strings.Contains(cmd, "syncconf") {
			syncAttempts++
			if syncAttempts == 1 {
				return "", "Unable to retrieve current interface configuration: Protocol not supported", 1, nil
			}
			// Second attempt succeeds after awg-quick up
			return "OK", "", 0, nil
		}
		if strings.Contains(cmd, "ip link show") && strings.Contains(cmd, "awg0") {
			ipLinkShowCalled = true
			return "", "Device \"awg0\" does not exist.", 1, nil
		}
		if strings.Contains(cmd, "awg-quick up") {
			awgQuickUpCalled = true
			return "[#] ip link add dev awg0 type amneziawg\n[#] awg setconf awg0 ...", "", 0, nil
		}
		return "OK", "", 0, nil
	}

	err := mgr.saveServerConfig(ctx, client, "[Interface]\nPrivateKey = test\n")
	if err != nil {
		t.Fatalf("saveServerConfig should have succeeded via self-healing, got: %v", err)
	}
	if !ipLinkShowCalled {
		t.Errorf("expected ip link show to be called to check interface status")
	}
	if !awgQuickUpCalled {
		t.Errorf("expected awg-quick up to be called for self-healing")
	}
	if syncAttempts != 2 {
		t.Errorf("expected 2 syncconf attempts, got %d", syncAttempts)
	}
}

func TestSaveServerConfig_SelfHealing_AwgQuickUpFails(t *testing.T) {
	ctx := context.Background()
	client := newMockAWGSSHClient()
	mgr := NewAWGManager(&mockAWGSSHProvider{client: client})

	client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		if strings.Contains(cmd, "docker ps") {
			return "amnezia-awg2", "", 0, nil
		}
		if strings.Contains(cmd, "docker cp") {
			return "", "", 0, nil
		}
		if strings.Contains(cmd, "rm -f") {
			return "", "", 0, nil
		}
		if strings.Contains(cmd, "test -d") && strings.Contains(cmd, "etc/amnezia/amneziawg") {
			return "", "", 1, nil
		}
		if strings.Contains(cmd, "syncconf") {
			return "", "Unable to retrieve current interface configuration: Protocol not supported", 1, nil
		}
		if strings.Contains(cmd, "ip link show") && strings.Contains(cmd, "awg0") {
			return "", "Device \"awg0\" does not exist.", 1, nil
		}
		if strings.Contains(cmd, "awg-quick up") {
			return "", "S4 must be more then 12 to use headerProtection", 1, nil
		}
		return "OK", "", 0, nil
	}

	err := mgr.saveServerConfig(ctx, client, "[Interface]\nPrivateKey = test\n")
	if err == nil {
		t.Fatalf("expected saveServerConfig to fail when awg-quick up fails")
	}
	if !strings.Contains(err.Error(), "S4 must be more then 12 to use headerProtection") {
		t.Errorf("expected error to include awg-quick up output, got: %v", err)
	}
}

func TestSaveServerConfig_InterfaceAlreadyUp_NoSelfHealing(t *testing.T) {
	ctx := context.Background()
	client := newMockAWGSSHClient()
	mgr := NewAWGManager(&mockAWGSSHProvider{client: client})

	awgQuickUpCalled := false

	client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		if strings.Contains(cmd, "docker ps") {
			return "amnezia-awg2", "", 0, nil
		}
		if strings.Contains(cmd, "docker cp") {
			return "", "", 0, nil
		}
		if strings.Contains(cmd, "rm -f") {
			return "", "", 0, nil
		}
		if strings.Contains(cmd, "test -d") && strings.Contains(cmd, "etc/amnezia/amneziawg") {
			return "", "", 1, nil
		}
		if strings.Contains(cmd, "syncconf") {
			return "", "Line 15: Syntax error in peer configuration", 1, nil
		}
		if strings.Contains(cmd, "ip link show") && strings.Contains(cmd, "awg0") {
			return "5: awg0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1280 qdisc noqueue state UNKNOWN", "", 0, nil
		}
		if strings.Contains(cmd, "awg-quick up") {
			awgQuickUpCalled = true
			return "", "", 0, nil
		}
		return "OK", "", 0, nil
	}

	err := mgr.saveServerConfig(ctx, client, "[Interface]\nPrivateKey = test\n")
	if err == nil {
		t.Fatalf("expected saveServerConfig to fail")
	}
	if awgQuickUpCalled {
		t.Errorf("awg-quick up should NOT have been called when interface is already UP")
	}
	if !strings.Contains(err.Error(), "Syntax error") {
		t.Errorf("expected error to contain syncconf output, got: %v", err)
	}
}

func TestSaveServerConfig_SanitizesTableOff(t *testing.T) {
	ctx := context.Background()
	client := newMockAWGSSHClient()
	client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		return "", "", 0, nil
	}
	mgr := NewAWGManager(&mockAWGSSHProvider{client: client})

	rawConfig := `[Interface]
PrivateKey = sPriv
Address = 10.8.1.1/24
ListenPort = 55424
MTU = 1280
`
	if err := mgr.saveServerConfig(ctx, client, rawConfig); err != nil {
		t.Fatalf("saveServerConfig failed: %v", err)
	}

	var uploadedConfig string
	for path, content := range client.files {
		if strings.Contains(path, "_amnz_edit_config") {
			uploadedConfig = string(content)
			break
		}
	}
	if uploadedConfig == "" {
		t.Fatalf("expected /tmp/_amnz_edit_config_*.conf to be uploaded")
	}

	if !strings.Contains(uploadedConfig, "Table = off") {
		t.Errorf("saveServerConfig did not inject Table = off into uploaded config:\n%s", uploadedConfig)
	}
}

func TestSaveServerConfig_RejectsOverlappingHeaderRanges(t *testing.T) {
	ctx := context.Background()
	sshAttempted := false
	client := newMockAWGSSHClient()
	client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		sshAttempted = true
		return "", "", 0, nil
	}
	mgr := NewAWGManager(&mockAWGSSHProvider{client: client})

	overlappingConfig := `[Interface]
PrivateKey = sPriv
Address = 10.8.1.1/24
ListenPort = 55424
H1 = 10000000-20000000
H2 = 15000000-25000000
`
	err := mgr.saveServerConfig(ctx, client, overlappingConfig)
	if err == nil {
		t.Fatalf("expected error when saving server config with overlapping H1-H4 ranges, got nil")
	}
	if !strings.Contains(err.Error(), "overlap") {
		t.Errorf("expected error to mention 'overlap', got: %v", err)
	}
	if sshAttempted {
		t.Errorf("saveServerConfig should have failed before executing SSH commands")
	}
	for path := range client.files {
		if strings.Contains(path, "_amnz_edit_config") {
			t.Errorf("saveServerConfig should have failed before uploading config file, found: %s", path)
		}
	}
}

func TestUpsertPeerInConfig_SanitizesTableOff(t *testing.T) {
	rawConfig := `[Interface]
PrivateKey = sPriv
Address = 10.8.1.1/24
ListenPort = 55424
MTU = 1280
`
	peerSec := `[Peer]
PublicKey = newPeerPub123=
AllowedIPs = 10.100.0.0/16
`
	out, err := upsertPeerInConfig(rawConfig, peerSec)
	if err != nil {
		t.Fatalf("upsertPeerInConfig failed: %v", err)
	}

	if !strings.Contains(out, "Table = off") {
		t.Errorf("upsertPeerInConfig did not inject Table = off:\n%s", out)
	}
	if !strings.Contains(out, "PublicKey = newPeerPub123=") {
		t.Errorf("upsertPeerInConfig missing peer public key:\n%s", out)
	}
}

func TestPostRebootRoutingHijack_RegressionSimulation(t *testing.T) {
	// Models the Linux policy routing table and FIB route lookup
	type RouteRule struct {
		Priority             int
		Table                int
		HasSuppress          bool
		SuppressPrefixLength int
		FwMark               int
		InvertFw             bool
	}

	type RouteEntry struct {
		DstCIDR   string
		Dev       string
		Gateway   string
		Table     int
		IsDefault bool
	}

	type KernelFIBState struct {
		Rules  []RouteRule
		Routes []RouteEntry
	}

	lookupRoute := func(fib KernelFIBState, dstIP string) (RouteEntry, error) {
		ip := net.ParseIP(dstIP)
		if ip == nil {
			return RouteEntry{}, fmt.Errorf("invalid IP %s", dstIP)
		}

		for _, rule := range fib.Rules {
			var defaultRoute *RouteEntry
			matchedSpecific := false
			var matchedRoute RouteEntry

			// In Linux FIB lookup, specific routes take precedence over the default route
			for _, r := range fib.Routes {
				if r.Table != rule.Table {
					continue
				}
				if r.IsDefault {
					if !(rule.HasSuppress && 0 <= rule.SuppressPrefixLength) {
						rCopy := r
						defaultRoute = &rCopy
					}
					continue
				}
				_, cidrNet, err := net.ParseCIDR(r.DstCIDR)
				if err == nil && cidrNet.Contains(ip) {
					matchedSpecific = true
					matchedRoute = r
					break
				}
			}
			if matchedSpecific {
				return matchedRoute, nil
			}
			if defaultRoute != nil {
				return *defaultRoute, nil
			}
		}
		return RouteEntry{}, errors.New("network unreachable")
	}

	t.Run("patched: Table = off prevents table 51820 creation and routing loop", func(t *testing.T) {
		// 1. Generate server configuration with Table = off
		params := &AWGParams{MTU: "1280"}
		peers := []AWGPeer{
			{
				PublicKey:  "portalDataPubkey123=",
				AllowedIPs: "10.100.0.0/16", // Portal subnet, NOT 0.0.0.0/0
			},
		}
		serverConf := RenderServerConfig("srvPriv", "10.8.1.1", "24", "55424", "1280", params, peers)

		// Verify Table = off is present
		if !strings.Contains(serverConf, "Table = off") {
			t.Fatalf("server config missing Table = off:\n%s", serverConf)
		}

		// 2. Simulate awg-quick up behavior with Table = off:
		// When Table = off, awg-quick does NOT install table 51820 or any ip rules.
		// Standard container routing state:
		fib := KernelFIBState{
			Rules: []RouteRule{
				{Priority: 0, Table: 255},     // local
				{Priority: 32766, Table: 254}, // main
				{Priority: 32767, Table: 253}, // default
			},
			Routes: []RouteEntry{
				{IsDefault: true, Dev: "eth0", Gateway: "172.29.172.1", Table: 254}, // main default
				{DstCIDR: "10.100.0.0/16", Dev: "awg0", Table: 254},                 // portal return route
			},
		}

		// 3. Verify route resolution for public internet IP 8.8.8.8
		route8, err := lookupRoute(fib, "8.8.8.8")
		if err != nil {
			t.Fatalf("route lookup for 8.8.8.8 failed: %v", err)
		}
		if route8.Dev != "eth0" || route8.Table != 254 {
			t.Errorf("8.8.8.8 resolved via unexpected device/table: %+v (want eth0 table 254)", route8)
		}

		// 4. Verify route resolution for portal client 10.100.0.42
		routePortal, err := lookupRoute(fib, "10.100.0.42")
		if err != nil {
			t.Fatalf("route lookup for portal client failed: %v", err)
		}
		if routePortal.Dev != "awg0" || routePortal.Table != 254 {
			t.Errorf("portal traffic resolved via unexpected device/table: %+v (want awg0 table 254)", routePortal)
		}
	})

	t.Run("negative control: missing Table = off with 0.0.0.0/0 creates table 51820 hijack", func(t *testing.T) {
		// Simulates the exact pre-fix failure on VPN #1 and VPN #3:
		// awg-quick up installs table 51820 default route and suppress_prefixlength 0 rule
		hijackedFIB := KernelFIBState{
			Rules: []RouteRule{
				{Priority: 0, Table: 255},                                                 // local
				{Priority: 32764, Table: 51820, FwMark: 51820, InvertFw: true},            // not fwmark 51820 table 51820
				{Priority: 32765, Table: 254, HasSuppress: true, SuppressPrefixLength: 0}, // table main suppress_prefixlength 0
				{Priority: 32766, Table: 254},                                             // lookup main
			},
			Routes: []RouteEntry{
				{IsDefault: true, Dev: "eth0", Gateway: "172.29.172.1", Table: 254}, // main default
				{IsDefault: true, Dev: "awg0", Table: 51820},                        // hijacked default in table 51820
			},
		}

		// Verify 8.8.8.8 is hijacked into awg0 / table 51820
		route8, err := lookupRoute(hijackedFIB, "8.8.8.8")
		if err != nil {
			t.Fatalf("route lookup failed: %v", err)
		}
		if route8.Dev != "awg0" || route8.Table != 51820 {
			t.Errorf("expected negative control to demonstrate hijack dev awg0 table 51820, got: %+v", route8)
		}

		// Verify defensive cleanup remediates the FIB:
		// Simulate:
		//   ip -4 rule del not fwmark 51820 table 51820
		//   ip -4 rule del table main suppress_prefixlength 0
		//   ip -4 route flush table 51820
		remediatedRules := make([]RouteRule, 0)
		for _, r := range hijackedFIB.Rules {
			if r.Table == 51820 || (r.Table == 254 && r.HasSuppress) {
				continue // deleted by defensive cleanup
			}
			remediatedRules = append(remediatedRules, r)
		}
		remediatedRoutes := make([]RouteEntry, 0)
		for _, r := range hijackedFIB.Routes {
			if r.Table == 51820 {
				continue // flushed
			}
			remediatedRoutes = append(remediatedRoutes, r)
		}
		remediatedFIB := KernelFIBState{
			Rules:  remediatedRules,
			Routes: remediatedRoutes,
		}

		route8Remediated, err := lookupRoute(remediatedFIB, "8.8.8.8")
		if err != nil {
			t.Fatalf("route lookup after remediation failed: %v", err)
		}
		if route8Remediated.Dev != "eth0" || route8Remediated.Table != 254 {
			t.Errorf("after remediation 8.8.8.8 should resolve via eth0 table 254, got: %+v", route8Remediated)
		}
	})
}

func TestRemovePeerFromConfig_PrefixIsolation(t *testing.T) {
	initialConf := `[Interface]
PrivateKey = serverPrivKey1234567890123456789012345=
Address = 10.66.66.1/24
ListenPort = 51820

[Peer]
PublicKey = pubKey2=====================================
AllowedIPs = 10.66.66.2/32

[Peer]
PublicKey = pubKey20====================================
AllowedIPs = 10.66.66.20/32

[Peer]
PublicKey = pubKey200===================================
AllowedIPs = 10.66.66.200/32
`

	t.Run("remove by public key for peer .2", func(t *testing.T) {
		res := removePeerFromConfig(initialConf, "pubKey2=====================================", "")
		if strings.Contains(res, "10.66.66.2/32") || strings.Contains(res, "pubKey2=====================================") {
			t.Errorf("expected peer .2 to be removed, got:\n%s", res)
		}
		if !strings.Contains(res, "10.66.66.20/32") || !strings.Contains(res, "pubKey20====================================") {
			t.Errorf("expected peer .20 to remain untouched, got:\n%s", res)
		}
		if !strings.Contains(res, "10.66.66.200/32") || !strings.Contains(res, "pubKey200===================================") {
			t.Errorf("expected peer .200 to remain untouched, got:\n%s", res)
		}
	})

	t.Run("remove by IP only for peer .2 (prefix isolation)", func(t *testing.T) {
		res := removePeerFromConfig(initialConf, "", "10.66.66.2")
		if strings.Contains(res, "10.66.66.2/32") || strings.Contains(res, "pubKey2=====================================") {
			t.Errorf("expected peer .2 to be removed by IP, got:\n%s", res)
		}
		if !strings.Contains(res, "10.66.66.20/32") || !strings.Contains(res, "pubKey20====================================") {
			t.Errorf("expected peer .20 to remain untouched when removing .2 by IP, got:\n%s", res)
		}
		if !strings.Contains(res, "10.66.66.200/32") || !strings.Contains(res, "pubKey200===================================") {
			t.Errorf("expected peer .200 to remain untouched when removing .2 by IP, got:\n%s", res)
		}
	})

	t.Run("remove by IP for peer .20 leaving .2 and .200", func(t *testing.T) {
		res := removePeerFromConfig(initialConf, "", "10.66.66.20")
		if strings.Contains(res, "10.66.66.20/32") || strings.Contains(res, "pubKey20====================================") {
			t.Errorf("expected peer .20 to be removed by IP, got:\n%s", res)
		}
		if !strings.Contains(res, "10.66.66.2/32") || !strings.Contains(res, "pubKey2=====================================") {
			t.Errorf("expected peer .2 to remain untouched when removing .20 by IP, got:\n%s", res)
		}
		if !strings.Contains(res, "10.66.66.200/32") || !strings.Contains(res, "pubKey200===================================") {
			t.Errorf("expected peer .200 to remain untouched when removing .20 by IP, got:\n%s", res)
		}
	})
}
