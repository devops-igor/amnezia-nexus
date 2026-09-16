package awg

// Tests for issue #27 & #36: backend NAT masquerade scoping and return routing
// for forwarded portal traffic. Portal data-plane clients use source IPs from
// the portal IPAM subnet (e.g. 10.100.0.0/16), so:
// 1. A return route `ip route replace <subnet> dev awg0` must be present.
// 2. POSTROUTING MASQUERADE must cover <subnet> and egress interfaces.
// 3. FORWARD accept rules must permit <subnet> source/destination.
// 4. Loose reverse path filtering (rp_filter=2) must be set on awg0 and all.

import (
	"context"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// startScriptRenderedForTest runs initializeServerKeysAndConfig against the
// mock SSH client and returns the uploaded start.sh contents.
func startScriptRenderedForTest(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	client := newMockAWGSSHClient()
	if err := initializeServerKeysAndConfig(ctx, client, "55424", &AWGParams{MTU: "1280"}); err != nil {
		t.Fatalf("initializeServerKeysAndConfig failed: %v", err)
	}
	script, ok := client.files["/tmp/_amnz_start.sh"]
	if !ok {
		t.Fatalf("start.sh was not uploaded to /tmp/_amnz_start.sh")
	}
	return string(script)
}

func TestStartScript_InterfaceScopedMasquerade(t *testing.T) {
	script := startScriptRenderedForTest(t)

	// The interface-scoped, idempotent POSTROUTING rule must be present.
	want := "iptables -t nat -C POSTROUTING -o eth0 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE"
	if !strings.Contains(script, want) {
		t.Errorf("start.sh missing interface-scoped idempotent MASQUERADE rule.\nWant substring:\n%s\nGot:\n%s", want, script)
	}

	// The old AWG server subnet-scoped POSTROUTING rule (10.8.1.1) must be gone.
	if strings.Contains(script, "POSTROUTING") && strings.Contains(script, "-s 10.8.1.1") {
		t.Errorf("start.sh still contains subnet-scoped POSTROUTING rule:\n%s", script)
	}

	// The portal client subnet POSTROUTING rule must be present (Issue #36).
	wantPortalNat := "iptables -t nat -C POSTROUTING -s 10.100.0.0/16 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s 10.100.0.0/16 -j MASQUERADE"
	if !strings.Contains(script, wantPortalNat) && !strings.Contains(script, "iptables -t nat -A POSTROUTING -s 10.100.0.0/16 -j MASQUERADE") {
		t.Errorf("start.sh missing portal subnet POSTROUTING rule")
	}

	// The portal client return route must be present (Issue #36).
	if !strings.Contains(script, "10.100.0.0/16 dev awg0") {
		t.Errorf("start.sh missing return route for portal subnet 10.100.0.0/16 dev awg0")
	}

	// Loose reverse path filtering must be set (Issue #36).
	if !strings.Contains(script, "net.ipv4.conf.all.rp_filter=2") || !strings.Contains(script, "net.ipv4.conf.awg0.rp_filter=2") {
		t.Errorf("start.sh missing rp_filter sysctl settings")
	}

	// FORWARD accept path must remain, including the interface-scoped and portal subnet rules.
	if !strings.Contains(script, "iptables -A FORWARD -i awg0 -j ACCEPT") {
		t.Errorf("start.sh missing 'iptables -A FORWARD -i awg0 -j ACCEPT':\n%s", script)
	}
	if !strings.Contains(script, "iptables -A FORWARD -i awg0 -o eth0 -j ACCEPT") {
		t.Errorf("start.sh missing interface-scoped FORWARD rule for portal traffic:\n%s", script)
	}
	if !strings.Contains(script, "-s 10.100.0.0/16 -j ACCEPT") || !strings.Contains(script, "-d 10.100.0.0/16 -j ACCEPT") {
		t.Errorf("start.sh missing FORWARD rules for portal subnet")
	}

	// TCPMSS clamping rule must be present for HTTP/2 and PMTU compatibility
	if !strings.Contains(script, "TCPMSS --clamp-mss-to-pmtu") {
		t.Errorf("start.sh missing TCPMSS clamp-mss-to-pmtu rule:\n%s", script)
	}

	// Defensive cleanup of stale table 51820 policy routing rules and route table
	if !strings.Contains(script, "ip -4 rule del not fwmark 51820 table 51820") {
		t.Errorf("start.sh missing 'ip -4 rule del not fwmark 51820 table 51820' defensive cleanup:\n%s", script)
	}
	if !strings.Contains(script, "ip -4 rule del table main suppress_prefixlength 0") {
		t.Errorf("start.sh missing 'ip -4 rule del table main suppress_prefixlength 0' defensive cleanup:\n%s", script)
	}
	if !strings.Contains(script, "ip -4 route flush table 51820") {
		t.Errorf("start.sh missing 'ip -4 route flush table 51820' defensive cleanup:\n%s", script)
	}
}

// TestEnsureBackendRoutingAndNAT_CommandsAndValidation verifies the live-remediation
// helper: container name validation, CIDR defaulting & validation, the exact commands issued
// (ip route, iptables NAT/FORWARD, and sysctl rp_filter), and error propagation.
func TestEnsureBackendRoutingAndNAT_CommandsAndValidation(t *testing.T) {
	ctx := context.Background()

	t.Run("issues all required routing, nat, forward, and sysctl rules with default subnet", func(t *testing.T) {
		client := newMockAWGSSHClient()
		var cmds []string
		client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
			cmds = append(cmds, cmd)
			return "", "", 0, nil
		}
		mgr := NewAWGManager(&mockAWGSSHProvider{client: client})

		if err := mgr.ensureBackendRoutingAndNAT(ctx, client, ""); err != nil {
			t.Fatalf("ensureBackendRoutingAndNAT failed: %v", err)
		}

		joined := strings.Join(cmds, "\n")

		// Verify return route command
		if !strings.Contains(joined, "ip route replace 10.100.0.0/16 dev awg0") {
			t.Errorf("missing return route command in: %s", joined)
		}

		// Verify NAT masquerade commands (both subnet-scoped and interface-scoped, with top-priority insertion)
		if !strings.Contains(joined, "iptables -t nat -C POSTROUTING -s 10.100.0.0/16 -j MASQUERADE") {
			t.Errorf("missing subnet-scoped POSTROUTING MASQUERADE rule in: %s", joined)
		}
		if !strings.Contains(joined, "iptables -t nat -I POSTROUTING 1 -s 10.100.0.0/16 -o eth0 -j MASQUERADE") {
			t.Errorf("missing top-priority eth0 POSTROUTING MASQUERADE rule in: %s", joined)
		}
		if !strings.Contains(joined, "iptables -t nat -I POSTROUTING 1 -s 10.100.0.0/16 -o eth1 -j MASQUERADE") {
			t.Errorf("missing top-priority eth1 POSTROUTING MASQUERADE rule in: %s", joined)
		}
		if !strings.Contains(joined, "iptables -t nat -C POSTROUTING -o eth0 -j MASQUERADE") {
			t.Errorf("missing eth0 POSTROUTING MASQUERADE rule in: %s", joined)
		}
		if !strings.Contains(joined, "! -o amn0 -j MASQUERADE") {
			t.Errorf("missing host-level defense-in-depth MASQUERADE rule in: %s", joined)
		}

		// Verify FORWARD rules (subnet -s and -d, and awg0->eth0)
		if !strings.Contains(joined, "iptables -C FORWARD -s 10.100.0.0/16 -j ACCEPT") {
			t.Errorf("missing FORWARD -s 10.100.0.0/16 rule in: %s", joined)
		}
		if !strings.Contains(joined, "iptables -C FORWARD -d 10.100.0.0/16 -j ACCEPT") {
			t.Errorf("missing FORWARD -d 10.100.0.0/16 rule in: %s", joined)
		}
		if !strings.Contains(joined, "iptables -C FORWARD -i awg0 -o eth0 -j ACCEPT") {
			t.Errorf("missing FORWARD -i awg0 -o eth0 rule in: %s", joined)
		}

		// Verify TCPMSS clamping rule
		if !strings.Contains(joined, "iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu") {
			t.Errorf("missing TCPMSS clamp-mss-to-pmtu rule in: %s", joined)
		}

		// Verify rp_filter sysctl commands
		if !strings.Contains(joined, "net.ipv4.conf.all.rp_filter=2") || !strings.Contains(joined, "net.ipv4.conf.awg0.rp_filter=2") {
			t.Errorf("missing rp_filter sysctl in: %s", joined)
		}

		// Verify defensive cleanup of stale table 51820 rules
		if !strings.Contains(joined, "ip -4 rule del not fwmark 51820 table 51820") {
			t.Errorf("missing defensive cleanup of 'not fwmark 51820 table 51820' in: %s", joined)
		}
		if !strings.Contains(joined, "ip -4 rule del table main suppress_prefixlength 0") {
			t.Errorf("missing defensive cleanup of 'table main suppress_prefixlength 0' in: %s", joined)
		}
		if !strings.Contains(joined, "ip -4 route flush table 51820") {
			t.Errorf("missing defensive cleanup of 'ip -4 route flush table 51820' in: %s", joined)
		}
	})

	t.Run("uses custom subnet CIDR when specified", func(t *testing.T) {
		client := newMockAWGSSHClient()
		var cmds []string
		client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
			cmds = append(cmds, cmd)
			return "", "", 0, nil
		}
		mgr := NewAWGManager(&mockAWGSSHProvider{client: client})

		if err := mgr.ensureBackendRoutingAndNAT(ctx, client, "10.200.0.0/16"); err != nil {
			t.Fatalf("ensureBackendRoutingAndNAT with custom subnet failed: %v", err)
		}

		joined := strings.Join(cmds, "\n")
		if !strings.Contains(joined, "10.200.0.0/16") {
			t.Errorf("expected commands to use custom subnet 10.200.0.0/16, got: %s", joined)
		}
		if strings.Contains(joined, "10.100.0.0/16") {
			t.Errorf("custom subnet run should not contain default subnet, got: %s", joined)
		}
	})

	t.Run("rejects invalid subnet CIDR", func(t *testing.T) {
		client := newMockAWGSSHClient()
		mgr := NewAWGManager(&mockAWGSSHProvider{client: client})

		err := mgr.ensureBackendRoutingAndNAT(ctx, client, "not-a-valid-cidr")
		if err == nil {
			t.Fatal("expected error for invalid CIDR, got nil")
		}
		if !strings.Contains(err.Error(), "invalid subnet CIDR") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("resolves dynamic container name like amnezia-awg2", func(t *testing.T) {
		client := newMockAWGSSHClient()
		var cmds []string
		client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
			if strings.Contains(cmd, "name=^amnezia-awg2$") {
				return "amnezia-awg2\n", "", 0, nil
			}
			if strings.Contains(cmd, "docker ps") {
				return "", "", 0, nil
			}
			cmds = append(cmds, cmd)
			return "", "", 0, nil
		}
		mgr := NewAWGManager(&mockAWGSSHProvider{client: client})

		if err := mgr.ensureBackendRoutingAndNAT(ctx, client, ""); err != nil {
			t.Fatalf("ensureBackendRoutingAndNAT failed: %v", err)
		}

		if len(cmds) == 0 {
			t.Fatal("no commands executed")
		}
		for _, cmd := range cmds {
			if strings.Contains(cmd, "docker exec") && !strings.Contains(cmd, "docker exec amnezia-awg2") {
				t.Errorf("expected container command to target amnezia-awg2, got: %s", cmd)
			}
		}
	})

	t.Run("propagates nonzero exit code", func(t *testing.T) {
		client := newMockAWGSSHClient()
		client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
			if strings.Contains(cmd, "iptables") {
				return "", "iptables: Permission denied", 3, nil
			}
			return "", "", 0, nil
		}
		mgr := NewAWGManager(&mockAWGSSHProvider{client: client})

		err := mgr.ensureBackendRoutingAndNAT(ctx, client, "")
		if err == nil {
			t.Fatal("expected error on nonzero exit code, got nil")
		}
		if !strings.Contains(err.Error(), "code 3") {
			t.Errorf("error should include exit code, got: %v", err)
		}
	})

	t.Run("propagates command error", func(t *testing.T) {
		client := newMockAWGSSHClient()
		client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
			if strings.Contains(cmd, "ip route") {
				return "", "", 0, context.DeadlineExceeded
			}
			return "", "", 0, nil
		}
		mgr := NewAWGManager(&mockAWGSSHProvider{client: client})

		if err := mgr.ensureBackendRoutingAndNAT(ctx, client, ""); err == nil {
			t.Fatal("expected error when command fails, got nil")
		}
	})

	t.Run("EnsureBackendRoutingAndNAT exported method succeeds with server", func(t *testing.T) {
		client := newMockAWGSSHClient()
		var cmds []string
		client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
			cmds = append(cmds, cmd)
			return "", "", 0, nil
		}
		mgr := NewAWGManager(&mockAWGSSHProvider{client: client})
		server := &models.Server{ID: 10, Host: "10.0.0.10", SSHPort: 22, SSHUser: "root"}

		if err := mgr.EnsureBackendRoutingAndNAT(ctx, server, "10.150.0.0/16"); err != nil {
			t.Fatalf("EnsureBackendRoutingAndNAT failed: %v", err)
		}

		joined := strings.Join(cmds, "\n")
		if !strings.Contains(joined, "10.150.0.0/16") {
			t.Errorf("expected EnsureBackendRoutingAndNAT to use subnet 10.150.0.0/16, got: %s", joined)
		}
	})
}

// TestEnsureBackendNATRule_Compatibility verifies the backward-compatibility wrapper.
func TestEnsureBackendNATRule_Compatibility(t *testing.T) {
	ctx := context.Background()
	client := newMockAWGSSHClient()
	var cmds []string
	client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		cmds = append(cmds, cmd)
		return "", "", 0, nil
	}
	mgr := NewAWGManager(&mockAWGSSHProvider{client: client})

	if err := mgr.ensureBackendNATRule(ctx, client); err != nil {
		t.Fatalf("ensureBackendNATRule failed: %v", err)
	}

	joined := strings.Join(cmds, "\n")
	if !strings.Contains(joined, "ip route replace 10.100.0.0/16 dev awg0") {
		t.Errorf("wrapper should execute return route, got: %s", joined)
	}
	if !strings.Contains(joined, "iptables -t nat -C POSTROUTING -s 10.100.0.0/16 -j MASQUERADE") {
		t.Errorf("wrapper should execute subnet NAT, got: %s", joined)
	}
}

// TestAddClient_EnsuresBackendNATRule verifies the EnableBackend data path:
// AddClient (invoked by EnableBackend for the "Portal Data Plane" peer) must
// call the NAT/routing ensure helper with a validated container name.
func TestAddClient_EnsuresBackendNATRule(t *testing.T) {
	ctx := context.Background()
	client := newMockAWGSSHClient()
	var natCmds []string
	client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		if strings.Contains(cmd, "iptables -t nat -C POSTROUTING") {
			natCmds = append(natCmds, cmd)
			return "", "", 0, nil
		}
		return defaultMockSudo(client, cmd)
	}
	mgr := NewAWGManager(&mockAWGSSHProvider{client: client})

	server := &models.Server{ID: 6, Host: "10.0.0.6", SSHPort: 22, SSHUser: "root"}
	// Mirrors the clientParams EnableBackend uses for the portal data plane.
	params := map[string]any{
		"clientName":  "Portal Data Plane",
		"public_key":  "portalDataPlanePublicKeyThatIsLongEnoughToBeValidAAA=",
		"allowed_ips": "0.0.0.0/0",
	}
	if _, err := mgr.AddClient(ctx, server, params); err != nil {
		t.Fatalf("AddClient failed: %v", err)
	}

	if len(natCmds) == 0 {
		t.Fatal("AddClient did not issue the backend NAT ensure command")
	}
	if !strings.Contains(natCmds[0], "docker exec amnezia-awg2") || !strings.Contains(natCmds[0], "iptables -t nat") {
		t.Errorf("NAT command should run inside the resolved container: %s", natCmds[0])
	}
}

// TestAddClient_EnsuresBackendNATRule_LegacyContainer verifies that legacy servers
// with amnezia-awg containers continue to execute NAT rules inside amnezia-awg.
func TestAddClient_EnsuresBackendNATRule_LegacyContainer(t *testing.T) {
	ctx := context.Background()
	client := newMockAWGSSHClient()
	var natCmds []string
	client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		if strings.Contains(cmd, "docker ps --filter name=^amnezia-awg$") {
			return "amnezia-awg\n", "", 0, nil
		}
		if strings.Contains(cmd, "docker ps --filter name=^amnezia-awg2$") {
			return "", "", 0, nil
		}
		if strings.Contains(cmd, "iptables -t nat -C POSTROUTING") {
			natCmds = append(natCmds, cmd)
			return "", "", 0, nil
		}
		return defaultMockSudo(client, cmd)
	}
	mgr := NewAWGManager(&mockAWGSSHProvider{client: client})

	server := &models.Server{ID: 8, Host: "10.0.0.8", SSHPort: 22, SSHUser: "root"}
	params := map[string]any{
		"clientName":  "Portal Data Plane",
		"public_key":  "portalDataPlanePublicKeyThatIsLongEnoughToBeValidAAA=",
		"allowed_ips": "0.0.0.0/0",
	}
	if _, err := mgr.AddClient(ctx, server, params); err != nil {
		t.Fatalf("AddClient failed: %v", err)
	}

	if len(natCmds) == 0 {
		t.Fatal("AddClient did not issue the backend NAT ensure command")
	}
	if !strings.Contains(natCmds[0], "docker exec amnezia-awg") || !strings.Contains(natCmds[0], "iptables -t nat") {
		t.Errorf("NAT command should run inside legacy resolved container amnezia-awg: %s", natCmds[0])
	}
}

// defaultMockSudo delegates to the mock's built-in command handling.
func defaultMockSudo(client *mockAWGSSHClient, cmd string) (string, string, int, error) {
	saved := client.sudoCmdHandler
	client.sudoCmdHandler = nil
	defer func() { client.sudoCmdHandler = saved }()
	return client.RunSudoCommand(context.Background(), cmd)
}

// TestAddClient_NATRuleFailureFailsLoudly verifies AddClient surfaces NAT
// ensure failures instead of silently registering a peer with broken egress.
func TestAddClient_NATRuleFailureFailsLoudly(t *testing.T) {
	ctx := context.Background()
	client := newMockAWGSSHClient()
	client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		if strings.Contains(cmd, "iptables -t nat -C POSTROUTING") {
			return "", "bash: iptables: command not found", 127, nil
		}
		return defaultMockSudo(client, cmd)
	}
	mgr := NewAWGManager(&mockAWGSSHProvider{client: client})

	server := &models.Server{ID: 7, Host: "10.0.0.7", SSHPort: 22, SSHUser: "root"}
	params := map[string]any{
		"clientName": "Portal Data Plane",
		"public_key": "portalDataPlanePublicKeyThatIsLongEnoughToBeValidAAA=",
	}
	_, err := mgr.AddClient(ctx, server, params)
	if err == nil {
		t.Fatal("expected AddClient to fail when NAT rule cannot be ensured")
	}
	if !strings.Contains(err.Error(), "failed to ensure backend NAT rules") {
		t.Errorf("error should wrap the NAT ensure failure, got: %v", err)
	}
}

// TestAddClient_ProbePeerBypassesNATRule verifies that health probe peers bypass
// backend NAT and routing rule application in AddClient, avoiding redundant SSH roundtrips.
func TestAddClient_ProbePeerBypassesNATRule(t *testing.T) {
	ctx := context.Background()
	client := newMockAWGSSHClient()
	var executedCmds []string
	client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		executedCmds = append(executedCmds, cmd)
		return defaultMockSudo(client, cmd)
	}
	mgr := NewAWGManager(&mockAWGSSHProvider{client: client})
	server := &models.Server{ID: 12, Host: "10.0.0.12", SSHPort: 22, SSHUser: "root"}

	_, proberPub := testProberKeypair(t)
	params := map[string]any{
		"clientName": "Health Probe",
		"public_key": proberPub,
	}

	res, err := mgr.AddClient(ctx, server, params)
	if err != nil {
		t.Fatalf("AddClient failed for probe peer: %v", err)
	}
	if res["client_id"] != proberPub {
		t.Fatalf("expected client_id %s, got %v", proberPub, res["client_id"])
	}

	// Verify that no NAT or routing commands were executed
	for _, cmd := range executedCmds {
		if strings.Contains(cmd, "iptables") || strings.Contains(cmd, "ip route replace") || strings.Contains(cmd, "rp_filter") {
			t.Errorf("probe peer registration should not execute NAT/routing commands, got: %s", cmd)
		}
	}
}

// TestEnsureBackendRoutingAndNAT_BatchedCompoundExecution verifies that ensureBackendRoutingAndNAT
// combines the 11 container routing/NAT rules into a single compound bash invocation.
func TestEnsureBackendRoutingAndNAT_BatchedCompoundExecution(t *testing.T) {
	ctx := context.Background()
	client := newMockAWGSSHClient()
	var dockerExecCmds []string
	client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		if strings.Contains(cmd, "docker exec") {
			dockerExecCmds = append(dockerExecCmds, cmd)
		}
		return "", "", 0, nil
	}
	mgr := NewAWGManager(&mockAWGSSHProvider{client: client})

	if err := mgr.ensureBackendRoutingAndNAT(ctx, client, "10.100.0.0/16"); err != nil {
		t.Fatalf("ensureBackendRoutingAndNAT failed: %v", err)
	}

	// Exactly 1 compound docker exec command should be executed for container rules
	if len(dockerExecCmds) != 1 {
		t.Fatalf("expected exactly 1 docker exec command for container rules, got %d:\n%s", len(dockerExecCmds), strings.Join(dockerExecCmds, "\n"))
	}

	cmd := dockerExecCmds[0]
	// Verify it targets resolved container amnezia-awg2
	if !strings.Contains(cmd, "docker exec amnezia-awg2 bash -c '") {
		t.Errorf("expected command to target amnezia-awg2 via bash -c, got: %s", cmd)
	}

	// Verify the compound command includes defensive cleanup and all 11 routing/NAT/forward rules joined with " && "
	rulesExpected := []string{
		"ip -4 rule del not fwmark 51820 table 51820",
		"ip -4 rule del table main suppress_prefixlength 0",
		"ip -4 route flush table 51820",
		"ip route replace 10.100.0.0/16 dev awg0",
		"iptables -t nat -C POSTROUTING -s 10.100.0.0/16 -o eth0 -j MASQUERADE",
		"iptables -t nat -C POSTROUTING -s 10.100.0.0/16 -o eth1 -j MASQUERADE",
		"iptables -t nat -C POSTROUTING -s 10.100.0.0/16 -j MASQUERADE",
		"iptables -t nat -C POSTROUTING -o eth0 -j MASQUERADE",
		"iptables -t nat -C POSTROUTING -o eth1 -j MASQUERADE",
		"iptables -C FORWARD -s 10.100.0.0/16 -j ACCEPT",
		"iptables -C FORWARD -d 10.100.0.0/16 -j ACCEPT",
		"iptables -C FORWARD -i awg0 -o eth0 -j ACCEPT",
		"iptables -C FORWARD -i awg0 -o eth1 -j ACCEPT",
		"iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu",
		"net.ipv4.conf.all.rp_filter=2",
		"net.ipv4.conf.awg0.rp_filter=2",
	}
	for _, expected := range rulesExpected {
		if !strings.Contains(cmd, expected) {
			t.Errorf("compound command missing expected rule element %q in: %s", expected, cmd)
		}
	}
}
