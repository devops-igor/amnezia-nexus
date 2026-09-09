package awg

// Tests for issue #27: backend NAT masquerade scoping for forwarded portal
// traffic. Portal data-plane clients use source IPs from the portal IPAM
// subnet (e.g. 10.100.0.0/16), so iptables rules scoped to the AWG subnet
// (10.8.1.1/24) never match; POSTROUTING MASQUERADE and the FORWARD accept
// rules must be interface-scoped and idempotent.

import (
	"context"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-web-ui-go/internal/models"
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

	// The old subnet-scoped POSTROUTING rule must be gone.
	if strings.Contains(script, "POSTROUTING") && strings.Contains(script, "-s 10.8.1.1") {
		t.Errorf("start.sh still contains subnet-scoped POSTROUTING rule:\n%s", script)
	}
	for _, line := range strings.Split(script, "\n") {
		if strings.Contains(line, "-t nat") && strings.Contains(line, "POSTROUTING") && strings.Contains(line, "-s ") {
			t.Errorf("start.sh POSTROUTING rule is still source-scoped: %q", line)
		}
	}

	// FORWARD accept path must remain, including the interface-scoped rule.
	if !strings.Contains(script, "iptables -A FORWARD -i awg0 -j ACCEPT") {
		t.Errorf("start.sh missing 'iptables -A FORWARD -i awg0 -j ACCEPT':\n%s", script)
	}
	if !strings.Contains(script, "iptables -A FORWARD -i awg0 -o eth0 -j ACCEPT") {
		t.Errorf("start.sh missing interface-scoped FORWARD rule for portal traffic:\n%s", script)
	}
	for _, line := range strings.Split(script, "\n") {
		if strings.Contains(line, "FORWARD") && strings.Contains(line, "-i awg0 -o eth0") && strings.Contains(line, "-s ") {
			t.Errorf("start.sh FORWARD awg0->eth0 rule is still source-scoped: %q", line)
		}
	}
}

// TestEnsureBackendNATRule_CommandsAndValidation verifies the live-remediation
// helper: container name validation, the exact iptables commands issued
// (idempotent -C || -A for both MASQUERADE and FORWARD), and error propagation.
func TestEnsureBackendNATRule_CommandsAndValidation(t *testing.T) {
	ctx := context.Background()

	t.Run("issues idempotent rules and succeeds", func(t *testing.T) {
		client := newMockAWGSSHClient()
		var cmds []string
		client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
			if strings.Contains(cmd, "iptables") {
				cmds = append(cmds, cmd)
				return "", "", 0, nil
			}
			return "", "", 0, nil
		}
		mgr := NewAWGManager(&mockAWGSSHProvider{client: client})

		if err := mgr.ensureBackendNATRule(ctx, client); err != nil {
			t.Fatalf("ensureBackendNATRule failed: %v", err)
		}

		if len(cmds) != 2 {
			t.Fatalf("expected 2 iptables commands, got %d: %v", len(cmds), cmds)
		}
		natCmd := cmds[0]
		if !strings.Contains(natCmd, "docker exec amnezia-awg bash -c 'iptables -t nat -C POSTROUTING -o eth0 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE'") {
			t.Errorf("unexpected NAT command: %s", natCmd)
		}
		fwdCmd := cmds[1]
		if !strings.Contains(fwdCmd, "iptables -C FORWARD -i awg0 -o eth0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i awg0 -o eth0 -j ACCEPT") {
			t.Errorf("unexpected FORWARD command: %s", fwdCmd)
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

		err := mgr.ensureBackendNATRule(ctx, client)
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
			if strings.Contains(cmd, "iptables") {
				return "", "", 0, context.DeadlineExceeded
			}
			return "", "", 0, nil
		}
		mgr := NewAWGManager(&mockAWGSSHProvider{client: client})

		if err := mgr.ensureBackendNATRule(ctx, client); err == nil {
			t.Fatal("expected error when command fails, got nil")
		}
	})
}

// TestAddClient_EnsuresBackendNATRule verifies the EnableBackend data path:
// AddClient (invoked by EnableBackend for the "Portal Data Plane" peer) must
// call the NAT-ensure helper with a validated container name.
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
	if !strings.Contains(natCmds[0], "docker exec amnezia-awg bash -c 'iptables -t nat") {
		t.Errorf("NAT command should run inside the resolved container: %s", natCmds[0])
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
