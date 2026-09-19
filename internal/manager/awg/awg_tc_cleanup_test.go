package awg

import (
	"context"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// TestCleanupLegacyTcRules_CommandSequence pins the exact, unconditional
// cleanup command sequence executed on the remote host. Backdrop (PR #231
// re-review): the speed-limit removal (74b34d9) deleted the tc control plane
// but NOT remote data-plane state, so containers installed by the old code may
// still enforce invisible HTB qdiscs/filters/ifb0 rules with no UI/API left to
// clear them. Order matters: the qdisc on ifb0 is torn down before the ifb0
// link is deleted. Every command ends in `|| true` — the sweep is strictly
// best-effort and must never fail its caller.
func TestCleanupLegacyTcRules_CommandSequence(t *testing.T) {
	client := newMockAWGSSHClient()
	var cmds []string
	client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		cmds = append(cmds, cmd)
		return "", "", 0, nil
	}

	NewAWGManager(nil).CleanupLegacyTcRules(context.Background(), client, "amnezia-awg2")

	want := []string{
		`docker exec -i 'amnezia-awg2' tc qdisc del dev awg0 root 2>/dev/null || true`,
		`docker exec -i 'amnezia-awg2' tc qdisc del dev ifb0 root 2>/dev/null || true`,
		`docker exec -i 'amnezia-awg2' ip link del ifb0 2>/dev/null || true`,
	}
	if len(cmds) != len(want) {
		t.Fatalf("expected exactly %d commands, got %d: %v", len(want), len(cmds), cmds)
	}
	for i, w := range want {
		if cmds[i] != w {
			t.Errorf("command[%d] = %q, want %q", i, cmds[i], w)
		}
	}
}

// TestCleanupLegacyTcRules_InvalidContainerNameSkipsExec verifies the safety
// valve: an invalid container name must never reach the docker exec command,
// and the sweep stays silent instead of failing.
func TestCleanupLegacyTcRules_InvalidContainerNameSkipsExec(t *testing.T) {
	client := newMockAWGSSHClient()
	called := false
	client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		called = true
		return "", "", 0, nil
	}

	NewAWGManager(nil).CleanupLegacyTcRules(context.Background(), client, "bad name; rm -rf /")

	if called {
		t.Fatalf("expected no commands for an invalid container name, got: %q", "executed")
	}
}

// TestCleanupLegacyTcRules_CommandFailureReturnsError locks the retry
// contract: a failing command must surface as a returned error so the
// status-path guard leaves the server unmarked and retries on the next poll.
func TestCleanupLegacyTcRules_CommandFailureReturnsError(t *testing.T) {
	client := newMockAWGSSHClient()
	client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		return "", "connection reset", 255, context.DeadlineExceeded
	}

	err := NewAWGManager(nil).CleanupLegacyTcRules(context.Background(), client, "amnezia-awg2")
	if err == nil {
		t.Fatal("expected an error when cleanup commands fail (retry contract)")
	}
}

// TestCleanupLegacyTcRules_OncePerServer pins the once-per-server guard: the
// sweep runs exactly once per server per panel process, then the guard short
// -circuits and no further SSH commands are issued.

// TestCleanupLegacyTcRules_RetriesAfterFailure is the re-review blocker's
// regression: the tcCleaned marker must be set ONLY after a successful sweep.
// A first failed cleanup (SSH error) leaves the server unmarked so the next
// status poll retries; a subsequent successful sweep marks it done.
func TestCleanupLegacyTcRules_RetriesAfterFailure(t *testing.T) {
	client := newMockAWGSSHClient()
	var cmds []string
	failCleanup := true
	client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		cmds = append(cmds, cmd)
		// Only the tc-cleanup commands fail on the first pass; discovery
		// and status commands must succeed so the status call completes.
		if failCleanup && (strings.Contains(cmd, "tc qdisc del") || strings.Contains(cmd, "ip link del ifb0")) {
			return "", "connection reset", 255, context.DeadlineExceeded
		}
		return "", "", 0, nil
	}
	server := &models.Server{ID: 77, Host: "10.0.0.77", SSHPort: 22, SSHUser: "root"}
	mgr := NewAWGManager(&mockAWGSSHProvider{client: client})

	// First status: cleanup fails -> server stays unmarked.
	if _, err := mgr.GetServerStatus(context.Background(), server); err != nil {
		t.Fatalf("first GetServerStatus failed: %v", err)
	}
	mgr.mu.Lock()
	marked := mgr.tcCleaned[server.ID]
	mgr.mu.Unlock()
	if marked {
		t.Fatal("server marked cleaned despite failed cleanup — permanent-skip bug")
	}

	// Second status with the SSH path healthy: cleanup must RUN AGAIN.
	failCleanup = false
	if _, err := mgr.GetServerStatus(context.Background(), server); err != nil {
		t.Fatalf("second GetServerStatus failed: %v", err)
	}
	mgr.mu.Lock()
	marked = mgr.tcCleaned[server.ID]
	mgr.mu.Unlock()
	if !marked {
		t.Fatal("server should be marked cleaned after a successful sweep")
	}
	if len(cmds) <= 3 {
		t.Fatalf("expected cleanup commands re-issued on retry, got %d total commands", len(cmds))
	}
}

func TestCleanupLegacyTcRules_OncePerServer(t *testing.T) {
	client := newMockAWGSSHClient()
	var cmds []string
	client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		cmds = append(cmds, cmd)
		return "", "", 0, nil
	}
	server := &models.Server{ID: 42, Host: "10.0.0.42", SSHPort: 22, SSHUser: "root"}
	mgr := NewAWGManager(&mockAWGSSHProvider{client: client})

	if _, err := mgr.GetServerStatus(context.Background(), server); err != nil {
		t.Fatalf("GetServerStatus failed: %v", err)
	}
	firstCount := len(cmds)
	if firstCount == 0 {
		t.Fatal("expected the first status call to issue SSH commands (cleanup ran)")
	}

	if _, err := mgr.GetServerStatus(context.Background(), server); err != nil {
		t.Fatalf("second GetServerStatus failed: %v", err)
	}
	// The status path itself issues discovery commands (docker ps -a for
	// container-name resolution) on every call — those must still happen.
	// The guard's contract is narrower: no tc-cleanup commands on the
	// second call.
	for _, cmd := range cmds[firstCount:] {
		if strings.Contains(cmd, "tc qdisc del") || strings.Contains(cmd, "ip link del ifb0") {
			t.Fatalf("guard leaked: tc cleanup command re-issued on second status call: %s", cmd)
		}
	}
}

// TestCleanupLegacyTcRules_OncePerServerIndependentManager verifies the guard
// is per-manager-instance (map field), not global: two managers watching the
// same server each sweep once.
func TestCleanupLegacyTcRules_OncePerServerIndependentManager(t *testing.T) {
	client := newMockAWGSSHClient()
	var cmds []string
	client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		cmds = append(cmds, cmd)
		return "", "", 0, nil
	}
	server := &models.Server{ID: 7, Host: "10.0.0.7", SSHPort: 22, SSHUser: "root"}
	mgr1 := NewAWGManager(&mockAWGSSHProvider{client: client})
	mgr2 := NewAWGManager(&mockAWGSSHProvider{client: client})

	if _, err := mgr1.GetServerStatus(context.Background(), server); err != nil {
		t.Fatalf("manager 1 status failed: %v", err)
	}
	if _, err := mgr2.GetServerStatus(context.Background(), server); err != nil {
		t.Fatalf("manager 2 status failed: %v", err)
	}

	counts := 0
	for _, cmd := range cmds {
		if strings.Contains(cmd, "tc qdisc del dev awg0 root") {
			counts++
		}
	}
	if counts != 2 {
		t.Fatalf("expected 2 sweeps (one per manager instance), got %d", counts)
	}
}
