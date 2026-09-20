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
// link is deleted. Error suppression (|| true) is moved inside the container
// shell so docker exec failures propagate to the host caller.
func TestCleanupLegacyTcRules_CommandSequence(t *testing.T) {
	client := newMockAWGSSHClient()
	var cmds []string
	client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		cmds = append(cmds, cmd)
		return "", "", 0, nil
	}

	if err := NewAWGManager(nil).CleanupLegacyTcRules(context.Background(), client, "amnezia-awg2"); err != nil {
		t.Fatalf("CleanupLegacyTcRules failed: %v", err)
	}

	want := []string{
		`docker exec -i 'amnezia-awg2' sh -c 'tc qdisc del dev awg0 root 2>/dev/null || true'`,
		`docker exec -i 'amnezia-awg2' sh -c 'tc qdisc del dev ifb0 root 2>/dev/null || true'`,
		`docker exec -i 'amnezia-awg2' sh -c 'ip link del ifb0 2>/dev/null || true'`,
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

	err := NewAWGManager(nil).CleanupLegacyTcRules(context.Background(), client, "bad name; rm -rf /")
	if err == nil {
		t.Fatal("expected error for invalid container name")
	}

	if called {
		t.Fatalf("expected no commands for an invalid container name, got: %q", "executed")
	}
}

// TestCleanupLegacyTcRules_CommandFailureReturnsError locks the retry
// contract: both SSH network errors (err != nil) and shell-level failures
// (code != 0, err == nil) must surface as returned errors so the status-path
// guard leaves the server unmarked and retries on the next poll.
func TestCleanupLegacyTcRules_CommandFailureReturnsError(t *testing.T) {
	tests := []struct {
		name    string
		handler func(cmd string) (string, string, int, error)
	}{
		{
			name: "ssh_network_error",
			handler: func(cmd string) (string, string, int, error) {
				return "", "connection reset", 255, context.DeadlineExceeded
			},
		},
		{
			name: "shell_level_failure",
			handler: func(cmd string) (string, string, int, error) {
				return "", "command failed", 1, nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newMockAWGSSHClient()
			client.sudoCmdHandler = tt.handler

			err := NewAWGManager(nil).CleanupLegacyTcRules(context.Background(), client, "amnezia-awg2")
			if err == nil {
				t.Fatal("expected an error when cleanup commands fail (retry contract)")
			}
		})
	}
}

// TestCleanupLegacyTcRules_RetriesAfterFailure is the re-review blocker's
// regression: the tcCleaned marker must be set ONLY after a successful sweep.
// A first failed cleanup (shell-level failure code: 1, err: nil) leaves the server
// unmarked so the next status poll retries; a subsequent successful sweep marks it done.
func TestCleanupLegacyTcRules_RetriesAfterFailure(t *testing.T) {
	client := newMockAWGSSHClient()
	var cmds []string
	failCleanup := true
	client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		cmds = append(cmds, cmd)
		// Only the tc-cleanup commands fail on the first pass (simulating shell failure);
		// non-cleanup commands delegate to defaultRunSudo so container discovery
		// and running checks succeed.
		if failCleanup && (strings.Contains(cmd, "tc qdisc del") || strings.Contains(cmd, "ip link del ifb0")) {
			return "", "container execution failed", 1, nil
		}
		return client.defaultRunSudo(cmd)
	}
	server := &models.Server{ID: 77, Host: "10.0.0.77", SSHPort: 22, SSHUser: "root"}
	mgr := NewAWGManager(&mockAWGSSHProvider{client: client})

	// First status: cleanup fails with exit code 1 -> server stays unmarked.
	if _, err := mgr.GetServerStatus(context.Background(), server); err != nil {
		t.Fatalf("first GetServerStatus failed: %v", err)
	}
	mgr.mu.Lock()
	marked := mgr.tcCleaned[server.ID]
	mgr.mu.Unlock()
	if marked {
		t.Fatal("server marked cleaned despite failed cleanup — permanent-skip bug")
	}

	// Second status with the execution path healthy: cleanup must RUN AGAIN.
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
		return client.defaultRunSudo(cmd)
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
		return client.defaultRunSudo(cmd)
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

// TestCleanupLegacyTcRules_StoppedOrMissingContainerSkipsCleanup verifies that
// GetServerStatus does not attempt legacy tc cleanup when the container does not exist
// or is not running, and leaves tcCleaned unmarked until the container is running.
func TestCleanupLegacyTcRules_StoppedOrMissingContainerSkipsCleanup(t *testing.T) {
	// Case 1: Container does not exist
	clientMissing := newMockAWGSSHClient()
	clientMissing.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		if strings.Contains(cmd, "docker ps -a") {
			return "", "", 0, nil // no containers exist
		}
		if strings.Contains(cmd, "tc qdisc del") || strings.Contains(cmd, "ip link del ifb0") {
			t.Fatalf("tc cleanup attempted on missing container: %s", cmd)
		}
		return clientMissing.defaultRunSudo(cmd)
	}
	serverMissing := &models.Server{ID: 88, Host: "10.0.0.88", SSHPort: 22, SSHUser: "root"}
	mgrMissing := NewAWGManager(&mockAWGSSHProvider{client: clientMissing})

	stMissing, err := mgrMissing.GetServerStatus(context.Background(), serverMissing)
	if err != nil {
		t.Fatalf("GetServerStatus failed on missing container: %v", err)
	}
	if exists, _ := stMissing["container_exists"].(bool); exists {
		t.Fatal("expected container_exists == false")
	}
	mgrMissing.mu.Lock()
	if mgrMissing.tcCleaned[serverMissing.ID] {
		t.Fatal("expected tcCleaned == false for missing container")
	}
	mgrMissing.mu.Unlock()

	// Case 2: Container exists but is stopped
	clientStopped := newMockAWGSSHClient()
	isRunning := false
	clientStopped.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		if strings.Contains(cmd, "docker ps --filter name=^") && strings.Contains(cmd, "Status") {
			if isRunning {
				return "Up 1 hour", "", 0, nil
			}
			return "Exited (0) 10 minutes ago", "", 0, nil
		}
		if strings.Contains(cmd, "tc qdisc del") || strings.Contains(cmd, "ip link del ifb0") {
			if !isRunning {
				t.Fatalf("tc cleanup attempted on stopped container: %s", cmd)
			}
		}
		return clientStopped.defaultRunSudo(cmd)
	}
	serverStopped := &models.Server{ID: 99, Host: "10.0.0.99", SSHPort: 22, SSHUser: "root"}
	mgrStopped := NewAWGManager(&mockAWGSSHProvider{client: clientStopped})

	stStopped, err := mgrStopped.GetServerStatus(context.Background(), serverStopped)
	if err != nil {
		t.Fatalf("GetServerStatus failed on stopped container: %v", err)
	}
	if running, _ := stStopped["container_running"].(bool); running {
		t.Fatal("expected container_running == false")
	}
	mgrStopped.mu.Lock()
	if mgrStopped.tcCleaned[serverStopped.ID] {
		t.Fatal("expected tcCleaned == false for stopped container")
	}
	mgrStopped.mu.Unlock()

	// Now start container and verify cleanup runs on next poll
	isRunning = true
	stRunning, err := mgrStopped.GetServerStatus(context.Background(), serverStopped)
	if err != nil {
		t.Fatalf("GetServerStatus failed on running container: %v", err)
	}
	if running, _ := stRunning["container_running"].(bool); !running {
		t.Fatal("expected container_running == true")
	}
	mgrStopped.mu.Lock()
	if !mgrStopped.tcCleaned[serverStopped.ID] {
		t.Fatal("expected tcCleaned == true after container started and cleaned")
	}
	mgrStopped.mu.Unlock()
}
