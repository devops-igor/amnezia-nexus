package awg

import (
	"context"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestIsValidContainerName(t *testing.T) {
	validNames := []string{
		"amnezia-awg",
		"amnezia-awg2",
		"amnezia-awg-legacy",
		"container.1_test",
		"my-awg-server.node",
		"A123_456",
		"awg0",
		"server-1",
		"test.container-name_v1.0",
	}
	for _, name := range validNames {
		if !IsValidContainerName(name) {
			t.Errorf("expected valid container name %q to pass validation", name)
		}
	}

	invalidNames := []string{
		"",
		"amnezia; rm -rf /",
		"amnezia`whoami`",
		"amnezia$(id)",
		"amnezia container",
		"../../etc/passwd",
		"-leading-dash",
		".leading-dot",
		"_leading-underscore",
		"container|cat",
		"container>file",
		"container&",
		"container\nnewline",
		"container'quoted'",
		"container\"quoted\"",
		"container/sub",
		"container\\sub",
		"container#comment",
		"container!bang",
	}
	for _, name := range invalidNames {
		if IsValidContainerName(name) {
			t.Errorf("expected invalid container name %q to fail validation", name)
		}
	}
}

func TestAWGManager_ContainerCaching(t *testing.T) {
	ctx := context.Background()
	var dockerPsCount int
	sID := int64(100)

	client := newMockAWGSSHClient()
	client.host = "10.0.0.1"
	client.port = 22
	client.serverID = &sID
	client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		if strings.Contains(cmd, "docker ps") {
			dockerPsCount++
			if strings.Contains(cmd, "amnezia-awg2") {
				return "amnezia-awg2\n", "", 0, nil
			}
			return "", "", 0, nil
		}
		if strings.Contains(cmd, "cat /opt/amnezia/awg/awg0.conf") {
			return string(client.files["/opt/amnezia/awg/awg0.conf"]), "", 0, nil
		}
		return "OK", "", 0, nil
	}

	mgr := NewAWGManager(&mockAWGSSHProvider{client: client})
	server := &models.Server{
		ID:      sID,
		Host:    "10.0.0.1",
		SSHPort: 22,
	}

	// 1. Initial resolution: cache miss, executes SSH discovery
	cName := mgr.resolveContainerName(ctx, client)
	if cName != "amnezia-awg2" {
		t.Fatalf("expected resolved name amnezia-awg2, got %q", cName)
	}
	initialPsCount := dockerPsCount
	if initialPsCount == 0 {
		t.Fatal("expected docker ps to be executed on cache miss")
	}

	// 2. Repeated resolution: cache hit, no duplicate SSH commands
	cName2 := mgr.resolveContainerName(ctx, client)
	if cName2 != "amnezia-awg2" {
		t.Fatalf("expected cached name amnezia-awg2, got %q", cName2)
	}
	if dockerPsCount != initialPsCount {
		t.Fatalf("expected no additional docker ps commands on cache hit; got %d, want %d", dockerPsCount, initialPsCount)
	}

	// 3. Different client instance with same server ID/host: cache hit
	client2 := newMockAWGSSHClient()
	client2.host = "10.0.0.1"
	client2.port = 22
	client2.serverID = &sID
	client2.sudoCmdHandler = client.sudoCmdHandler

	cName3 := mgr.resolveContainerName(ctx, client2)
	if cName3 != "amnezia-awg2" {
		t.Fatalf("expected cached name amnezia-awg2 on client2, got %q", cName3)
	}
	if dockerPsCount != initialPsCount {
		t.Fatalf("expected no additional docker ps commands on client2 cache hit; got %d, want %d", dockerPsCount, initialPsCount)
	}

	// 4. Test GetServerStatus records foundName in cache and passes it downstream
	sID2 := int64(200)
	clientStatus := newMockAWGSSHClient()
	clientStatus.host = "10.0.0.2"
	clientStatus.port = 22
	clientStatus.serverID = &sID2
	var statusPsCount int
	clientStatus.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		if strings.Contains(cmd, "docker ps") {
			statusPsCount++
			var res string
			if strings.Contains(cmd, "ps -a") && strings.Contains(cmd, "amnezia-awg2") {
				res = "amnezia-awg2\n"
			} else if strings.Contains(cmd, "Status") || strings.Contains(cmd, "status") {
				res = "Up 3 hours\n"
			}
			return res, "", 0, nil
		}
		if strings.Contains(cmd, "cat /opt/amnezia/awg/awg0.conf") {
			return string(clientStatus.files["/opt/amnezia/awg/awg0.conf"]), "", 0, nil
		}
		if strings.Contains(cmd, "docker port") {
			return "0.0.0.0:55424\n", "", 0, nil
		}
		return "OK", "", 0, nil
	}

	mgrStatus := NewAWGManager(&mockAWGSSHProvider{client: clientStatus})
	serverStatus := &models.Server{
		ID:      sID2,
		Host:    "10.0.0.2",
		SSHPort: 22,
	}

	st, err := mgrStatus.GetServerStatus(ctx, serverStatus)
	if err != nil {
		t.Fatalf("GetServerStatus failed: %v", err)
	}
	if st["container_running"] != true {
		t.Errorf("expected container_running=true, got %v", st["container_running"])
	}

	// Check that subsequent resolveContainerName uses the cached name recorded by GetServerStatus
	countBeforeResolve := statusPsCount
	resolvedFromStatus := mgrStatus.resolveContainerName(ctx, clientStatus)
	if resolvedFromStatus != "amnezia-awg2" {
		t.Fatalf("expected cached name amnezia-awg2 from GetServerStatus, got %q", resolvedFromStatus)
	}
	if statusPsCount != countBeforeResolve {
		t.Errorf("resolveContainerName issued unexpected SSH commands after GetServerStatus cached foundName")
	}

	// 5. Test cache invalidation on Uninstall
	if err := mgr.Uninstall(ctx, server); err != nil {
		t.Fatalf("Uninstall failed: %v", err)
	}
	psCountAfterUninstall := dockerPsCount
	_ = mgr.resolveContainerName(ctx, client)
	if dockerPsCount <= psCountAfterUninstall {
		t.Errorf("expected cache miss and new docker ps command after Uninstall invalidation")
	}
}

func TestAWGManager_ResolveContainerName_MaliciousRejected(t *testing.T) {
	ctx := context.Background()
	client := newMockAWGSSHClient()
	client.host = "10.0.0.99"
	client.port = 22
	client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		if strings.Contains(cmd, "docker ps") {
			// Malicious injection attempt in container name output
			return "amnezia-awg; rm -rf /\n", "", 0, nil
		}
		return "OK", "", 0, nil
	}

	mgr := NewAWGManager(&mockAWGSSHProvider{client: client})
	cName := mgr.resolveContainerName(ctx, client)

	// Malicious name must be rejected and fallback to safe default "amnezia-awg2"
	if cName != "amnezia-awg2" {
		t.Fatalf("expected fallback to safe default 'amnezia-awg2', got %q", cName)
	}
	if !IsValidContainerName(cName) {
		t.Fatalf("fallback name %q is not valid", cName)
	}

	// Also verify extractContainerPort rejects malicious containerName argument
	var injectedCmd string
	client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		injectedCmd = cmd
		return "", "", 0, nil
	}
	_ = mgr.extractContainerPort(ctx, client, "amnezia-awg`whoami`")
	if strings.Contains(injectedCmd, "`whoami`") {
		t.Fatalf("malicious container name was interpolated into command: %s", injectedCmd)
	}

	// Also verify getServerConfig rejects malicious containerName argument
	injectedCmd = ""
	_, _ = mgr.getServerConfig(ctx, client, "amnezia-awg; id")
	if strings.Contains(injectedCmd, "; id") {
		t.Fatalf("malicious container name was interpolated into command: %s", injectedCmd)
	}
}
