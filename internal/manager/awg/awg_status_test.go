package awg

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestAWGManager_GetServerStatus_LegacyContainersAndErrors(t *testing.T) {
	ctx := context.Background()

	// Test with amnezia-awg2 container
	client2 := newMockAWGSSHClient()
	client2.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		if strings.Contains(cmd, "docker ps -a --filter name=^'amnezia-awg2'$") {
			return "amnezia-awg2\n", "", 0, nil
		}
		if strings.Contains(cmd, "docker ps -a --filter") {
			return "", "", 0, nil
		}
		if strings.Contains(cmd, "docker ps --filter name=^'amnezia-awg2'$") {
			return "Up 5 hours", "", 0, nil
		}
		return "OK", "", 0, nil
	}
	mgr2 := NewAWGManager(&mockAWGSSHProvider{client: client2})
	server := &models.Server{ID: 1, Host: "1.2.3.4"}
	status2, err := mgr2.GetServerStatus(ctx, server)
	if err != nil {
		t.Fatalf("GetServerStatus failed for amnezia-awg2: %v", err)
	}
	if exists, ok := status2["container_exists"].(bool); !ok || !exists {
		t.Errorf("expected amnezia-awg2 to exist")
	}
	if running, ok := status2["container_running"].(bool); !ok || !running {
		t.Errorf("expected amnezia-awg2 to be running")
	}

	// Test with docker daemon error
	clientErr := newMockAWGSSHClient()
	clientErr.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		if strings.Contains(cmd, "docker ps") {
			return "", "Cannot connect to the Docker daemon", 1, errors.New("exit code 1")
		}
		return "", "", 0, nil
	}
	mgrErr := NewAWGManager(&mockAWGSSHProvider{client: clientErr})
	if _, err := mgrErr.GetServerStatus(ctx, server); err == nil {
		t.Errorf("expected GetServerStatus to fail when docker daemon fails")
	}

	// Test GetServerPublicKey and GetServerPSK
	pubKey, err := mgr2.GetServerPublicKey(ctx, server)
	if err != nil || pubKey == "" {
		t.Errorf("GetServerPublicKey failed: %v", err)
	}
	psk, err := mgr2.GetServerPSK(ctx, server)
	if err != nil || psk == "" {
		t.Errorf("GetServerPSK failed: %v", err)
	}
}

func TestGetServerStatus_ProtocolGenerationEnrichment(t *testing.T) {
	tests := []struct {
		name              string
		conf              string
		wantGeneration    string
		wantHasGeneration bool
	}{
		{
			name: "31_backend_reports_3_1",
			conf: `[Interface]
PrivateKey = k
Address = 10.8.1.1/24
MTU = 1280
ListenPort = 55424
Jc = 4
H1 = 12345
HeaderProtectionKey = AbCdEf1234567890AbCdEf1234567890AbCdEf12=
RandomTrailers = on
DisableCookies = on
`,
			wantGeneration:    "3.1",
			wantHasGeneration: true,
		},
		{
			name: "20_backend_reports_2_0",
			conf: `[Interface]
PrivateKey = k
Address = 10.8.1.1/24
MTU = 1280
ListenPort = 55424
Jc = 4
H1 = 12345
`,
			wantGeneration:    "2.0",
			wantHasGeneration: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := newMockAWGSSHClient()
			client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
				if strings.Contains(cmd, "cat ") && strings.Contains(cmd, "awg0.conf") {
					return tc.conf, "", 0, nil
				}
				if strings.Contains(cmd, "awg") && strings.Contains(cmd, "--version") {
					return "wireguard-go version 0.0.20230223-amneziawg\n", "", 0, nil
				}
				if strings.Contains(cmd, "docker ps --filter") {
					return "Up 2 hours", "", 0, nil
				}
				if strings.Contains(cmd, "docker ps -a --filter") {
					return "amnezia-awg", "", 0, nil
				}
				return "OK", "", 0, nil
			}
			mgr := NewAWGManager(&mockAWGSSHProvider{client: client})
			server := &models.Server{ID: 1, Host: "1.2.3.4"}

			status, err := mgr.GetServerStatus(context.Background(), server)
			if err != nil {
				t.Fatalf("GetServerStatus failed: %v", err)
			}
			if got, ok := status["protocol_generation"]; !ok || got != tc.wantGeneration {
				t.Errorf("protocol_generation = %v (present=%v), want %q", got, ok, tc.wantGeneration)
			}
			if v, ok := status["awg_version"]; !ok || v != "wireguard-go version 0.0.20230223-amneziawg" {
				t.Errorf("awg_version = %v (present=%v), want mocked version line", v, ok)
			}
		})
	}
}

func TestGetServerStatus_AWGVersionNonFatal(t *testing.T) {
	client := newMockAWGSSHClient()
	client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		if strings.Contains(cmd, "awg") && strings.Contains(cmd, "--version") {
			return "", "command not found", 127, nil
		}
		if strings.Contains(cmd, "docker ps --filter") {
			return "Up 2 hours", "", 0, nil
		}
		if strings.Contains(cmd, "docker ps -a --filter") {
			return "amnezia-awg", "", 0, nil
		}
		return "OK", "", 0, nil
	}
	mgr := NewAWGManager(&mockAWGSSHProvider{client: client})
	server := &models.Server{ID: 1, Host: "1.2.3.4"}

	status, err := mgr.GetServerStatus(context.Background(), server)
	if err != nil {
		t.Fatalf("GetServerStatus must not fail when awg --version fails: %v", err)
	}
	if v, ok := status["awg_version"]; ok && fmt.Sprint(v) != "" {
		t.Errorf("awg_version should be absent/empty on failure, got %v", v)
	}
	// protocol_generation comes from the config, which still parses fine here.
	if got := status["protocol_generation"]; got != "2.0" {
		t.Errorf("protocol_generation = %v, want 2.0", got)
	}
}
