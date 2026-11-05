package awg

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// TestRework3_AWGInstallPersistsCompleteWireParameters verifies F7:
// AWGManager.Install persists complete wire parameters (Jc, Jmin, Jmax, S1, S2,
// H1, H2, H3, H4, HeaderProtectionKey) in server.Protocols["awg"].
func TestRework3_AWGInstallPersistsCompleteWireParameters(t *testing.T) {
	client := newMockAWGSSHClient()
	mgr := NewAWGManager(&mockAWGSSHProvider{client: client})

	server := &models.Server{
		ID:        1,
		Name:      "awg-f7-server",
		Host:      "198.51.100.99",
		SSHPort:   22,
		SSHUser:   "root",
		Protocols: make(map[string]any),
	}

	params := map[string]any{
		"port":                  "51820",
		"awg_header_protection": true,
		"awg_profile":           "standard",
	}

	if err := mgr.Install(context.Background(), server, params); err != nil {
		t.Fatalf("Install failed: %v", err)
	}

	awgMeta, ok := server.Protocols["awg"].(map[string]any)
	if !ok {
		t.Fatal("expected server.Protocols[\"awg\"] to be map[string]any")
	}

	if awgMeta["public_key"] == "" {
		t.Error("expected public_key to be populated")
	}

	rawParams, hasAWGParams := awgMeta["awg_params"]
	if !hasAWGParams {
		t.Fatal("expected awg_params in awgMeta")
	}
	pMap, ok := rawParams.(map[string]any)
	if !ok {
		t.Fatalf("expected awg_params to be map[string]any, got %T", rawParams)
	}

	requiredKeys := []string{
		"Jc", "Jmin", "Jmax",
		"S1", "S2",
		"H1", "H2", "H3", "H4",
		"HeaderProtectionKey",
	}
	for _, k := range requiredKeys {
		val, exists := pMap[k]
		if !exists || fmt.Sprint(val) == "" {
			t.Errorf("missing or empty required wire parameter %q in awg_params", k)
		}
	}
}

// TestRework3_AWGRetryIdempotentContainerManagement verifies F2:
// Retrying AWG installation on an existing container resumes cleanly:
// 1. When existing container is running, it reuses it without UDP port collision.
// 2. When existing container is stopped, it starts it without docker run exit 125 collision.
func TestRework3_AWGRetryIdempotentContainerManagement(t *testing.T) {
	for _, running := range []bool{true, false} {
		t.Run(fmt.Sprintf("running=%t", running), func(t *testing.T) {
			created := false
			mockClient := &testStatefulSSHClient{
				mockAWGSSHClient: newMockAWGSSHClient(),
				cmdFunc: func(ctx context.Context, cmd string) (string, string, int, error) {
					if cmd == "docker --version" {
						return "Docker version 24.0.5", "", 0, nil
					}
					if strings.Contains(cmd, "docker ps --filter publish=") && created && running {
						return "0.0.0.0:51820->51820/udp", "", 0, nil
					}
					if strings.Contains(cmd, "docker inspect -f '{{.State.Status}}'") {
						if created {
							if running {
								return "running", "", 0, nil
							}
							return "exited", "", 0, nil
						}
						return "", "No such container", 1, nil
					}
					if strings.Contains(cmd, "docker run -d") {
						if created {
							return "", "Conflict. The container name amnezia-awg2 is already in use", 125, nil
						}
						created = true
						return "container_id_12345", "", 0, nil
					}
					if strings.Contains(cmd, "docker start") {
						return "amnezia-awg2", "", 0, nil
					}
					return "", "", 0, nil
				},
			}

			mgr := NewAWGManager(&testAWGSSHProvider{client: mockClient})
			server := &models.Server{
				ID:        2,
				Name:      "awg-f2-server",
				Host:      "198.51.100.88",
				SSHPort:   22,
				SSHUser:   "root",
				Protocols: make(map[string]any),
			}

			// First installation
			params1 := map[string]any{
				"port":                "51820",
				"preserve_containers": true,
				"reconcile":           true,
			}
			if err := mgr.Install(context.Background(), server, params1); err != nil {
				t.Fatalf("first install failed: %v", err)
			}
			if !created {
				t.Fatal("expected first install to create container")
			}

			// Retry installation: must succeed without port or name conflict
			params2 := map[string]any{
				"port":                "51820",
				"preserve_containers": true,
				"reconcile":           true,
			}
			if err := mgr.Install(context.Background(), server, params2); err != nil {
				t.Fatalf("retry install failed (running=%t): %v", running, err)
			}
		})
	}
}

type testAWGSSHProvider struct {
	client ssh.SSHClient
}

func (p *testAWGSSHProvider) Get(ctx context.Context, server *models.Server) (ssh.SSHClient, error) {
	return p.client, nil
}

type testStatefulSSHClient struct {
	*mockAWGSSHClient
	cmdFunc func(ctx context.Context, cmd string) (string, string, int, error)
}

func (c *testStatefulSSHClient) RunCommand(ctx context.Context, cmd string) (string, string, int, error) {
	if c.cmdFunc != nil {
		return c.cmdFunc(ctx, cmd)
	}
	return c.mockAWGSSHClient.RunCommand(ctx, cmd)
}

func (c *testStatefulSSHClient) RunSudoCommand(ctx context.Context, cmd string) (string, string, int, error) {
	if c.cmdFunc != nil {
		return c.cmdFunc(ctx, cmd)
	}
	return c.mockAWGSSHClient.RunSudoCommand(ctx, cmd)
}
