package awg

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/manager/awg/cps"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestBuildAndRunAWGContainer_PinnedImageAndPull(t *testing.T) {
	var dockerfile string
	var commands []string
	client := newMockAWGSSHClient()
	client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		commands = append(commands, cmd)
		if strings.Contains(cmd, "ss -lun") {
			// Preflight: no UDP listener on the requested port.
			return "", "", 0, nil
		}
		if strings.Contains(cmd, "docker ps") {
			// Preflight: publish filter finds no existing binding.
			return "", "", 0, nil
		}
		if strings.Contains(cmd, "docker build") {
			uploaded, ok := client.files["/opt/amnezia/amnezia-awg2/Dockerfile"]
			if !ok {
				return "", "Dockerfile missing", 1, nil
			}
			dockerfile = string(uploaded)
		}
		return "OK", "", 0, nil
	}

	if err := buildAndRunAWGContainer(context.Background(), client, "55424"); err != nil {
		t.Fatalf("buildAndRunAWGContainer failed: %v", err)
	}

	if dockerfile == "" {
		t.Fatalf("Dockerfile was never uploaded before docker build")
	}
	if !strings.Contains(dockerfile, "FROM "+awgBaseImage+"\n") {
		t.Errorf("Dockerfile must pin FROM %s, got:\n%s", awgBaseImage, dockerfile)
	}
	if !strings.Contains(dockerfile, "FROM devopsigor/amneziawg:") {
		t.Errorf("Dockerfile must use the multiarch devopsigor/amneziawg base image (ARM64 support), got:\n%s", dockerfile)
	}

	pullIdx, buildIdx := -1, -1
	for i, cmd := range commands {
		if strings.HasPrefix(cmd, "docker pull '"+awgBaseImage+"'") && pullIdx == -1 {
			pullIdx = i
		}
		if strings.Contains(cmd, "docker build") && buildIdx == -1 {
			buildIdx = i
		}
	}
	if pullIdx == -1 {
		t.Errorf("expected an explicit %q command, got: %v", "docker pull "+awgBaseImage, commands)
	}
	if buildIdx == -1 {
		t.Errorf("expected a docker build command, got: %v", commands)
	}
	if pullIdx != -1 && buildIdx != -1 && pullIdx > buildIdx {
		t.Errorf("docker pull (idx %d) must run before docker build (idx %d)", pullIdx, buildIdx)
	}
}

func TestBuildAndRunAWGContainer_PullFailureAborts(t *testing.T) {
	client := newMockAWGSSHClient()
	client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		if strings.Contains(cmd, "ss -lun") || strings.Contains(cmd, "docker ps") {
			// Preflight: port free.
			return "", "", 0, nil
		}
		if strings.HasPrefix(cmd, "docker pull '") {
			return "", "manifest unknown", 1, nil
		}
		if strings.Contains(cmd, "docker build") {
			t.Error("docker build must not run when the base image pull fails")
		}
		return "OK", "", 0, nil
	}

	err := buildAndRunAWGContainer(context.Background(), client, "55424")
	if err == nil {
		t.Fatalf("expected an error when docker pull fails")
	}
	if !strings.Contains(err.Error(), awgBaseImage) {
		t.Errorf("error should mention the pinned base image, got: %v", err)
	}
}

// TestInstall_HeaderProtectionDefaultOn verifies the plumbing contract:
// absent awg_header_protection defaults to true (AWG 3.1), explicit false
// keeps 2.0 semantics, explicit true generates 3.1 params.
func TestInstall_HeaderProtectionDefaultOn(t *testing.T) {
	tests := []struct {
		name        string
		hpValue     any
		wantHPKey   bool
		wantRandom  bool
		wantCookies bool
	}{
		{name: "absent_defaults_true", hpValue: nil, wantHPKey: true, wantRandom: true, wantCookies: true},
		{name: "explicit_true", hpValue: true, wantHPKey: true, wantRandom: true, wantCookies: true},
		{name: "string_true", hpValue: "true", wantHPKey: true, wantRandom: true, wantCookies: true},
		{name: "explicit_false_2_0", hpValue: false, wantHPKey: false, wantRandom: false, wantCookies: false},
		{name: "string_false_2_0", hpValue: "false", wantHPKey: false, wantRandom: false, wantCookies: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			params := map[string]any{"port": "55424", "awg_profile": "standard"}
			if tc.hpValue != nil {
				params["awg_header_protection"] = tc.hpValue
			}

			awgParams, err := generateAWGParamsForInstall(params)
			if err != nil {
				t.Fatalf("generateAWGParamsForInstall failed: %v", err)
			}
			hasHP := awgParams.HeaderProtectionKey != ""
			if hasHP != tc.wantHPKey {
				t.Errorf("HeaderProtectionKey present = %v, want %v", hasHP, tc.wantHPKey)
			}
			if (awgParams.RandomTrailers != "") != tc.wantRandom {
				t.Errorf("RandomTrailers present = %v, want %v", awgParams.RandomTrailers != "", tc.wantRandom)
			}
			if (awgParams.DisableCookies != "") != tc.wantCookies {
				t.Errorf("DisableCookies present = %v, want %v", awgParams.DisableCookies != "", tc.wantCookies)
			}
		})
	}
}

// generateAWGParamsForInstall mirrors Install()'s parameter and CPS defaulting
// logic so the install defaults contract is testable without touching live hosts.
func generateAWGParamsForInstall(params map[string]any) (*AWGParams, error) {
	profile := "standard"
	if p, ok := params["awg_profile"]; ok && fmt.Sprint(p) != "" {
		profile = fmt.Sprint(p)
	}
	hpOn := true
	if v, ok := parseBoolParam(params["awg_header_protection"]); ok {
		hpOn = v
	}
	awgParams, err := GenerateAWGParams(profile, hpOn)
	if err != nil {
		return nil, err
	}
	cpsProto := "sip"
	if params != nil {
		if cp, ok := params["awg_cps_protocol"]; ok && fmt.Sprint(cp) != "" {
			cpsProto = strings.ToLower(strings.TrimSpace(fmt.Sprint(cp)))
		}
	}
	d := cps.FallbackDomains[cpsProto]
	if cpsPackets, err := cps.GenerateCPSPackets(profile, d, cpsProto); err == nil {
		awgParams.I1 = cpsPackets["i1"]
		awgParams.I2 = cpsPackets["i2"]
		awgParams.I3 = cpsPackets["i3"]
		awgParams.I4 = cpsPackets["i4"]
		awgParams.I5 = cpsPackets["i5"]
	}
	return awgParams, nil
}

func TestInstall_ProducesSIPI1ByDefault_StandardAndLite(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name    string
		params  map[string]any
		checkI1 func(t *testing.T, p *AWGParams)
	}{
		{
			name:   "standard_defaults_to_sip",
			params: map[string]any{"port": "55424", "awg_profile": "standard"},
			checkI1: func(t *testing.T, p *AWGParams) {
				t.Helper()
				if !strings.HasPrefix(p.I1, "<b 0x") {
					t.Fatalf("expected I1 to have '<b 0x' tag, got: %s", p.I1)
				}
				raw, err := cps.ParseCPSBlob(p.I1)
				if err != nil {
					t.Fatalf("ParseCPSBlob failed: %v", err)
				}
				rawStr := string(raw)
				if !strings.Contains(rawStr, "REGISTER sip:") {
					t.Errorf("expected I1 to contain 'REGISTER sip:', got: %s", rawStr)
				}
				if !strings.Contains(rawStr, "Content-Length: 0") {
					t.Errorf("expected I1 to contain 'Content-Length: 0', got: %s", rawStr)
				}
			},
		},
		{
			name:   "lite_defaults_to_sip",
			params: map[string]any{"port": "55424", "awg_profile": "lite"},
			checkI1: func(t *testing.T, p *AWGParams) {
				t.Helper()
				if !strings.HasPrefix(p.I1, "<b 0x") {
					t.Fatalf("expected I1 to have '<b 0x' tag, got: %s", p.I1)
				}
				raw, err := cps.ParseCPSBlob(p.I1)
				if err != nil {
					t.Fatalf("ParseCPSBlob failed: %v", err)
				}
				rawStr := string(raw)
				if !strings.Contains(rawStr, "REGISTER sip:") {
					t.Errorf("expected I1 to contain 'REGISTER sip:', got: %s", rawStr)
				}
				if !strings.Contains(rawStr, "Content-Length: 0") {
					t.Errorf("expected I1 to contain 'Content-Length: 0', got: %s", rawStr)
				}
			},
		},
		{
			name: "standard_respects_explicit_dns",
			params: map[string]any{
				"port":             "55424",
				"awg_profile":      "standard",
				"awg_cps_protocol": "dns",
			},
			checkI1: func(t *testing.T, p *AWGParams) {
				t.Helper()
				if !strings.HasPrefix(p.I1, "<r 2><b 0x") {
					t.Fatalf("expected dns I1 to have '<r 2><b 0x' tag, got: %s", p.I1)
				}
				raw, err := cps.ParseCPSBlob(p.I1)
				if err != nil {
					t.Fatalf("ParseCPSBlob failed: %v", err)
				}
				if len(raw) < 12 {
					t.Errorf("dns packet too short: %d bytes", len(raw))
				}
			},
		},
		{
			name: "standard_respects_explicit_quic",
			params: map[string]any{
				"port":             "55424",
				"awg_profile":      "standard",
				"awg_cps_protocol": "quic",
			},
			checkI1: func(t *testing.T, p *AWGParams) {
				t.Helper()
				if !strings.HasPrefix(p.I1, "<b 0x") {
					t.Fatalf("expected quic I1 to start with '<b 0x', got: %s", p.I1)
				}
				raw, err := cps.ParseCPSBlob(p.I1)
				if err != nil {
					t.Fatalf("ParseCPSBlob failed: %v", err)
				}
				if strings.Contains(string(raw), "SIP/2.0") {
					t.Errorf("expected QUIC packet, got SIP: %s", string(raw))
				}
			},
		},
		{
			name: "lite_respects_explicit_dns",
			params: map[string]any{
				"port":             "55424",
				"awg_profile":      "lite",
				"awg_cps_protocol": "dns",
			},
			checkI1: func(t *testing.T, p *AWGParams) {
				t.Helper()
				if !strings.HasPrefix(p.I1, "<r 2><b 0x") {
					t.Fatalf("expected dns I1 to have '<r 2><b 0x' tag, got: %s", p.I1)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newMockAWGSSHClient()
			provider := &mockAWGSSHProvider{client: client}
			mgr := NewAWGManager(provider)
			server := &models.Server{ID: 1, Host: "198.51.100.10"}

			var captured *AWGParams
			mgr.SetInstallHookForTest(func(p *AWGParams) {
				captured = p
			})

			if err := mgr.Install(ctx, server, tt.params); err != nil {
				t.Fatalf("Install failed: %v", err)
			}
			if captured == nil {
				t.Fatalf("installHook was not called")
			}
			tt.checkI1(t, captured)
		})
	}
}

func TestInstall_CreatesAWG2Container_CommandsAndConfig(t *testing.T) {
	ctx := context.Background()
	client := newMockAWGSSHClient()
	var commandsRun []string

	client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		commandsRun = append(commandsRun, cmd)
		if strings.Contains(cmd, "docker ps") {
			if strings.Contains(cmd, "amnezia-awg2") {
				return "amnezia-awg2\n", "", 0, nil
			}
			return "", "", 0, nil
		}
		if strings.Contains(cmd, "docker cp") {
			return "", "", 0, nil
		}
		return "OK", "", 0, nil
	}

	mgr := NewAWGManager(&mockAWGSSHProvider{client: client})
	if mgr.containerName() != "amnezia-awg2" {
		t.Fatalf("expected default containerName to be amnezia-awg2, got %q", mgr.containerName())
	}

	server := &models.Server{ID: 10, Host: "10.0.0.10", SSHPort: 22, SSHUser: "root"}
	params := map[string]any{
		"port":        "55424",
		"awg_profile": "standard",
	}
	if err := mgr.Install(ctx, server, params); err != nil {
		t.Fatalf("Install failed: %v", err)
	}

	// 1. Verify Dockerfile uploaded to /opt/amnezia/amnezia-awg2/Dockerfile
	dockerfileBytes, ok := client.files["/opt/amnezia/amnezia-awg2/Dockerfile"]
	if !ok {
		t.Fatalf("Dockerfile was not uploaded to /opt/amnezia/amnezia-awg2/Dockerfile")
	}
	if !strings.Contains(string(dockerfileBytes), "FROM "+awgBaseImage) {
		t.Errorf("Dockerfile missing pinned base image (got Dockerfile without FROM %s)", awgBaseImage)
	}

	// 2. Verify command sequence targets amnezia-awg2
	var foundPull, foundBuild, foundRun, foundNetwork, foundKeygen, foundCpConf, foundCpStart, foundChmod, foundRestart bool
	for _, cmd := range commandsRun {
		if strings.HasPrefix(cmd, "docker pull '"+awgBaseImage+"'") {
			foundPull = true
		}
		if strings.Contains(cmd, "docker build --no-cache -t 'amnezia-awg2'") {
			foundBuild = true
		}
		if strings.Contains(cmd, "docker run -d") && strings.Contains(cmd, "--name 'amnezia-awg2'") && strings.Contains(cmd, "'amnezia-awg2'") {
			foundRun = true
		}
		if strings.Contains(cmd, "docker network connect amnezia-dns-net 'amnezia-awg2'") {
			foundNetwork = true
		}
		if strings.Contains(cmd, "docker exec -i 'amnezia-awg2' bash -c") && strings.Contains(cmd, "wireguard_server_private_key.key") {
			foundKeygen = true
		}
		if strings.Contains(cmd, "docker cp '/tmp/_amnz_awg0.conf' 'amnezia-awg2':'/opt/amnezia/awg/awg0.conf'") {
			foundCpConf = true
		}
		if strings.Contains(cmd, "docker cp '/tmp/_amnz_start.sh' 'amnezia-awg2':'/opt/amnezia/start.sh'") {
			foundCpStart = true
		}
		if strings.Contains(cmd, "docker exec 'amnezia-awg2' chmod +x /opt/amnezia/start.sh") {
			foundChmod = true
		}
		if strings.Contains(cmd, "docker restart 'amnezia-awg2'") {
			foundRestart = true
		}
	}

	if !foundPull {
		t.Errorf("expected docker pull %s command", awgBaseImage)
	}
	if !foundBuild {
		t.Errorf("expected docker build command targeting amnezia-awg2")
	}
	if !foundRun {
		t.Errorf("expected docker run command with --name amnezia-awg2")
	}
	if !foundNetwork {
		t.Errorf("expected docker network connect command targeting amnezia-awg2")
	}
	if !foundKeygen {
		t.Errorf("expected keygen docker exec command targeting amnezia-awg2")
	}
	if !foundCpConf {
		t.Errorf("expected docker cp config targeting amnezia-awg2")
	}
	if !foundCpStart {
		t.Errorf("expected docker cp start.sh targeting amnezia-awg2")
	}
	if !foundChmod {
		t.Errorf("expected chmod docker exec command targeting amnezia-awg2")
	}
	if !foundRestart {
		t.Errorf("expected docker restart amnezia-awg2")
	}
}

func TestUninstall_CleansUpBothAWGAndAWG2(t *testing.T) {
	ctx := context.Background()
	client := newMockAWGSSHClient()
	var commandsRun []string

	client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		commandsRun = append(commandsRun, cmd)
		return "OK", "", 0, nil
	}

	mgr := NewAWGManager(&mockAWGSSHProvider{client: client})
	server := &models.Server{ID: 11, Host: "10.0.0.11", SSHPort: 22}

	if err := mgr.Uninstall(ctx, server); err != nil {
		t.Fatalf("Uninstall failed: %v", err)
	}

	var stoppedAwg, stoppedAwg2, rmAwg, rmAwg2, rmiAwg, rmiAwg2, rmDirs bool
	for _, cmd := range commandsRun {
		if strings.Contains(cmd, "docker stop 'amnezia-awg'") {
			stoppedAwg = true
		}
		if strings.Contains(cmd, "docker stop 'amnezia-awg2'") {
			stoppedAwg2 = true
		}
		if strings.Contains(cmd, "docker rm -fv 'amnezia-awg'") {
			rmAwg = true
		}
		if strings.Contains(cmd, "docker rm -fv 'amnezia-awg2'") {
			rmAwg2 = true
		}
		if strings.Contains(cmd, "docker rmi 'amnezia-awg'") {
			rmiAwg = true
		}
		if strings.Contains(cmd, "docker rmi 'amnezia-awg2'") {
			rmiAwg2 = true
		}
		if strings.Contains(cmd, "rm -rf /opt/amnezia/amnezia-awg /opt/amnezia/amnezia-awg2 /opt/amnezia/awg") {
			rmDirs = true
		}
	}

	if !stoppedAwg || !stoppedAwg2 {
		t.Errorf("Uninstall must stop both containers: stoppedAwg=%v, stoppedAwg2=%v", stoppedAwg, stoppedAwg2)
	}
	if !rmAwg || !rmAwg2 {
		t.Errorf("Uninstall must remove both containers: rmAwg=%v, rmAwg2=%v", rmAwg, rmAwg2)
	}
	if !rmiAwg || !rmiAwg2 {
		t.Errorf("Uninstall must remove images for both: rmiAwg=%v, rmiAwg2=%v", rmiAwg, rmiAwg2)
	}
	if !rmDirs {
		t.Errorf("Uninstall must remove directories for both amnezia-awg and amnezia-awg2")
	}
}

func TestBackwardCompatibility_LegacyAmneziaAWGContainer(t *testing.T) {
	ctx := context.Background()
	client := newMockAWGSSHClient()

	client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		// Strictly fail if any command targets amnezia-awg2
		if strings.Contains(cmd, "amnezia-awg2") {
			if strings.Contains(cmd, "docker ps") {
				return "", "", 0, nil
			}
			return "", "Error: No such container: amnezia-awg2", 1, errors.New("container not found")
		}

		// amnezia-awg exists and is running
		if strings.Contains(cmd, "docker ps --filter name=^'amnezia-awg'$") {
			if strings.Contains(cmd, "{{.Names}}") {
				return "amnezia-awg\n", "", 0, nil
			}
			return "Up 24 hours\n", "", 0, nil
		}
		if strings.Contains(cmd, "docker ps -a --filter name=^'amnezia-awg'$") {
			return "amnezia-awg\n", "", 0, nil
		}
		if strings.Contains(cmd, "docker ps --filter name=amnezia-awg") {
			return "amnezia-awg\n", "", 0, nil
		}

		// Container reads and cp for amnezia-awg
		if strings.Contains(cmd, "cat ") && strings.Contains(cmd, "awg0.conf") {
			return string(client.files["/opt/amnezia/awg/awg0.conf"]), "", 0, nil
		}
		if strings.Contains(cmd, "cat ") && strings.Contains(cmd, "clientsTable") {
			return string(client.files["/opt/amnezia/awg/clientsTable"]), "", 0, nil
		}
		if strings.Contains(cmd, "cat ") && strings.Contains(cmd, "wireguard_server_public_key.key") {
			return string(client.files["/opt/amnezia/awg/wireguard_server_public_key.key"]), "", 0, nil
		}
		if strings.Contains(cmd, "cat ") && strings.Contains(cmd, "wireguard_psk.key") {
			return string(client.files["/opt/amnezia/awg/wireguard_psk.key"]), "", 0, nil
		}
		if strings.Contains(cmd, "docker cp") && strings.Contains(cmd, "_amnz_clients") && strings.Contains(cmd, "clientsTable") {
			for p, c := range client.files {
				if strings.Contains(p, "_amnz_clients") {
					client.files["/opt/amnezia/awg/clientsTable"] = c
					break
				}
			}
			return "", "", 0, nil
		}
		if strings.Contains(cmd, "docker cp") && strings.Contains(cmd, "_amnz_edit_config") && strings.Contains(cmd, "awg0.conf") {
			for p, c := range client.files {
				if strings.Contains(p, "_amnz_edit_config") {
					client.files["/opt/amnezia/awg/awg0.conf"] = c
					break
				}
			}
			return "", "", 0, nil
		}

		return "OK", "", 0, nil
	}

	mgr := NewAWGManager(&mockAWGSSHProvider{client: client})
	server := &models.Server{ID: 12, Host: "10.0.0.12", SSHPort: 22}

	// 1. Resolve container name
	resolved := mgr.ResolveContainerName(ctx, client)
	if resolved != "amnezia-awg" {
		t.Fatalf("expected legacy container amnezia-awg, got %q", resolved)
	}

	// 2. GetServerStatus
	status, err := mgr.GetServerStatus(ctx, server)
	if err != nil {
		t.Fatalf("GetServerStatus failed on legacy container: %v", err)
	}
	if exists, ok := status["container_exists"].(bool); !ok || !exists {
		t.Errorf("expected legacy container to exist")
	}
	if running, ok := status["container_running"].(bool); !ok || !running {
		t.Errorf("expected legacy container to be running")
	}

	// 3. GetServerPublicKey & PSK
	pubKey, err := mgr.GetServerPublicKey(ctx, server)
	if err != nil || pubKey == "" {
		t.Fatalf("GetServerPublicKey failed on legacy container: %v", err)
	}
	psk, err := mgr.GetServerPSK(ctx, server)
	if err != nil || psk == "" {
		t.Fatalf("GetServerPSK failed on legacy container: %v", err)
	}

	// 4. GetClients
	clients, err := mgr.GetClients(ctx, server)
	if err != nil {
		t.Fatalf("GetClients failed on legacy container: %v", err)
	}
	if len(clients) == 0 {
		t.Errorf("expected clients on legacy container")
	}

	// 5. AddClient
	addParams := map[string]any{
		"name": "LegacyClientUser",
	}
	newClient, err := mgr.AddClient(ctx, server, addParams)
	if err != nil {
		t.Fatalf("AddClient failed on legacy container: %v", err)
	}
	clientID, ok := newClient["client_id"].(string)
	if !ok || clientID == "" {
		t.Fatalf("AddClient did not return clientID on legacy container")
	}

	// 6. GetClientConfig
	clientCfg, err := mgr.GetClientConfig(ctx, server, clientID)
	if err != nil {
		t.Fatalf("GetClientConfig failed on legacy container: %v", err)
	}
	if !strings.Contains(clientCfg, "Endpoint = 10.0.0.12:55424") {
		t.Errorf("GetClientConfig missing correct Endpoint: %s", clientCfg)
	}

	// 7. RemoveClient
	if err := mgr.RemoveClient(ctx, server, clientID); err != nil {
		t.Fatalf("RemoveClient failed on legacy container: %v", err)
	}
}

func TestPrepareHostAndContainers_DirectoryCreation(t *testing.T) {
	ctx := context.Background()
	client := newMockAWGSSHClient()
	var prepScriptExecuted string

	client.sudoScriptHandler = func(script string) (string, string, int, error) {
		prepScriptExecuted = script
		return "OK", "", 0, nil
	}

	if err := prepareHostAndContainers(ctx, client); err != nil {
		t.Fatalf("prepareHostAndContainers failed: %v", err)
	}

	if !strings.Contains(prepScriptExecuted, "/opt/amnezia/amnezia-awg2") {
		t.Errorf("prep script missing /opt/amnezia/amnezia-awg2 path:\n%s", prepScriptExecuted)
	}
}
