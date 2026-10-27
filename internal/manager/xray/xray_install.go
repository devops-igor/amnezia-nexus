package xray

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func extractVLESSOptions(vo any) (portStr, serverName, flow string, flowSpecified bool) {
	switch opt := vo.(type) {
	case *models.VLESSInstallOptions:
		if opt != nil {
			return opt.Port, opt.ServerName, opt.Flow, opt.FlowSet || opt.Flow != ""
		}
	case models.VLESSInstallOptions:
		return opt.Port, opt.ServerName, opt.Flow, opt.FlowSet || opt.Flow != ""
	case map[string]any:
		p, _ := opt["port"].(string)
		sn, _ := opt["server_name"].(string)
		fl, ok := opt["flow"].(string)
		return p, sn, fl, ok
	}
	return "", "", "", false
}

func parseXrayInstallOptions(params map[string]any) (int, string, string) {
	portPrimary := 443
	if p, ok := params["port"]; ok && fmt.Sprint(p) != "" {
		if pInt, err := strconv.Atoi(fmt.Sprint(p)); err == nil && pInt > 0 {
			portPrimary = pInt
		}
	}

	serverName := "gateway.icloud.com"
	flow := "xtls-rprx-vision"
	if f, ok := params["flow"]; ok {
		flow = fmt.Sprint(f)
	}
	if vo, ok := params["vless_options"]; ok && vo != nil {
		pStr, sn, fl, flSet := extractVLESSOptions(vo)
		if pStr != "" {
			if pInt, err := strconv.Atoi(pStr); err == nil && pInt > 0 {
				portPrimary = pInt
			}
		}
		if sn != "" {
			serverName = sn
		}
		if flSet {
			flow = fl
		}
	}
	if flow == "none" {
		flow = ""
	}
	return portPrimary, serverName, flow
}

func (m *XrayManager) resolveRealityCredentials(
	ctx context.Context,
	client ssh.SSHClient,
) (string, string, string, []string, []XrayClient, error) {
	exists, err := client.FileExists(ctx, XrayConfigPath)
	if errors.Is(err, os.ErrPermission) {
		testCmd := fmt.Sprintf("test -f %s", ssh.EscapeShellArg(XrayConfigPath))
		_, errOut, code, sudoErr := client.RunSudoCommand(ctx, testCmd)
		switch {
		case sudoErr != nil:
			err = sudoErr
		case code > 1:
			err = fmt.Errorf("privileged existence check exited %d: %s", code, strings.TrimSpace(errOut))
		default:
			exists, err = code == 0, nil
		}
	}
	if err != nil {
		return "", "", "", nil, nil, fmt.Errorf("failed to check existence of xray config %s: %w", XrayConfigPath, err)
	}
	if !exists {
		privB64, pubB64, genErr := GenerateRealityKeypair()
		if genErr != nil {
			return "", "", "", nil, nil, fmt.Errorf("generate reality keypair: %w", genErr)
		}
		shortID, genErr := GenerateShortID()
		if genErr != nil {
			return "", "", "", nil, nil, fmt.Errorf("generate short ID: %w", genErr)
		}
		return privB64, pubB64, shortID, []string{shortID}, []XrayClient{}, nil
	}

	catCmd := fmt.Sprintf("cat %s 2>/dev/null", ssh.EscapeShellArg(XrayConfigPath))
	catOut, catErrOut, catCode, catErr := client.RunSudoCommand(ctx, catCmd)
	var existingCfgBytes []byte
	if catErr == nil && catCode == 0 && strings.TrimSpace(catOut) != "" && strings.TrimSpace(catOut) != "OK" {
		existingCfgBytes = []byte(catOut)
	} else {
		data, dlErr := client.DownloadFile(ctx, XrayConfigPath)
		if dlErr != nil {
			return "", "", "", nil, nil, fmt.Errorf("failed to read existing xray config %s (cat code %d: %s, download err: %w)", XrayConfigPath, catCode, strings.TrimSpace(catErrOut), dlErr)
		}
		existingCfgBytes = data
	}

	trimmed := strings.TrimSpace(string(existingCfgBytes))
	if len(trimmed) == 0 {
		return "", "", "", nil, nil, fmt.Errorf("existing xray config %s is empty or truncated", XrayConfigPath)
	}

	parsed, parseErr := ParseXrayConfig(existingCfgBytes)
	if parseErr != nil {
		return "", "", "", nil, nil, fmt.Errorf("failed to parse existing xray config %s: %w", XrayConfigPath, parseErr)
	}

	if len(parsed.Inbounds) == 0 {
		return "", "", "", nil, nil, fmt.Errorf("existing xray config %s contains no inbounds", XrayConfigPath)
	}

	inbound := parsed.Inbounds[0]
	reality := inbound.StreamSettings.RealitySettings
	if reality.PrivateKey == "" {
		return "", "", "", nil, nil, fmt.Errorf("existing xray config %s missing reality private key", XrayConfigPath)
	}

	derivedPub, pubErr := DerivePublicKey(reality.PrivateKey)
	if pubErr != nil {
		return "", "", "", nil, nil, fmt.Errorf("failed to derive public key from existing reality private key: %w", pubErr)
	}

	privB64 := reality.PrivateKey
	pubB64 := derivedPub
	shortIDs := reality.ShortIDs
	var shortID string
	if len(shortIDs) > 0 && shortIDs[0] != "" {
		shortID = shortIDs[0]
	} else {
		var genErr error
		shortID, genErr = GenerateShortID()
		if genErr != nil {
			return "", "", "", nil, nil, fmt.Errorf("generate short ID: %w", genErr)
		}
		shortIDs = []string{shortID}
	}

	clients := inbound.Settings.Clients
	if clients == nil {
		clients = []XrayClient{}
	}

	return privB64, pubB64, shortID, shortIDs, clients, nil
}

func (m *XrayManager) launchContainer(ctx context.Context, client ssh.SSHClient) error {
	stopCmd := fmt.Sprintf("docker stop %s 2>/dev/null || true; docker rm -fv %s 2>/dev/null || true",
		ssh.EscapeShellArg(XrayContainerName), ssh.EscapeShellArg(XrayContainerName))
	_, _, _, _ = client.RunSudoCommand(ctx, stopCmd)

	_, _, _, _ = client.RunSudoCommand(ctx, fmt.Sprintf("docker pull %s 2>/dev/null || true", ssh.EscapeShellArg(XrayBaseImage)))

	runCmd := fmt.Sprintf(`docker run -d \
--name %s \
--restart unless-stopped \
--network host \
--user 0:0 \
--cap-drop ALL \
--cap-add NET_BIND_SERVICE \
--security-opt no-new-privileges:true \
--log-driver none \
--tmpfs /tmp:rw,noexec,nosuid,size=16m \
--tmpfs /run:rw,noexec,nosuid,size=16m \
-v %s:/etc/xray:ro \
-v %s:/usr/local/etc/xray:ro \
%s`,
		ssh.EscapeShellArg(XrayContainerName),
		ssh.EscapeShellArg(XrayConfigDir),
		ssh.EscapeShellArg(XrayConfigDir),
		ssh.EscapeShellArg(XrayBaseImage),
	)

	if _, errOut, code, err := client.RunSudoCommand(ctx, runCmd); err != nil || code != 0 {
		return fmt.Errorf("failed to run xray container (code %d): %s: %w", code, errOut, err)
	}

	checkCmd := fmt.Sprintf("docker inspect -f '{{.State.Running}} {{.State.Restarting}}' %s", ssh.EscapeShellArg(XrayContainerName))
	out, errOut, code, err := client.RunSudoCommand(ctx, checkCmd)
	if err != nil || code != 0 {
		return fmt.Errorf("xray container failed to inspect (code %d): %s: %w", code, errOut, err)
	}
	fields := strings.Fields(strings.TrimSpace(out))
	if len(fields) < 2 || fields[0] != "true" || fields[1] != "false" {
		return fmt.Errorf("xray container is not running (state: %s)", strings.TrimSpace(out))
	}
	return nil
}

// Install prepares the host, renders VLESS+REALITY configuration, and launches amnezia-xray.
func (m *XrayManager) Install(ctx context.Context, server *models.Server, params map[string]any) error {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return err
	}

	unlock, err := m.lockServer(ctx, client, server.ID)
	if err != nil {
		return err
	}
	defer unlock()

	// 1. Check Docker is installed
	out, _, code, _ := client.RunCommand(ctx, "docker --version")
	if code != 0 || !strings.Contains(strings.ToLower(out), "docker") {
		return errors.New("docker is not installed on the remote server")
	}

	// 2. Parse installation options
	portPrimary, serverName, flow := parseXrayInstallOptions(params)

	// 3. Generate or preserve REALITY cryptographic credentials and existing clients
	privB64, pubB64, shortID, shortIDs, clients, err := m.resolveRealityCredentials(ctx, client)
	if err != nil {
		return err
	}

	// 4. Create directory structure
	mkdirCmd := fmt.Sprintf("mkdir -p %s && chmod 0700 %s", ssh.EscapeShellArg(XrayConfigDir), ssh.EscapeShellArg(XrayConfigDir))
	if _, errOut, code, err := client.RunSudoCommand(ctx, mkdirCmd); err != nil || code != 0 {
		return fmt.Errorf("failed to create xray config directory (code %d): %s: %w", code, errOut, err)
	}

	// 5. Render and upload config.json
	portHigh := 54321
	dest := netJoinHostPort(serverName, "443")
	cfgBytes, err := RenderXrayConfig(portPrimary, portHigh, serverName, dest, privB64, shortIDs, clients)
	if err != nil {
		return fmt.Errorf("render xray config: %w", err)
	}

	if err := client.UploadSudoFile(ctx, XrayConfigPath, cfgBytes, 0600); err != nil {
		return fmt.Errorf("upload xray config: %w", err)
	}

	// 6. Launch amnezia-xray container
	if err := m.launchContainer(ctx, client); err != nil {
		return err
	}

	m.containerCache.set(m.containerCache.keyForServer(server), true)

	// Update server.Protocols in-memory for caller awareness
	if server.Protocols == nil {
		server.Protocols = make(map[string]any)
	}
	server.Protocols[models.ProtocolVLESS] = map[string]any{
		"installed":   true,
		"port":        portPrimary,
		"server_name": serverName,
		"public_key":  pubB64,
		"short_id":    shortID,
		"flow":        flow,
	}

	return nil
}

// Uninstall terminates and removes the amnezia-xray container and config directory.
func (m *XrayManager) Uninstall(ctx context.Context, server *models.Server) error {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return err
	}

	unlock, err := m.lockServer(ctx, client, server.ID)
	if err != nil {
		return err
	}
	defer unlock()

	// 1. Inspect whether container is absent
	inspectCmd := fmt.Sprintf("docker inspect %s", ssh.EscapeShellArg(XrayContainerName))
	out, errOut, code, err := client.RunSudoCommand(ctx, inspectCmd)
	if err != nil {
		return fmt.Errorf("failed to inspect xray container: %w", err)
	}

	containerAbsent := false
	if code != 0 {
		combined := strings.ToLower(out + " " + errOut)
		if strings.Contains(combined, "no such") {
			containerAbsent = true
		} else {
			return fmt.Errorf("failed to inspect xray container (code %d): %s", code, strings.TrimSpace(errOut))
		}
	} else if strings.TrimSpace(out) == "false false" {
		containerAbsent = true
	}

	// 2. If present, stop and remove container without || true
	if !containerAbsent {
		rmCmd := fmt.Sprintf("docker stop %s && docker rm -fv %s",
			ssh.EscapeShellArg(XrayContainerName),
			ssh.EscapeShellArg(XrayContainerName),
		)
		if _, errOut, code, err := client.RunSudoCommand(ctx, rmCmd); err != nil || code != 0 {
			return fmt.Errorf("failed to stop and remove xray container (code %d): %s: %w", code, strings.TrimSpace(errOut), err)
		}

		verifyOut, verifyErrOut, verifyCode, verifyErr := client.RunSudoCommand(ctx, inspectCmd)
		if verifyErr != nil {
			return fmt.Errorf("failed to verify xray container removal: %w", verifyErr)
		}
		if verifyCode == 0 && strings.TrimSpace(verifyOut) != "false false" {
			return fmt.Errorf("xray container %s still present after removal", XrayContainerName)
		}
		if verifyCode != 0 && !strings.Contains(strings.ToLower(verifyOut+" "+verifyErrOut), "no such") {
			return fmt.Errorf("unexpected inspect status for %s (code %d): %s", XrayContainerName, verifyCode, strings.TrimSpace(verifyErrOut))
		}
	}

	// 3. Remove configuration directory only after container removal is confirmed
	rmDirCmd := fmt.Sprintf("rm -rf %s", ssh.EscapeShellArg(XrayConfigDir))
	if _, errOut, code, err := client.RunSudoCommand(ctx, rmDirCmd); err != nil || code != 0 {
		return fmt.Errorf("failed to remove xray config directory (code %d): %s: %w", code, strings.TrimSpace(errOut), err)
	}

	m.containerCache.invalidate(m.containerCache.keyForServer(server))

	if server.Protocols != nil {
		delete(server.Protocols, models.ProtocolVLESS)
	}
	return nil
}

func netJoinHostPort(host, port string) string {
	if strings.Contains(host, ":") {
		return host
	}
	return fmt.Sprintf("%s:%s", host, port)
}
