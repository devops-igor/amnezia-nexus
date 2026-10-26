package xray

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func extractVLESSOptions(vo any) (portStr, serverName, flow string) {
	switch opt := vo.(type) {
	case *models.VLESSInstallOptions:
		if opt != nil {
			return opt.Port, opt.ServerName, opt.Flow
		}
	case models.VLESSInstallOptions:
		return opt.Port, opt.ServerName, opt.Flow
	case map[string]any:
		p, _ := opt["port"].(string)
		sn, _ := opt["server_name"].(string)
		fl, _ := opt["flow"].(string)
		return p, sn, fl
	}
	return "", "", ""
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
	if vo, ok := params["vless_options"]; ok && vo != nil {
		pStr, sn, fl := extractVLESSOptions(vo)
		if pStr != "" {
			if pInt, err := strconv.Atoi(pStr); err == nil && pInt > 0 {
				portPrimary = pInt
			}
		}
		if sn != "" {
			serverName = sn
		}
		if fl != "" {
			flow = fl
		}
	}
	return portPrimary, serverName, flow
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

	// 3. Generate REALITY cryptographic credentials
	privB64, pubB64, err := GenerateRealityKeypair()
	if err != nil {
		return fmt.Errorf("generate reality keypair: %w", err)
	}

	shortID, err := GenerateShortID()
	if err != nil {
		return fmt.Errorf("generate short ID: %w", err)
	}

	// 4. Create directory structure
	mkdirCmd := fmt.Sprintf("mkdir -p %s", ssh.EscapeShellArg(XrayConfigDir))
	if _, errOut, code, err := client.RunSudoCommand(ctx, mkdirCmd); err != nil || code != 0 {
		return fmt.Errorf("failed to create xray config directory (code %d): %s: %w", code, errOut, err)
	}

	// 5. Render and upload initial config.json
	portHigh := 54321
	dest := netJoinHostPort(serverName, "443")
	cfgBytes, err := RenderXrayConfig(portPrimary, portHigh, serverName, dest, privB64, []string{shortID}, []XrayClient{})
	if err != nil {
		return fmt.Errorf("render xray config: %w", err)
	}

	if err := client.UploadSudoFile(ctx, XrayConfigPath, cfgBytes, 0644); err != nil {
		return fmt.Errorf("upload xray config: %w", err)
	}

	// 6. Cleanup any stale xray container
	stopCmd := fmt.Sprintf("docker stop %s 2>/dev/null || true; docker rm -fv %s 2>/dev/null || true",
		ssh.EscapeShellArg(XrayContainerName), ssh.EscapeShellArg(XrayContainerName))
	_, _, _, _ = client.RunSudoCommand(ctx, stopCmd)

	// Best effort image pull
	_, _, _, _ = client.RunSudoCommand(ctx, fmt.Sprintf("docker pull %s 2>/dev/null || true", ssh.EscapeShellArg(XrayBaseImage)))

	// 7. Launch amnezia-xray container
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

	// 8. Verify container is alive and not restarting
	checkCmd := fmt.Sprintf("docker inspect -f '{{.State.Running}} {{.State.Restarting}}' %s", ssh.EscapeShellArg(XrayContainerName))
	out, errOut, code, err := client.RunSudoCommand(ctx, checkCmd)
	if err != nil || code != 0 {
		return fmt.Errorf("xray container failed to inspect (code %d): %s: %w", code, errOut, err)
	}
	fields := strings.Fields(strings.TrimSpace(out))
	if len(fields) < 2 || fields[0] != "true" || fields[1] != "false" {
		return fmt.Errorf("xray container is not running (state: %s)", strings.TrimSpace(out))
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

	cleanupCmd := fmt.Sprintf(
		"docker stop %s 2>/dev/null || true; docker rm -fv %s 2>/dev/null || true; rm -rf %s",
		ssh.EscapeShellArg(XrayContainerName),
		ssh.EscapeShellArg(XrayContainerName),
		ssh.EscapeShellArg(XrayConfigDir),
	)
	_, _, _, _ = client.RunSudoCommand(ctx, cleanupCmd)
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
