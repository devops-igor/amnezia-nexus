package xray

import (
	"context"
	"encoding/json"
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

func resolveInstallNetworkOptions(params map[string]any) (int, string, string, bool, bool, bool) {
	portPrimary := 443
	hasPort := false
	if p, ok := params["port"]; ok && fmt.Sprint(p) != "" {
		if pInt, err := strconv.Atoi(fmt.Sprint(p)); err == nil && pInt > 0 {
			portPrimary = pInt
			hasPort = true
		}
	}

	serverName := "gateway.icloud.com"
	hasServerName := false
	flow := "xtls-rprx-vision"
	hasFlow := false

	if sn, ok := params["server_name"]; ok && fmt.Sprint(sn) != "" {
		serverName = fmt.Sprint(sn)
		hasServerName = true
	}
	if f, ok := params["flow"]; ok {
		flow = fmt.Sprint(f)
		hasFlow = true
	}
	if vo, ok := params["vless_options"]; ok && vo != nil {
		pStr, sn, fl, flSet := extractVLESSOptions(vo)
		if pStr != "" {
			if pInt, err := strconv.Atoi(pStr); err == nil && pInt > 0 {
				portPrimary = pInt
				hasPort = true
			}
		}
		if sn != "" {
			serverName = sn
			hasServerName = true
		}
		if flSet {
			flow = fl
			hasFlow = true
		}
	}
	if flow == "none" {
		flow = ""
	}
	return portPrimary, serverName, flow, hasPort, hasServerName, hasFlow
}

func detectRunningEngineProfile(ctx context.Context, client ssh.SSHClient) string {
	if client == nil {
		return ""
	}
	verCmd := fmt.Sprintf("docker exec %s xray version 2>/dev/null", ssh.EscapeShellArg(XrayContainerName))
	if verOut, _, code, err := client.RunSudoCommand(ctx, verCmd); err == nil && code == 0 && strings.TrimSpace(verOut) != "" {
		fields := strings.Fields(strings.TrimSpace(verOut))
		if len(fields) >= 2 && strings.EqualFold(fields[0], "Xray") {
			ver := fields[1]
			if strings.HasPrefix(ver, "26.10.") || strings.HasPrefix(ver, "v26.10.") {
				return string(EngineProfileModernPQ)
			}
			if strings.HasPrefix(ver, "1.8.") || strings.HasPrefix(ver, "v1.8.") {
				return string(EngineProfileLegacy)
			}
		}
	}

	imgCmd := fmt.Sprintf("docker inspect -f '{{.Config.Image}}' %s 2>/dev/null", ssh.EscapeShellArg(XrayContainerName))
	if imgOut, _, code, err := client.RunSudoCommand(ctx, imgCmd); err == nil && code == 0 && strings.TrimSpace(imgOut) != "" {
		img := strings.TrimSpace(imgOut)
		if strings.Contains(img, "26.10.") {
			return string(EngineProfileModernPQ)
		}
		if strings.Contains(img, "1.8.") {
			return string(EngineProfileLegacy)
		}
	}
	return ""
}

func resolveInstallProfileParam(ctx context.Context, client ssh.SSHClient, params map[string]any, server *models.Server) string {
	keys := []string{"engine_profile", "profile", "engine_version"}
	for _, k := range keys {
		if p, ok := params[k]; ok && fmt.Sprint(p) != "" {
			return fmt.Sprint(p)
		}
	}
	if vo, ok := params["vless_options"]; ok && vo != nil {
		switch v := vo.(type) {
		case map[string]any:
			for _, k := range []string{"engine_profile", "profile"} {
				if p, ok := v[k]; ok && fmt.Sprint(p) != "" {
					return fmt.Sprint(p)
				}
			}
		case *models.VLESSInstallOptions:
			if v != nil && v.EngineProfile != "" {
				return v.EngineProfile
			}
		case models.VLESSInstallOptions:
			if v.EngineProfile != "" {
				return v.EngineProfile
			}
		}
	}
	if server != nil && server.Protocols != nil {
		if vMeta, ok := server.Protocols[models.ProtocolVLESS].(map[string]any); ok {
			for _, k := range []string{"engine_profile", "engine_version"} {
				if val, ok := vMeta[k].(string); ok && val != "" {
					return val
				}
			}
		}
	}
	if client != nil {
		if detected := detectRunningEngineProfile(ctx, client); detected != "" {
			return detected
		}
	}
	return ""
}

func parseXrayInstallOptions(ctx context.Context, client ssh.SSHClient, params map[string]any, server *models.Server) (int, string, string, bool, bool, bool, EngineProfileInfo, error) {
	portPrimary, serverName, flow, hasPort, hasServerName, hasFlow := resolveInstallNetworkOptions(params)
	profileParam := resolveInstallProfileParam(ctx, client, params, server)
	profile, err := ResolveEngineProfile(profileParam)
	if err != nil {
		return 0, "", "", false, false, false, EngineProfileInfo{}, err
	}
	return portPrimary, serverName, flow, hasPort, hasServerName, hasFlow, profile, nil
}

func (m *XrayManager) resolveRealityCredentials(
	ctx context.Context,
	client ssh.SSHClient,
) (string, string, string, []string, []XrayClient, []byte, *XrayConfig, error) {
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
		return "", "", "", nil, nil, nil, nil, fmt.Errorf("failed to check existence of xray config %s: %w", XrayConfigPath, err)
	}
	if !exists {
		privB64, pubB64, genErr := GenerateRealityKeypair()
		if genErr != nil {
			return "", "", "", nil, nil, nil, nil, fmt.Errorf("generate reality keypair: %w", genErr)
		}
		shortID, genErr := GenerateShortID()
		if genErr != nil {
			return "", "", "", nil, nil, nil, nil, fmt.Errorf("generate short ID: %w", genErr)
		}
		return privB64, pubB64, shortID, []string{shortID}, []XrayClient{}, nil, nil, nil
	}

	catCmd := fmt.Sprintf("cat %s 2>/dev/null", ssh.EscapeShellArg(XrayConfigPath))
	catOut, catErrOut, catCode, catErr := client.RunSudoCommand(ctx, catCmd)
	var existingCfgBytes []byte
	if catErr == nil && catCode == 0 && strings.TrimSpace(catOut) != "" && strings.TrimSpace(catOut) != "OK" {
		existingCfgBytes = []byte(catOut)
	} else {
		data, dlErr := client.DownloadFile(ctx, XrayConfigPath)
		if dlErr != nil {
			return "", "", "", nil, nil, nil, nil, fmt.Errorf("failed to read existing xray config %s (cat code %d: %s, download err: %w)", XrayConfigPath, catCode, strings.TrimSpace(catErrOut), dlErr)
		}
		existingCfgBytes = data
	}

	trimmed := strings.TrimSpace(string(existingCfgBytes))
	if len(trimmed) == 0 {
		return "", "", "", nil, nil, nil, nil, fmt.Errorf("existing xray config %s is empty or truncated", XrayConfigPath)
	}

	parsed, parseErr := ParseXrayConfig(existingCfgBytes)
	if parseErr != nil {
		return "", "", "", nil, nil, nil, nil, fmt.Errorf("failed to parse existing xray config %s: %w", XrayConfigPath, parseErr)
	}

	if len(parsed.Inbounds) == 0 {
		return "", "", "", nil, nil, nil, nil, fmt.Errorf("existing xray config %s contains no inbounds", XrayConfigPath)
	}

	inbound := parsed.Inbounds[0]
	reality := inbound.StreamSettings.RealitySettings
	if reality.PrivateKey == "" {
		return "", "", "", nil, nil, nil, nil, fmt.Errorf("existing xray config %s missing reality private key", XrayConfigPath)
	}

	derivedPub, pubErr := DerivePublicKey(reality.PrivateKey)
	if pubErr != nil {
		return "", "", "", nil, nil, nil, nil, fmt.Errorf("failed to derive public key from existing reality private key: %w", pubErr)
	}

	privB64 := reality.PrivateKey
	pubB64 := derivedPub
	shortIDs := reality.ShortIDs
	var shortID string
	// A non-empty list is an existing identity, even when its first entry is "" (valid REALITY "no short ID").
	if len(shortIDs) > 0 {
		shortID = shortIDs[0]
	} else {
		var genErr error
		shortID, genErr = GenerateShortID()
		if genErr != nil {
			return "", "", "", nil, nil, nil, nil, fmt.Errorf("generate short ID: %w", genErr)
		}
		shortIDs = []string{shortID}
	}

	clients := inbound.Settings.Clients
	if clients == nil {
		clients = []XrayClient{}
	}

	return privB64, pubB64, shortID, shortIDs, clients, existingCfgBytes, parsed, nil
}

func (m *XrayManager) launchContainer(ctx context.Context, client ssh.SSHClient, image string, existingCfgBytes []byte) error {
	pullCmd := fmt.Sprintf("docker pull %s", ssh.EscapeShellArg(image))
	if _, pullErrOut, pullCode, pullErr := client.RunSudoCommand(ctx, pullCmd); pullErr != nil || pullCode != 0 {
		return fmt.Errorf("failed to pull xray image %s (code %d): %s: %w", image, pullCode, strings.TrimSpace(pullErrOut), pullErr)
	}

	backupContainerName := fmt.Sprintf("%s-backup", XrayContainerName)

	inspectExistingCmd := fmt.Sprintf("docker inspect -f '{{.State.Running}}' %s 2>/dev/null", ssh.EscapeShellArg(XrayContainerName))
	existingOut, _, existingCode, _ := client.RunSudoCommand(ctx, inspectExistingCmd)
	hasExistingContainer := existingCode == 0 && strings.TrimSpace(existingOut) != ""
	wasRunning := false
	if hasExistingContainer {
		fields := strings.Fields(strings.TrimSpace(existingOut))
		if len(fields) > 0 && fields[0] == "true" {
			wasRunning = true
		}
	}

	if hasExistingContainer {
		rmBackupCmd := fmt.Sprintf("docker rm -fv %s 2>/dev/null || true", ssh.EscapeShellArg(backupContainerName))
		_, _, _, _ = client.RunSudoCommand(ctx, rmBackupCmd)

		stopCmd := fmt.Sprintf("docker stop %s 2>/dev/null || true", ssh.EscapeShellArg(XrayContainerName))
		_, _, _, _ = client.RunSudoCommand(ctx, stopCmd)

		renameCmd := fmt.Sprintf("docker rename %s %s",
			ssh.EscapeShellArg(XrayContainerName),
			ssh.EscapeShellArg(backupContainerName),
		)
		if _, renameErrOut, renameCode, renameErr := client.RunSudoCommand(ctx, renameCmd); renameErr != nil || renameCode != 0 {
			return fmt.Errorf("failed to stage existing xray container for replacement (code %d): %s: %w", renameCode, strings.TrimSpace(renameErrOut), renameErr)
		}
	} else {
		rmCmd := fmt.Sprintf("docker rm -fv %s 2>/dev/null || true", ssh.EscapeShellArg(XrayContainerName))
		_, _, _, _ = client.RunSudoCommand(ctx, rmCmd)
	}

	rollback := func(triggerErr error) error {
		rmFailedCmd := fmt.Sprintf("docker stop %s 2>/dev/null || true; docker rm -fv %s 2>/dev/null || true",
			ssh.EscapeShellArg(XrayContainerName), ssh.EscapeShellArg(XrayContainerName))
		_, _, _, _ = client.RunSudoCommand(ctx, rmFailedCmd)

		if hasExistingContainer {
			if len(existingCfgBytes) > 0 {
				if rUpErr := client.UploadSudoFile(ctx, XrayConfigPath, existingCfgBytes, 0600); rUpErr != nil {
					return fmt.Errorf("%w (rollback failed to restore previous config: %v)", triggerErr, rUpErr)
				}
			}
			restoreCmd := fmt.Sprintf("docker rename %s %s",
				ssh.EscapeShellArg(backupContainerName), ssh.EscapeShellArg(XrayContainerName))
			if wasRunning {
				restoreCmd += fmt.Sprintf(" && docker start %s", ssh.EscapeShellArg(XrayContainerName))
			}
			if _, rErrOut, rCode, rErr := client.RunSudoCommand(ctx, restoreCmd); rErr != nil || rCode != 0 {
				return fmt.Errorf("%w (rollback failed to restore previous container, code %d: %s: %v)",
					triggerErr, rCode, strings.TrimSpace(rErrOut), rErr)
			}
			return fmt.Errorf("%w (rolled back to previous container)", triggerErr)
		}
		return triggerErr
	}

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
		ssh.EscapeShellArg(image),
	)

	if _, errOut, code, err := client.RunSudoCommand(ctx, runCmd); err != nil || code != 0 {
		return rollback(fmt.Errorf("failed to run xray container (code %d): %s: %w", code, strings.TrimSpace(errOut), err))
	}

	checkCmd := fmt.Sprintf("docker inspect -f '{{.State.Running}} {{.State.Restarting}}' %s", ssh.EscapeShellArg(XrayContainerName))
	out, errOut, code, err := client.RunSudoCommand(ctx, checkCmd)
	if err != nil || code != 0 {
		return rollback(fmt.Errorf("xray container failed to inspect (code %d): %s: %w", code, strings.TrimSpace(errOut), err))
	}
	fields := strings.Fields(strings.TrimSpace(out))
	if len(fields) < 2 || fields[0] != "true" || fields[1] != "false" {
		return rollback(fmt.Errorf("xray container is not running (state: %s)", strings.TrimSpace(out)))
	}

	if hasExistingContainer {
		rmBackupCmd := fmt.Sprintf("docker rm -fv %s 2>/dev/null || true", ssh.EscapeShellArg(backupContainerName))
		_, _, _, _ = client.RunSudoCommand(ctx, rmBackupCmd)
	}

	return nil
}

func resolveExistingPort(inbound XrayInbound, server *models.Server, fallbackPort int) int {
	if inbound.Port > 0 {
		return inbound.Port
	}
	if server != nil && server.Protocols != nil {
		if vMeta, ok := server.Protocols[models.ProtocolVLESS].(map[string]any); ok {
			if p, ok := vMeta["port"].(int); ok && p > 0 {
				return p
			}
			if pStr, ok := vMeta["port"].(string); ok {
				if pInt, err := strconv.Atoi(pStr); err == nil && pInt > 0 {
					return pInt
				}
			}
		}
	}
	return fallbackPort
}

func resolveExistingServerName(reality XrayRealitySettings, server *models.Server, fallback string) string {
	if len(reality.ServerNames) > 0 && reality.ServerNames[0] != "" {
		return reality.ServerNames[0]
	}
	if server != nil && server.Protocols != nil {
		if vMeta, ok := server.Protocols[models.ProtocolVLESS].(map[string]any); ok {
			if sn, ok := vMeta["server_name"].(string); ok && sn != "" {
				return sn
			}
		}
	}
	return fallback
}

func resolveExistingFlow(inbound XrayInbound, server *models.Server, fallback string) string {
	if server != nil && server.Protocols != nil {
		if vMeta, ok := server.Protocols[models.ProtocolVLESS].(map[string]any); ok {
			if fl, ok := vMeta["flow"].(string); ok {
				return fl
			}
		}
	}
	if len(inbound.Settings.Clients) > 0 && inbound.Settings.Clients[0].Flow != "" {
		return inbound.Settings.Clients[0].Flow
	}
	return fallback
}

func (m *XrayManager) prepareConfigBytes(
	existingCfgBytes []byte,
	existingParsed *XrayConfig,
	portPrimary int,
	serverName, flow string,
	hasPort, hasServerName, hasFlow bool,
	privB64 string,
	shortIDs []string,
	clients []XrayClient,
	server *models.Server,
) ([]byte, int, string, string, error) {
	if existingCfgBytes == nil || existingParsed == nil || len(existingParsed.Inbounds) == 0 {
		portHigh := 54321
		dest := netJoinHostPort(serverName, "443")
		rendered, err := RenderXrayConfig(portPrimary, portHigh, serverName, dest, privB64, shortIDs, clients)
		if err != nil {
			return nil, 0, "", "", fmt.Errorf("render xray config: %w", err)
		}
		return rendered, portPrimary, serverName, flow, nil
	}

	existingInbound := existingParsed.Inbounds[0]
	existingReality := existingInbound.StreamSettings.RealitySettings

	if !hasPort {
		portPrimary = resolveExistingPort(existingInbound, server, portPrimary)
	}
	if !hasServerName {
		serverName = resolveExistingServerName(existingReality, server, serverName)
	}
	if !hasFlow {
		flow = resolveExistingFlow(existingInbound, server, flow)
	}

	portChanged := hasPort && (portPrimary != existingInbound.Port)
	sniChanged := hasServerName && (len(existingReality.ServerNames) == 0 || existingReality.ServerNames[0] != serverName)
	flowChanged := hasFlow

	if !portChanged && !sniChanged && !flowChanged {
		return existingCfgBytes, portPrimary, serverName, flow, nil
	}

	updated, err := updateExistingConfig(existingCfgBytes, portPrimary, serverName, flow, portChanged, sniChanged, flowChanged)
	if err != nil {
		return nil, 0, "", "", err
	}
	return updated, portPrimary, serverName, flow, nil
}

func updateExistingConfig(existingCfgBytes []byte, portPrimary int, serverName, flow string, portChanged, sniChanged, flowChanged bool) ([]byte, error) {
	var doc map[string]any
	if err := json.Unmarshal(existingCfgBytes, &doc); err != nil {
		return nil, fmt.Errorf("unmarshal existing xray config: %w", err)
	}
	if inbounds, ok := doc["inbounds"].([]any); ok && len(inbounds) > 0 {
		if in0, ok := inbounds[0].(map[string]any); ok {
			if portChanged {
				in0["port"] = portPrimary
			}
			if sniChanged {
				if ss, ok := in0["streamSettings"].(map[string]any); ok {
					if rs, ok := ss["realitySettings"].(map[string]any); ok {
						rs["serverNames"] = []any{serverName}
						rs["dest"] = netJoinHostPort(serverName, "443")
					}
				}
			}
			if flowChanged {
				if settings, ok := in0["settings"].(map[string]any); ok {
					if cls, ok := settings["clients"].([]any); ok {
						for _, c := range cls {
							if cm, ok := c.(map[string]any); ok {
								cm["flow"] = flow
							}
						}
					}
				}
			}
		}
	}
	updated, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal updated xray config: %w", err)
	}
	return updated, nil
}

func determineRunningEngineVersion(ctx context.Context, client ssh.SSHClient, defaultVersion string) string {
	verCmd := fmt.Sprintf("docker exec %s xray version 2>/dev/null", ssh.EscapeShellArg(XrayContainerName))
	if verOut, _, code, err := client.RunSudoCommand(ctx, verCmd); err == nil && code == 0 && strings.TrimSpace(verOut) != "" {
		if fields := strings.Fields(strings.TrimSpace(verOut)); len(fields) >= 2 && strings.EqualFold(fields[0], "Xray") {
			return fields[1]
		}
	}
	return defaultVersion
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

	// 2. Parse installation options and resolve engine profile
	portPrimary, serverName, flow, hasPort, hasServerName, hasFlow, profile, err := parseXrayInstallOptions(ctx, client, params, server)
	if err != nil {
		return err
	}

	// 3. Generate or preserve REALITY cryptographic credentials and existing clients
	privB64, pubB64, shortID, shortIDs, clients, existingCfgBytes, existingParsed, err := m.resolveRealityCredentials(ctx, client)
	if err != nil {
		return err
	}

	// 4. Create directory structure
	mkdirCmd := fmt.Sprintf("mkdir -p %s && chmod 0700 %s", ssh.EscapeShellArg(XrayConfigDir), ssh.EscapeShellArg(XrayConfigDir))
	if _, errOut, code, err := client.RunSudoCommand(ctx, mkdirCmd); err != nil || code != 0 {
		return fmt.Errorf("failed to create xray config directory (code %d): %s: %w", code, errOut, err)
	}

	// 5. Render or preserve and upload config.json
	cfgBytes, portPrimary, serverName, flow, err := m.prepareConfigBytes(
		existingCfgBytes, existingParsed, portPrimary, serverName, flow,
		hasPort, hasServerName, hasFlow, privB64, shortIDs, clients, server,
	)
	if err != nil {
		return err
	}

	if err := client.UploadSudoFile(ctx, XrayConfigPath, cfgBytes, 0600); err != nil {
		return fmt.Errorf("upload xray config: %w", err)
	}

	// 6. Launch amnezia-xray container with resolved profile image
	if err := m.launchContainer(ctx, client, profile.Image, existingCfgBytes); err != nil {
		return err
	}

	m.containerCache.set(m.containerCache.keyForServer(server), true)

	// Determine running engine version from container inspect/exec
	runningVersion := determineRunningEngineVersion(ctx, client, profile.Version)

	// Update server.Protocols in-memory for caller awareness
	if server.Protocols == nil {
		server.Protocols = make(map[string]any)
	}
	protoMeta, _ := server.Protocols[models.ProtocolVLESS].(map[string]any)
	if protoMeta == nil {
		protoMeta = make(map[string]any)
	}
	protoMeta["installed"] = true
	protoMeta["port"] = portPrimary
	protoMeta["server_name"] = serverName
	protoMeta["public_key"] = pubB64
	protoMeta["short_id"] = shortID
	protoMeta["flow"] = flow
	protoMeta["engine_profile"] = string(profile.Name)
	protoMeta["engine_version"] = profile.Version
	protoMeta["engine_image"] = profile.Image
	protoMeta["running_engine_version"] = runningVersion
	server.Protocols[models.ProtocolVLESS] = protoMeta

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
