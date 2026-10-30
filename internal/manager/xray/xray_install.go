package xray

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/google/uuid"
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

type containerLaunchOptions struct {
	image            string
	engineProfile    string
	existingCfgBytes []byte
	server           *models.Server
	portPrimary      int
	serverName       string
	pubB64           string
	shortID          string
	flow             string
	clients          []XrayClient
}

func (m *XrayManager) pullImage(ctx context.Context, client ssh.SSHClient, image string) error {
	pullCmd := fmt.Sprintf("docker pull %s", ssh.EscapeShellArg(image))
	if _, pullErrOut, pullCode, pullErr := client.RunSudoCommand(ctx, pullCmd); pullErr != nil || pullCode != 0 {
		return fmt.Errorf("failed to pull xray image %s (code %d): %s: %w", image, pullCode, strings.TrimSpace(pullErrOut), pullErr)
	}
	return nil
}

func (m *XrayManager) stageExistingContainer(
	ctx context.Context,
	client ssh.SSHClient,
	backupContainerName string,
	existingCfgBytes []byte,
) (bool, bool, error) {
	inspectExistingCmd := fmt.Sprintf("docker inspect -f '{{.State.Running}}' %s 2>/dev/null", ssh.EscapeShellArg(XrayContainerName))
	existingOut, _, existingCode, _ := client.RunSudoCommand(ctx, inspectExistingCmd)
	hasExistingContainer := existingCode == 0 && strings.TrimSpace(existingOut) != "" && strings.TrimSpace(existingOut) != "false false"
	wasRunning := false
	if hasExistingContainer {
		if len(existingCfgBytes) == 0 {
			return false, false, fmt.Errorf("existing xray container detected but original configuration could not be recovered; aborting to preserve container state")
		}
		fields := strings.Fields(strings.TrimSpace(existingOut))
		if len(fields) > 0 && fields[0] == "true" {
			wasRunning = true
		}
		rmBackupCmd := fmt.Sprintf("docker rm -fv %s 2>/dev/null || true", ssh.EscapeShellArg(backupContainerName))
		_, _, _, _ = client.RunSudoCommand(ctx, rmBackupCmd)

		if wasRunning {
			stopCmd := fmt.Sprintf("docker stop %s", ssh.EscapeShellArg(XrayContainerName))
			if _, stopErrOut, stopCode, stopErr := client.RunSudoCommand(ctx, stopCmd); stopErr != nil || stopCode != 0 {
				recCtx, recCancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
				defer recCancel()
				var recErrs []string
				if len(existingCfgBytes) > 0 {
					if rUpErr := client.UploadSudoFile(recCtx, XrayConfigPath, existingCfgBytes, 0600); rUpErr != nil {
						recErrs = append(recErrs, fmt.Sprintf("failed to restore config: %v", rUpErr))
					}
				}
				startCmd := fmt.Sprintf("docker start %s", ssh.EscapeShellArg(XrayContainerName))
				if _, sErrOut, sCode, sErr := client.RunSudoCommand(recCtx, startCmd); sErr != nil || sCode != 0 {
					recErrs = append(recErrs, fmt.Sprintf("failed to restart container (code %d): %s: %v", sCode, strings.TrimSpace(sErrOut), sErr))
				}
				errBase := fmt.Errorf("failed to stop existing xray container for staging (code %d): %s: %w", stopCode, strings.TrimSpace(stopErrOut), stopErr)
				if len(recErrs) > 0 {
					return false, false, fmt.Errorf("%w (recovery failures: %s)", errBase, strings.Join(recErrs, "; "))
				}
				return false, false, errBase
			}
		}

		renameCmd := fmt.Sprintf("docker rename %s %s",
			ssh.EscapeShellArg(XrayContainerName),
			ssh.EscapeShellArg(backupContainerName),
		)
		if _, renameErrOut, renameCode, renameErr := client.RunSudoCommand(ctx, renameCmd); renameErr != nil || renameCode != 0 {
			recCtx, recCancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer recCancel()
			var recErrs []string
			if len(existingCfgBytes) > 0 {
				if rUpErr := client.UploadSudoFile(recCtx, XrayConfigPath, existingCfgBytes, 0600); rUpErr != nil {
					recErrs = append(recErrs, fmt.Sprintf("failed to restore config: %v", rUpErr))
				}
			}
			if wasRunning {
				startCmd := fmt.Sprintf("docker start %s", ssh.EscapeShellArg(XrayContainerName))
				if _, sErrOut, sCode, sErr := client.RunSudoCommand(recCtx, startCmd); sErr != nil || sCode != 0 {
					recErrs = append(recErrs, fmt.Sprintf("failed to restart container (code %d): %s: %v", sCode, strings.TrimSpace(sErrOut), sErr))
				}
			}
			errBase := fmt.Errorf("failed to stage existing xray container for replacement (code %d): %s: %w", renameCode, strings.TrimSpace(renameErrOut), renameErr)
			if len(recErrs) > 0 {
				return false, false, fmt.Errorf("%w (recovery failures: %s)", errBase, strings.Join(recErrs, "; "))
			}
			return false, false, errBase
		}
	} else {
		rmCmd := fmt.Sprintf("docker rm -fv %s 2>/dev/null || true", ssh.EscapeShellArg(XrayContainerName))
		_, _, _, _ = client.RunSudoCommand(ctx, rmCmd)
		hasExistingContainer = false
		wasRunning = false
	}
	return hasExistingContainer, wasRunning, nil
}

func (m *XrayManager) verifyContainerReadiness(ctx context.Context, client ssh.SSHClient, opts containerLaunchOptions) error {
	const (
		readinessAttempts = 3
		readinessInterval = 50 * time.Millisecond
	)

	for attempt := 1; attempt <= readinessAttempts; attempt++ {
		if attempt > 1 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(readinessInterval):
			}
		}

		checkCmd := fmt.Sprintf("docker inspect -f '{{.State.Running}} {{.State.Restarting}}' %s", ssh.EscapeShellArg(XrayContainerName))
		out, errOut, code, err := client.RunSudoCommand(ctx, checkCmd)
		if err != nil || code != 0 {
			logCmd := fmt.Sprintf("docker logs --tail 50 %s 2>&1", ssh.EscapeShellArg(XrayContainerName))
			logsOut, _, _, _ := client.RunSudoCommand(ctx, logCmd)
			return fmt.Errorf("xray container failed to inspect on readiness check (attempt %d, code %d): %s: %w (logs: %s)",
				attempt, code, strings.TrimSpace(errOut), err, strings.TrimSpace(logsOut))
		}
		fields := strings.Fields(strings.TrimSpace(out))
		if len(fields) < 2 || fields[0] != "true" || fields[1] != "false" {
			logCmd := fmt.Sprintf("docker logs --tail 50 %s 2>&1", ssh.EscapeShellArg(XrayContainerName))
			logsOut, _, _, _ := client.RunSudoCommand(ctx, logCmd)
			return fmt.Errorf("xray container readiness check failed (attempt %d, state: %s, logs: %s)",
				attempt, strings.TrimSpace(out), strings.TrimSpace(logsOut))
		}
	}

	m.mu.Lock()
	probeFn := m.vlessProbeFn
	trafficProbeFn := m.vlessTrafficProbeFn
	m.mu.Unlock()

	hasClients := len(opts.clients) > 0
	var activeProbeFn VLESSProbeFunc
	probeMode := "REALITY handshake"

	if hasClients {
		if trafficProbeFn != nil {
			activeProbeFn = trafficProbeFn
			probeMode = "VLESS traffic"
		} else if probeFn != nil {
			// Fallback to handshake probe if traffic probe is not explicitly configured
			activeProbeFn = probeFn
			probeMode = "REALITY handshake"
		}
	} else {
		// Fresh install without clients: keep TLS handshake probe and document it explicitly.
		// Fresh installs have an empty clients list, so VLESS client traffic authorization
		// cannot be tested until user credentials are added. The REALITY TLS probe verifies
		// container startup, TLS certificate/key configuration, and shortID handling.
		activeProbeFn = probeFn
		probeMode = "REALITY handshake"
	}

	if activeProbeFn != nil && opts.server != nil && opts.portPrimary > 0 {
		probeUUID := ""
		probeFlow := opts.flow
		if hasClients {
			probeUUID = opts.clients[0].ID
			if opts.clients[0].Flow != "" {
				probeFlow = opts.clients[0].Flow
			}
		}
		if probeUUID == "" {
			probeUUID = uuid.NewString()
		}

		probeParams := models.VLESSRealityParams{
			UUID:          probeUUID,
			Flow:          probeFlow,
			PublicKey:     opts.pubB64,
			ShortID:       opts.shortID,
			ServerName:    opts.serverName,
			EngineProfile: opts.engineProfile,
		}
		endpoint := net.JoinHostPort(opts.server.Host, strconv.Itoa(opts.portPrimary))
		probeCtx, probeCancel := context.WithTimeout(ctx, 3*time.Second)
		defer probeCancel()

		if _, probeErr := activeProbeFn(probeCtx, endpoint, probeParams, 3*time.Second); probeErr != nil {
			logCmd := fmt.Sprintf("docker logs --tail 50 %s 2>&1", ssh.EscapeShellArg(XrayContainerName))
			logsOut, _, _, _ := client.RunSudoCommand(ctx, logCmd)
			return fmt.Errorf("xray container failed %s readiness probe: %w (logs: %s)", probeMode, probeErr, strings.TrimSpace(logsOut))
		}
	}

	return nil
}

func (m *XrayManager) launchContainer(ctx context.Context, client ssh.SSHClient, opts containerLaunchOptions) error {
	backupContainerName := fmt.Sprintf("%s-backup", XrayContainerName)

	hasExistingContainer, wasRunning, err := m.stageExistingContainer(ctx, client, backupContainerName, opts.existingCfgBytes)
	if err != nil {
		return err
	}

	rollback := func(triggerErr error) error {
		recoveryCtx, recoveryCancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer recoveryCancel()

		rmFailedCmd := fmt.Sprintf("docker stop %s 2>/dev/null || true; docker rm -fv %s 2>/dev/null || true",
			ssh.EscapeShellArg(XrayContainerName), ssh.EscapeShellArg(XrayContainerName))
		_, _, _, _ = client.RunSudoCommand(recoveryCtx, rmFailedCmd)

		if hasExistingContainer {
			if len(opts.existingCfgBytes) > 0 {
				if rUpErr := client.UploadSudoFile(recoveryCtx, XrayConfigPath, opts.existingCfgBytes, 0600); rUpErr != nil {
					return fmt.Errorf("%w (rollback failed to restore previous config: %v)", triggerErr, rUpErr)
				}
			}
			restoreCmd := fmt.Sprintf("docker rename %s %s",
				ssh.EscapeShellArg(backupContainerName), ssh.EscapeShellArg(XrayContainerName))
			if wasRunning {
				restoreCmd += fmt.Sprintf(" && docker start %s", ssh.EscapeShellArg(XrayContainerName))
			}
			if _, rErrOut, rCode, rErr := client.RunSudoCommand(recoveryCtx, restoreCmd); rErr != nil || rCode != 0 {
				return fmt.Errorf("%w (rollback failed to restore previous container, code %d: %s: %v)",
					triggerErr, rCode, strings.TrimSpace(rErrOut), rErr)
			}
			return fmt.Errorf("%w (rolled back to previous container)", triggerErr)
		}
		if len(opts.existingCfgBytes) > 0 {
			_ = client.UploadSudoFile(recoveryCtx, XrayConfigPath, opts.existingCfgBytes, 0600)
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
		ssh.EscapeShellArg(opts.image),
	)

	if _, errOut, code, err := client.RunSudoCommand(ctx, runCmd); err != nil || code != 0 {
		return rollback(fmt.Errorf("failed to run xray container (code %d): %s: %w", code, strings.TrimSpace(errOut), err))
	}

	if err := m.verifyContainerReadiness(ctx, client, opts); err != nil {
		return rollback(err)
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

	// 5. Pre-pull / validate container image BEFORE mutating live configuration on disk.
	if err := m.pullImage(ctx, client, profile.Image); err != nil {
		return err
	}

	// 6. Render or preserve and upload config.json
	cfgBytes, portPrimary, serverName, flow, err := m.prepareConfigBytes(
		existingCfgBytes, existingParsed, portPrimary, serverName, flow,
		hasPort, hasServerName, hasFlow, privB64, shortIDs, clients, server,
	)
	if err != nil {
		return err
	}

	if err := client.UploadSudoFile(ctx, XrayConfigPath, cfgBytes, 0600); err != nil {
		if len(existingCfgBytes) > 0 {
			recCtx, recCancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			_ = client.UploadSudoFile(recCtx, XrayConfigPath, existingCfgBytes, 0600)
			recCancel()
		}
		return fmt.Errorf("upload xray config: %w", err)
	}

	// 7. Launch amnezia-xray container with resolved profile image and verify readiness before deleting backup
	launchOpts := containerLaunchOptions{
		image:            profile.Image,
		engineProfile:    string(profile.Name),
		existingCfgBytes: existingCfgBytes,
		server:           server,
		portPrimary:      portPrimary,
		serverName:       serverName,
		pubB64:           pubB64,
		shortID:          shortID,
		flow:             flow,
		clients:          clients,
	}
	if err := m.launchContainer(ctx, client, launchOpts); err != nil {
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
