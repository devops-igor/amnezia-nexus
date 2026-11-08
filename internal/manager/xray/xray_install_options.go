package xray

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// This file owns resolution of installation options from the loosely typed
// params map that handlers pass to Install. It is a cohesive unit: everything
// here maps operator/API input onto concrete install settings without touching
// SSH, disk or containers.

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

	serverName := DefaultDecoyDomain
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
	if exp, ok := params["port_explicit"].(bool); ok {
		hasPort = exp
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

// parseMuxParam reports the operator's requested mux preference and whether it
// was specified at all. The value is recorded as server metadata only; it is
// deliberately NOT emitted into the generated vless:// URI (see
// DEV_OWNED_REPAIR.md, mux decision) because no interoperable, contract-backed
// share-link spelling exists for VLESS+Vision.
func parseMuxParam(params map[string]any) (bool, bool) {
	if params == nil {
		return false, false
	}
	if m, ok := params["mux"].(bool); ok {
		return m, true
	}
	if m, ok := params["mux"].(string); ok {
		return strings.EqualFold(m, "true"), true
	}
	switch vo := params["vless_options"].(type) {
	case map[string]any:
		if m, ok := vo["mux"].(bool); ok {
			return m, true
		}
		if m, ok := vo["mux"].(string); ok {
			return strings.EqualFold(m, "true"), true
		}
	case *models.VLESSInstallOptions:
		if vo != nil && vo.Mux != nil {
			return *vo.Mux, true
		}
	case models.VLESSInstallOptions:
		if vo.Mux != nil {
			return *vo.Mux, true
		}
	}
	return false, false
}
