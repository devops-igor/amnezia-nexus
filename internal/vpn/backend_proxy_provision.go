package vpn

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// ErrEmptyParams indicates that proxy protocol parameters are missing.
var ErrEmptyParams = errors.New("protocol parameters cannot be empty")

// ErrMultiProtocolBackendsDisabled indicates that multi-protocol backends are disabled in configuration.
var ErrMultiProtocolBackendsDisabled = errors.New("multi-protocol backends are disabled")

// MultiProtocolEnabled reports whether multi-protocol backends are enabled.
func (s *Service) MultiProtocolEnabled() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg != nil && s.cfg.EnableMultiProtocolBackends
}

// ResolveServerEngineProfile returns the configured engine profile for proto from server metadata,
// returning "" if unconfigured or not a proxy protocol.
func ResolveServerEngineProfile(server *models.Server, proto string) string {
	if server == nil || server.Protocols == nil {
		return ""
	}
	normProto := models.NormalizeTunnelProtocol(proto)
	pInfo, ok := server.Protocols[normProto].(map[string]any)
	if !ok || pInfo == nil {
		return ""
	}
	for _, k := range []string{"engine_profile", "profile", "engine_version"} {
		if val, ok := pInfo[k].(string); ok && strings.TrimSpace(val) != "" {
			return strings.TrimSpace(val)
		}
	}
	return ""
}

// SyncVLESSParamsEngineProfile ensures that VLESS protocol parameters reflect the authoritative
// engine_profile from server metadata (e.g. "modern_pq" or "legacy") when not explicitly overridden.
func SyncVLESSParamsEngineProfile(rawParams json.RawMessage, server *models.Server) json.RawMessage {
	if len(rawParams) == 0 || server == nil {
		return rawParams
	}
	engineProfile := ResolveServerEngineProfile(server, models.ProtocolVLESS)
	if engineProfile == "" {
		return rawParams
	}
	var p models.VLESSRealityParams
	if err := json.Unmarshal(rawParams, &p); err != nil {
		return rawParams
	}
	if p.EngineProfile == engineProfile {
		return rawParams
	}
	p.EngineProfile = engineProfile
	if updated, err := json.Marshal(p); err == nil {
		return updated
	}
	return rawParams
}

// ResolveServerProxyProtocol inspects server.Protocols. If AWG is not installed,
// it checks whether VLESS or Naive is installed and returns the protocol name and its
// preserved protocol parameters if present in metadata.
func ResolveServerProxyProtocol(server *models.Server) (string, json.RawMessage, error) {
	if server == nil || server.Protocols == nil {
		return "", nil, nil
	}
	if awgInfo, ok := server.Protocols["awg"].(map[string]any); ok {
		if inst, _ := awgInfo["installed"].(bool); inst {
			return "", nil, nil
		}
		if pub, _ := awgInfo["public_key"].(string); pub != "" {
			return "", nil, nil
		}
	}
	for _, p := range []string{models.ProtocolVLESS, models.ProtocolNaive} {
		if pInfo, ok := server.Protocols[p].(map[string]any); ok {
			if inst, _ := pInfo["installed"].(bool); inst {
				params, err := DeriveProxyProtocolParams(server, p)
				if err != nil && !errors.Is(err, ErrEmptyParams) {
					return "", nil, err
				}
				return p, params, nil
			}
		}
	}
	return "", nil, nil
}

// DeriveProxyProtocolParams retrieves typed protocol parameters (VLESSRealityParams
// or NaiveProxyParams) for a server that has the proxy protocol installed in server.Protocols.
// If valid params or protocol_params are already present, they are returned.
// Otherwise, ErrEmptyParams is returned because proxy credentials must be provisioned
// via protocol managers and cannot be synthesized locally.
func DeriveProxyProtocolParams(server *models.Server, proto string) (json.RawMessage, error) {
	if server == nil || server.Protocols == nil {
		return nil, errors.New("server protocols not available")
	}
	normProto := models.NormalizeTunnelProtocol(proto)
	pInfo, ok := server.Protocols[normProto].(map[string]any)
	if !ok || pInfo == nil {
		return nil, fmt.Errorf("protocol %s not configured on server", normProto)
	}

	// 1. Preserve existing params or protocol_params if already populated in metadata.
	if pVal, ok := pInfo["params"]; ok && pVal != nil {
		if b, err := json.Marshal(pVal); err == nil && len(bytes.TrimSpace(b)) > 2 && string(bytes.TrimSpace(b)) != "null" {
			if normProto == models.ProtocolVLESS {
				b = SyncVLESSParamsEngineProfile(b, server)
			}
			return b, nil
		}
	}
	if pVal, ok := pInfo["protocol_params"]; ok && pVal != nil {
		if b, err := json.Marshal(pVal); err == nil && len(bytes.TrimSpace(b)) > 2 && string(bytes.TrimSpace(b)) != "null" {
			if normProto == models.ProtocolVLESS {
				b = SyncVLESSParamsEngineProfile(b, server)
			}
			return b, nil
		}
	}

	return nil, fmt.Errorf("protocol parameters required for proxy backend: %w", ErrEmptyParams)
}
