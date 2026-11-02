package vpn

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// ErrEmptyParams indicates that proxy protocol parameters are missing.
var ErrEmptyParams = errors.New("protocol parameters cannot be empty")

// Deprecated: Multi-protocol backends are unconditionally active. Retained for package compatibility.
var ErrMultiProtocolBackendsDisabled = errors.New("multi-protocol backends are disabled")

const (
	// PeerOwnershipAutoProvisioned marks credentials auto-provisioned by Nexus.
	// These credentials may be cleaned up by reconciliation if orphaned.
	PeerOwnershipAutoProvisioned = "auto_provisioned"
	// PeerOwnershipOperatorSupplied marks credentials supplied by an operator or external source.
	// These credentials must never be automatically revoked by reconciliation.
	PeerOwnershipOperatorSupplied = "operator_supplied"
)

// MultiProtocolEnabled reports whether multi-protocol backends are enabled.
// Multi-protocol backends are unconditionally active out-of-the-box (#661).
func (s *Service) MultiProtocolEnabled() bool {
	return true
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

// RecordBackendProxyPeerLifecycle records a backend proxy peer in peer_lifecycle with status "backend_active".
func RecordBackendProxyPeerLifecycle(ctx context.Context, db *database.DB, serverID int64, proto, clientID, name string) error {
	return RecordBackendProxyPeerLifecycleWithOwnership(ctx, db, serverID, proto, clientID, name, PeerOwnershipAutoProvisioned)
}

// RecordBackendProxyPeerLifecycleWithOwnership records a backend proxy peer in peer_lifecycle with status "backend_active" and explicit ownership metadata.
// It preserves any existing non-empty user_id associated with the peer so user associations are not overwritten on conflict.
func RecordBackendProxyPeerLifecycleWithOwnership(ctx context.Context, db *database.DB, serverID int64, proto, clientID, name, ownership string) error {
	if db == nil || clientID == "" {
		return nil
	}
	if name == "" {
		name = fmt.Sprintf("vpn-backend-%d", serverID)
	}
	if ownership == "" {
		ownership = PeerOwnershipOperatorSupplied
	}
	targetUserID := ownership
	if lifecycles, err := db.GetPeerLifecycles(ctx, serverID, proto); err == nil {
		if existing, ok := lifecycles[clientID]; ok {
			if existing.UserID != "" && existing.UserID != PeerOwnershipAutoProvisioned && existing.UserID != PeerOwnershipOperatorSupplied {
				targetUserID = existing.UserID
			}
		}
	}
	return db.RecordPeerLifecycle(ctx, serverID, proto, clientID, name, targetUserID, "backend_active")
}

// ExtractClientIDFromProtocolParams extracts the client identifier (UUID or username)
// from typed or untyped proxy protocol parameters.
func ExtractClientIDFromProtocolParams(proto string, params json.RawMessage) string {
	if len(params) == 0 {
		return ""
	}
	normProto := models.NormalizeTunnelProtocol(proto)
	switch normProto {
	case models.ProtocolVLESS:
		var vless models.VLESSRealityParams
		if err := json.Unmarshal(params, &vless); err == nil && vless.UUID != "" {
			return vless.UUID
		}
	case models.ProtocolNaive:
		var naive models.NaiveProxyParams
		if err := json.Unmarshal(params, &naive); err == nil && naive.Username != "" {
			return naive.Username
		}
	}
	var raw map[string]any
	if err := json.Unmarshal(params, &raw); err == nil {
		for _, k := range []string{"username", "client_id", "clientId", "uuid", "user", "id"} {
			if v, ok := raw[k].(string); ok && v != "" {
				return v
			}
		}
	}
	return ""
}

// EnsureBackendProxyPeerPreservation ensures that any proxy credential associated with a
// backend tunnel retains or establishes durable peer_lifecycle preservation before the
// backend registration is deleted. If no lifecycle record exists (e.g. following a failed
// enrollment write), a durable non-auto "operator_supplied" record with status "active" is
// persisted. If persistence fails, an error is returned so deletion can fail closed.
func EnsureBackendProxyPeerPreservation(ctx context.Context, db *database.DB, serverID int64, proto string, params json.RawMessage) error {
	if db == nil {
		return nil
	}
	normProto := models.NormalizeTunnelProtocol(proto)
	if normProto != models.ProtocolVLESS && normProto != models.ProtocolNaive {
		return nil
	}
	cid := ExtractClientIDFromProtocolParams(normProto, params)
	if cid == "" {
		return nil
	}
	lifecycles, err := db.GetPeerLifecycles(ctx, serverID, normProto)
	if err != nil {
		return fmt.Errorf("failed to query peer lifecycles for backend %d: %w", serverID, err)
	}
	if existing, ok := lifecycles[cid]; ok {
		// If already tracked as auto_provisioned, preserve known-auto cleanup semantics.
		if existing.UserID == PeerOwnershipAutoProvisioned {
			return nil
		}
		// If already tracked with non-auto ownership (operator_supplied or real user ID),
		// ensure its status is active if it was backend_active.
		if existing.Status == "backend_active" {
			if err := db.SetPeerLifecycleStatus(ctx, serverID, normProto, cid, "active"); err != nil {
				return fmt.Errorf("failed to update peer lifecycle status to active for backend %d: %w", serverID, err)
			}
		}
		return nil
	}
	// No lifecycle record exists! Missing or failed enrollment.
	// Establish a durable non-auto preservation record with status="active" and operator ownership.
	name := fmt.Sprintf("vpn-backend-%d", serverID)
	if err := db.RecordPeerLifecycle(ctx, serverID, normProto, cid, name, PeerOwnershipOperatorSupplied, "active"); err != nil {
		return fmt.Errorf("failed to persist operator peer lifecycle preservation for backend %d: %w", serverID, err)
	}
	return nil
}
