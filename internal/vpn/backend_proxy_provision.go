package vpn

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// ErrEmptyParams indicates that proxy protocol parameters are missing.
var ErrEmptyParams = errors.New("protocol parameters cannot be empty")

// ErrMultiProtocolBackendsDisabled indicates that multi-protocol backends are disabled in configuration.
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
func (s *Service) MultiProtocolEnabled() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg != nil && s.cfg.EnableMultiProtocolBackends
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
			return b, nil
		}
	}
	if pVal, ok := pInfo["protocol_params"]; ok && pVal != nil {
		if b, err := json.Marshal(pVal); err == nil && len(bytes.TrimSpace(b)) > 2 && string(bytes.TrimSpace(b)) != "null" {
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
	return db.RecordPeerLifecycle(ctx, serverID, proto, clientID, name, ownership, "backend_active")
}
