package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// withdrawUserConnection revokes a user connection row. If the client ID is actively used
// by a backend tunnel, remote credential removal is bypassed, the connection row in SQLite
// is deleted, and the peer lifecycle record is preserved as operator-supplied active.
func (h *Handlers) withdrawUserConnection(ctx context.Context, c *models.UserConnection) error {
	isBackend, err := h.isBackendTunnelClient(ctx, c.ServerID, c.ClientID)
	if err != nil {
		return fmt.Errorf("check backend tunnel: %w", err)
	}
	if isBackend {
		slog.Info("preserving active backend tunnel credential while withdrawing user connection",
			"server_id", c.ServerID, "protocol", c.Protocol, "client_id", c.ClientID, "user_id", c.UserID)
		if _, err := h.db.DeleteConnection(ctx, c.ID); err != nil {
			return fmt.Errorf("delete connection: %w", err)
		}
		if h.db != nil {
			name := c.Name
			if name == "" {
				name = fmt.Sprintf("vpn-backend-%d", c.ServerID)
			}
			_ = h.db.RecordPeerLifecycle(ctx, c.ServerID, c.Protocol, c.ClientID, name, "", "active")
			_ = h.db.RecordPeerLifecycle(ctx, c.ServerID, c.Protocol, c.ClientID, name, "operator_supplied", "active")
		}
		return nil
	}
	if err := h.removeRemoteClient(ctx, c); err != nil {
		return err
	}
	if _, err := h.db.DeleteConnection(ctx, c.ID); err != nil {
		return fmt.Errorf("delete connection: %w", err)
	}
	_ = h.db.DeletePeerLifecycle(ctx, c.ServerID, c.Protocol, c.ClientID)
	return nil
}

func (h *Handlers) isBackendTunnelClient(ctx context.Context, serverID int64, clientID string) (bool, error) {
	if h.db == nil || clientID == "" || serverID == 0 {
		return false, nil
	}
	tunnels, err := h.db.GetBackendTunnelsByServerID(ctx, serverID)
	if err != nil {
		return false, fmt.Errorf("get backend tunnels for server %d: %w", serverID, err)
	}
	for _, t := range tunnels {
		if isMatchingBackendTunnelClient(&t, clientID) {
			return true, nil
		}
	}
	return false, nil
}

func isMatchingBackendTunnelClient(t *models.BackendTunnel, clientID string) bool {
	if t == nil || clientID == "" {
		return false
	}
	if len(t.ProtocolParams) > 0 {
		var naive models.NaiveProxyParams
		if err := json.Unmarshal(t.ProtocolParams, &naive); err == nil && naive.Username != "" {
			if naive.Username == clientID {
				return true
			}
		}
		var vless models.VLESSRealityParams
		if err := json.Unmarshal(t.ProtocolParams, &vless); err == nil && vless.UUID != "" {
			if strings.EqualFold(vless.UUID, clientID) {
				return true
			}
		}
		var raw map[string]any
		if err := json.Unmarshal(t.ProtocolParams, &raw); err == nil {
			for _, k := range []string{"username", "user", "client_id", "clientId", "uuid", "id"} {
				if v, ok := raw[k].(string); ok && v != "" {
					if strings.EqualFold(v, clientID) {
						return true
					}
				}
			}
		}
	}
	if t.PublicKey != "" && t.PublicKey == clientID {
		return true
	}
	return false
}
