package handlers

import (
	"context"
	"fmt"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// withdrawUserConnection revokes a user connection row only after remote revocation.
func (h *Handlers) withdrawUserConnection(ctx context.Context, c *models.UserConnection) error {
	shared, err := h.db.HasOtherUserConnectionCredential(ctx, c)
	if err != nil {
		return fmt.Errorf("check shared user credential: %w", err)
	}
	if shared {
		return fmt.Errorf("connection %s: %w", c.ID, database.ErrSharedUserCredential)
	}
	isBackend, err := h.db.IsBackendTunnelClient(ctx, c.ServerID, c.Protocol, c.ClientID)
	if err != nil {
		return fmt.Errorf("check backend tunnel: %w", err)
	}
	if isBackend {
		server, err := h.db.GetServer(ctx, c.ServerID)
		if err != nil || server == nil {
			return fmt.Errorf("load backend server %d: %v", c.ServerID, err)
		}
		mgr, err := h.GetProtocolManager(c.Protocol)
		if err != nil || mgr == nil {
			return fmt.Errorf("load backend protocol manager %q: %v", c.Protocol, err)
		}
		if err := h.vpnSvc.RotateSharedBackendCredential(ctx, server, mgr, c.Protocol, c.ClientID); err != nil {
			return fmt.Errorf("rotate shared backend credential: %w", err)
		}
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
