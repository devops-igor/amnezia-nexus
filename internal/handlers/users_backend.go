package handlers

import (
	"context"
	"errors"
	"fmt"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// ErrSharedBackendCredential prevents an existing shared credential from being silently orphaned.
var ErrSharedBackendCredential = errors.New("user credential is shared with a backend; rotate backend credentials before revoking user")

// withdrawUserConnection revokes a user connection row only after remote revocation.
func (h *Handlers) withdrawUserConnection(ctx context.Context, c *models.UserConnection) error {
	isBackend, err := h.db.IsBackendTunnelClient(ctx, c.ServerID, c.Protocol, c.ClientID)
	if err != nil {
		return fmt.Errorf("check backend tunnel: %w", err)
	}
	if isBackend {
		return ErrSharedBackendCredential
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
