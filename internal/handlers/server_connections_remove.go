package handlers

import (
	"context"
	"fmt"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func (h *Handlers) resolveCanonicalClientID(
	ctx context.Context,
	serverID int64,
	protocol, requestedID string,
) (string, *models.UserConnection, error) {
	conn, err := h.db.GetConnection(ctx, requestedID)
	if err != nil {
		return "", nil, fmt.Errorf("get connection by row ID: %w", err)
	}
	if conn == nil || conn.ServerID != serverID {
		conn, err = h.db.GetConnectionByClientID(ctx, requestedID, serverID)
		if err != nil {
			return "", nil, fmt.Errorf("get connection by client ID: %w", err)
		}
	}
	if conn != nil && conn.ServerID == serverID && conn.Protocol == protocol && conn.ClientID != "" {
		return conn.ClientID, conn, nil
	}
	return requestedID, conn, nil
}

func (h *Handlers) deleteServerConnectionRecords(
	ctx context.Context,
	serverID int64,
	protocol, requestedID, canonicalClientID string,
	conn *models.UserConnection,
) error {
	connectionIDs := []string{requestedID}
	if canonicalClientID != requestedID {
		connectionIDs = append(connectionIDs, canonicalClientID)
	}
	if conn != nil && conn.ID != requestedID && conn.ID != canonicalClientID {
		connectionIDs = append(connectionIDs, conn.ID)
	}
	for _, connectionID := range connectionIDs {
		if err := h.deleteConnectionByClientIDAndProtocol(ctx, serverID, connectionID, protocol); err != nil {
			return err
		}
		_ = h.db.DeletePeerLifecycle(ctx, serverID, protocol, connectionID)
	}
	return nil
}
