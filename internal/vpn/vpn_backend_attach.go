package vpn

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

func (s *Service) resolveServerAWGParams(ctx context.Context, serverID int64) (map[string]any, error) {
	if s.db == nil {
		return nil, errors.New("database not available")
	}
	srv, err := s.db.GetServerByID(ctx, serverID)
	if err != nil || srv == nil {
		return nil, fmt.Errorf("failed to load server %d: %w", serverID, err)
	}
	if awgInfo, ok := srv.Protocols["awg"].(map[string]any); ok {
		if p, ok := awgInfo["awg_params"].(map[string]any); ok && p != nil {
			return p, nil
		} else if p, ok := awgInfo["params"].(map[string]any); ok && p != nil {
			return p, nil
		}
	}
	return nil, nil
}

// backendTunnelReady rejects a deleted, replaced, or disabled pool entry.
func (s *Service) backendTunnelReady(t *models.BackendTunnel) error {
	if s.pool == nil {
		return errors.New("tunnel pool not initialized")
	}
	current, err := s.pool.GetTunnel(t.ServerID)
	if err != nil {
		return err
	}
	if current == nil || current.ID != t.ID {
		return tunnel.ErrTunnelNotFound
	}
	if !current.Enabled {
		return ErrTunnelDisabled
	}
	if t.StateVersion > 0 && current.StateVersion != t.StateVersion {
		return tunnel.ErrStaleStateVersion
	}
	if t.Endpoint != "" && current.Endpoint != t.Endpoint {
		return tunnel.ErrStaleStateVersion
	}
	return nil
}

// ensureBackendDeviceAttached verifies that a data-plane device is attached for the tunnel.
// If missing, it attempts to attach the device using persisted server AWG credentials or proxy config.
func (s *Service) ensureBackendDeviceAttached(ctx context.Context, t *models.BackendTunnel) error {
	if t == nil {
		return nil
	}
	if err := s.backendTunnelReady(t); err != nil {
		return err
	}
	s.mu.RLock()
	hasDev := s.backendDevices != nil && s.backendDevices[t.ID] != nil && !s.backendDevices[t.ID].IsClosed()
	s.mu.RUnlock()
	if hasDev {
		return nil
	}

	proto := models.NormalizeTunnelProtocol(t.Protocol)
	var awgParams map[string]any
	if proto == models.ProtocolAWG {
		var loadErr error
		awgParams, loadErr = s.resolveServerAWGParams(ctx, t.ServerID)
		if loadErr != nil {
			log.Printf("[vpn] warning: tunnel %d (server %d) probe succeeded but failed to load server credentials: %v", t.ID, t.ServerID, loadErr)
			return loadErr
		}
	}

	s.mu.RLock()
	hook := s.ensureDevicePreLockHook
	s.mu.RUnlock()
	if hook != nil {
		hook()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.isServerDeletedLocked(t.ServerID) {
		return fmt.Errorf("server %d is deleted", t.ServerID)
	}

	if err := s.backendTunnelReady(t); err != nil {
		return err
	}
	if s.backendDevices != nil && s.backendDevices[t.ID] != nil && !s.backendDevices[t.ID].IsClosed() {
		return nil
	}

	if attachErr := s.attachBackendForwarder(t, awgParams); attachErr != nil {
		log.Printf("[vpn] warning: tunnel %d (server %d) probe succeeded but failed to attach data plane: %v", t.ID, t.ServerID, attachErr)
		return attachErr
	}
	return nil
}
