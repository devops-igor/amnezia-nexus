package vpn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/ingress"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/ipam"
)

// HandleIncomingPeerForTest is a test helper that simulates client peer connection admission
// by validating the peer against database authentication and invoking EnsureBackendSessionForIngress.
// This replaces the deprecated HandleIncomingPeer production method for tests across packages.
//
//nolint:gocyclo // test helper admission logic mirrors multi-step registration
func (s *Service) HandleIncomingPeerForTest(ctx context.Context, peerPublicKey string) (*models.VPNSession, *models.BackendTunnel, error) {
	if s == nil || s.auth == nil || s.sessionMgr == nil || s.pool == nil {
		return nil, nil, errors.New("subsystems not initialized")
	}
	user, conn, err := s.auth.AuthenticatePeer(ctx, peerPublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("peer authentication failed: %w", err)
	}

	var assignedIP net.IP
	if conn != nil && conn.ClientParams != nil {
		if req, ok := conn.ClientParams["config_regeneration_required"].(bool); ok && req {
			return nil, nil, fmt.Errorf("peer %s IP was quarantined: %w (config regeneration required)", peerPublicKey, ipam.ErrIPAlreadyAllocated)
		}
		if qIP, ok := conn.ClientParams["quarantined_ip_collision"]; ok && qIP != nil && qIP != "" {
			return nil, nil, fmt.Errorf("peer %s IP was quarantined: %w (config regeneration required)", peerPublicKey, ipam.ErrIPAlreadyAllocated)
		}
		if rawIP, ok := conn.ClientParams["assigned_ip"].(string); ok && rawIP != "" {
			assignedIP = net.ParseIP(rawIP)
		}
	}
	if assignedIP != nil && s.ipam != nil {
		if err := s.ipam.Reserve(assignedIP, peerPublicKey); err != nil {
			return nil, nil, fmt.Errorf("peer %s persisted IP %s conflicts with another client: %w", peerPublicKey, assignedIP, err)
		}
	}
	var allocatedNew bool
	if assignedIP == nil && s.ipam != nil {
		assignedIP, err = s.ipam.Allocate(peerPublicKey)
		if err != nil {
			return nil, nil, err
		}
		allocatedNew = true
		if conn != nil {
			params := make(map[string]any, len(conn.ClientParams)+1)
			for k, v := range conn.ClientParams {
				params[k] = v
			}
			delete(params, "config_regeneration_required")
			delete(params, "quarantined_ip_collision")
			params["assigned_ip"] = assignedIP.String()
			if s.db != nil && conn.ID != "" {
				updated, updateErr := s.db.UpdateConnection(ctx, conn.ID, map[string]any{"client_params": params})
				if updateErr != nil || !updated {
					_ = s.ipam.Release(peerPublicKey)
					if updateErr == nil {
						updateErr = errors.New("connection was removed")
					}
					return nil, nil, fmt.Errorf("persist assigned IP for peer %s (updated=%t): %w", peerPublicKey, updated, updateErr)
				}
			}
			conn.ClientParams = params
		}
	}

	connID := ""
	if conn != nil {
		connID = conn.ID
	}
	uID := ""
	if user != nil {
		uID = user.ID
	}
	var assignedAddr netip.Addr
	if assignedIP != nil {
		if ip4 := assignedIP.To4(); ip4 != nil {
			assignedAddr = netip.AddrFrom4([4]byte(ip4))
		} else {
			assignedAddr, _ = netip.AddrFromSlice(assignedIP)
		}
	}
	sess, backend, _, err := s.EnsureBackendSessionForIngress(ctx, ingress.PeerOwnership{
		PeerPublicKey: peerPublicKey,
		ConnectionID:  connID,
		UserID:        uID,
		IP:            assignedAddr,
	})
	if err != nil {
		if allocatedNew && s.ipam != nil {
			_ = s.ipam.Release(peerPublicKey)
		}
		return nil, nil, err
	}
	return sess, backend, nil
}

// SyncBackendTunnelsForTest synchronizes backend tunnels from the database into the
// in-memory pool without binding UDP listeners or starting background pump routines.
func (s *Service) SyncBackendTunnelsForTest(ctx context.Context) error {
	if s == nil || s.pool == nil {
		return errors.New("subsystems not initialized")
	}
	return s.pool.SyncFromDB(ctx)
}
