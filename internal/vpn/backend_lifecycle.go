package vpn

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/loadbalancer"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

// DisableBackend disables a backend server and initiates connection draining.
func (s *Service) DisableBackend(ctx context.Context, serverID int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.disableBackendLocked(ctx, serverID)
}

// disableBackendLocked applies DisableBackend semantics; the caller must hold
// s.mu (write). It disables the tunnel, detaches and closes the backend's
// forwarder device, and fails over active sessions (sticky affinities, DB
// rows, live forwarder routes, pool counters) onto healthy backends so
// traffic keeps flowing before any further mutation by the caller.
func (s *Service) disableBackendLocked(ctx context.Context, serverID int64) error {
	if s.pool == nil {
		return errors.New("tunnel pool not initialized")
	}

	tunnel, err := s.pool.GetTunnel(serverID)
	if err != nil {
		return err
	}

	if err := s.pool.SetTunnelEnabled(ctx, serverID, false, models.DisableReasonAdmin); err != nil {
		return fmt.Errorf("failed to persist administrative backend disable: %w", err)
	}

	if s.prober != nil {
		s.prober.MarkAdminDisabled(serverID)
	}

	// Detach and stop the backend UDP device created by EnableBackend so the
	// forwarder stops routing client packets to a disabled backend.
	if s.forwarder != nil {
		s.forwarder.DetachBackendDevice(tunnel.ID)
	}
	if dev, ok := s.backendDevices[tunnel.ID]; ok {
		if dev != nil {
			_ = dev.Close()
		}
		if dev != nil {
			// The retirement TRANSFER: the device's direction x reason
			// breakdown moves into the lifetime buckets, so nothing is
			// double counted while it was live and nothing is reclassified
			// now that it is gone.
			s.retiredBackendDeviceDrops.addInto(snapshotBackendDeviceDrops(dev))
		}
		delete(s.backendDevices, tunnel.ID)
	}
	if s.backendDeviceEndpoints != nil {
		delete(s.backendDeviceEndpoints, tunnel.ID)
	}

	// Trigger failover for active sessions on this backend
	if s.stickyMgr != nil {
		activeTunnels := s.pool.GetActiveTunnels()
		// Issue #85: HandleFailover returns a result with successful
		// migrations AND explicitly reported skipped peers — every peer left
		// on the disabled backend is logged here so stranding is visible.
		failover, err := s.stickyMgr.HandleFailover(ctx, tunnel.ID, activeTunnels)
		if err != nil {
			log.Printf("[vpn] failover for backend %d found no healthy target: %v", serverID, err)
		}
		if failover != nil {
			for _, sk := range failover.Skipped {
				log.Printf("[vpn] failover for backend %d: peer %s (user %s) NOT migrated: %s", serverID, sk.PeerPublicKey, sk.UserID, sk.Reason)
			}
		}
		// Redirect live traffic: the detached backend's device is closed, so
		// any session still routed to it would silently drop packets. The
		// sticky maps alone do not move the forwarder's per-session route.
		var migrations []loadbalancer.FailoverMigration
		if failover != nil {
			migrations = failover.Migrations
		}
		for _, m := range migrations {
			if s.forwarder != nil {
				if err := s.forwarder.UpdateSessionBackend(m.PeerPublicKey, m.NewBackendTunnelID); err != nil {
					// ErrSessionNotRegistered = session has no live route
					// (already disconnected); nothing to redirect then.
					log.Printf("[vpn] failover route redirect for peer %s -> backend %d: %v", m.PeerPublicKey, m.NewBackendTunnelID, err)
				}
			}
			// Move the connection count with the session: the pool counter
			// tracks currently-connected peers per backend and feeds
			// least-connections and capacity filtering.
			s.pool.DecrementConnections(tunnel.ID)
			s.pool.IncrementConnections(m.NewBackendTunnelID)
		}
		if len(migrations) > 0 && s.sessionMgr != nil {
			s.sessionMgr.BumpLifecycleVersion()
		}
	}

	return nil
}

func (s *Service) resolveNewBackendEndpoint(ctx context.Context, serverID int64, currentEndpoint, newHost string) (string, error) {
	cleanHost := strings.Trim(strings.TrimSpace(newHost), "[]")
	if _, port, splitErr := net.SplitHostPort(currentEndpoint); splitErr == nil && port != "" {
		return net.JoinHostPort(cleanHost, port), nil
	}
	if s.db == nil {
		return "", fmt.Errorf("database not available to resolve server %d credentials", serverID)
	}
	srv, loadErr := s.db.GetServerByID(ctx, serverID)
	if loadErr != nil || srv == nil {
		return "", fmt.Errorf("failed to load server %d: %w", serverID, loadErr)
	}
	_, p, _, credErr := s.resolveBackendCredentials(ctx, serverID, srv)
	if credErr != nil {
		return "", fmt.Errorf("failed to resolve backend credentials for server %d: %w", serverID, credErr)
	}
	return net.JoinHostPort(cleanHost, strconv.Itoa(p)), nil
}

func (s *Service) syncBackendForwarderOnHostUpdateLocked(ctx context.Context, serverID, expectedTunnelID int64, awgParams map[string]any) error {
	if s.syncBackendForwarderHook != nil {
		if err := s.syncBackendForwarderHook(); err != nil {
			return err
		}
	}

	currentTun, err := s.pool.GetTunnel(serverID)
	if err != nil {
		if errors.Is(err, tunnel.ErrTunnelNotFound) {
			return nil
		}
		return err
	}
	if currentTun == nil || currentTun.ID != expectedTunnelID {
		return nil
	}

	if !currentTun.Enabled {
		return nil
	}

	if currentTun.Status == TunnelStatusActive || currentTun.Status == TunnelStatusDegraded ||
		currentTun.Status == models.TunnelStatusActive || currentTun.Status == models.TunnelStatusDegraded {
		attachErr := s.attachBackendForwarder(currentTun, awgParams)
		if attachErr != nil {
			log.Printf("[vpn] warning: failed to attach backend forwarder for server %d after host update: %v", serverID, attachErr)
			_ = s.pool.SetTunnelStatus(ctx, serverID, TunnelStatusDegraded, 0)
			return fmt.Errorf("failed to attach backend forwarder: %w", attachErr)
		}
	}

	if s.prober != nil {
		s.prober.ResetFailCount(serverID)
	}

	return nil
}

// UpdateBackendServerHost updates the endpoint of a server in the VPN backend pool.
func (s *Service) UpdateBackendServerHost(ctx context.Context, serverID int64, newHost string) error {
	if s == nil || s.pool == nil {
		return nil
	}

	s.mu.RLock()
	injectedErr := s.updateBackendServerHostErr
	s.mu.RUnlock()
	if injectedErr != nil {
		return injectedErr
	}

	tun, err := s.pool.GetTunnel(serverID)
	if err != nil {
		if errors.Is(err, tunnel.ErrTunnelNotFound) {
			return nil
		}
		return err
	}
	if tun == nil {
		return nil
	}

	newEndpoint, err := s.resolveNewBackendEndpoint(ctx, serverID, tun.Endpoint, newHost)
	if err != nil {
		return err
	}

	if tun.Endpoint == newEndpoint {
		s.mu.RLock()
		dev := s.backendDevices[tun.ID]
		var attachedEndpoint string
		if s.backendDeviceEndpoints != nil {
			attachedEndpoint = s.backendDeviceEndpoints[tun.ID]
		}
		s.mu.RUnlock()

		// Genuinely synchronized idempotent no-op: device exists, is open,
		// and its configured endpoint matches the requested endpoint.
		if dev != nil && !dev.IsClosed() && attachedEndpoint == newEndpoint {
			return nil
		}

		// Runtime device is missing, closed, or attached to a stale endpoint -> reconcile.
		awgParams, _ := s.resolveServerAWGParams(ctx, serverID)

		s.mu.RLock()
		hook := s.updateBackendServerHostPreLockHook
		s.mu.RUnlock()
		if hook != nil {
			hook()
		}

		if err := ctx.Err(); err != nil {
			return err
		}

		s.mu.Lock()
		defer s.mu.Unlock()
		return s.syncBackendForwarderOnHostUpdateLocked(ctx, serverID, tun.ID, awgParams)
	}

	oldEndpoint := tun.Endpoint
	if err := s.pool.SetTunnelEndpoint(ctx, tun.ID, newEndpoint); err != nil {
		return fmt.Errorf("failed to update backend tunnel endpoint in pool: %w", err)
	}
	tun.Endpoint = newEndpoint

	rollbackEndpoint := func(originalErr error) error {
		rbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if rbErr := s.pool.SetTunnelEndpoint(rbCtx, tun.ID, oldEndpoint); rbErr != nil {
			log.Printf("[vpn] warning: failed to rollback backend tunnel endpoint for server %d: %v", serverID, rbErr)
			return errors.Join(originalErr, fmt.Errorf("%w: failed to restore endpoint to %s: %v", ErrVPNRollbackFailed, oldEndpoint, rbErr))
		}
		return originalErr
	}

	awgParams, _ := s.resolveServerAWGParams(ctx, serverID)

	s.mu.RLock()
	hook := s.updateBackendServerHostPreLockHook
	s.mu.RUnlock()
	if hook != nil {
		hook()
	}

	if err := ctx.Err(); err != nil {
		return rollbackEndpoint(err)
	}

	s.mu.Lock()
	syncErr := s.syncBackendForwarderOnHostUpdateLocked(ctx, serverID, tun.ID, awgParams)
	s.mu.Unlock()

	if syncErr != nil {
		return rollbackEndpoint(syncErr)
	}

	return nil
}

type deleteServerContextKey struct{}

func withDeleteServer(ctx context.Context) context.Context {
	return context.WithValue(ctx, deleteServerContextKey{}, true)
}

func isDeleteServerContext(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	val, ok := ctx.Value(deleteServerContextKey{}).(bool)
	return ok && val
}

func (s *Service) isServerDeletedLocked(serverID int64) bool {
	if s.deletedServers == nil {
		return false
	}
	_, ok := s.deletedServers[serverID]
	return ok
}

// DeleteServer tombstones the server to prevent concurrent resurrection by EnableBackend
// or automated self-healing, tears down any associated VPN backend tunnel and drains sessions.
func (s *Service) DeleteServer(ctx context.Context, serverID int64) error {
	s.mu.Lock()
	if s.deletedServers == nil {
		s.deletedServers = make(map[int64]struct{})
	}
	s.deletedServers[serverID] = struct{}{}
	if s.deleteBackendErr != nil {
		err := s.deleteBackendErr
		delete(s.deletedServers, serverID)
		s.mu.Unlock()
		return err
	}
	s.mu.Unlock()

	err := s.DeleteBackend(withDeleteServer(ctx), serverID)
	if err != nil {
		if errors.Is(err, ErrBackendTunnelNotFound) {
			return nil
		}
		s.mu.Lock()
		delete(s.deletedServers, serverID)
		s.mu.Unlock()
		return err
	}
	return nil
}

// ClearServerDeletedTombstone removes the deletion tombstone for a server ID,
// allowing subsequent additions or restores of that server ID to succeed.
func (s *Service) ClearServerDeletedTombstone(serverID int64) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.deletedServers != nil {
		delete(s.deletedServers, serverID)
	}
}

// DeleteBackend permanently removes a backend tunnel from the load-balancing
// pool (issue #29): the server itself and its AWG protocol configuration are
// untouched — only the backend_tunnels registration and the in-memory pool
// entry are dropped.
//
// Ordering matters: DisableBackend semantics run FIRST (status change,
// forwarder device detach, sticky failover of connected sessions) while the
// tunnel is still resolvable, so active sessions migrate to healthy backends
// and no vpn_sessions row is left referencing the deleted backend_tunnels
// row. Only then is the tunnel removed from the pool (which also deletes the
// persisted row) and a defensive DB sweep catches any leftover row the pool
// could not see (missing row is not an error: log and continue).
func (s *Service) DeleteBackend(ctx context.Context, serverID int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.deleteBackendErr != nil {
		return s.deleteBackendErr
	}

	if s.isServerDeletedLocked(serverID) && !isDeleteServerContext(ctx) {
		return ErrBackendTunnelNotFound
	}

	if s.pool == nil {
		return errors.New("tunnel pool not initialized")
	}

	// Guard: unknown backend -> not-found, before any state mutation.
	tunnel, err := s.pool.GetTunnel(serverID)
	if err != nil {
		return err
	}

	// Phase 1 — drain: disable + failover while the tunnel is still in the
	// pool, so HandleFailover's session migration has healthy targets and
	// the caller's sessions never orphan onto a removed tunnel ID.
	if err := s.disableBackendLocked(ctx, serverID); err != nil {
		return err
	}

	// Phase 2 — removal: drops the pool entries and the persisted
	// backend_tunnels row.
	if err := s.pool.RemoveTunnel(ctx, serverID); err != nil {
		return fmt.Errorf("failed to remove tunnel for server %d: %w", serverID, err)
	}

	// Phase 3 — defensive sweep: RemoveTunnel only deletes the row matching
	// the in-memory tunnel ID. If the DB drifted (row recreated under a new
	// ID, pool re-synced from a stale snapshot), a leftover backend_tunnels
	// row for this server would keep serving stale lookups. The sweep
	// reassigns any connected sessions still on it to a surviving active
	// backend, deletes the leftover row, and never fails the delete: a
	// missing row is the expected path.
	//
	// DB calls run without s.mu held (db methods take their own locks) — the
	// disabled tunnel cannot re-enter the pool in between: pool mutations
	// all happen under s.mu, which we re-acquire immediately after.
	//
	// failoverTarget is a surviving ACTIVE pool tunnel (never the deleted
	// one): reassigning sessions onto the just-deleted row would only move
	// the orphan. Zero means no healthy target exists — HandleFailover
	// already hit the same terminal state and logged it.
	failoverTarget := int64(0)
	for _, tun := range s.pool.GetActiveTunnels() {
		if tun.ID != tunnel.ID {
			failoverTarget = tun.ID
			break
		}
	}

	s.mu.Unlock()
	leftover, dbErr := s.db.GetBackendTunnelByServerID(ctx, serverID)
	if dbErr != nil {
		leftover = nil
		log.Printf("[vpn] warning: delete backend %d: DB sweep lookup failed: %v", serverID, dbErr)
	}
	if leftover != nil {
		// Reassign connected sessions that lost the failover race onto the
		// leftover row, marking them draining (issue #29: no orphaned
		// vpn_sessions row may reference a deleted backend_tunnels row).
		//
		// GetActiveVPNSessions returns ONLY status='connected' rows, so the
		// sweep covers exactly those. Sessions already marked 'draining' are
		// intentionally NOT swept: draining is a terminal state per issue
		// #44 — such sessions are winding down and must never be migrated
		// again, even if their stale backend_tunnels row is deleted here.
		if sessions, sessErr := s.db.GetActiveVPNSessions(ctx); sessErr != nil {
			log.Printf("[vpn] warning: delete backend %d: orphan-session sweep lookup failed: %v", serverID, sessErr)
		} else {
			for i := range sessions {
				if sessions[i].BackendTunnelID != leftover.ID {
					continue
				}
				if failoverTarget == 0 {
					log.Printf("[vpn] warning: delete backend %d: no healthy backend left to reassign session %s (leftover row %d deleted, session left draining)", serverID, sessions[i].ID, leftover.ID)
					continue
				}
				if err := s.db.UpdateVPNSessionBackendTunnel(ctx, sessions[i].ID, failoverTarget); err != nil {
					log.Printf("[vpn] warning: delete backend %d: could not reassign session %s off leftover row %d: %v", serverID, sessions[i].ID, leftover.ID, err)
				} else {
					log.Printf("[vpn] delete backend %d: reassigned session %s off leftover backend_tunnels row %d onto backend %d (draining)", serverID, sessions[i].ID, leftover.ID, failoverTarget)
				}
			}
		}
		if err := s.db.DeleteBackendTunnel(ctx, leftover.ID); err != nil {
			log.Printf("[vpn] warning: delete backend %d: failed to delete leftover backend_tunnels row %d: %v", serverID, leftover.ID, err)
		}
	}
	s.mu.Lock()

	return nil
}
