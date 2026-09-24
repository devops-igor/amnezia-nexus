package reconciliation

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/manager"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// StatusChecker defines an interface for checking protocol installation on a remote host.
type StatusChecker interface {
	GetServerStatus(ctx context.Context, server *models.Server) (map[string]any, error)
}

// ProtocolResolver resolves a ProtocolManager by protocol name.
type ProtocolResolver interface {
	Get(proto string) (manager.ProtocolManager, bool)
}

// Option configures Reconciler periodic background service.
type Option func(*Reconciler)

// WithInterval configures the periodic zombie peer cleanup interval.
func WithInterval(interval time.Duration) Option {
	return func(r *Reconciler) {
		if interval > 0 {
			r.interval = interval
		}
	}
}

// WithBootDelay configures initial delay before first background cleanup.
func WithBootDelay(delay time.Duration) Option {
	return func(r *Reconciler) {
		if delay >= 0 {
			r.bootDelay = delay
		}
	}
}

// Reconciler executes startup synchronization and periodic background audits
// to clean up orphaned connections, stale protocols, and zombie container peers.
type Reconciler struct {
	db        *database.DB
	registry  ProtocolResolver
	mu        sync.Mutex
	running   bool
	cancel    context.CancelFunc
	stopCh    chan struct{}
	interval  time.Duration
	bootDelay time.Duration
}

// New creates a new Reconciler instance.
func New(db *database.DB, registry ProtocolResolver, opts ...Option) *Reconciler {
	r := &Reconciler{
		db:        db,
		registry:  registry,
		interval:  10 * time.Minute,
		bootDelay: 30 * time.Second,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Name returns the background service worker name.
func (r *Reconciler) Name() string {
	return "protocol_reconciler"
}

// Start executes periodic zombie peer cleanup in a loop until stopped or ctx canceled.
func (r *Reconciler) Start(ctx context.Context) error {
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return errors.New("protocol_reconciler is already running")
	}
	subCtx, cancel := context.WithCancel(ctx)
	r.cancel = cancel
	r.running = true
	r.stopCh = make(chan struct{})
	interval := r.interval
	bootDelay := r.bootDelay
	r.mu.Unlock()

	slog.Info("Protocol reconciler background service started", "interval", interval, "boot_delay", bootDelay)

	// 1. Initial boot delay
	if bootDelay > 0 {
		select {
		case <-subCtx.Done():
			r.setStopped()
			return subCtx.Err()
		case <-r.stopCh:
			r.setStopped()
			return nil
		case <-time.After(bootDelay):
		}
	}

	// 2. Main periodic loop
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Initial run after boot delay
	if err := r.CleanupZombiePeers(subCtx); err != nil && subCtx.Err() == nil {
		slog.Warn("Protocol reconciler initial cleanup encountered error", "err", err)
	}

	for {
		select {
		case <-subCtx.Done():
			r.setStopped()
			return subCtx.Err()
		case <-r.stopCh:
			r.setStopped()
			return nil
		case <-ticker.C:
			if err := r.CleanupZombiePeers(subCtx); err != nil && subCtx.Err() == nil {
				slog.Warn("Protocol reconciler periodic cleanup encountered error", "err", err)
			}
		}
	}
}

// Stop stops the periodic reconciler background service.
func (r *Reconciler) Stop(ctx context.Context) error {
	r.mu.Lock()
	if !r.running {
		r.mu.Unlock()
		return nil
	}
	if r.cancel != nil {
		r.cancel()
	}
	select {
	case <-r.stopCh:
	default:
		close(r.stopCh)
	}
	r.running = false
	r.mu.Unlock()

	slog.Info("Protocol reconciler background service stopped cleanly")
	return nil
}

func (r *Reconciler) setStopped() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.running = false
}

// CleanupStaleProtocols performs a three-phase cleanup:
// Phase 1 (DB-only): Removes user_connections for protocols no longer in server.protocols.
// Phase 2 (SSH-based): Verifies installed containers/binaries on each server; if missing, removes connections and protocol.
// Phase 3 (Remote peers): Audits remote container peers against active DB connections and removes unmanaged zombie peers.
func (r *Reconciler) CleanupStaleProtocols(ctx context.Context) error {
	if r.db == nil {
		return errors.New("database is not configured")
	}

	servers, err := r.db.GetAllServers(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch servers for startup reconciliation: %w", err)
	}

	r.cleanupPhase1DBOnly(ctx, servers)

	if r.registry != nil {
		r.cleanupPhase2Remote(ctx, servers)
		r.cleanupPhase3ZombiePeers(ctx, servers)
	}

	return nil
}

func (r *Reconciler) cleanupPhase1DBOnly(ctx context.Context, servers []models.Server) {
	for _, server := range servers {
		serverID := server.ID
		activeProtos := make(map[string]bool, len(server.Protocols))
		for proto := range server.Protocols {
			activeProtos[models.NormalizeProtocol(proto)] = true
		}

		conns, err := r.db.GetConnectionsByServerID(ctx, serverID)
		if err != nil {
			slog.Warn("Reconciliation Phase 1: failed to query connections", "server_id", serverID, "err", err)
			continue
		}

		orphanProtos := make(map[string]bool)
		for _, c := range conns {
			normalized := models.NormalizeProtocol(c.Protocol)
			if !activeProtos[normalized] {
				orphanProtos[c.Protocol] = true
			}
		}

		for proto := range orphanProtos {
			deleted, err := r.db.DeleteConnectionsByServerAndProtocol(ctx, serverID, proto)
			if err != nil {
				slog.Warn("Reconciliation Phase 1: error deleting orphaned connections",
					"server_id", serverID, "protocol", proto, "err", err)
			} else if deleted > 0 {
				slog.Info("Startup cleanup: removed orphaned connections (protocol not in server.protocols)",
					"server_id", serverID,
					"protocol", proto,
					"count", deleted,
				)
			}
		}
	}
}

func (r *Reconciler) cleanupPhase2Remote(ctx context.Context, servers []models.Server) {
	for _, server := range servers {
		serverID := server.ID
		if len(server.Protocols) == 0 {
			continue
		}

		srvCopy := server
		protocolsCopy := make(map[string]any, len(srvCopy.Protocols))
		for k, v := range srvCopy.Protocols {
			protocolsCopy[k] = v
		}

		var staleProtos []string
		for protoKey := range protocolsCopy {
			if r.isProtocolStale(ctx, &srvCopy, protoKey) {
				staleProtos = append(staleProtos, protoKey)
			}
		}

		if len(staleProtos) > 0 {
			for _, proto := range staleProtos {
				deleted, _ := r.db.DeleteConnectionsByServerAndProtocol(ctx, serverID, proto)
				delete(protocolsCopy, proto)
				slog.Info("Startup cleanup: removed stale protocol and associated connections",
					"server_id", serverID,
					"protocol", proto,
					"deleted_connections", deleted,
				)
			}
			_ = r.db.UpdateServer(ctx, serverID, map[string]any{"protocols": protocolsCopy})
		}
	}
}

func (r *Reconciler) isProtocolStale(ctx context.Context, server *models.Server, protoKey string) bool {
	proto := models.NormalizeProtocol(protoKey)
	mgr, ok := r.registry.Get(proto)
	if !ok {
		return false
	}

	checker, isChecker := mgr.(StatusChecker)
	if !isChecker {
		return false
	}

	status, err := checker.GetServerStatus(ctx, server)
	if err != nil {
		slog.Warn("Startup cleanup: failed to check protocol status on server",
			"server_id", server.ID,
			"protocol", proto,
			"err", err,
		)
		return false
	}

	if status == nil {
		return false
	}

	if errMsg, hasErr := status["error"]; hasErr && errMsg != nil && fmt.Sprint(errMsg) != "" {
		slog.Warn("Startup cleanup: protocol status reported error, skipping stale cleanup",
			"server_id", server.ID,
			"protocol", proto,
			"error", errMsg,
		)
		return false
	}

	existsVal, ok := status["container_exists"]
	if !ok {
		return false
	}
	exists, isBool := existsVal.(bool)
	if !isBool {
		return false
	}

	return !exists
}

// CleanupZombiePeers audits all remote server containers across installed protocols,
// removing unmanaged or zombie peers that do not exist in the database, while preserving
// infrastructure peers (Portal Data Plane, Health Probe) and external unmanaged peers.
func (r *Reconciler) CleanupZombiePeers(ctx context.Context) error {
	if r.db == nil {
		return errors.New("database is not configured")
	}

	servers, err := r.db.GetAllServers(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch servers for zombie peer cleanup: %w", err)
	}

	if r.registry != nil {
		r.cleanupPhase3ZombiePeers(ctx, servers)
	}

	return nil
}

func (r *Reconciler) cleanupPhase3ZombiePeers(ctx context.Context, servers []models.Server) {
	for _, server := range servers {
		serverID := server.ID
		srvCopy := server
		for protoKey := range server.Protocols {
			proto := models.NormalizeProtocol(protoKey)
			mgr, ok := r.registry.Get(proto)
			if !ok {
				continue
			}

			clients, err := mgr.GetClients(ctx, &srvCopy)
			if err != nil {
				slog.Warn("Reconciliation Phase 3: failed to fetch remote clients",
					"server_id", serverID,
					"protocol", proto,
					"err", err,
				)
				continue
			}

			conns, err := r.db.GetConnectionsByServerAndProtocol(ctx, serverID, proto)
			if err != nil {
				slog.Warn("Reconciliation Phase 3: failed to fetch database connections",
					"server_id", serverID,
					"protocol", proto,
					"err", err,
				)
				continue
			}

			activeLifecycleIDs, err := r.db.GetActivePeerIDs(ctx, serverID, proto)
			if err != nil {
				slog.Warn("Reconciliation Phase 3: failed to fetch active peer lifecycle IDs",
					"server_id", serverID,
					"protocol", proto,
					"err", err,
				)
			}

			validIDs := make(map[string]bool, len(conns)+len(activeLifecycleIDs))
			for _, conn := range conns {
				if conn.ClientID != "" {
					validIDs[conn.ClientID] = true
				}
			}
			for cid := range activeLifecycleIDs {
				validIDs[cid] = true
			}

			for _, client := range clients {
				clientID, _ := client["clientId"].(string)
				if clientID == "" {
					clientID, _ = client["client_id"].(string)
				}
				if clientID == "" {
					continue
				}

				if validIDs[clientID] {
					continue
				}

				if isInfrastructurePeer(client) {
					continue
				}

				if isExternalPeer(client) {
					continue
				}

				if isRecentlyCreatedPeer(client, 2*time.Minute) {
					continue
				}

				if err := mgr.RemoveClient(ctx, &srvCopy, clientID); err != nil {
					slog.Warn("Reconciliation Phase 3: failed to remove zombie peer from remote container",
						"server_id", serverID,
						"protocol", proto,
						"client_id", clientID,
						"err", err,
					)
				} else {
					slog.Info("Reconciliation: removed zombie peer from remote container",
						"server_id", serverID,
						"protocol", proto,
						"client_id", clientID,
					)
				}
			}
		}
	}
}

func isRecentlyCreatedPeer(client map[string]any, gracePeriod time.Duration) bool {
	findTime := func(val any) *time.Time {
		if val == nil {
			return nil
		}
		switch v := val.(type) {
		case time.Time:
			return &v
		case string:
			str := strings.TrimSpace(v)
			if str == "" {
				return nil
			}
			if t, err := time.Parse(time.RFC3339, str); err == nil {
				return &t
			}
			if t, err := time.Parse(time.RFC3339Nano, str); err == nil {
				return &t
			}
			if sec, err := strconv.ParseInt(str, 10, 64); err == nil && sec > 0 {
				t := time.Unix(sec, 0).UTC()
				return &t
			}
		case int64:
			if v > 0 {
				t := time.Unix(v, 0).UTC()
				return &t
			}
		case int:
			if v > 0 {
				t := time.Unix(int64(v), 0).UTC()
				return &t
			}
		case float64:
			if v > 0 {
				t := time.Unix(int64(v), 0).UTC()
				return &t
			}
		}
		return nil
	}

	keys := []string{"creationDate", "created_at", "creation_date", "createdAt"}
	for _, k := range keys {
		if t := findTime(client[k]); t != nil {
			if time.Since(*t) < gracePeriod && time.Since(*t) >= 0 {
				return true
			}
		}
	}
	if ud, ok := client["userData"].(map[string]any); ok {
		for _, k := range keys {
			if t := findTime(ud[k]); t != nil {
				if time.Since(*t) < gracePeriod && time.Since(*t) >= 0 {
					return true
				}
			}
		}
	}
	return false
}

func isInfrastructurePeer(client map[string]any) bool {
	match := func(v any) bool {
		s, ok := v.(string)
		if !ok {
			return false
		}
		trimmed := strings.TrimSpace(s)
		return strings.EqualFold(trimmed, "Portal Data Plane") ||
			strings.EqualFold(trimmed, "Portal Health Probe") ||
			strings.EqualFold(trimmed, "Health Probe")
	}

	if match(client["clientName"]) || match(client["name"]) {
		return true
	}
	if ud, ok := client["userData"].(map[string]any); ok {
		if match(ud["clientName"]) || match(ud["name"]) {
			return true
		}
	}
	return false
}

func isExternalPeer(client map[string]any) bool {
	isExt := func(v any) bool {
		b, ok := v.(bool)
		return ok && b
	}

	if isExt(client["externalClient"]) || isExt(client["external_client"]) {
		return true
	}
	if ud, ok := client["userData"].(map[string]any); ok {
		if isExt(ud["externalClient"]) || isExt(ud["external_client"]) {
			return true
		}
	}
	return false
}
