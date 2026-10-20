package vpn

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

// restoreBackendDevices restores data-plane devices for active and degraded tunnels loaded from DB.
func (s *Service) restoreBackendDevices(ctx context.Context) {
	for _, tun := range s.pool.ListTunnels() {
		if !tun.Enabled {
			continue
		}
		if tun.Status != TunnelStatusActive && tun.Status != TunnelStatusDegraded {
			continue
		}
		var awgParams map[string]any
		var attachErr error
		if s.db != nil {
			srv, err := s.db.GetServerByID(ctx, tun.ServerID)
			if err != nil || srv == nil {
				attachErr = fmt.Errorf("failed to load server %d: %w", tun.ServerID, err)
			} else if awgInfo, ok := srv.Protocols["awg"].(map[string]any); ok {
				awgParams, _ = awgInfo["awg_params"].(map[string]any)
			}
		} else {
			attachErr = errors.New("database not available")
		}
		if attachErr == nil {
			s.mu.Lock()
			attachErr = s.attachBackendForwarder(tun, awgParams)
			s.mu.Unlock()
		}
		if attachErr != nil {
			log.Printf("[vpn] warning: failed to restore data plane for tunnel %d (server %d): %v", tun.ID, tun.ServerID, attachErr)
			_ = s.pool.SetTunnelStatus(ctx, tun.ServerID, TunnelStatusDegraded, 0)
		}
	}
}

// reattachBackendDevicesLocked re-attaches active backend devices with fresh parameters.
// Must be called with s.mu held.
func (s *Service) reattachBackendDevicesLocked() {
	if s.pool == nil || s.backendDevices == nil {
		return
	}
	ctx := context.Background()
	for _, tun := range s.pool.GetTunnels() {
		if tun == nil || !tun.Enabled {
			continue
		}
		if s.backendDevices[tun.ID] == nil {
			continue
		}
		var awgParams map[string]any
		var attachErr error
		if s.db != nil {
			srv, err := s.db.GetServer(ctx, tun.ServerID)
			if err != nil || srv == nil {
				attachErr = fmt.Errorf("failed to load server %d: %w", tun.ServerID, err)
			} else if awgInfo, ok := srv.Protocols["awg"].(map[string]any); ok {
				awgParams, _ = awgInfo["awg_params"].(map[string]any)
			}
		} else {
			attachErr = errors.New("database not available")
		}
		if attachErr == nil {
			attachErr = s.attachBackendForwarder(tun, awgParams)
		}
		if attachErr != nil {
			log.Printf("[vpn] warning: failed to reattach backend device for tunnel %d (server %d): %v", tun.ID, tun.ServerID, attachErr)
			_ = s.pool.SetTunnelStatus(ctx, tun.ServerID, models.TunnelStatusDegraded, 0)
		}
	}
}

// EnableBackend restores administrative eligibility by loading the backend's
// AWG credentials, registering (or refreshing) the tunnel, and attaching its
// data-plane device. It does not declare the backend healthy: runtime health
// remains owned by the prober/self-healing subsystem.
func (s *Service) EnableBackend(ctx context.Context, serverID int64) error {
	s.mu.RLock()
	if s.isServerDeletedLocked(serverID) {
		s.mu.RUnlock()
		return fmt.Errorf("%w: server %d is deleted", ErrServerNotFound, serverID)
	}
	pool := s.pool
	db := s.db
	awgProv := s.awgProvider
	startEpoch := s.adminDisableEpoch[serverID]
	s.mu.RUnlock()

	if pool == nil {
		return errors.New("tunnel pool not initialized")
	}
	if db == nil {
		return errors.New("database not available")
	}

	server, err := db.GetServerByID(ctx, serverID)
	if err != nil {
		return fmt.Errorf("failed to load server %d: %w", serverID, err)
	}
	if server == nil {
		return fmt.Errorf("%w: server %d", ErrServerNotFound, serverID)
	}

	pub, port, awgParams, err := s.resolveBackendCredentials(ctx, serverID, server)
	if err != nil {
		return err
	}

	// Validate I1 parameter preparation early (before pool.AddTunnel) so that
	// a generator failure aborts immediately without mutating pool or remote peers (CodeRabbit #1).
	deviceParams, err := s.prepareBackendDeviceParams(ctx, awgParams)
	if err != nil {
		return err
	}

	endpoint := net.JoinHostPort(server.Host, strconv.Itoa(port))

	s.mu.RLock()
	preAddHook := s.enableBackendPreAddTunnelHook
	s.mu.RUnlock()
	if preAddHook != nil {
		preAddHook()
	}

	s.mu.Lock()
	if s.isServerDeletedLocked(serverID) {
		s.mu.Unlock()
		return fmt.Errorf("%w: server %d is deleted", ErrServerNotFound, serverID)
	}
	if s.db != nil {
		checkCtx, checkCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		srv, err := s.db.GetServer(checkCtx, serverID)
		checkCancel()
		if err != nil {
			s.mu.Unlock()
			return fmt.Errorf("failed to verify server %d in database: %w", serverID, err)
		}
		if srv == nil {
			s.mu.Unlock()
			return fmt.Errorf("%w: server %d not found in database", ErrServerNotFound, serverID)
		}
		if !srv.CreatedAt.Equal(server.CreatedAt) || srv.Host != server.Host {
			s.mu.Unlock()
			return fmt.Errorf("%w: server %d generation changed during enable", ErrServerNotFound, serverID)
		}
	}
	tun, err := pool.AddTunnel(ctx, serverID, endpoint, pub)
	s.mu.Unlock()
	if err != nil {
		return fmt.Errorf("failed to register backend tunnel for server %d: %w", serverID, err)
	}

	s.mu.RLock()
	postAddHook := s.enableBackendPostAddTunnelHook
	s.mu.RUnlock()
	if postAddHook != nil {
		postAddHook()
	}

	// Register the portal peers on the backend server (issue #43):
	//   - "Portal Data Device": identity = derive(tunnel.PrivateKey) - the DATA
	//     device key with AllowedIPs scoped to portal client subnet so the backend accepts data
	//     traffic from the portal subnet and routes replies to the data device (never 0.0.0.0/0).
	//   - "Portal Health Probe": identity = derive(tunnel.ProbePrivateKey) - a
	//     dedicated probe key so prober handshakes never roam the data peer's
	//     return endpoint (per-peer endpoint roaming: last sender wins).
	// AddClient is an idempotent upsert on the caller-supplied key, so repeat
	// registrations refresh in place; a legacy shared-key peer registered under
	// the data identity keeps its client_ip entry and is re-pointed at the
	// data-device identity.
	if awgProv != nil {
		if err := s.registerBackendPortalPeers(ctx, server, tun); err != nil {
			_ = pool.SetTunnelStatus(ctx, serverID, TunnelStatusDegraded, 0)
			return err
		}
	}

	// Ensure return routing and NAT masquerade for portal client subnet.
	// Run safely: log warning on failure so temporary SSH issues don't block enabling the backend.
	if err := s.remediateBackendRouting(ctx, serverID); err != nil {
		log.Printf("[vpn] warning: failed to ensure backend routing and NAT for server %d: %v", serverID, err)
	}

	return s.finishEnableBackend(ctx, pool, tun, awgParams, serverID, startEpoch, deviceParams)
}

func (s *Service) dataPlaneI1Protocol() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg.DataPlaneI1Protocol()
}

func (s *Service) prepareBackendDeviceParams(ctx context.Context, awgParams map[string]any) (map[string]any, error) {
	proto := s.dataPlaneI1Protocol()
	return s.buildBackendDeviceParams(ctx, proto, awgParams)
}

func (s *Service) prepareBackendDeviceParamsLocked(awgParams map[string]any) (map[string]any, error) {
	proto := s.cfg.DataPlaneI1Protocol()
	return s.buildBackendDeviceParams(context.Background(), proto, awgParams)
}

// buildBackendDeviceParams constructs the device parameters used by AWGClientDevice.
// The configured data plane I1 protocol (SIP by default, or DNS) always overrides
// any existing backend I1 setting stored in the database.
func (s *Service) buildBackendDeviceParams(ctx context.Context, proto string, awgParams map[string]any) (map[string]any, error) {
	deviceParams := make(map[string]any, len(awgParams)+1)
	for k, v := range awgParams {
		// Data plane I1 setting always overrides stored backend I1 (any casing/variant)
		if tunnel.NormalizeAWGKey(k) == "i1" {
			continue
		}
		deviceParams[k] = v
	}

	mimicryPacketsMu.RLock()
	genFn := generateMimicryPackets
	mimicryPacketsMu.RUnlock()

	packets, err := genFn(ctx, proto, "", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to generate data plane I1 packet: %w", err)
	}
	i1Val, ok := packets["i1"]
	if !ok || i1Val == "" {
		return nil, fmt.Errorf("generator returned empty data plane I1 packet for protocol %q", proto)
	}
	deviceParams["i1"] = i1Val
	return deviceParams, nil
}

func (s *Service) finishEnableBackend(
	ctx context.Context,
	pool *tunnel.Pool,
	tun *models.BackendTunnel,
	awgParams map[string]any,
	serverID int64,
	startEpoch uint64,
	prepared ...map[string]any,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	currTun, err := pool.GetTunnel(serverID)
	if err != nil {
		return err
	}
	if tunnel.IsSelfHealingContext(ctx) && !currTun.Enabled {
		return errors.New("backend was administratively disabled; aborting enable")
	}
	if s.adminDisableEpoch[serverID] != startEpoch {
		return errors.New("backend was administratively disabled; aborting enable")
	}
	// Guard on the tunnel's identity, not StateVersion: the health prober bumps
	// StateVersion on every status write, and registering portal peers over SSH
	// routinely outlasts the probe interval, so a version check aborts valid
	// enables (issue #607). Runtime status/latency changes do not invalidate it.
	if !models.SameTunnelIdentity(currTun, tun) {
		return errors.New("backend identity modified concurrently; aborting enable")
	}

	if err := s.attachBackendForwarder(tun, awgParams, prepared...); err != nil {
		return err
	}

	// Issue #50: clear the prober's consecutive-failure counter so the
	// re-enabled backend gets the full FailureThreshold grace period.
	if s.prober != nil {
		s.prober.ResetFailCount(serverID)
	}

	if tunnel.IsSelfHealingContext(ctx) {
		return nil
	}

	legacyAdminOnlyState := currTun.Status == TunnelStatusDisabled && currTun.DisableReason == models.DisableReasonAdmin
	if err := pool.SetTunnelEnabled(ctx, serverID, true, models.DisableReasonNone); err != nil {
		return fmt.Errorf("failed to persist administrative backend enable: %w", err)
	}
	if legacyAdminOnlyState {
		// Legacy rows encoded administrative disable in runtime status. Once
		// enabled is authoritative, that old status has no trustworthy health
		// meaning, so make it unknown/connecting and require a fresh probe.
		return pool.SetTunnelStatusWithReason(ctx, serverID, TunnelStatusConnecting, models.DisableReasonNone, 0)
	}
	return nil
}

// registerBackendPortalPeers registers the portal's two identities on the
// backend server (issue #43 key separation):
//
//  1. "Portal Data Plane" — the DATA device identity derive(tun.PrivateKey)
//     with AllowedIPs scoped to the portal client subnet (s.getPortalSubnet(),
//     e.g. 10.100.0.0/16), so the backend accepts data traffic from the
//     portal client subnet and routes replies to the data device. The portal
//     data plane peer must NEVER be granted 0.0.0.0/0 to prevent awg-quick from
//     creating a default route hijack on reboot. The legacy
//     name is kept deliberately: backends provisioned before the split already
//     hold a peer of this name keyed by the same data identity, so the
//     manager's upsert refreshes it in place instead of appending a duplicate
//     [Peer] (which amneziawg would reject).
//
//  2. "Portal Health Probe" — the dedicated probe identity
//     derive(tun.ProbePrivateKey) with NO allowed_ips key, so the manager's
//     peerSectionFor defaults it to clientIP/32. The probe peer must NEVER own
//     0.0.0.0/0: its only traffic is the prober's handshake/keepalive
//     exchange, and a wide AllowedIPs would let probe packets shadow the data
//     plane.
//
// The DATA peer is registered FIRST so a mid-way failure cannot leave a
// backend with a probe peer but no data peer. On any failure the error is
// wrapped with the server ID and the caller degrades the tunnel.
func (s *Service) registerBackendPortalPeers(ctx context.Context, server *models.Server, tun *models.BackendTunnel) error {
	s.mu.RLock()
	awgProv := s.awgProvider
	db := s.db
	s.mu.RUnlock()

	adder, ok := awgProv.(interface {
		AddClient(ctx context.Context, server *models.Server, clientParams map[string]any) (map[string]any, error)
	})
	if !ok {
		// Provider without AddClient capability (e.g. status-only
		// implementations): there is no peer-registration path on this
		// backend, so skip silently — same semantics as before #43.
		return nil
	}

	dataPub, err := tunnel.DataDevicePublicKey(tun)
	if err != nil {
		return fmt.Errorf("failed to derive data device public key for server %d: %w", server.ID, err)
	}
	probePub, err := tunnel.ClientPublicKey(tun)
	if err != nil {
		return fmt.Errorf("failed to derive probe public key for server %d: %w", server.ID, err)
	}
	if tun.ProbePrivateKey == "" || probePub == dataPub {
		return fmt.Errorf("probe key for backend tunnel %d on server %d is missing or collides with the data key", tun.ID, server.ID)
	}

	portalSubnet := s.getPortalSubnet()
	dataParams := map[string]any{
		"clientName":        "Portal Data Plane",
		"name":              "Portal Data Plane",
		"public_key":        dataPub,
		"client_public_key": dataPub,
		"allowed_ips":       portalSubnet,
	}
	if _, err := adder.AddClient(ctx, server, dataParams); err != nil {
		return fmt.Errorf("failed to register portal data plane peer on backend server %d: %w", server.ID, err)
	}

	probeParams := map[string]any{
		"clientName":        "Portal Health Probe",
		"name":              "Portal Health Probe",
		"public_key":        probePub,
		"client_public_key": probePub,
		// No allowed_ips key: peerSectionFor defaults to clientIP/32. The
		// probe peer must never be granted 0.0.0.0/0.
	}
	if _, err := adder.AddClient(ctx, server, probeParams); err != nil {
		return fmt.Errorf("failed to register portal health probe peer on backend server %d: %w", server.ID, err)
	}

	// Persist the probe key so the identity is stable across restarts
	// (Fernet-encrypted at rest by the database layer).
	if db != nil {
		if err := db.UpdateBackendTunnel(ctx, tun.ID, map[string]any{"probe_private_key": tun.ProbePrivateKey}); err != nil {
			return fmt.Errorf("failed to persist probe private key for backend tunnel %d (server %d): %w", tun.ID, server.ID, err)
		}
	}
	return nil
}

// EnsureBackendProbeKeys is the issue-#43 startup migration: every tunnel in
// the pool must carry a dedicated probe key and have both portal peers
// registered on its backend server. Pool.SyncFromDB backfills keys missing
// from legacy rows in memory; this pass guarantees persistence and provisions
// the probe peer. Registration is idempotent (AddClient upserts by the
// caller-supplied public key), so running it on every boot for every
// non-disabled tunnel is safe and self-healing — it also re-points any legacy
// shared-key probe peer and drops stale PSK variants.
//
// Best-effort by design: an unreachable backend is logged and left as-is; the
// health prober and the next EnableBackend/startup pass retry later.
func (s *Service) EnsureBackendProbeKeys(ctx context.Context) {
	s.mu.RLock()
	pool := s.pool
	s.mu.RUnlock()
	if pool == nil {
		return
	}

	for _, tun := range pool.ListTunnels() {
		if !tun.Enabled {
			continue
		}

		// SyncFromDB already backfills missing keys; this defensive second
		// pass keeps the migration correct if it ever runs against a pool
		// populated by another path.
		if tun.ProbePrivateKey == "" {
			_, sk, err := tunnel.GenerateCurve25519KeyPair()
			if err != nil {
				log.Printf("[vpn] warning: probe-key migration for tunnel %d (server %d): failed to generate keypair: %v", tun.ID, tun.ServerID, err)
				continue
			}
			tun.ProbePrivateKey = sk
			s.mu.RLock()
			db := s.db
			s.mu.RUnlock()
			if db != nil {
				if err := db.UpdateBackendTunnel(ctx, tun.ID, map[string]any{"probe_private_key": sk}); err != nil {
					log.Printf("[vpn] warning: probe-key migration for tunnel %d (server %d): persist failed: %v", tun.ID, tun.ServerID, err)
					continue
				}
			}
		}

		s.mu.RLock()
		awgProv := s.awgProvider
		db := s.db
		s.mu.RUnlock()
		if awgProv == nil || db == nil {
			continue
		}
		server, err := db.GetServerByID(ctx, tun.ServerID)
		if err != nil || server == nil {
			log.Printf("[vpn] warning: probe-peer migration for tunnel %d: server %d not loadable: %v", tun.ID, tun.ServerID, err)
			continue
		}
		regCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		if err := s.registerBackendPortalPeers(regCtx, server, tun); err != nil {
			log.Printf("[vpn] warning: probe-peer migration for tunnel %d (server %d) failed, leaving tunnel as-is: %v", tun.ID, tun.ServerID, err)
		}
		cancel()
	}
}

// resolveBackendCredentials retrieves AWG credentials for a backend, falling back to live discovery.
func (s *Service) resolveBackendCredentials(ctx context.Context, serverID int64, server *models.Server) (string, int, map[string]any, error) {
	var pub string
	var port int
	var awgParams map[string]any
	if awgInfo, ok := server.Protocols["awg"].(map[string]any); ok {
		pub, _ = awgInfo["public_key"].(string)
		port = parsePort(awgInfo["port"])
		if p, ok := awgInfo["awg_params"].(map[string]any); ok && p != nil {
			awgParams = p
		} else if p, ok := awgInfo["params"].(map[string]any); ok && p != nil {
			awgParams = p
		}
	}

	if (pub == "" || port <= 0) && s.awgProvider != nil {
		if livePub, livePort, ok := s.discoverLiveAWG(ctx, serverID, server); ok {
			pub = livePub
			port = livePort
			if awgInfo, ok := server.Protocols["awg"].(map[string]any); ok {
				if p, ok := awgInfo["awg_params"].(map[string]any); ok && p != nil {
					awgParams = p
				} else if p, ok := awgInfo["params"].(map[string]any); ok && p != nil {
					awgParams = p
				}
			}
		}
	}

	if pub == "" || port <= 0 {
		return "", 0, nil, ErrAWGNotInstalled
	}

	return pub, port, awgParams, nil
}

// discoverLiveAWG attempts to query the running AWG container and persists discovered configuration to DB.
func (s *Service) discoverLiveAWG(ctx context.Context, serverID int64, server *models.Server) (string, int, bool) {
	status, err := s.awgProvider.GetServerStatus(ctx, server)
	if err != nil || status == nil {
		return "", 0, false
	}
	if running, _ := status["container_running"].(bool); !running {
		return "", 0, false
	}
	livePub, _ := status["public_key"].(string)
	livePort := parsePort(status["port"])
	if livePub == "" || livePort <= 0 {
		return "", 0, false
	}

	if server.Protocols == nil {
		server.Protocols = make(map[string]any)
	}
	protoMap, _ := server.Protocols["awg"].(map[string]any)
	if protoMap == nil {
		protoMap = make(map[string]any)
	}
	protoMap["installed"] = true
	protoMap["port"] = livePort
	protoMap["public_key"] = livePub
	if psk, ok := status["psk"].(string); ok && psk != "" {
		protoMap["psk"] = psk
	}
	if awgParams, ok := status["awg_params"]; ok && awgParams != nil {
		protoMap["awg_params"] = awgParams
	}
	if clientsCount, ok := status["clients_count"]; ok && clientsCount != nil {
		protoMap["clients_count"] = clientsCount
	}
	server.Protocols["awg"] = protoMap
	_ = s.db.UpdateServerProtocols(ctx, serverID, server.Protocols)

	return livePub, livePort, true
}

func (s *Service) attachBackendForwarder(tun *models.BackendTunnel, awgParams map[string]any, prepared ...map[string]any) error {
	if tun == nil {
		return errors.New("backend tunnel is nil")
	}
	if s.forwarder == nil {
		return nil
	}

	var deviceParams map[string]any
	if len(prepared) > 0 && prepared[0] != nil {
		deviceParams = prepared[0]
	} else {
		var prepErr error
		deviceParams, prepErr = s.prepareBackendDeviceParamsLocked(awgParams)
		if prepErr != nil {
			return fmt.Errorf("failed to prepare backend device parameters for server %d: %w", tun.ServerID, prepErr)
		}
	}

	// Detach and close previous device for this tunnel to prevent leaks
	if s.backendDevices != nil {
		if oldDev, ok := s.backendDevices[tun.ID]; ok {
			s.forwarder.DetachBackendDevice(tun.ID)
			if oldDev != nil {
				_ = oldDev.Close()
				s.retiredBackendDeviceDrops.addInto(snapshotBackendDeviceDrops(oldDev))
			}
			delete(s.backendDevices, tun.ID)
			if s.backendDeviceEndpoints != nil {
				delete(s.backendDeviceEndpoints, tun.ID)
			}
		}
	}

	beMTU := 1280
	if deviceParams != nil {
		if mVal, ok := deviceParams["mtu"].(string); ok && mVal != "" {
			if parsed, err := strconv.Atoi(mVal); err == nil && parsed > 0 {
				beMTU = parsed
			}
		} else if mInt, ok := deviceParams["mtu"].(int); ok && mInt > 0 {
			beMTU = mInt
		}
	}

	dev, devErr := tunnel.NewAWGClientDevice(fmt.Sprintf("awg-be-%d", tun.ServerID), tun.Endpoint, tun.PrivateKey, tun.PublicKey, beMTU, deviceParams)
	if devErr != nil {
		return fmt.Errorf("failed to create backend AWG device for server %d: %w", tun.ServerID, devErr)
	}
	s.forwarder.AttachBackendDevice(tun.ID, dev)
	if s.backendDevices == nil {
		s.backendDevices = make(map[int64]BackendDevice)
	}
	s.backendDevices[tun.ID] = dev
	if s.backendDeviceEndpoints == nil {
		s.backendDeviceEndpoints = make(map[int64]string)
	}
	s.backendDeviceEndpoints[tun.ID] = tun.Endpoint

	// Spawn backend read loop to route packets back to clients
	go s.pumpBackendReturns(tun.ID, tun.ServerID, dev)

	// Trigger backend routing and NAT remediation asynchronously in the background
	// so tunnel attachment and data-plane startup are never blocked by SSH latency.
	go s.triggerBackendRoutingRemediation(tun.ServerID)

	return nil
}

// pumpBackendReturns reads backend plaintext and dispatches through the production forwarder.
func (s *Service) pumpBackendReturns(backendID, serverID int64, device io.Reader) {
	buf := make([]byte, 2048)
	for {
		n, err := device.Read(buf)
		if err != nil {
			return
		}
		if n >= 20 && (buf[0]>>4) == 4 { // IPv4
			destIP := net.IPv4(buf[16], buf[17], buf[18], buf[19]).String()
			if err := s.forwarder.RouteBackendToClient(backendID, buf[:n], destIP); err != nil {
				// Throttle drop logs: a stalled route would otherwise
				// produce one log line per packet (issue #39: 7687
				// "packet queue is full" lines in 2 h). Counters are
				// exposed via Forwarder.DropStats / the stats API, so
				// rate-limiting the log loses no information.
				now := time.Now().Unix()
				if s.dropLogUntil.Load() <= now {
					s.dropLogUntil.Store(now + 1)
					log.Printf("[vpn/forwarder] dropped backend return packet to %s (backend_tunnel_id=%d server_id=%d): %v",
						destIP, backendID, serverID, err)
				}
			}
		}
	}
}

// getPortalSubnet returns the configured portal client subnet CIDR or defaults to "10.100.0.0/16".
func (s *Service) getPortalSubnet() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.cfg != nil && s.cfg.SubnetCIDR != "" {
		return s.cfg.SubnetCIDR
	}
	return "10.100.0.0/16"
}

// remediateBackendRouting invokes EnsureBackendRoutingAndNAT on the configured AWG provider
// for the given server ID and portal subnet.
func (s *Service) remediateBackendRouting(ctx context.Context, serverID int64) error {
	s.mu.RLock()
	db := s.db
	awgProv := s.awgProvider
	s.mu.RUnlock()

	if db == nil {
		return errors.New("database not available")
	}
	if awgProv == nil {
		return errors.New("awg provider not available")
	}
	remediator, ok := awgProv.(RoutingRemediator)
	if !ok {
		return nil
	}

	server, err := db.GetServerByID(ctx, serverID)
	if err != nil {
		return fmt.Errorf("failed to load server %d: %w", serverID, err)
	}
	if server == nil {
		return fmt.Errorf("server %d not found", serverID)
	}

	subnet := s.getPortalSubnet()
	return remediator.EnsureBackendRoutingAndNAT(ctx, server, subnet)
}

// triggerBackendRoutingRemediation runs remediation in the background with a 30-second timeout.
// If the AWG provider or database is not yet ready at startup, it polls with a bounded retry.
func (s *Service) triggerBackendRoutingRemediation(serverID int64) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Bounded wait for awgProvider and db to become available during startup lifecycle
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	timeout := time.After(5 * time.Second)
	for {
		s.mu.RLock()
		ready := s.db != nil && s.awgProvider != nil
		s.mu.RUnlock()

		if ready {
			break
		}

		select {
		case <-ctx.Done():
			return
		case <-timeout:
			goto execute
		case <-ticker.C:
		}
	}

execute:
	if err := s.remediateBackendRouting(ctx, serverID); err != nil {
		if !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "database is closed") {
			log.Printf("[vpn] warning: failed to ensure backend routing and NAT for server %d: %v", serverID, err)
		}
	}
}
