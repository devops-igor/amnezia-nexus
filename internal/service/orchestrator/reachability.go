package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/awg/health"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"golang.org/x/sync/errgroup"
)

// AWGHealthProbeManager defines interface for AWG health probe client provisioning.
type AWGHealthProbeManager interface {
	GetServerPublicKey(ctx context.Context, server *models.Server) (string, error)
	GetClients(ctx context.Context, server *models.Server) ([]map[string]any, error)
	AddClient(ctx context.Context, server *models.Server, clientParams map[string]any) (map[string]any, error)
}

// CheckServerReachability probes all servers for network reachability via AWG Noise handshake or TCP.
func (o *Orchestrator) CheckServerReachability(ctx context.Context) (map[int64]map[string]any, error) {
	if o.db == nil {
		return nil, errors.New("database is not configured")
	}

	slog.Info("Starting background server reachability check...")

	servers, err := o.db.GetAllServers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch servers: %w", err)
	}

	results := make(map[int64]map[string]any)
	var mu sync.Mutex

	g, gCtx := errgroup.WithContext(ctx)
	g.SetLimit(o.maxConcurrency)

	for _, srv := range servers {
		server := srv
		g.Go(func() (err error) {
			defer func() {
				if r := recover(); r != nil {
					slog.Error("Panic recovered in reachability probe goroutine", "server_id", server.ID, "panic", r)
					res := map[string]any{
						"reachable":    false,
						"latency_ms":   0,
						"protocol":     "error",
						"last_checked": time.Now().UTC().Format(time.RFC3339),
						"error":        fmt.Sprintf("probe panicked: %v", r),
					}
					mu.Lock()
					results[server.ID] = res
					mu.Unlock()
				}
			}()
			res := o.probeSingleServer(gCtx, &server)
			mu.Lock()
			results[server.ID] = res
			mu.Unlock()
			return nil
		})
	}

	_ = g.Wait()

	o.mu.Lock()
	o.reachabilityCache = results
	o.mu.Unlock()

	return results, nil
}

func (o *Orchestrator) probeSingleServer(ctx context.Context, server *models.Server) map[string]any {
	if server == nil {
		return map[string]any{
			"reachable":    false,
			"latency_ms":   0,
			"protocol":     "tcp",
			"last_checked": time.Now().UTC().Format(time.RFC3339),
			"error":        "nil server pointer",
		}
	}

	host := strings.TrimSpace(server.Host)
	if host == "" {
		if o.db != nil {
			_ = o.db.UpdateServerReachability(ctx, server.ID, models.ReachabilityOffline)
		}
		return map[string]any{
			"reachable":    false,
			"latency_ms":   0,
			"protocol":     "tcp",
			"last_checked": time.Now().UTC().Format(time.RFC3339),
			"error":        "empty host address",
		}
	}

	nowStr := time.Now().UTC().Format(time.RFC3339)
	var preservedAutoTrials map[string]map[string]any

	// 1. If AWG is installed on server, attempt Noise IK handshake probe
	if awgInfo, ok := server.Protocols["awg"].(map[string]any); ok && awgInfo != nil {
		port := extractAWGPort(awgInfo)
		serverPub, clientPriv, psk := o.resolveAWGProbeKeys(ctx, server, awgInfo)
		awgParams, _ := awgInfo["awg_params"].(map[string]any)
		var hpKey string
		if awgParams != nil {
			hpKey = health.ExtractHeaderProtectionKey(awgParams)
		}

		if serverPub != "" {
			reachRes, autoTrials, ok := o.probeAWGHealth(ctx, server, host, port, serverPub, clientPriv, psk, hpKey, awgParams)
			if ok {
				return reachRes
			}
			preservedAutoTrials = autoTrials
		}
	}

	// 2. Fallback to TCP SSH port probe
	return o.probeTCPFallback(ctx, server, host, nowStr, preservedAutoTrials)
}

func extractAWGPort(awgInfo map[string]any) int {
	port := 55424
	if pVal, ok := awgInfo["port"]; ok && pVal != nil {
		if p, err := strconv.Atoi(fmt.Sprint(pVal)); err == nil && p > 0 {
			port = p
		}
	}
	return port
}

func (o *Orchestrator) resolveAWGProbeKeys(ctx context.Context, server *models.Server, awgInfo map[string]any) (string, string, string) {
	serverPub, _ := awgInfo["public_key"].(string)

	o.mu.RLock()
	cached := o.healthProbeKeys[server.ID]
	o.mu.RUnlock()

	if serverPub == "" {
		serverPub = cached.serverPub
	}
	if cached.clientPriv != "" {
		return serverPub, cached.clientPriv, cached.psk
	}

	if o.registry == nil {
		return serverPub, "", ""
	}
	mgr, ok := o.registry.Get("awg")
	if !ok {
		return serverPub, "", ""
	}
	hpm, isHealthProbeMgr := mgr.(AWGHealthProbeManager)
	if !isHealthProbeMgr {
		return serverPub, "", ""
	}
	return o.provisionProbeIdentity(ctx, server, hpm, serverPub)
}

// provisionProbeIdentity resolves the server public key together with the
// identity the reachability prober signs with, and caches that decision so
// repeated cycles do not re-register or re-read the backend.
//
// Identity, PSK policy and server key travel as one unit because they all describe
// the same peer:
//
//   - identity: the private key the probe handshake signs with. The AWG manager
//     owns it: the probe peer's keypair is generated and stored backend-side in
//     the clientsTable, which is the only place it survives a panel restart.
//   - psk: the handshake must derive IKpsk2 with the SAME PSK the backend
//     registered for this peer. Current registrations are PSK-less; a peer written
//     by the older server-PSK path keeps deriving with the PSK recorded for it.
//   - serverPub: the server's own public key, required by the handshake.
func (o *Orchestrator) provisionProbeIdentity(ctx context.Context, server *models.Server, hpm AWGHealthProbeManager, serverPub string) (string, string, string) {
	if serverPub == "" {
		if pub, err := hpm.GetServerPublicKey(ctx, server); err == nil && pub != "" {
			serverPub = pub
		}
	}

	identity, err := o.ensureHealthProbeIdentity(ctx, server, hpm)
	if err != nil {
		// No usable identity means the Noise handshake cannot be attributed to a
		// registered peer. Report it once and let the caller fall back instead of
		// signing with a key the backend does not know.
		slog.Warn("reachability probe identity unavailable; outer AWG handshake not attempted",
			"server_id", server.ID, "err", err)
	}
	if identity.clientPriv == "" {
		o.cacheProbeKeys(server.ID, "", serverPub, "")
		return serverPub, "", ""
	}

	o.cacheProbeKeys(server.ID, identity.clientPriv, serverPub, identity.psk)
	return serverPub, identity.clientPriv, identity.psk
}

// cacheProbeKeys stores the resolved probe identity for the server, so repeated
// cycles do not re-read the backend. The cache is written once per resolution and
// never partially.
func (o *Orchestrator) cacheProbeKeys(serverID int64, clientPriv, serverPub, psk string) {
	if clientPriv == "" && serverPub == "" && psk == "" {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.healthProbeKeys == nil {
		o.healthProbeKeys = make(map[int64]healthProbeKey)
	}
	o.healthProbeKeys[serverID] = healthProbeKey{
		clientPriv: clientPriv,
		serverPub:  serverPub,
		psk:        psk,
	}
}

// healthProbeIdentity is the resolved reachability-probe peer identity for one
// server: the private key to sign with, and the PresharedKey the backend
// registered for that peer.
type healthProbeIdentity struct {
	clientPriv string
	psk        string
}

// ensureHealthProbeIdentity resolves the probe identity for a server at most once
// per in-flight batch. Concurrent callers share one resolution: two independent
// registrations would leave the backend holding whichever identity was written
// last while one caller signs with the other, so only one may run.
//
// Coalesced callers share the first caller's context. That is correct here
// because every caller in a cycle derives from the same run context - a canceled
// cycle must not register a peer - and a resolution is never retried implicitly.
func (o *Orchestrator) ensureHealthProbeIdentity(ctx context.Context, server *models.Server, hpm AWGHealthProbeManager) (healthProbeIdentity, error) {
	key := strconv.FormatInt(server.ID, 10)
	res, err, _ := o.probeIdentityGroup.Do(key, func() (any, error) {
		return o.resolveOrCreateHealthProbeClient(ctx, server, hpm)
	})
	if err != nil {
		return healthProbeIdentity{}, err
	}
	identity, ok := res.(healthProbeIdentity)
	if !ok {
		return healthProbeIdentity{}, errors.New("health-probe identity resolution returned an unexpected result")
	}
	return identity, nil
}

// resolveOrCreateHealthProbeClient resolves the reachability probe peer's identity
// on the backend, registering the peer only when the backend holds no credential
// for it.
//
// Credential ownership is the manager's: a probe registration generates the
// keypair, records the private half in the backend's clientsTable and returns no
// credential (the peer is PSK-less and has no client config). The clientsTable is
// therefore the authoritative, durable home of that key, and the prober reads it
// back — including immediately after registering, so the very first cycle after an
// install or a reinstall can sign a handshake instead of waiting a whole probe
// interval for the next scheduled read. Later cycles, and a new panel process after
// a restart, recover the same key from that table rather than minting a new one, so
// the registered peer identity stays stable.
func (o *Orchestrator) resolveOrCreateHealthProbeClient(ctx context.Context, server *models.Server, hpm AWGHealthProbeManager) (healthProbeIdentity, error) {
	if stored, ok, err := o.storedHealthProbeIdentity(ctx, server, hpm); err != nil {
		return healthProbeIdentity{}, err
	} else if ok {
		return stored, nil
	}

	// No credential is stored for the probe peer: register it. Registration is
	// idempotent on the peer name, so an unreadable-but-present peer is refreshed
	// rather than duplicated.
	if _, addErr := hpm.AddClient(ctx, server, map[string]any{
		"name":       "Health Probe",
		"clientName": "Health Probe",
	}); addErr != nil {
		return healthProbeIdentity{}, fmt.Errorf("failed to provision the health-probe peer: %w", addErr)
	}

	stored, ok, err := o.storedHealthProbeIdentity(ctx, server, hpm)
	if err != nil {
		return healthProbeIdentity{}, err
	}
	if !ok {
		return healthProbeIdentity{}, errors.New("health-probe peer registration stored no usable credential")
	}
	return stored, nil
}

// storedHealthProbeIdentity reads the probe peer's credential from the backend.
func (o *Orchestrator) storedHealthProbeIdentity(ctx context.Context, server *models.Server, hpm AWGHealthProbeManager) (healthProbeIdentity, bool, error) {
	clients, err := hpm.GetClients(ctx, server)
	if err != nil {
		return healthProbeIdentity{}, false, fmt.Errorf("failed to read backend clients for the health-probe identity: %w", err)
	}
	identity, ok := storedHealthProbeKey(clients)
	return identity, ok, nil
}

// storedHealthProbeKey returns the identity the backend still stores for the
// reachability probe peer, including the PresharedKey that peer was registered
// with. ok is false when the peer holds no caller-owned credential.
func storedHealthProbeKey(clients []map[string]any) (healthProbeIdentity, bool) {
	for _, cl := range clients {
		uData, ok := cl["userData"].(map[string]any)
		if !ok || uData == nil {
			continue
		}
		cName, _ := uData["clientName"].(string)
		if !strings.EqualFold(strings.TrimSpace(cName), "health probe") {
			continue
		}
		priv, _ := uData["clientPrivateKey"].(string)
		if priv == "" {
			continue
		}
		psk, _ := uData["psk"].(string)
		return healthProbeIdentity{clientPriv: priv, psk: psk}, true
	}
	return healthProbeIdentity{}, false
}

func (o *Orchestrator) dataPlaneI1Protocol(ctx context.Context) string {
	if o != nil && o.db != nil {
		vpnCfg, err := o.db.GetVPNConfig(ctx)
		if err != nil {
			slog.WarnContext(ctx, "failed to load VPN config for data-plane I1 protocol", "err", err)
		} else if vpnCfg != nil {
			return vpnCfg.DataPlaneI1Protocol()
		}
	}
	return (*models.VPNConfig)(nil).DataPlaneI1Protocol()
}

func (o *Orchestrator) probeAWGHealth(ctx context.Context, server *models.Server, host string, port int, serverPub, clientPriv, psk, hpKey string, awgParams map[string]any) (map[string]any, map[string]map[string]any, bool) {
	proto := o.dataPlaneI1Protocol(ctx)
	reachRes, err := health.PerformAWGHandshake(ctx, host, port, serverPub, clientPriv, psk, hpKey, awgParams, proto, 3*time.Second)
	if err != nil {
		return nil, nil, false
	}

	autoTrials, _ := health.RunAutoTrialProfiles(ctx, host, port, serverPub, clientPriv, psk, hpKey, awgParams, 2*time.Second)
	reachRes["auto_trials"] = autoTrials

	if isReachable, _ := reachRes["reachable"].(bool); isReachable {
		if o.db != nil && server != nil {
			_ = o.db.UpdateServerReachability(ctx, server.ID, models.ReachabilityOnline)
		}
		return reachRes, autoTrials, true
	}
	return reachRes, autoTrials, false
}

func (o *Orchestrator) probeTCPFallback(ctx context.Context, server *models.Server, host string, nowStr string, preservedAutoTrials map[string]map[string]any) map[string]any {
	sshPort := 22
	if server != nil && server.SSHPort > 0 {
		sshPort = server.SSHPort
	}

	cleanHost := strings.Trim(strings.TrimSpace(host), "[]")
	addr := net.JoinHostPort(cleanHost, strconv.Itoa(sshPort))
	t0 := time.Now()

	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		res := map[string]any{
			"reachable":    false,
			"latency_ms":   0,
			"protocol":     "tcp",
			"last_checked": nowStr,
			"error":        err.Error(),
		}
		if preservedAutoTrials != nil {
			res["auto_trials"] = preservedAutoTrials
		}
		if o.db != nil && server != nil {
			_ = o.db.UpdateServerReachability(ctx, server.ID, models.ReachabilityOffline)
		}
		return res
	}
	_ = conn.Close()

	latency := time.Since(t0).Milliseconds()
	if latency <= 0 {
		latency = 1
	}

	res := map[string]any{
		"reachable":    true,
		"latency_ms":   latency,
		"protocol":     "tcp",
		"last_checked": nowStr,
	}
	if preservedAutoTrials != nil {
		res["auto_trials"] = preservedAutoTrials
	}

	if o.db != nil && server != nil {
		_ = o.db.UpdateServerReachability(ctx, server.ID, models.ReachabilityOnline)
	}
	return res
}
