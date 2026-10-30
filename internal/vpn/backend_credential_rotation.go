package vpn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/manager"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

// rotations serializes remote provisioning for a given backend without holding Service.mu.
// Reference counts keep a waiting caller's lock from being removed prematurely.
var rotations = struct {
	sync.Mutex
	byBackend map[rotationKey]*rotationLock
}{byBackend: make(map[rotationKey]*rotationLock)}

type rotationKey struct {
	service  *Service
	serverID int64
}

type rotationLock struct {
	sync.Mutex
	users int
}

func lockBackendRotation(s *Service, serverID int64) func() {
	key := rotationKey{service: s, serverID: serverID}
	rotations.Lock()
	lock := rotations.byBackend[key]
	if lock == nil {
		lock = &rotationLock{}
		rotations.byBackend[key] = lock
	}
	lock.users++
	rotations.Unlock()
	lock.Lock()
	return func() {
		rotations.Lock()
		lock.users--
		if lock.users == 0 {
			delete(rotations.byBackend, key)
		}
		lock.Unlock()
		rotations.Unlock()
	}
}

// RotateSharedBackendCredential provisions a separate remote proxy identity and switches
// the persisted and live backend before callers revoke the former user's identity.
// A failed switch leaves the former identity untouched for a later retry.
//
//nolint:gocyclo // provisioning, ownership, persistence and rollback are one fail-closed operation.
func (s *Service) RotateSharedBackendCredential(
	ctx context.Context, server *models.Server, mgr manager.ProtocolManager, proto, oldID string,
) error {
	if s == nil || s.db == nil || s.pool == nil || server == nil || mgr == nil {
		return errors.New("backend rotation requires a VPN service, server and protocol manager")
	}
	proto = models.NormalizeProtocol(proto)
	if proto != models.ProtocolNaive && proto != models.ProtocolVLESS {
		return fmt.Errorf("cannot rotate backend credential for protocol %q", proto)
	}

	unlock := lockBackendRotation(s, server.ID)
	defer unlock()

	s.mu.Lock()
	current, err := s.pool.GetTunnel(server.ID)
	if errors.Is(err, tunnel.ErrTunnelNotFound) {
		if err = s.pool.SyncFromDB(ctx); err == nil {
			current, err = s.pool.GetTunnel(server.ID)
		}
	}
	s.mu.Unlock()
	if err != nil {
		return fmt.Errorf("load live backend for server %d: %w", server.ID, err)
	}
	if models.NormalizeTunnelProtocol(current.Protocol) != proto || !sameProxyClient(proto, ExtractClientIDFromProtocolParams(proto, current.ProtocolParams), oldID) {
		return errors.New("backend credential changed during rotation")
	}
	// Capture the durable server generation before remote provisioning. A delete
	// and recreate at the same ID must not acquire the old remote credential.
	generation, err := s.db.GetServer(ctx, server.ID)
	if err != nil {
		return fmt.Errorf("load backend server generation %d: %w", server.ID, err)
	}
	if generation == nil {
		return fmt.Errorf("backend server %d disappeared before rotation", server.ID)
	}
	name := fmt.Sprintf("vpn-backend-%d", server.ID)
	res, err := mgr.AddClient(ctx, server, map[string]any{"name": name})
	if err != nil {
		return fmt.Errorf("provision replacement backend credential: %w", err)
	}
	params, newID, err := rotatedProxyParams(proto, current.ProtocolParams, res)
	if err == nil && sameProxyClient(proto, newID, oldID) {
		err = errors.New("replacement credential matches the former user credential")
	}
	var assigned bool
	var ownershipChecked bool
	if err == nil {
		assigned, err = s.db.HasUserConnectionCredential(ctx, server.ID, proto, newID)
		ownershipChecked = err == nil
		if err == nil && assigned {
			err = errors.New("replacement credential is already assigned to a user")
		}
	}
	if err != nil {
		// Never remove an identity that might be the old backend or another user's.
		if newID != "" && !sameProxyClient(proto, newID, oldID) && ownershipChecked && !assigned {
			return errors.Join(err, cleanupRotatedCredential(ctx, s.db, mgr, server, proto, newID))
		}
		return err
	}

	// Only the local commit is serialized with admissions and enable/disable.
	// Remote compensation is deliberately done after releasing Service.mu.
	s.mu.Lock()
	commitErr, safeToClean := s.commitBackendRotation(ctx, server.ID, generation, current, proto, params, newID, name)
	s.mu.Unlock()
	if commitErr != nil && safeToClean {
		return errors.Join(commitErr, cleanupRotatedCredential(ctx, s.db, mgr, server, proto, newID))
	}
	return commitErr
}

func (s *Service) commitBackendRotation(
	ctx context.Context, serverID int64, generation *models.Server, current *models.BackendTunnel,
	proto string, params json.RawMessage, newID, name string,
) (error, bool) {
	live, err := s.pool.GetTunnel(serverID)
	if err != nil || s.isServerDeletedLocked(serverID) || !models.SameTunnelIdentity(live, current) {
		// An external enable may already have adopted the replacement identity.
		// Never remove the credential currently used by a live backend.
		if err == nil && sameProxyClient(proto, ExtractClientIDFromProtocolParams(proto, live.ProtocolParams), newID) {
			return errors.New("backend changed during remote credential provisioning"), false
		}
		return errors.New("backend changed during remote credential provisioning"), true
	}
	server, err := s.db.GetServer(ctx, serverID)
	if err != nil {
		return fmt.Errorf("revalidate backend server %d: %w", serverID, err), false
	}
	if server == nil || !server.CreatedAt.Equal(generation.CreatedAt) || server.Host != generation.Host {
		return errors.New("backend server generation changed during rotation"), true
	}
	assigned, err := s.db.HasUserConnectionCredential(ctx, serverID, proto, newID)
	if err != nil {
		return fmt.Errorf("revalidate replacement credential ownership: %w", err), false
	}
	if assigned {
		return errors.New("replacement credential became assigned to a user"), false
	}
	if err := RecordBackendProxyPeerLifecycle(ctx, s.db, serverID, proto, newID, name); err != nil {
		return fmt.Errorf("record replacement backend ownership: %w", err), true
	}
	updated, err := s.pool.AddTunnelWithConfig(ctx, serverID, current.Endpoint, current.PublicKey,
		tunnel.BackendTunnelOptions{Protocol: proto, ProtocolParams: params})
	if err != nil {
		return fmt.Errorf("switch backend credentials: %w", err), true
	}
	// AddTunnelWithConfig preserves the live administrative state. DisableBackend
	// already detached its device; never reattach it after a concurrent disable.
	if !live.Enabled {
		return nil, false
	}
	if err := s.attachBackendForwarder(updated, nil); err != nil {
		// Old remote identity is still valid; roll back before revoking anything.
		_, rollbackErr := s.pool.AddTunnelWithConfig(ctx, serverID, current.Endpoint, current.PublicKey,
			tunnel.BackendTunnelOptions{Protocol: proto, ProtocolParams: current.ProtocolParams})
		if rollbackErr != nil {
			return errors.Join(fmt.Errorf("attach replacement backend: %w", err),
				fmt.Errorf("restore former backend: %w", rollbackErr)), false
		}
		return fmt.Errorf("attach replacement backend: %w", err), true
	}
	return nil, false
}

func cleanupRotatedCredential(ctx context.Context, db *database.DB, mgr manager.ProtocolManager, server *models.Server, proto, clientID string) error {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	if err := mgr.RemoveClient(cleanupCtx, server, clientID); err != nil {
		_ = db.SetPeerLifecycleStatus(cleanupCtx, server.ID, proto, clientID, "failed")
		return fmt.Errorf("remove uncommitted replacement %q: %w", clientID, err)
	}
	if err := db.DeletePeerLifecycle(cleanupCtx, server.ID, proto, clientID); err != nil {
		return fmt.Errorf("remove uncommitted replacement lifecycle %q: %w", clientID, err)
	}
	return nil
}

func sameProxyClient(proto, a, b string) bool {
	if proto == models.ProtocolVLESS {
		return strings.EqualFold(a, b)
	}
	return a == b
}

func rotatedProxyParams(proto string, previous json.RawMessage, res map[string]any) (json.RawMessage, string, error) {
	if res == nil {
		return nil, "", errors.New("backend provisioning returned no credentials")
	}
	get := func(key string) string { value, _ := res[key].(string); return value }
	id := get("client_id")
	if id == "" {
		id = get("clientId")
	}
	switch proto {
	case models.ProtocolNaive:
		var p models.NaiveProxyParams
		if err := json.Unmarshal(previous, &p); err != nil {
			return nil, "", fmt.Errorf("decode former naive backend: %w", err)
		}
		if username := get("username"); username != "" {
			id = username
		}
		password := get("password")
		if id == "" || password == "" {
			return nil, id, errors.New("replacement naive credential missing username or password")
		}
		p.Username, p.Password = id, password
		if domain := get("domain"); domain != "" {
			p.Domain = domain
		}
		// #nosec G117 -- Backend credentials are encrypted by Pool.AddTunnelWithConfig before persistence.
		params, err := json.Marshal(p)
		return params, id, err
	case models.ProtocolVLESS:
		var p models.VLESSRealityParams
		if err := json.Unmarshal(previous, &p); err != nil {
			return nil, "", fmt.Errorf("decode former vless backend: %w", err)
		}
		if uuid := get("uuid"); uuid != "" {
			id = uuid
		}
		if id == "" {
			return nil, "", errors.New("replacement vless credential missing uuid")
		}
		p.UUID = id
		if flow, ok := res["flow"].(string); ok {
			p.Flow = flow
		}
		if publicKey := get("public_key"); publicKey != "" {
			p.PublicKey = publicKey
		}
		if shortID := get("short_id"); shortID != "" {
			p.ShortID = shortID
		}
		if serverName := get("server_name"); serverName != "" {
			p.ServerName = serverName
		}
		params, err := json.Marshal(p)
		return params, id, err
	default:
		return nil, "", fmt.Errorf("unsupported proxy protocol %q", proto)
	}
}
