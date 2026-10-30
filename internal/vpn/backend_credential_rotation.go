package vpn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/manager"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

// RotateSharedBackendCredential provisions a separate remote proxy identity and switches
// the persisted and live backend before callers revoke the former user's identity.
// A failed switch leaves the former identity untouched for a later retry.
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

	// Hold the same service lock as backend enable/disable while the remote identity
	// is provisioned and the pool and its data-plane device are replaced.
	s.mu.Lock()
	defer s.mu.Unlock()

	current, err := s.pool.GetTunnel(server.ID)
	if errors.Is(err, tunnel.ErrTunnelNotFound) {
		if err = s.pool.SyncFromDB(ctx); err == nil {
			current, err = s.pool.GetTunnel(server.ID)
		}
	}
	if err != nil {
		return fmt.Errorf("load live backend for server %d: %w", server.ID, err)
	}
	if models.NormalizeTunnelProtocol(current.Protocol) != proto || !sameProxyClient(proto, ExtractClientIDFromProtocolParams(proto, current.ProtocolParams), oldID) {
		return errors.New("backend credential changed during rotation")
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
	if err := RecordBackendProxyPeerLifecycle(ctx, s.db, server.ID, proto, newID, name); err != nil {
		return errors.Join(fmt.Errorf("record replacement backend ownership: %w", err),
			cleanupRotatedCredential(ctx, s.db, mgr, server, proto, newID))
	}

	updated, err := s.pool.AddTunnelWithConfig(ctx, server.ID, current.Endpoint, current.PublicKey,
		tunnel.BackendTunnelOptions{Protocol: proto, ProtocolParams: params})
	if err != nil {
		return errors.Join(fmt.Errorf("switch backend credentials: %w", err),
			cleanupRotatedCredential(ctx, s.db, mgr, server, proto, newID))
	}
	if err := s.attachBackendForwarder(updated, nil); err != nil {
		// Old remote identity is still valid. Restore the durable/live tunnel
		// before the caller is allowed to revoke it.
		_, rollbackErr := s.pool.AddTunnelWithConfig(ctx, server.ID, current.Endpoint, current.PublicKey,
			tunnel.BackendTunnelOptions{Protocol: proto, ProtocolParams: current.ProtocolParams})
		if rollbackErr != nil {
			return errors.Join(fmt.Errorf("attach replacement backend: %w", err),
				fmt.Errorf("restore former backend: %w", rollbackErr))
		}
		return errors.Join(fmt.Errorf("attach replacement backend: %w", err),
			cleanupRotatedCredential(ctx, s.db, mgr, server, proto, newID))
	}
	return nil
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
		if flow := get("flow"); flow != "" {
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
