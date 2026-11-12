package tunnel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// BackendTunnelOptions holds optional protocol and configuration parameters for a backend tunnel.
type BackendTunnelOptions struct {
	Protocol       string
	ProtocolParams json.RawMessage
}

type deployEnrollmentContextKey struct{}

// DeployEnrollmentKey is used in context to signal that initial enrollment
// should start in non-eligible connecting status until traffic is qualified.
var DeployEnrollmentKey = deployEnrollmentContextKey{}

// AddTunnel establishes or registers an in-process AWG backend tunnel for a server.
// Optional options allow specifying protocol and protocol parameters.
func (p *Pool) AddTunnel(ctx context.Context, serverID int64, endpoint, serverPubKey string, opts ...BackendTunnelOptions) (*models.BackendTunnel, error) {
	var opt BackendTunnelOptions
	if len(opts) > 1 {
		return nil, errors.New("multiple tunnel options not supported")
	}
	if len(opts) == 1 {
		opt = opts[0]
	}
	return p.AddTunnelWithConfig(ctx, serverID, endpoint, serverPubKey, opt)
}

// AddTunnelWithConfig establishes or registers a backend tunnel with explicit protocol configuration.
//
//nolint:gocyclo // multi-protocol validation, key generation, and identity comparison are centralized.
func (p *Pool) AddTunnelWithConfig(ctx context.Context, serverID int64, endpoint, serverPubKey string, opts BackendTunnelOptions) (*models.BackendTunnel, error) {
	if serverID <= 0 {
		return nil, errors.New("server_id must be greater than 0")
	}
	if endpoint == "" {
		return nil, errors.New("endpoint cannot be empty")
	}

	proto := models.NormalizeTunnelProtocol(opts.Protocol)
	if !models.IsSupportedBackendProtocol(proto) {
		return nil, fmt.Errorf("unsupported protocol: %s", opts.Protocol)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil, ErrPoolClosed
	}

	if proto != models.ProtocolAWG {
		if !p.multiProtocolEnabled {
			return nil, errors.New("multi-protocol backends are disabled")
		}
		if len(opts.ProtocolParams) == 0 {
			return nil, errors.New("protocol parameters cannot be empty for proxy backends")
		}
		if proto == models.ProtocolVLESS {
			var vlessParams models.VLESSRealityParams
			if err := json.Unmarshal(opts.ProtocolParams, &vlessParams); err != nil {
				return nil, fmt.Errorf("invalid vless parameters: %w", err)
			}
		} else if proto == models.ProtocolNaive {
			var naiveParams models.NaiveProxyParams
			if err := json.Unmarshal(opts.ProtocolParams, &naiveParams); err != nil {
				return nil, fmt.Errorf("invalid naive parameters: %w", err)
			}
		}
	}

	if existing, ok := p.tunnelsByServerID[serverID]; ok {
		existingProto := models.NormalizeTunnelProtocol(existing.Protocol)
		if existingProto != proto {
			return nil, fmt.Errorf("cannot change backend protocol from %s to %s; disable and replace instead", existingProto, proto)
		}

		if proto == models.ProtocolAWG {
			candEndpoint := endpoint
			candPubKey := serverPubKey
			if candPubKey == "" {
				candPubKey = existing.PublicKey
			}
			candPrivKey := existing.PrivateKey
			candProbePrivKey := existing.ProbePrivateKey

			if candPrivKey == "" {
				_, sk, err := p.genKeyPair()
				if err != nil {
					return nil, fmt.Errorf("failed to generate backend private key: %w", err)
				}
				candPrivKey = sk
			}

			if candProbePrivKey == "" {
				_, sk, err := p.genKeyPair()
				if err != nil {
					return nil, fmt.Errorf("failed to generate probe private key: %w", err)
				}
				candProbePrivKey = sk
			}

			cand := models.BackendTunnel{
				ID:              existing.ID,
				Endpoint:        candEndpoint,
				PublicKey:       candPubKey,
				PrivateKey:      candPrivKey,
				ProbePrivateKey: candProbePrivKey,
				Protocol:        models.ProtocolAWG,
			}
			changed := !models.SameTunnelIdentity(existing, &cand) || (ctx != nil && ctx.Value(DeployEnrollmentKey) != nil)

			candStateVersion := existing.StateVersion
			if changed {
				candStateVersion = existing.StateVersion + 1
				if existing.StateVersion <= 0 {
					candStateVersion = 2
				}
			}

			if p.db != nil {
				updates := map[string]any{
					"endpoint":          candEndpoint,
					"public_key":        candPubKey,
					"private_key":       candPrivKey,
					"probe_private_key": candProbePrivKey,
				}
				if changed {
					updates["state_version"] = candStateVersion
				}
				if err := p.persistTunnelEnrollment(ctx, existing, updates); err != nil {
					return nil, fmt.Errorf("failed to persist backend tunnel updates: %w", err)
				}
			}

			existing.Endpoint = candEndpoint
			existing.PublicKey = candPubKey
			existing.PrivateKey = candPrivKey
			existing.ProbePrivateKey = candProbePrivKey
			resetTunnelEnrollmentHealth(ctx, existing)
			if changed {
				existing.StateVersion = candStateVersion
			}
			copyTunnel := *existing
			return &copyTunnel, nil
		}

		// Proxy existing update
		cand := models.BackendTunnel{
			ID:             existing.ID,
			Endpoint:       endpoint,
			Protocol:       proto,
			ProtocolParams: bytes.Clone(opts.ProtocolParams),
		}
		changed := !models.SameTunnelIdentity(existing, &cand) || (ctx != nil && ctx.Value(DeployEnrollmentKey) != nil)

		candStateVersion := existing.StateVersion
		if changed {
			candStateVersion = existing.StateVersion + 1
			if existing.StateVersion <= 0 {
				candStateVersion = 2
			}
		}

		if p.db != nil {
			updates := map[string]any{
				"endpoint":        endpoint,
				"protocol":        proto,
				"protocol_params": opts.ProtocolParams,
			}
			if changed {
				updates["state_version"] = candStateVersion
			}
			if err := p.persistTunnelEnrollment(ctx, existing, updates); err != nil {
				return nil, fmt.Errorf("failed to persist backend tunnel updates: %w", err)
			}
		}

		existing.Endpoint = endpoint
		existing.Protocol = proto
		existing.ProtocolParams = bytes.Clone(opts.ProtocolParams)
		resetTunnelEnrollmentHealth(ctx, existing)
		if changed {
			existing.StateVersion = candStateVersion
		}
		copyTunnel := *existing
		return &copyTunnel, nil
	}

	var tunnel *models.BackendTunnel
	now := time.Now().UTC()

	if proto == models.ProtocolAWG {
		pubKey := serverPubKey
		var privKey string
		if pubKey == "" {
			pk, sk, err := p.genKeyPair()
			if err != nil {
				return nil, err
			}
			pubKey = pk
			privKey = sk
		} else {
			_, sk, err := p.genKeyPair()
			if err != nil {
				return nil, err
			}
			privKey = sk
		}

		probePrivPub, probePrivKey, err := p.genKeyPair()
		if err != nil {
			return nil, fmt.Errorf("failed to generate probe keypair: %w", err)
		}
		_ = probePrivPub

		ifName := fmt.Sprintf("awg-be-%d", serverID)
		initStatus := models.TunnelStatusActive
		initLatency := int64(10)
		if ctx != nil && (ctx.Value(DeployEnrollmentKey) != nil || opts.Protocol != "") {
			initStatus = models.TunnelStatusConnecting
			initLatency = 0
		}
		tunnel = &models.BackendTunnel{
			ServerID:          serverID,
			InterfaceName:     ifName,
			PublicKey:         pubKey,
			PrivateKey:        privKey,
			ProbePrivateKey:   probePrivKey,
			Endpoint:          endpoint,
			Enabled:           true,
			Status:            initStatus,
			DisableReason:     models.DisableReasonNone,
			StateVersion:      1,
			LastHealthCheck:   nil,
			LatencyMS:         initLatency,
			ActiveConnections: 0,
			CreatedAt:         now,
			Protocol:          models.ProtocolAWG,
		}
	} else {
		// Proxies skip Curve25519 key generation and start at connecting status
		ifName := fmt.Sprintf("%s-be-%d", proto, serverID)
		tunnel = &models.BackendTunnel{
			ServerID:          serverID,
			InterfaceName:     ifName,
			Endpoint:          endpoint,
			Enabled:           true,
			Status:            models.TunnelStatusConnecting,
			DisableReason:     models.DisableReasonNone,
			StateVersion:      1,
			LastHealthCheck:   nil,
			LatencyMS:         0,
			ActiveConnections: 0,
			CreatedAt:         now,
			Protocol:          proto,
			ProtocolParams:    bytes.Clone(opts.ProtocolParams),
		}
	}

	if p.db != nil {
		id, err := p.db.CreateBackendTunnel(ctx, tunnel)
		if err != nil {
			return nil, fmt.Errorf("failed to persist backend tunnel: %w", err)
		}
		tunnel.ID = id
		if ctx != nil && ctx.Value(DeployEnrollmentKey) != nil {
			if err = p.recordDeployQuarantine(ctx, id, serverID); err != nil {
				return nil, err
			}
		}
	} else {
		tunnel.ID = serverID
	}

	p.tunnelsByServerID[serverID] = tunnel
	p.tunnelsByID[tunnel.ID] = tunnel
	p.tunnelsByIfName[tunnel.InterfaceName] = tunnel

	copyTunnel := *tunnel
	return &copyTunnel, nil
}

// recordDeployQuarantine persists the durable enrollment marker for a backend that
// was just created by a deploy-context add, and compensates if that write fails.
//
// The row already exists at this point, so a silent marker failure would leave a
// backend present with no owner marking it unqualified. The compensating row
// delete keeps the two in step and the error is returned so the caller never sees
// a successful deploy add it could not quarantine.
func (p *Pool) recordDeployQuarantine(ctx context.Context, tunnelID, serverID int64) error {
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := p.db.SetBackendPendingEnrollment(writeCtx, serverID, true); err != nil {
		// Compensate. The cleanup gets its OWN context and its own error handling:
		// reusing the failed write's context would make the rollback fail for the
		// same reason the marker write did, and discarding that error would claim a
		// rollback that may not have happened.
		cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cleanupCancel()
		delErr := p.db.DeleteBackendTunnel(cleanupCtx, tunnelID)
		if delErr != nil {
			// The quarantine AND its compensation both failed, so the backend row
			// may still exist without a quarantine. Report BOTH errors: the caller
			// must not receive a plain "marker write failed" and assume the row is
			// gone, and the retry path needs to know the state is uncertain.
			return fmt.Errorf("failed to record pending enrollment for server %d (%w) and failed to roll back backend %d (%w): state is unquarantined and cleanup is unverified",
				serverID, err, tunnelID, delErr)
		}
		return fmt.Errorf("failed to record pending enrollment for server %d: %w (backend %d rolled back)", serverID, err, tunnelID)
	}
	return nil
}
