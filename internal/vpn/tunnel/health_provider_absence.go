package tunnel

// The provider-absence boundary for backend probes.
//
// A tunnel row is deliberately retained when its server disappears from the
// provider's inventory: the panel keeps the record rather than deleting it. What
// must stop is the network work, and that is decided here - at the dispatch every
// probe passes through - instead of at each caller. The ordinary sweep, the
// self-healing sweep and the reconnect manager all reach probeEndpoint, so a
// caller cannot probe without passing this check, including one written later.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// ErrProviderAbsent reports that a probe was refused because the provider's own
// inventory no longer lists the tunnel's server.
//
// It is a refusal, not a measurement: no packet was sent, so nothing about the
// backend's health was learned. Callers must not record a failure, write a status
// or migrate sessions on it - the prior observation stands.
var ErrProviderAbsent = errors.New("probe refused: the provider's inventory no longer lists this server")

// providerAbsent reports whether the provider's own inventory has confirmed that
// the tunnel's server no longer exists.
//
// It is asked at the probe boundary for every tunnel, so a retained tunnel of a
// removed server stops being dialed without the tunnel being disabled or deleted.
// A database read failure is reported as "not confirmed" and logged: a store
// hiccup must not stop health checking, and the fail-safe direction here is to
// keep the behavior the panel had before this observation existed.
func (hp *HealthProber) providerAbsent(ctx context.Context, serverID int64) bool {
	if hp.db == nil || serverID <= 0 {
		return false
	}
	readCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	absent, err := hp.db.IsServerProviderAbsent(readCtx, serverID)
	if err != nil {
		slog.Debug("provider absence not confirmed; probing as before", "server_id", serverID, "err", err)
		return false
	}
	return absent
}

// probeEndpoint dispatches the probe according to the backend tunnel's protocol.
//
// It is the boundary every network probe of a backend tunnel passes through -
// the ordinary sweep, the self-healing sweep and any future caller - so the
// provider-absence refusal lives here rather than in each caller. When the
// server's row carries the absence observation, no handshake or proxy probe is
// attempted and ErrProviderAbsent is returned; the callers treat that as "not
// measured" rather than as a failed sample.
func (hp *HealthProber) probeEndpoint(ctx context.Context, tunnel *models.BackendTunnel) (int64, error) {
	if tunnel == nil {
		return 0, errors.New("tunnel is nil")
	}
	if hp.providerAbsent(ctx, tunnel.ServerID) {
		slog.Debug("probe refused for a server absent from the provider inventory",
			"server_id", tunnel.ServerID, "tunnel_id", tunnel.ID)
		return 0, ErrProviderAbsent
	}

	proto := models.NormalizeTunnelProtocol(tunnel.Protocol)
	switch proto {
	case models.ProtocolAWG:
		return hp.probeAWG(ctx, tunnel)
	case models.ProtocolVLESS:
		return hp.probeVLESS(ctx, tunnel)
	case models.ProtocolNaive:
		return hp.probeNaive(ctx, tunnel)
	default:
		return 0, fmt.Errorf("unsupported protocol: %s", tunnel.Protocol)
	}
}
