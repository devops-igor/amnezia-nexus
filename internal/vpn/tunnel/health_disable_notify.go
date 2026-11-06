package tunnel

import (
	"context"
	"log/slog"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// A health auto-disable only changes backend status; moving the client
// sessions that are still pinned to that backend is the data plane owner's
// responsibility, because it alone owns the sticky affinity map, the live
// forwarder routes, the durable vpn_sessions rows and the pool connection
// counters.
//
// HealthDisabledNotifier is that optional capability. The prober discovers it
// on the same provider value it already receives through SetDeviceProvider, so
// the composition root needs no extra construction step.
type HealthDisabledNotifier interface {
	BackendHealthDisabled(ctx context.Context, tunnel *models.BackendTunnel) error
}

// SetHealthDisabledNotifier registers that callback. It is invoked exactly at
// the terminal health-disable commit points, never under hp.mu or pool.mu, and
// only for a tunnel that is still ENABLED, still disabled and still disabled
// for health reasons - so a concurrent administrative disable, a re-enable or
// a self-healing recovery suppresses it. Administrative disable and delete
// keep their own existing failover path (Service.disableBackendLocked) and
// never route through here.
//
// Nil-receiver safe, matching SetCanaryProbeFunc's guard style.
func (hp *HealthProber) SetHealthDisabledNotifier(fn func(ctx context.Context, tunnel *models.BackendTunnel) error) {
	if hp == nil {
		return
	}
	hp.mu.Lock()
	defer hp.mu.Unlock()
	hp.healthDisabledNotifier = fn
}

// NotifyHealthDisabledForTest exposes notifyHealthDisabled so the suppression
// rules can be driven directly, without a full probe cycle. Test-only seam in
// the same style as the package's other *ForTest accessors.
func (hp *HealthProber) NotifyHealthDisabledForTest(ctx context.Context, serverID, tunnelID int64) {
	hp.notifyHealthDisabled(ctx, serverID, tunnelID)
}

// applyProviderCapabilities lets a data plane owner contribute the optional
// capabilities it implements on the value the prober already receives through
// SetDeviceProvider: its portal subnet and its health-disable failover target.
// Discovering them here keeps the composition root free of extra wiring, and
// interfaces are only consulted, never required.
func (hp *HealthProber) applyProviderCapabilities(provider any) {
	if subnet, ok := provider.(interface{ SubnetCIDR() string }); ok {
		if c := subnet.SubnetCIDR(); c != "" {
			hp.SetSubnetCIDR(c)
		}
	}
	if notifier, ok := provider.(HealthDisabledNotifier); ok {
		hp.SetHealthDisabledNotifier(notifier.BackendHealthDisabled)
	}
}

// healthDisableNotifyTarget reports whether a live tunnel is the backend the
// notification was committed for, in the exact terminal state it describes:
// administratively enabled, runtime-disabled, and disabled for health reasons.
// Anything else — a concurrent administrative disable, a re-enable, a
// self-healing recovery or a newer status — means another writer already
// re-decided this backend, and that writer owns the ordering and the intent.
func healthDisableNotifyTarget(cur *models.BackendTunnel, serverID int64) bool {
	if cur == nil || cur.ServerID != serverID || !cur.Enabled {
		return false
	}
	return cur.Status == models.TunnelStatusDisabled &&
		cur.DisableReason == models.DisableReasonHealth
}

// notifyHealthDisabled reports a committed health auto-disable to the data
// plane owner so established sessions can be migrated off the backend.
//
// The notification performs external I/O (DB, forwarder), so it runs after the
// status write and outside every prober/pool lock. Failures are logged, never
// propagated: the health state is already committed and a probe must not
// report a data-plane error for it.
func (hp *HealthProber) notifyHealthDisabled(ctx context.Context, serverID, tunnelID int64) {
	if hp == nil || hp.pool == nil || tunnelID == 0 || ctx.Err() != nil {
		return
	}
	hp.mu.RLock()
	notifier := hp.healthDisabledNotifier
	hp.mu.RUnlock()
	if notifier == nil {
		return
	}
	cur, err := hp.pool.GetTunnelByID(tunnelID)
	if err != nil || !healthDisableNotifyTarget(cur, serverID) {
		return
	}
	if nErr := notifier(ctx, cur); nErr != nil {
		slog.Warn("health-disabled backend session failover failed",
			"server_id", serverID, "tunnel_id", tunnelID, "err", nErr)
	}
}
