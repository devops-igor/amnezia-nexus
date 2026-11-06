package vpn

import (
	"context"
	"errors"
	"fmt"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

// Ensure Service implements tunnel.DeviceProvider at compile time.
var _ tunnel.DeviceProvider = (*Service)(nil)

// GetDevice implements tunnel.DeviceProvider for HealthProber to access live backend packet devices.
func (s *Service) GetDevice(id int64) (tunnel.PacketDevice, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.backendDevices == nil {
		return nil, false
	}
	if dev, ok := s.backendDevices[id]; ok && dev != nil {
		return dev, true
	}
	// Fallback if id is a serverID instead of tunnelID
	if s.pool != nil {
		if tun, err := s.pool.GetTunnel(id); err == nil && tun != nil {
			if dev, ok := s.backendDevices[tun.ID]; ok && dev != nil {
				return dev, true
			}
		}
	}
	return nil, false
}

// SubnetCIDR implements the subnet provider interface for HealthProber so canary probes
// are generated with source IPs authorized by the remote peer's AllowedIPs.
// It resolves through getPortalSubnet so there is a single source of truth for the
// configured portal CIDR; the value and the 10.100.0.0/16 fallback are unchanged.
func (s *Service) SubnetCIDR() string {
	return s.getPortalSubnet()
}

// ProbeCanary probes the data plane of a backend tunnel using the service's health prober.
func (s *Service) ProbeCanary(ctx context.Context, t *models.BackendTunnel) error {
	if s == nil || s.prober == nil {
		return errors.New("health prober not initialized")
	}
	// Keep the prober's canary source subnet in step with the portal configuration
	// before probing (the subnet can change at runtime). SetSubnetCIDR takes the
	// prober lock only, and no service lock is held across this call.
	if cidr := s.SubnetCIDR(); cidr != "" {
		s.prober.SetSubnetCIDR(cidr)
	}
	if err := s.ensureBackendDeviceAttached(ctx, t); err != nil {
		return fmt.Errorf("failed to ensure backend device attached: %w", err)
	}
	return s.prober.ProbeCanary(ctx, t)
}

// HasCanaryProber reports whether a canary prober or active device is available for the tunnel.
func (s *Service) HasCanaryProber(t *models.BackendTunnel) bool {
	if s == nil || s.prober == nil {
		return false
	}
	return s.prober.HasCanaryProber(t)
}

// SetCanarySuccessCallback registers a callback invoked whenever HealthProber verifies inner canary success.
func (s *Service) SetCanarySuccessCallback(cb func(tunnelID int64)) {
	if s == nil || s.prober == nil {
		return
	}
	s.prober.SetCanarySuccessCallback(cb)
}

// CanaryFailureCount exposes the shared, generation-fenced inner history to
// scheduled health checks. Legacy success notifications do not own this state.
func (s *Service) CanaryFailureCount(tunnelID int64) int {
	if s == nil || s.prober == nil {
		return 0
	}
	return s.prober.CanaryFailureCount(tunnelID)
}

// PromoteQualifiedTunnel promotes a connecting backend tunnel to active (or degraded if latency is high)
// after both outer handshake and inner canary probe have succeeded.
func (s *Service) PromoteQualifiedTunnel(ctx context.Context, serverID int64, latencyMS int64) error {
	if s == nil || s.pool == nil {
		return errors.New("vpn service or pool not initialized")
	}
	targetStatus := s.targetStatusForLatency(latencyMS)
	if err := s.commitPromoteWithRetry(ctx, serverID, targetStatus, latencyMS); err != nil {
		return err
	}
	// commitPromoteWithRetry releases the durable marker atomically with the
	// status commit (finding F10). Only the in-memory prober map still needs
	// clearing, and only after the durable release actually succeeded.
	if s.prober != nil {
		s.prober.SetPendingEnrollment(serverID, false)
	}
	return nil
}

func (s *Service) targetStatusForLatency(latencyMS int64) string {
	thresh := int64(500)
	if s.prober != nil {
		thresh = s.prober.LatencyThresholdMS()
	}
	if latencyMS > thresh {
		return models.TunnelStatusDegraded
	}
	return models.TunnelStatusActive
}

func (s *Service) commitPromoteWithRetry(ctx context.Context, serverID int64, targetStatus string, latencyMS int64) error {
	for attempts := 0; attempts < 3; attempts++ {
		tun, err := s.pool.GetTunnel(serverID)
		if err != nil || tun == nil {
			return fmt.Errorf("backend tunnel not found for server %d", serverID)
		}
		if !tun.Enabled {
			return errors.New("cannot promote disabled tunnel")
		}
		// Finding F10: the qualification verdict and the durable enrollment
		// release commit in one transaction, so no crash can leave a qualified
		// backend still marked unqualified.
		err = s.pool.PromoteTunnelWithEnrollmentRelease(ctx, serverID, tun.ID, tun.StateVersion, targetStatus, latencyMS)
		if err == nil {
			return nil
		}
		if !errors.Is(err, tunnel.ErrStaleStateVersion) {
			return err
		}
	}
	return tunnel.ErrStaleStateVersion
}

// SetPendingEnrollment sets whether a backend server is undergoing initial enrollment qualification.
func (s *Service) SetPendingEnrollment(serverID int64, pending bool) {
	if s == nil || s.prober == nil {
		return
	}
	s.prober.SetPendingEnrollment(serverID, pending)
}

// QualifyProxyTraffic performs the protocol-appropriate authenticated
// application request/reply that must succeed before a proxy backend is admitted.
// Finding F10: this is the terminal qualification VLESS/Naive enrollment lacked.
func (s *Service) QualifyProxyTraffic(ctx context.Context, t *models.BackendTunnel) (int64, error) {
	if s == nil || s.prober == nil {
		return 0, errors.New("health prober not initialized")
	}
	return s.prober.QualifyProxyTraffic(ctx, t)
}

// SetCanaryProbeFunc configures a custom canary probe function on the health prober for testing.
func (s *Service) SetCanaryProbeFunc(fn tunnel.CanaryProbeFunc) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.prober != nil {
		s.prober.SetCanaryProbeFunc(fn)
	}
}
