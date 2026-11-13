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
//
// The promotion is scoped to the generation the qualification actually OBSERVED,
// not to the server slot: an observation that returns after the operator deleted
// or re-enrolled that backend must not admit whatever owns the slot now. The
// pool decides that under its own lock, at the same commit that writes the
// status, so there is no check-to-commit window and no retry that could adopt a
// replacement. A retired observation yields ErrTunnelGenerationRetired and
// changes nothing.
func (s *Service) PromoteQualifiedTunnel(ctx context.Context, observed *models.BackendTunnel, latencyMS int64) error {
	if s == nil || s.pool == nil {
		return errors.New("vpn service or pool not initialized")
	}
	if observed == nil {
		return tunnel.ErrTunnelGenerationRetired
	}
	targetStatus := s.targetStatusForLatency(latencyMS)
	if err := s.pool.PromoteObservedTunnelWithEnrollmentRelease(ctx, observed, targetStatus, latencyMS); err != nil {
		return err
	}
	// The pool released its generation quarantine inside the commit above and
	// PromoteObservedTunnelWithEnrollmentRelease released the durable marker in
	// the same transaction (finding F10). Only this generation's caller mark
	// remains, and it is released by IDENTITY so a replacement that acquired the
	// server slot in the meantime keeps its own quarantine.
	if s.prober != nil {
		s.prober.ReleaseEnrollmentForGeneration(observed.ServerID, observed.ID)
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

// WithdrawObservedEnrollment withdraws the backend generation a qualification
// observed when that qualification FAILED or was refused, and treats a retired
// observation as inert.
//
// Identity, mark and disable are decided in ONE Service.mu critical section —
// the same write lock EnableBackendWithConfig, DeleteBackend and the credential
// rotation take while they replace the slot's identity and administrative state.
// That matters twice: the generation validated is the generation withdrawn, and
// an obsolete timeout can neither disable nor quarantine a replacement the
// operator has since created. The withdrawal itself is the pre-existing
// semantics (durable and runtime quarantine kept, backend administratively
// disabled, forwarder device detached), reached through the same locked helper
// DisableBackend uses, so no new lock scope or new lock ordering is introduced.
func (s *Service) WithdrawObservedEnrollment(ctx context.Context, observed *models.BackendTunnel) error {
	if s == nil || s.pool == nil {
		return errors.New("vpn service or pool not initialized")
	}
	if observed == nil {
		return tunnel.ErrTunnelGenerationRetired
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	return s.withdrawObservedBackendLocked(ctx, observed)
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
