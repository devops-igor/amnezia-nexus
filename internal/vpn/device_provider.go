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

// SubnetCIDR returns the configured portal subnet CIDR or defaults to "10.100.0.0/16".
func (s *Service) SubnetCIDR() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.cfg != nil && s.cfg.SubnetCIDR != "" {
		return s.cfg.SubnetCIDR
	}
	return "10.100.0.0/16"
}

// ProbeCanary probes the data plane of a backend tunnel using the service's health prober.
func (s *Service) ProbeCanary(ctx context.Context, t *models.BackendTunnel) error {
	if s == nil || s.prober == nil {
		return errors.New("health prober not initialized")
	}
	if cidr := s.SubnetCIDR(); cidr != "" {
		s.prober.SetSubnetCIDR(cidr)
	}
	s.mu.RLock()
	var dev tunnel.PacketDevice
	if s.backendDevices != nil && t != nil {
		dev = s.backendDevices[t.ID]
		if dev == nil && t.ServerID > 0 {
			dev = s.backendDevices[t.ServerID]
		}
	}
	s.mu.RUnlock()
	return s.prober.ProbeCanaryWithDevice(ctx, t, dev)
}

// PromoteQualifiedTunnel promotes a connecting backend tunnel to active (or degraded if latency is high)
// after both outer handshake and inner canary probe have succeeded.
func (s *Service) PromoteQualifiedTunnel(ctx context.Context, serverID int64, latencyMS int64) error {
	if s == nil || s.pool == nil {
		return errors.New("vpn service or pool not initialized")
	}
	if s.prober != nil {
		defer s.prober.SetPendingEnrollment(serverID, false)
	}
	targetStatus := s.targetStatusForLatency(latencyMS)
	return s.commitPromoteWithRetry(ctx, serverID, targetStatus, latencyMS)
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
		err = s.pool.SetTunnelStatusIfCurrentWithVersion(ctx, serverID, tun.ID, tun.StateVersion, targetStatus, latencyMS)
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
