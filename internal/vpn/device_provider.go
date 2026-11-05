package vpn

import (
	"context"
	"errors"

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
func (s *Service) SubnetCIDR() string {
	return s.getPortalSubnet()
}

// ProbeCanary probes the data plane of a backend tunnel using the service's health prober.
func (s *Service) ProbeCanary(ctx context.Context, t *models.BackendTunnel) error {
	if s.prober == nil {
		return errors.New("health prober not initialized")
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
