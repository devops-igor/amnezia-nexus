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
