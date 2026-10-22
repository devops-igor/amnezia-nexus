package vpn

import (
	"context"
	"errors"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

// SetProbeFunc sets the health probe function for testing or customized reachability probing.
func (s *Service) SetProbeFunc(fn tunnel.ProbeFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.prober != nil {
		s.prober.SetProbeFunc(fn)
	}
}

// SetBackendDeviceForTest sets a backend device for testing.
func (s *Service) SetBackendDeviceForTest(tunID int64, dev BackendDevice) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.backendDevices == nil {
		s.backendDevices = make(map[int64]BackendDevice)
	}
	s.backendDevices[tunID] = dev
}

// SetBackendDeviceEndpointForTest sets the recorded endpoint for a backend device for testing.
func (s *Service) SetBackendDeviceEndpointForTest(tunID int64, endpoint string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.backendDeviceEndpoints == nil {
		s.backendDeviceEndpoints = make(map[int64]string)
	}
	s.backendDeviceEndpoints[tunID] = endpoint
}

// GetBackendDeviceForTest returns the backend device for a tunnel ID.
func (s *Service) GetBackendDeviceForTest(tunID int64) BackendDevice {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.backendDevices == nil {
		return nil
	}
	return s.backendDevices[tunID]
}

// GetBackendDeviceEndpointForTest returns the recorded endpoint for a backend device for testing.
func (s *Service) GetBackendDeviceEndpointForTest(tunID int64) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.backendDeviceEndpoints == nil {
		return ""
	}
	return s.backendDeviceEndpoints[tunID]
}

// ProbeTunnel probes a tunnel using the service's health prober.
func (s *Service) ProbeTunnel(ctx context.Context, t *models.BackendTunnel) (int64, error) {
	if s.prober == nil {
		return 0, errors.New("health prober not initialized")
	}
	return s.prober.ProbeTunnel(ctx, t)
}

// SelfHealSweep sweeps auto-disabled backend tunnels and attempts to recover them.
func (s *Service) SelfHealSweep(ctx context.Context) int {
	s.mu.RLock()
	prober := s.prober
	s.mu.RUnlock()

	if prober == nil {
		return 0
	}
	return prober.SelfHealSweep(ctx)
}

// SetHealthProber sets a custom health prober instance.
func (s *Service) SetHealthProber(prober *tunnel.HealthProber) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prober = prober
	if s.prober != nil {
		s.prober.SetOnActiveHook(func(ctx context.Context, t *models.BackendTunnel) error {
			return s.ensureBackendDeviceAttached(ctx, t)
		})
		s.prober.SetOnSelfHealHook(func(ctx context.Context, t *models.BackendTunnel) error {
			return s.EnableBackend(tunnel.ContextWithSelfHealing(ctx), t.ServerID)
		})
	}
}

// SetEnsureDevicePreLockHook sets a hook called immediately before acquiring s.mu in ensureBackendDeviceAttached.
func (s *Service) SetEnsureDevicePreLockHook(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureDevicePreLockHook = fn
}

// SetUpdateBackendServerHostPreLockHook sets a hook called immediately before acquiring s.mu in UpdateBackendServerHost.
func (s *Service) SetUpdateBackendServerHostPreLockHook(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.updateBackendServerHostPreLockHook = fn
}

// SetUpdateServerHostPreLockHook is an alias for SetUpdateBackendServerHostPreLockHook.
func (s *Service) SetUpdateServerHostPreLockHook(fn func()) {
	s.SetUpdateBackendServerHostPreLockHook(fn)
}

// SetUpdateBackendServerHostErrorForTest sets an error to be returned by UpdateBackendServerHost for testing.
func (s *Service) SetUpdateBackendServerHostErrorForTest(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.updateBackendServerHostErr = err
}

// SetDeleteBackendErrorForTest sets an error to be returned by DeleteBackend for testing.
func (s *Service) SetDeleteBackendErrorForTest(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleteBackendErr = err
}

// SetEnableBackendPreAddTunnelHookForTest sets a hook called immediately before calling pool.AddTunnel in EnableBackend.
func (s *Service) SetEnableBackendPreAddTunnelHookForTest(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enableBackendPreAddTunnelHook = fn
}

// SetEnableBackendPostAddTunnelHookForTest sets a hook called immediately after calling pool.AddTunnel in EnableBackend.
func (s *Service) SetEnableBackendPostAddTunnelHookForTest(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enableBackendPostAddTunnelHook = fn
}

// SetSyncBackendForwarderHookForTest sets a test hook called inside syncBackendForwarderOnHostUpdateLocked.
func (s *Service) SetSyncBackendForwarderHookForTest(fn func() error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.syncBackendForwarderHook = fn
}

// SetTunnelEndpointHookForTest sets a test hook for SetTunnelEndpoint on the pool.
func (s *Service) SetTunnelEndpointHookForTest(fn func(ctx context.Context, tunnelID int64, endpoint string) error) {
	if s == nil || s.pool == nil {
		return
	}
	s.pool.SetSetTunnelEndpointHookForTest(fn)
}
