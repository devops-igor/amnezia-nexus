package vpn

import (
	"context"
	"io"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

// preparePresentNaiveCandidate is the network-preparation entry for enablement,
// before the service acquires its commit lock. Other locked attachment paths
// consume already-prepared candidates and must not gain database I/O here.
func (s *Service) preparePresentNaiveCandidate(ctx context.Context, tun *models.BackendTunnel, prepared ...map[string]any) (BackendDevice, io.Closer, error) {
	if err := s.refuseAbsentReadiness(ctx, tun.ServerID); err != nil {
		return nil, nil, err
	}
	return s.prepareNaiveCandidateDevice(ctx, tun, prepared...)
}

// refuseAbsentReadiness makes no lifecycle change on refusal.
func (s *Service) refuseAbsentReadiness(ctx context.Context, serverID int64) error {
	if s.db == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	absent, err := s.db.IsServerProviderAbsent(ctx, serverID)
	if err != nil {
		return err
	}
	if absent {
		return tunnel.ErrProviderAbsent
	}
	return nil
}
