package vpn

import (
	"context"
	"errors"
	"fmt"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

// commitSessionMigration nests session -> pool -> database ownership. Publication
// never re-enters those owners, and gauge persistence runs after their release.
func (s *Service) commitSessionMigration(ctx context.Context, observed models.VPNSession, targetID, expectedVersion int64) error {
	var persist func()
	err := s.sessionMgr.CommitBackendMigration(observed, targetID, func(publishSession func()) error {
		commit := func(publishCounters func()) error {
			publish := func() error {
				if err := s.publishMigrationRoute(observed, targetID); err != nil {
					return err
				}
				publishSession()
				publishCounters()
				if s.stickyMgr != nil {
					s.stickyMgr.AssignPeerAffinity(observed.PeerPublicKey, targetID)
				}
				return nil
			}
			if s.db == nil {
				return publish()
			}
			return s.db.CommitVPNSessionMigration(ctx, observed.ID, observed.BackendTunnelID, targetID, publish)
		}
		if s.pool == nil {
			return commit(func() {})
		}
		var err error
		persist, err = s.pool.CommitConnectionTransfer(observed.BackendTunnelID, targetID, expectedVersion, commit)
		return err
	})
	if err != nil {
		return fmt.Errorf("commit session %s backend migration: %w", observed.ID, err)
	}
	if persist != nil {
		persist()
	}
	return nil
}

func (s *Service) publishMigrationRoute(observed models.VPNSession, targetID int64) error {
	if s.forwarder == nil {
		return nil
	}
	err := s.forwarder.UpdateSessionBackend(observed.PeerPublicKey, targetID)
	if errors.Is(err, forwarder.ErrSessionNotRegistered) {
		return nil
	}
	return err
}
