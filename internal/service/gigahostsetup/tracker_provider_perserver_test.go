package gigahostsetup

// The tracker fixture's per-server answer, kept out of tracker_test.go because that
// file already sits above the repository's size ceiling.

import (
	"context"
	"fmt"

	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// GetServer answers for one server. The tracker fixture defines no per-server
// answer, so an unexpected call refuses rather than inventing ownership.
func (p *fakeProvider) GetDashboard(_ context.Context) (*gigahost.Dashboard, error) {
	return &gigahost.Dashboard{ServicesPresent: false}, nil
}

func (p *fakeProvider) GetServer(_ context.Context, serverID int64) (*gigahost.ServerInfo, error) {
	return nil, fmt.Errorf("tracker fixture defines no per-server answer for server %d", serverID)
}
