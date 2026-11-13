package vpn

import (
	"context"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

// Ownership handoff of the runtime caller mark across a sequential enrollment
// retry (issue #794 group B).
//
// A backend has three quarantine owners. The durable row marker and the pool's
// generation gate are re-bound to a new enrollment attempt by the pool itself, in
// the critical section that commits the re-enrollment. The prober's caller mark is
// server-keyed and is established BEFORE that attempt exists: the deploy consumer
// marks the server while the slot still holds the previous row, and the prober
// deliberately does not invent an attempt, so the mark keeps whichever attempt
// last wrote it.
//
// After a FAILED enrollment, the withdraw path stamps the mark with the failed
// attempt's id. A later successful retry commits a new attempt, releases the durable
// and pool owners and reports Ready, and then its own release is refused because
// nothing re-bound the caller mark to the attempt that now owns the row. The next
// ordinary healthy probe reads the retained mark and persists connecting, on every
// sweep, indefinitely: Ready while the backend is not eligible.
//
// This file is the producer side of that handoff. It lives apart from
// backend_enable.go to keep that file under the repository's file-size review
// ceiling.
//
// adoptCommittedEnrollmentAttempt hands a deploy enrollment's committed attempt to
// the runtime caller mark, so the attempt that actually qualified is the one that
// can release it.
//
// Placement is the substance. This runs in finishEnableBackend, under Service.mu,
// once the pool has committed the re-enrollment, the data plane is attached and the
// administrative enable succeeded, i.e. for a retry that actually got that far. A
// retry that fails its qualification never reaches here, so it inherits the previous
// protection instead of consuming it. The prober call takes only hp.mu and does no
// I/O, and no pool lock is held, so the documented hp.mu -> pool.mu order is
// untouched.
func (s *Service) adoptCommittedEnrollmentAttempt(ctx context.Context, live *models.BackendTunnel) {
	if s.prober == nil || live == nil || live.EnrollmentAttempt == 0 {
		return
	}
	if !isDeployEnablement(ctx) {
		return
	}
	s.prober.AdoptEnrollmentAttempt(live.ServerID, live.ID, live.EnrollmentAttempt)
}

// isDeployEnablement reports whether this enable is a deployment enrollment. It
// reads the same context key the pool uses to decide enrollment, so the service and
// the pool cannot disagree about which enables are enrollments.
func isDeployEnablement(ctx context.Context) bool {
	return ctx != nil && ctx.Value(tunnel.DeployEnrollmentKey) != nil
}
