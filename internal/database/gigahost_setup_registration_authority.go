package database

// Registration authority: a panel server row must not come into existence for an order the
// panel has already recorded as gone.
//
// The install journal is fenced, and that fence closes the phases it authorizes. Registration
// is authorized by a journal write too, but the row itself is created later, after intervening
// network work - the provider's per-server account read - and the journal write that opened
// the phase is not re-examined at the insert. A complete own-account inventory omission that
// commits inside that window therefore retired the order while its registration was already
// authorized, and a server row appeared for a deployment the panel presents as DELETED.
//
// The fence therefore belongs at the write that creates the row, inside the same transaction
// as the insert, reading the ledger through that transaction. It is the mechanism the backend
// promotion path already uses for a revoked approval (setup_admission_authority.go): decide
// the durable fact in the transaction that commits the effect, so there is no
// check-to-commit window and no second signal a caller has to remember to consult.
//
// Both registration paths share that writer - the immediate setup in gigahost_deploy.go and
// the saved installer in gigahost_setup_install_plan.go - so neither can drift from the other.

import (
	"context"
	"fmt"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// ErrOrderEndedBeforeRegistration reports that the panel recorded this order as over before
// its server row could be created. It is a refusal, not a failure: registration is the first
// persistent effect of a deployment, and a deployment the panel has recorded as gone must not
// produce one.
var ErrOrderEndedBeforeRegistration = fmt.Errorf("%w: registration refused because the order ended", ErrOrderEnded)

// CreateDeployedServer inserts a deployment's server row and its host-identity pin in one
// transaction, and refuses when the panel's own records say orderID has ended.
//
// It is CreateServerWithFingerprint plus the order question, and it shares that method's
// insert so the two cannot disagree about what registration means. The retirement question is
// asked inside the transaction, so a retirement committed at any point before the commit is
// visible to it, and a refusal commits nothing: no server row and no pin.
//
// A read failure is returned rather than treated as consent. The caller is about to make a
// deployment visible in the panel, and "could not ask whether this order still exists" must
// not authorize that.
func (d *DB) CreateDeployedServer(
	ctx context.Context, s *models.Server, fingerprint, orderID string,
) (int64, error) {
	return d.createServerRow(ctx, s, fingerprint, orderID)
}
