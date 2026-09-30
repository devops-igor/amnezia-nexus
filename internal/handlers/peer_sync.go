package handlers

import (
	"context"
	"errors"
	"net/http"

	"github.com/devops-igor/amnezia-nexus/internal/database"
)

// peerChangeError renders a failed durable access change. A commit that
// succeeded but whose runtime enforcement did not is reported as
// runtime_sync_failed (HTTP 500), which is the caller-visible contract of
// #391: the caller is told the truth about whether VPN access actually
// changed.
func (h *Handlers) peerChangeError(w http.ResponseWriter, err error) {
	if errors.Is(err, database.ErrPeerRuntimeSync) {
		h.JSONError(w, http.StatusInternalServerError, "runtime_sync_failed",
			"Change was saved, but VPN access could not be confirmed; runtime reconciliation will retry")
		return
	}
	h.JSONError(w, http.StatusInternalServerError, "database_error", "Failed to save change")
}

// peerChangeConverged confirms the runtime enforcement of a durable access
// change the handler just committed, and answers the caller accordingly
// (issue #391 round 4b, finding 4).
//
// The post-commit notification is deliberately asynchronous, so the durable
// call itself cannot report the runtime outcome: it returns as soon as the
// change is committed and the enforcement is queued. This is where the missing
// half of that design is supplied. It is called AFTER the durable call
// returned and after every lock the handler held was released, which is what
// makes it safe: it performs no device I/O itself and holds no runtime lock,
// it only waits for the serialized worker that does. It is bounded by the
// request context and by the worker's own deadline, so a wedged portal device
// delays the response by a bounded amount instead of hanging it, and an
// unconfirmed enforcement is reported rather than passed off as success.
//
// It returns true when the handler may continue to its success response.
// When it returns false the response has already been written.
//
// Every call site already holds a request-derived context, so the confirmation
// takes that context directly rather than the request.
func (h *Handlers) peerChangeConvergedContext(w http.ResponseWriter, ctx context.Context) bool {
	if err := h.db.AwaitPeerRuntimeSync(ctx); err != nil {
		h.peerChangeError(w, err)
		return false
	}
	return true
}
