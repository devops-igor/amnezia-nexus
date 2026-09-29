package handlers

import (
	"errors"
	"net/http"

	"github.com/devops-igor/amnezia-nexus/internal/database"
)

func (h *Handlers) peerChangeError(w http.ResponseWriter, err error) {
	if errors.Is(err, database.ErrPeerRuntimeSync) {
		h.JSONError(w, http.StatusInternalServerError, "runtime_sync_failed",
			"Change was saved, but VPN access could not be confirmed; runtime reconciliation will retry")
		return
	}
	h.JSONError(w, http.StatusInternalServerError, "database_error", "Failed to save change")
}
