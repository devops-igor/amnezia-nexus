package handlers

import (
	"net/http"
)

// GetUpstreamStatusHandler returns the cached or freshly queried upstream status.
// Accepts query parameter ?refresh=true or ?force=true to force an immediate refresh.
func (h *Handlers) GetUpstreamStatusHandler(w http.ResponseWriter, r *http.Request) {
	forceRefresh := r.URL.Query().Get("refresh") == "true" || r.URL.Query().Get("force") == "true"

	if h.upstreamSvc == nil {
		h.JSONError(w, http.StatusServiceUnavailable, "upstream_service_unavailable", "Upstream service not initialized")
		return
	}

	status, err := h.upstreamSvc.Check(r.Context(), forceRefresh)
	if err != nil {
		h.JSONError(w, http.StatusServiceUnavailable, "upstream_check_failed", err.Error())
		return
	}

	h.JSON(w, http.StatusOK, status)
}
