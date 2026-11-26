package handlers

import (
	"net/http"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// serverNotMeasured deliberately omits every sample field. In particular false
// docker_installed or connection=failed would turn a refusal into a measurement.
func (h *Handlers) serverNotMeasured(w http.ResponseWriter) {
	h.JSON(w, http.StatusOK, map[string]any{
		"status":          models.ProviderAbsentStatus,
		"not_measured":    true,
		"provider_absent": true,
	})
}
