package handlers

import (
	"net/http"

	"github.com/devops-igor/amnezia-nexus/internal/config"
)

// HealthResponse defines the standard payload returned by /api/health.
type HealthResponse struct {
	Status           string `json:"status"`
	Version          string `json:"version"`
	ActiveEngine     string `json:"active_engine,omitempty"`
	ReturnRouteOwner string `json:"return_route_owner,omitempty"`
}

// HealthHandler returns application health status and version.
func (h *Handlers) HealthHandler(w http.ResponseWriter, r *http.Request) {
	version := config.AppVersion
	if h.cfg != nil && h.cfg.AppVersion != "" {
		version = h.cfg.AppVersion
	}

	activeEngine := config.ClientAWGEngineCustom
	if h.vpnSvc != nil {
		activeEngine = h.vpnSvc.ClientAWGEngine()
	} else if h.cfg != nil && h.cfg.ClientAWGEngine != "" {
		activeEngine = h.cfg.ClientAWGEngine
	}

	h.JSON(w, http.StatusOK, HealthResponse{
		Status:           "ok",
		Version:          version,
		ActiveEngine:     activeEngine,
		ReturnRouteOwner: activeEngine,
	})
}

// VersionHandler returns current application semantic version and codename.
func (h *Handlers) VersionHandler(w http.ResponseWriter, r *http.Request) {
	version := config.AppVersion
	if h.cfg != nil && h.cfg.AppVersion != "" {
		version = h.cfg.AppVersion
	}
	codename := config.AppCodename
	if h.cfg != nil && h.cfg.AppCodename != "" {
		codename = h.cfg.AppCodename
	}

	h.JSON(w, http.StatusOK, map[string]string{
		"version":  version,
		"codename": codename,
	})
}
