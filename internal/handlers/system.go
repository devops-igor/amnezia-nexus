package handlers

import (
	"net/http"

	"github.com/devops-igor/amnezia-nexus/internal/config"
)

// HealthResponse defines the standard payload returned by /api/health.
type HealthResponse struct {
	Status           string `json:"status"`
	Version          string `json:"version"`
	ConfiguredEngine string `json:"configured_engine,omitempty"`
	ActiveEngine     string `json:"active_engine,omitempty"`
	EngineRunning    bool   `json:"engine_running"`
	ReturnRouteOwner string `json:"return_route_owner,omitempty"`
}

// HealthHandler returns application health status and version.
func (h *Handlers) HealthHandler(w http.ResponseWriter, r *http.Request) {
	version := config.AppVersion
	if h.cfg != nil && h.cfg.AppVersion != "" {
		version = h.cfg.AppVersion
	}

	configuredEngine := "upstream"
	activeEngine := "none"
	engineRunning := false
	returnRouteOwner := "none"

	if h.vpnSvc != nil {
		stat, err := h.vpnSvc.GetStatus(r.Context())
		if err == nil && stat != nil {
			configuredEngine = stat.ConfiguredEngine
			activeEngine = stat.ActiveEngine
			engineRunning = stat.EngineRunning
			returnRouteOwner = stat.ReturnRouteOwner
		} else {
			engineRunning = h.vpnSvc.IsRunning()
			if engineRunning {
				activeEngine = "upstream"
				returnRouteOwner = h.vpnSvc.ReturnRouteOwner()
			}
		}
	}

	h.JSON(w, http.StatusOK, HealthResponse{
		Status:           "ok",
		Version:          version,
		ConfiguredEngine: configuredEngine,
		ActiveEngine:     activeEngine,
		EngineRunning:    engineRunning,
		ReturnRouteOwner: returnRouteOwner,
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
