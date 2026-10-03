package handlers

import "net/http"

// VPNMetricsHandler serves a bounded Prometheus snapshot under the existing
// admin/support session authentication. Scrapers use a signed session Cookie;
// this endpoint does not introduce bearer tokens or public telemetry.
func (h *Handlers) VPNMetricsHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	// The response has begun; a transport failure cannot be replaced by an
	// HTTP error body. The bounded exporter does not retain or retry the writer.
	_ = h.vpnSvc.WriteMetrics(w)
}
