package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/xray/scanner"
)

// ScanRealitySNIRequest defines optional parameters for scanning camouflage domains.
type ScanRealitySNIRequest struct {
	Domains     []string `json:"domains,omitempty"`
	Concurrency int      `json:"concurrency,omitempty"`
	TimeoutSec  int      `json:"timeout_sec,omitempty"`
}

// ScanRealitySNIHandler executes offline ASN/geo proximity filtering and TLS 1.3 / H2 probing
// for candidate REALITY camouflage domains against the target server host.
// Probes are tunneled over SSH direct-tcpip when available (scope ssh_tunneled_proximity);
// otherwise they run panel-side and the report carries fallback_to_panel and a warning.
func (h *Handlers) ScanRealitySNIHandler(w http.ResponseWriter, r *http.Request) {
	serverID, err := parseServerID(r)
	if err != nil {
		h.JSONError(w, http.StatusBadRequest, "invalid_parameter", "Invalid server_id")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	server, err := h.db.GetServer(ctx, serverID)
	if err != nil || server == nil {
		h.JSONError(w, http.StatusNotFound, "not_found", "Server not found")
		return
	}

	var req ScanRealitySNIRequest
	if r.Body != nil && r.ContentLength > 0 {
		_ = h.DecodeJSON(r, &req)
	}

	timeout := 5 * time.Second
	if req.TimeoutSec > 0 && req.TimeoutSec <= 30 {
		timeout = time.Duration(req.TimeoutSec) * time.Second
	}

	concurrency := 5
	if req.Concurrency > 0 && req.Concurrency <= 20 {
		concurrency = req.Concurrency
	}

	opts := scanner.ScannerOptions{
		Concurrency: concurrency,
		Timeout:     timeout,
		Domains:     req.Domains,
	}
	if sshClient, err := h.GetSSHClient(ctx, server); err == nil && sshClient != nil {
		if underlying := sshClient.GetUnderlyingClient(); underlying != nil {
			opts.DialContext = underlying.DialContext
		}
	}
	fellBack := opts.DialContext == nil

	report, err := scanner.ScanSNI(ctx, server.Host, opts)
	if err != nil {
		h.JSONError(w, http.StatusInternalServerError, "scan_failed", err.Error())
		return
	}
	if fellBack {
		report.FallbackToPanel = true
		report.Warning = "SSH tunnel unavailable; probe conducted from panel host"
	}

	h.audit(r, "server.reality_scan_sni", map[string]any{
		"server_id":   serverID,
		"server_host": server.Host,
		"results":     len(report.Results),
	})

	h.JSON(w, http.StatusOK, report)
}
