package handlers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

var clearServerContainers = []string{
	"amnezia-awg",
	"amnezia-awg2",
	"amnezia-awg-legacy",
	"telemt",
	"amnezia-dns",
	"amnezia-xray",
	"amnezia-caddy",
}

// teardownServerContainers stops and removes all known protocol containers on the remote host.
// If remote stop or remove fails for any container, it returns an error immediately so the caller
// can abort before wiping configuration directories or database records.
func (h *Handlers) teardownServerContainers(ctx context.Context, client ssh.SSHClient) error {
	for _, c := range clearServerContainers {
		inspectCmd := fmt.Sprintf("docker inspect %s", ssh.EscapeShellArg(c))
		out, errOut, code, err := client.RunSudoCommand(ctx, inspectCmd)
		if err != nil {
			return fmt.Errorf("failed to inspect container %s: %w", c, err)
		}
		if code != 0 {
			combined := strings.ToLower(out + " " + errOut)
			if strings.Contains(combined, "no such") {
				continue
			}
			return fmt.Errorf("failed to inspect container %s (code %d): %s", c, code, strings.TrimSpace(errOut))
		}

		stopCmd := fmt.Sprintf("docker stop %s", ssh.EscapeShellArg(c))
		if out, errOut, code, err := client.RunSudoCommand(ctx, stopCmd); err != nil || code != 0 {
			combined := strings.ToLower(out + " " + errOut)
			if !strings.Contains(combined, "no such") {
				return fmt.Errorf("failed to stop container %s (code %d): %s", c, code, strings.TrimSpace(errOut))
			}
		}
		rmCmd := fmt.Sprintf("docker rm -f %s", ssh.EscapeShellArg(c))
		if out, errOut, code, err := client.RunSudoCommand(ctx, rmCmd); err != nil || code != 0 {
			combined := strings.ToLower(out + " " + errOut)
			if !strings.Contains(combined, "no such") {
				return fmt.Errorf("failed to remove container %s (code %d): %s", c, code, strings.TrimSpace(errOut))
			}
		}
	}
	netCmd := "docker network rm amnezia-dns-net"
	if out, errOut, code, err := client.RunSudoCommand(ctx, netCmd); err != nil || code != 0 {
		combined := strings.ToLower(out + " " + errOut)
		if !strings.Contains(combined, "not found") && !strings.Contains(combined, "no such") {
			return fmt.Errorf("failed to remove DNS network (code %d): %s", code, strings.TrimSpace(errOut))
		}
	}
	return nil
}

// ToggleContainerHandler starts, stops, or restarts a protocol container.
func (h *Handlers) ToggleContainerHandler(w http.ResponseWriter, r *http.Request) {
	serverID, err := parseServerID(r)
	if err != nil {
		h.JSONError(w, http.StatusBadRequest, "invalid_parameter", "Invalid server_id")
		return
	}

	var req struct {
		Protocol string `json:"protocol"`
		Action   string `json:"action"`
	}
	if err := h.DecodeJSON(r, &req); err != nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Invalid request body")
		return
	}

	req.Protocol = models.NormalizeProtocol(req.Protocol)
	if !models.IsValidProtocol(req.Protocol) {
		h.JSONError(w, http.StatusBadRequest, "invalid_protocol", "Unknown protocol")
		return
	}

	if req.Protocol == models.ProtocolVLESS || req.Protocol == models.ProtocolNaive {
		session := h.GetSession(r)
		if session == nil || !session.IsAdmin() {
			h.JSONError(w, http.StatusForbidden, "forbidden", "Admin privileges required")
			return
		}
	}

	containerName, ok := models.ContainerNameForProtocol(req.Protocol)
	if !ok {
		h.JSONError(w, http.StatusBadRequest, "invalid_protocol", "Unknown protocol")
		return
	}

	if req.Action == "" {
		req.Action = "restart"
	}
	if req.Action != "start" && req.Action != "stop" && req.Action != "restart" {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Invalid action: must be start, stop, or restart")
		return
	}

	ctx := r.Context()
	server, err := h.db.GetServer(ctx, serverID)
	if err != nil || server == nil {
		h.JSONError(w, http.StatusNotFound, "not_found", "Server not found")
		return
	}

	client, err := h.GetSSHClient(ctx, server)
	if err != nil {
		h.JSONError(w, http.StatusBadRequest, "connection_failed", "SSH connection failed")
		return
	}

	var runOut, runStderr string
	var runCode int
	var runErr error
	switch req.Action {
	case "start":
		runOut, runStderr, runCode, runErr = client.RunSudoCommand(ctx, fmt.Sprintf("docker start %s", ssh.EscapeShellArg(containerName)))
	case "stop":
		runOut, runStderr, runCode, runErr = client.RunSudoCommand(ctx, fmt.Sprintf("docker stop %s", ssh.EscapeShellArg(containerName)))
	default:
		runOut, runStderr, runCode, runErr = client.RunSudoCommand(ctx, fmt.Sprintf("docker restart %s", ssh.EscapeShellArg(containerName)))
	}
	if runErr != nil || runCode != 0 {
		errMsg := strings.TrimSpace(runStderr)
		if errMsg == "" && runOut != "" {
			errMsg = strings.TrimSpace(runOut)
		}
		if runErr != nil {
			if errMsg != "" {
				errMsg += ": " + runErr.Error()
			} else {
				errMsg = runErr.Error()
			}
		}
		h.JSONError(w, http.StatusInternalServerError, "operation_failed", fmt.Sprintf("Failed to %s container %s (code %d): %s", req.Action, containerName, runCode, errMsg))
		return
	}

	h.audit(r, "server.container_toggle", map[string]any{"server_id": serverID, "protocol": req.Protocol, "action": req.Action})
	h.JSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"state":  req.Action,
	})
}

// queryProtocolsStatus queries remote managers for protocol container status.
func (h *Handlers) queryProtocolsStatus(ctx context.Context, server *models.Server) map[string]any {
	protocolsStatus := make(map[string]any)
	if h.awgMgr != nil {
		if status, err := h.awgMgr.GetServerStatus(ctx, server); err == nil {
			protocolsStatus["awg"] = status
		}
	}
	if h.mtproxylMgr != nil {
		if status, err := h.mtproxylMgr.GetServerStatus(ctx, server); err == nil {
			protocolsStatus["telemt"] = status
		}
	}
	if h.dnsMgr != nil {
		if status, err := h.dnsMgr.GetServerStatus(ctx, server); err == nil {
			protocolsStatus["dns"] = status
		}
	}
	if h.xrayMgr != nil {
		if status, err := h.xrayMgr.GetServerStatus(ctx, server); err == nil {
			protocolsStatus["vless"] = status
		}
	}
	if h.naiveMgr != nil {
		if status, err := h.naiveMgr.GetServerStatus(ctx, server); err == nil {
			protocolsStatus["naive"] = status
		}
	}
	return protocolsStatus
}

// syncDiscoveredProtocols updates server.Protocols with running protocol configurations.
func syncDiscoveredProtocols(server *models.Server, protocolsStatus map[string]any) bool {
	if server.Protocols == nil {
		server.Protocols = make(map[string]any)
	}
	updated := false

	for proto, stAny := range protocolsStatus {
		st, ok := stAny.(map[string]any)
		if !ok {
			continue
		}
		if running, _ := st["container_running"].(bool); !running {
			continue
		}

		protoMap, _ := server.Protocols[proto].(map[string]any)
		if protoMap == nil {
			protoMap = make(map[string]any)
		}
		protoMap["installed"] = true

		if pVal, ok := st["port"]; ok && pVal != nil && fmt.Sprint(pVal) != "" {
			if pInt, err := strconv.Atoi(fmt.Sprint(pVal)); err == nil && pInt > 0 {
				protoMap["port"] = pInt
			} else {
				protoMap["port"] = pVal
			}
		}
		if pubKey, ok := st["public_key"].(string); ok && pubKey != "" {
			protoMap["public_key"] = pubKey
		}
		if psk, ok := st["psk"].(string); ok && psk != "" {
			protoMap["psk"] = psk
		}
		if awgParams, ok := st["awg_params"]; ok && awgParams != nil {
			protoMap["awg_params"] = awgParams
		}
		if clientsCount, ok := st["clients_count"]; ok && clientsCount != nil {
			protoMap["clients_count"] = clientsCount
		}
		if dnsIP, ok := st["dns_ip"].(string); ok && dnsIP != "" {
			protoMap["dns_ip"] = dnsIP
		}

		server.Protocols[proto] = protoMap
		updated = true
	}

	return updated
}

// teardownAdminProtocols uninstalls the Admin-managed (VLESS/Naive) protocols
// installed on a server ahead of its deletion, so no remote container or client
// credential outlives the records. When force is false, it returns false (keeping records
// intact) and writes HTTP 409 if remote host is unreachable, or HTTP 500 on other errors.
// When force is true, it attempts uninstallation with a bounded timeout, logging any failures
// and continuing deletion.
func (h *Handlers) teardownAdminProtocols(w http.ResponseWriter, r *http.Request, server *models.Server, force bool) bool {
	for proto := range server.Protocols {
		if norm := models.NormalizeProtocol(proto); (norm != models.ProtocolVLESS && norm != models.ProtocolNaive) || !isProtocolInstalled(server, proto) {
			continue
		}
		if session := h.GetSession(r); session == nil || !session.IsAdmin() {
			h.JSONError(w, http.StatusForbidden, "forbidden", "Admin privileges required")
			return false
		}
		mgr, err := h.GetProtocolManager(proto)
		if err != nil || mgr == nil {
			if force {
				slog.Warn("force delete: no protocol manager available to remove, ignoring", "server_id", server.ID, "protocol", proto, "error", err)
				continue
			}
			h.JSONError(w, http.StatusInternalServerError, "uninstall_failed", fmt.Sprintf("No protocol manager available to remove %s", proto))
			return false
		}
		if force {
			timeoutCtx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			err := mgr.Uninstall(timeoutCtx, server)
			cancel()
			if err != nil {
				slog.Warn("force delete: failed to uninstall protocol container, ignoring", "server_id", server.ID, "protocol", proto, "error", err)
			}
			continue
		}
		if err := mgr.Uninstall(r.Context(), server); err != nil {
			slog.Error("failed to uninstall protocol before server delete", "server_id", server.ID, "protocol", proto, "error", err)
			if isRemoteTeardownError(err) {
				h.JSONError(w, http.StatusConflict, "server_unreachable", "Remote server is unreachable: container cleanup failed. Use force delete to remove from panel.")
				return false
			}
			h.JSONError(w, http.StatusInternalServerError, "uninstall_failed", fmt.Sprintf("Failed to remove protocol container: %v", err))
			return false
		}
	}
	return true
}

// isRemoteTeardownError returns true if err represents a network unreachability,
// dial timeout, connection refusal, SSH handshake failure, or authentication failure
// indicating that the remote host cannot be reached or logged into for container teardown.
func isRemoteTeardownError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	if errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.ETIMEDOUT) ||
		errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETUNREACH) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	var sysErr syscall.Errno
	if errors.As(err, &sysErr) {
		if sysErr == syscall.ECONNREFUSED ||
			sysErr == syscall.ETIMEDOUT ||
			sysErr == syscall.EHOSTUNREACH ||
			sysErr == syscall.ENETUNREACH {
			return true
		}
	}
	lower := strings.ToLower(err.Error())
	patterns := []string{
		"i/o timeout",
		"connection refused",
		"no route to host",
		"network is unreachable",
		"failed to dial",
		"unable to authenticate",
		"handshake failed",
		"permission denied",
		"auth failed",
	}
	for _, p := range patterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// isNetworkOrDialError is an alias for isRemoteTeardownError for backwards compatibility.
func isNetworkOrDialError(err error) bool {
	return isRemoteTeardownError(err)
}
