package handlers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/awg"
	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn"
	"github.com/go-chi/chi/v5"
)

// AddServerHandler initiates the SSH connection test and fingerprint retrieval.
func (h *Handlers) AddServerHandler(w http.ResponseWriter, r *http.Request) {
	var req models.AddServerRequest
	if err := h.DecodeJSON(r, &req); err != nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Invalid request body")
		return
	}

	if err := req.Validate(); err != nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return
	}

	req.Host = strings.TrimSpace(req.Host)
	req.Username = strings.TrimSpace(req.Username)
	if req.Host == "" || req.Username == "" {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Host and username are required")
		return
	}
	if req.Password == "" && req.PrivateKey == "" {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Password or SSH key is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	sshCfg := ssh.Config{
		Host:       req.Host,
		Port:       req.SSHPort,
		User:       req.Username,
		Password:   req.Password,
		PrivateKey: req.PrivateKey,
		Timeout:    10 * time.Second,
	}

	client, err := ssh.Dial(ctx, sshCfg)
	if err != nil {
		h.JSONError(w, http.StatusBadRequest, "connection_failed", "SSH connection failed")
		return
	}
	defer client.Close()

	fingerprint := client.CapturedFingerprint()
	serverInfo, _, _, _ := client.RunCommand(ctx, "uname -a 2>/dev/null || cat /etc/os-release 2>/dev/null || echo Linux")
	serverInfo = strings.TrimSpace(serverInfo)

	h.JSON(w, http.StatusOK, map[string]any{
		"status":               "pending_fingerprint_confirmation",
		"fingerprint_required": true,
		"fingerprint":          fingerprint,
		"server_info":          serverInfo,
	})
}

// ConfirmFingerprintHandler persists the server and verified host key fingerprint.
func (h *Handlers) ConfirmFingerprintHandler(w http.ResponseWriter, r *http.Request) {
	var req models.ConfirmFingerprintRequest
	if err := h.DecodeJSON(r, &req); err != nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Invalid request body")
		return
	}

	if err := req.Validate(); err != nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return
	}

	req.Host = strings.TrimSpace(req.Host)
	req.Username = strings.TrimSpace(req.Username)
	req.Fingerprint = strings.TrimSpace(req.Fingerprint)

	if req.Host == "" || req.Username == "" {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Host and username are required")
		return
	}
	if req.Password == "" && req.PrivateKey == "" {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Password or SSH key is required")
		return
	}
	if req.Fingerprint == "" {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Fingerprint is required")
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = req.Host
	}

	ctx := r.Context()
	server := &models.Server{
		Name:      name,
		Host:      req.Host,
		SSHPort:   req.SSHPort,
		SSHUser:   req.Username,
		SSHPass:   req.Password,
		SSHKey:    req.PrivateKey,
		Protocols: make(map[string]any),
		CreatedAt: time.Now(),
	}

	serverID, err := h.db.CreateServer(ctx, server)
	if err != nil {
		h.JSONError(w, http.StatusInternalServerError, "internal_error", "Failed to save server")
		return
	}

	_ = h.db.SaveKnownHostFingerprint(ctx, serverID, req.Fingerprint)

	h.audit(r, "server.confirm_fingerprint", map[string]any{"server_id": serverID, "name": name, "host": req.Host})

	h.JSON(w, http.StatusOK, map[string]any{
		"status":    "ok",
		"server_id": serverID,
	})
}

// DeleteServerHandler removes a server and all its associated connections.
func (h *Handlers) DeleteServerHandler(w http.ResponseWriter, r *http.Request) {
	serverID, err := parseServerID(r)
	if err != nil {
		h.JSONError(w, http.StatusBadRequest, "invalid_parameter", "Invalid server_id")
		return
	}

	ctx := r.Context()
	server, err := h.db.GetServer(ctx, serverID)
	if err != nil || server == nil {
		h.JSONError(w, http.StatusNotFound, "not_found", "Server not found")
		return
	}

	if h.sshPool != nil {
		h.sshPool.Remove(serverID)
	}

	if _, err := h.db.DeleteConnectionsByServer(ctx, serverID); err != nil {
		h.JSONError(w, http.StatusInternalServerError, "database_error", "Failed to delete server connections")
		return
	}
	if _, err := h.db.DeleteKnownHost(ctx, serverID); err != nil {
		h.JSONError(w, http.StatusInternalServerError, "database_error", "Failed to delete server known host")
		return
	}
	if _, err := h.db.DeleteServer(ctx, serverID); err != nil {
		h.JSONError(w, http.StatusInternalServerError, "database_error", "Failed to delete server")
		return
	}

	h.audit(r, "server.delete", map[string]any{"server_id": serverID, "name": server.Name})
	h.JSONOK(w)
}

// RenameServerHandler updates the display name of a server.
func (h *Handlers) RenameServerHandler(w http.ResponseWriter, r *http.Request) {
	serverID, err := parseServerID(r)
	if err != nil {
		h.JSONError(w, http.StatusBadRequest, "invalid_parameter", "Invalid server_id")
		return
	}

	var req models.RenameServerRequest
	if err := h.DecodeJSON(r, &req); err != nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Invalid request body")
		return
	}

	if err := req.Validate(); err != nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return
	}

	ctx := r.Context()
	server, err := h.db.GetServer(ctx, serverID)
	if err != nil || server == nil {
		h.JSONError(w, http.StatusNotFound, "not_found", "Server not found")
		return
	}

	if err := h.db.UpdateServer(ctx, serverID, map[string]any{"name": req.Name}); err != nil {
		h.JSONError(w, http.StatusInternalServerError, "database_error", "Failed to update server name")
		return
	}

	h.audit(r, "server.rename", map[string]any{
		"server_id": serverID,
		"old_name":  server.Name,
		"new_name":  req.Name,
	})

	h.JSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"name":   req.Name,
	})
}

// UpdateServerHostHandler updates the host / IP address of a server.
func (h *Handlers) UpdateServerHostHandler(w http.ResponseWriter, r *http.Request) {
	serverID, err := parseServerID(r)
	if err != nil {
		h.JSONError(w, http.StatusBadRequest, "invalid_parameter", "Invalid server_id")
		return
	}

	var req models.UpdateServerHostRequest
	if err := h.DecodeJSON(r, &req); err != nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Invalid request body")
		return
	}

	if err := req.Validate(); err != nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return
	}

	unlock := h.lockServerHost(serverID)
	defer unlock()

	ctx := r.Context()
	server, err := h.db.GetServer(ctx, serverID)
	if err != nil || server == nil {
		h.JSONError(w, http.StatusNotFound, "not_found", "Server not found")
		return
	}

	if err := h.db.UpdateServer(ctx, serverID, map[string]any{"host": req.Host}); err != nil {
		h.JSONError(w, http.StatusInternalServerError, "database_error", "Failed to update server host")
		return
	}

	if h.sshPool != nil {
		h.sshPool.Remove(serverID)
	}

	if h.vpnSvc != nil {
		if err := h.vpnSvc.UpdateBackendServerHost(ctx, serverID, req.Host); err != nil {
			slog.Error("failed to update VPN backend endpoint, rolling back server host", "server_id", serverID, "err", err)
			rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()

			var vpnRollbackErr error
			if errors.Is(err, vpn.ErrVPNRollbackFailed) {
				vpnRollbackErr = err
			} else if h.vpnSvc != nil {
				vpnRollbackErr = h.vpnSvc.UpdateBackendServerHost(rollbackCtx, serverID, server.Host)
			}

			tunnelRestored := true
			if errors.Is(vpnRollbackErr, vpn.ErrVPNRollbackFailed) {
				tunnelRestored = false
			} else if currentTun, getErr := h.vpnSvc.GetTunnel(serverID); getErr == nil && currentTun != nil {
				expectedEndpointHost, _, splitErr := net.SplitHostPort(currentTun.Endpoint)
				if splitErr != nil {
					expectedEndpointHost = currentTun.Endpoint
				}
				cleanEndpoint := strings.Trim(strings.TrimSpace(expectedEndpointHost), "[]")
				cleanServerHost := strings.Trim(strings.TrimSpace(server.Host), "[]")
				if cleanEndpoint != cleanServerHost {
					tunnelRestored = false
				}
			} else if vpnRollbackErr != nil {
				tunnelRestored = false
			}

			if tunnelRestored {
				if rbErr := h.db.UpdateServer(rollbackCtx, serverID, map[string]any{"host": server.Host}); rbErr != nil {
					slog.Error("failed to rollback server host after VPN failure", "server_id", serverID, "err", rbErr)
				}
				if h.sshPool != nil {
					h.sshPool.Remove(serverID)
				}
			} else {
				slog.Error("CRITICAL: VPN backend rollback failed; refusing to restore server host in database to prevent split-brain state",
					"server_id", serverID,
					"server_host_retained", req.Host,
					"original_host", server.Host,
					"err", vpnRollbackErr,
				)
			}
			h.JSONError(w, http.StatusInternalServerError, "vpn_propagation_failed", "Failed to update VPN backend endpoint")
			return
		}
	}

	h.audit(r, "server.update_ip", map[string]any{
		"server_id": serverID,
		"old_host":  server.Host,
		"new_host":  req.Host,
	})

	h.JSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"host":   req.Host,
	})
}

// RebootServerHandler triggers a remote host reboot via SSH.
func (h *Handlers) RebootServerHandler(w http.ResponseWriter, r *http.Request) {
	serverID, err := parseServerID(r)
	if err != nil {
		h.JSONError(w, http.StatusBadRequest, "invalid_parameter", "Invalid server_id")
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

	if _, _, _, err := client.RunSudoCommand(ctx, "nohup reboot > /dev/null 2>&1 &"); err != nil {
		h.JSONError(w, http.StatusInternalServerError, "operation_failed", "Failed to execute reboot command: "+err.Error())
		return
	}

	if h.sshPool != nil {
		h.sshPool.Remove(serverID)
	}

	h.audit(r, "server.reboot", map[string]any{"server_id": serverID, "name": server.Name})
	h.JSONOK(w)
}

// ClearServerHandler stops all protocol containers and wipes server configuration.
func (h *Handlers) ClearServerHandler(w http.ResponseWriter, r *http.Request) {
	serverID, err := parseServerID(r)
	if err != nil {
		h.JSONError(w, http.StatusBadRequest, "invalid_parameter", "Invalid server_id")
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

	containers := []string{
		"amnezia-awg",
		"amnezia-awg2",
		"amnezia-awg-legacy",
		"telemt",
		"amnezia-dns",
	}

	for _, c := range containers {
		_, _, _, _ = client.RunSudoCommand(ctx, fmt.Sprintf("docker stop %s || true", ssh.EscapeShellArg(c)))
		_, _, _, _ = client.RunSudoCommand(ctx, fmt.Sprintf("docker rm %s || true", ssh.EscapeShellArg(c)))
	}
	_, _, _, _ = client.RunSudoCommand(ctx, "docker network rm amnezia-dns-net || true")
	if _, _, _, err := client.RunSudoCommand(ctx, "rm -rf /opt/amnezia"); err != nil {
		h.JSONError(w, http.StatusInternalServerError, "operation_failed", "Failed to clear server directory: "+err.Error())
		return
	}

	if _, err := h.db.DeleteConnectionsByServer(ctx, serverID); err != nil {
		h.JSONError(w, http.StatusInternalServerError, "database_error", "Failed to delete server connections")
		return
	}
	if err := h.db.UpdateServerProtocols(ctx, serverID, make(map[string]any)); err != nil {
		h.JSONError(w, http.StatusInternalServerError, "database_error", "Failed to clear server protocols")
		return
	}

	h.audit(r, "server.clear", map[string]any{"server_id": serverID, "name": server.Name})
	h.JSONOK(w)
}

// ServerStatsHandler collects telemetry and resource utilization from the remote host.
func (h *Handlers) ServerStatsHandler(w http.ResponseWriter, r *http.Request) {
	serverID, err := parseServerID(r)
	if err != nil {
		h.JSONError(w, http.StatusBadRequest, "invalid_parameter", "Invalid server_id")
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

	combinedCmd := "echo '===CPU==='; " +
		"top -bn1 | grep 'Cpu(s)' | awk '{print $2}' | cut -d'%' -f1 2>/dev/null || " +
		"awk '{u=$2+$4; t=$2+$4+$5; if(NR==1){pu=u;pt=t} else printf \"%.1f\", (u-pu)/(t-pt)*100}' <(grep 'cpu ' /proc/stat) <(sleep 0.5 && grep 'cpu ' /proc/stat) 2>/dev/null; " +
		"echo ''; " +
		"echo '===RAM==='; " +
		"free -b | awk 'NR==2{printf \"%d %d\", $3, $2}'; " +
		"echo ''; " +
		"echo '===DISK==='; " +
		"df -B1 / | awk 'NR==2{printf \"%d %d\", $3, $2}'; " +
		"echo ''; " +
		"echo '===NET==='; " +
		"DEV=$(ip route | awk '/default/ {print $5}' | head -1); " +
		"cat /proc/net/dev | awk -v dev=\"$DEV:\" '$1==dev{printf \"%d %d\", $2, $10}'; " +
		"echo ''; " +
		"echo '===UPTIME==='; " +
		"uptime -p 2>/dev/null || uptime"

	out, _, code, err := client.RunCommand(ctx, combinedCmd)
	if err != nil || code != 0 {
		h.JSONError(w, http.StatusBadGateway, "stats_failed", "Failed to collect server statistics")
		return
	}

	stats, err := parseCombinedStats(out)
	if err != nil {
		h.JSONError(w, http.StatusBadGateway, "stats_failed", "Malformed server statistics output")
		return
	}

	h.JSON(w, http.StatusOK, stats)
}

// ServerCheckHandler checks connectivity and Docker protocol status on the server.
func (h *Handlers) ServerCheckHandler(w http.ResponseWriter, r *http.Request) {
	serverID, err := parseServerID(r)
	if err != nil {
		h.JSONError(w, http.StatusBadRequest, "invalid_parameter", "Invalid server_id")
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
		h.JSON(w, http.StatusOK, models.ServerCheckResponse{
			Connection:      "failed",
			DockerInstalled: false,
			Protocols:       make(map[string]any),
		})
		return
	}

	_ = h.db.UpdateServerReachability(ctx, serverID, models.ReachabilityOnline)

	// Check docker
	dockerOut, _, code, _ := client.RunCommand(ctx, "docker --version")
	dockerInstalled := code == 0 && strings.Contains(strings.ToLower(dockerOut), "docker")

	protocolsStatus := h.queryProtocolsStatus(ctx, server)
	if syncDiscoveredProtocols(server, protocolsStatus) {
		if err := h.db.UpdateServerProtocols(ctx, serverID, server.Protocols); err != nil {
			slog.Warn("ServerCheckHandler: failed to persist detected protocols", "server_id", serverID, "err", err)
		}
	}

	h.JSON(w, http.StatusOK, models.ServerCheckResponse{
		Connection:      "ok",
		DockerInstalled: dockerInstalled,
		Protocols:       protocolsStatus,
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

// InstallProtocolHandler deploys a VPN protocol backend to the remote server.
func (h *Handlers) InstallProtocolHandler(w http.ResponseWriter, r *http.Request) {
	serverID, err := parseServerID(r)
	if err != nil {
		h.JSONError(w, http.StatusBadRequest, "invalid_parameter", "Invalid server_id")
		return
	}

	var req models.InstallProtocolRequest
	if err := h.DecodeJSON(r, &req); err != nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Invalid request body")
		return
	}

	if err := req.Validate(); err != nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return
	}

	ctx := r.Context()
	server, err := h.db.GetServer(ctx, serverID)
	if err != nil || server == nil {
		h.JSONError(w, http.StatusNotFound, "not_found", "Server not found")
		return
	}

	protoMgr, err := h.GetProtocolManager(req.Protocol)
	if err != nil {
		h.JSONError(w, http.StatusBadRequest, "invalid_protocol", err.Error())
		return
	}

	params := map[string]any{
		"port": req.Port,
	}
	if req.TLSEmulation != nil {
		params["tls_emulation"] = *req.TLSEmulation
	}
	if req.TLSDomain != nil {
		params["tls_domain"] = *req.TLSDomain
	}
	if req.MaxConnections != nil {
		params["max_connections"] = *req.MaxConnections
	}
	if req.AWGProfile != nil {
		params["awg_profile"] = string(*req.AWGProfile)
	}
	if req.AWGCPSProtocol != nil {
		params["awg_cps_protocol"] = *req.AWGCPSProtocol
	}
	if req.AWGHeaderProtection != nil {
		params["awg_header_protection"] = *req.AWGHeaderProtection
	}

	if err := protoMgr.Install(ctx, server, params); err != nil {
		slog.Error("protocol install failed", "server_id", serverID, "protocol", req.Protocol, "port", req.Port, "err", err)
		h.JSONError(w, http.StatusInternalServerError, "install_failed", "Failed to install protocol")
		return
	}

	if server.Protocols == nil {
		server.Protocols = make(map[string]any)
	}
	server.Protocols[req.Protocol] = map[string]any{
		"installed": true,
		"port":      req.Port,
	}
	_ = h.db.UpdateServerProtocols(ctx, serverID, server.Protocols)

	h.audit(r, "server.protocol_install", map[string]any{"server_id": serverID, "protocol": req.Protocol, "port": req.Port})
	h.JSON(w, http.StatusOK, map[string]any{
		"status":   "ok",
		"protocol": req.Protocol,
	})
}

// UninstallProtocolHandler removes a protocol container and removes associated connections.
func (h *Handlers) UninstallProtocolHandler(w http.ResponseWriter, r *http.Request) {
	serverID, err := parseServerID(r)
	if err != nil {
		h.JSONError(w, http.StatusBadRequest, "invalid_parameter", "Invalid server_id")
		return
	}

	var req models.ProtocolRequest
	if err := h.DecodeJSON(r, &req); err != nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Invalid request body")
		return
	}

	if err := req.Validate(); err != nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return
	}

	ctx := r.Context()
	server, err := h.db.GetServer(ctx, serverID)
	if err != nil || server == nil {
		h.JSONError(w, http.StatusNotFound, "not_found", "Server not found")
		return
	}

	protoMgr, err := h.GetProtocolManager(req.Protocol)
	if err == nil && protoMgr != nil {
		_ = protoMgr.Uninstall(ctx, server)
	}

	if server.Protocols != nil {
		delete(server.Protocols, req.Protocol)
		_ = h.db.UpdateServerProtocols(ctx, serverID, server.Protocols)
	}
	_, _ = h.db.DeleteConnectionsByServerAndProtocol(ctx, serverID, req.Protocol)

	h.audit(r, "server.protocol_uninstall", map[string]any{"server_id": serverID, "protocol": req.Protocol})
	h.JSONOK(w)
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

	var runErr error
	switch req.Action {
	case "start":
		_, _, _, runErr = client.RunSudoCommand(ctx, fmt.Sprintf("docker start %s", ssh.EscapeShellArg(containerName)))
	case "stop":
		_, _, _, runErr = client.RunSudoCommand(ctx, fmt.Sprintf("docker stop %s", ssh.EscapeShellArg(containerName)))
	default:
		_, _, _, runErr = client.RunSudoCommand(ctx, fmt.Sprintf("docker restart %s", ssh.EscapeShellArg(containerName)))
	}
	if runErr != nil {
		h.JSONError(w, http.StatusInternalServerError, "operation_failed", fmt.Sprintf("Failed to %s container %s: %v", req.Action, containerName, runErr))
		return
	}

	h.audit(r, "server.container_toggle", map[string]any{"server_id": serverID, "protocol": req.Protocol, "action": req.Action})
	h.JSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"state":  req.Action,
	})
}

// GetServerConfigHandler retrieves configuration text for a server protocol.
func (h *Handlers) GetServerConfigHandler(w http.ResponseWriter, r *http.Request) {
	serverID, err := parseServerID(r)
	if err != nil {
		h.JSONError(w, http.StatusBadRequest, "invalid_parameter", "Invalid server_id")
		return
	}

	var req models.ProtocolRequest
	if err := h.DecodeJSON(r, &req); err != nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Invalid request body")
		return
	}

	req.Protocol = models.NormalizeProtocol(req.Protocol)
	if !models.IsValidProtocol(req.Protocol) {
		h.JSONError(w, http.StatusBadRequest, "invalid_protocol", "Unknown protocol")
		return
	}

	configPath, ok := models.ConfigPathForProtocol(req.Protocol)
	if !ok {
		h.JSONError(w, http.StatusBadRequest, "invalid_protocol", "Unknown protocol")
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

	out, _, code, err := client.RunSudoCommand(ctx, fmt.Sprintf("cat %s 2>/dev/null", ssh.EscapeShellArg(configPath)))
	if err != nil || code != 0 {
		out = "# Configuration not found or empty"
	}

	h.JSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"config": out,
	})
}

// SaveServerConfigHandler overwrites configuration text for a server protocol.
func (h *Handlers) SaveServerConfigHandler(w http.ResponseWriter, r *http.Request) {
	serverID, err := parseServerID(r)
	if err != nil {
		h.JSONError(w, http.StatusBadRequest, "invalid_parameter", "Invalid server_id")
		return
	}

	var req models.ServerConfigSaveRequest
	if err := h.DecodeJSON(r, &req); err != nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Invalid request body")
		return
	}

	if err := req.Validate(); err != nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return
	}

	if req.Protocol == "awg" {
		params, _, err := awg.ParseServerConfig(req.Config)
		if err != nil {
			h.JSONError(w, http.StatusBadRequest, "validation_failed", err.Error())
			return
		}
		if len(params) > 0 {
			if err := awg.ValidateAWGParams(params); err != nil {
				h.JSONError(w, http.StatusBadRequest, "validation_failed", err.Error())
				return
			}
		}
	}

	configPath, ok := models.ConfigPathForProtocol(req.Protocol)
	if !ok {
		h.JSONError(w, http.StatusBadRequest, "invalid_protocol", "Unknown protocol")
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

	if err := client.UploadSudoFile(ctx, configPath, []byte(req.Config), 0600); err != nil {
		h.JSONError(w, http.StatusInternalServerError, "save_failed", "Failed to save config")
		return
	}

	h.audit(r, "server.config_save", map[string]any{"server_id": serverID, "protocol": req.Protocol})
	h.JSONOK(w)
}

// GetServerReachabilityHandler returns server connectivity and latency status.
func (h *Handlers) GetServerReachabilityHandler(w http.ResponseWriter, r *http.Request) {
	serverID, err := parseServerID(r)
	if err != nil {
		h.JSONError(w, http.StatusBadRequest, "invalid_parameter", "Invalid server_id")
		return
	}

	ctx := r.Context()
	server, err := h.db.GetServer(ctx, serverID)
	if err != nil || server == nil {
		h.JSONError(w, http.StatusNotFound, "not_found", "Server not found")
		return
	}

	status, _ := h.db.GetServerStatus(ctx, serverID)

	sshPort := server.SSHPort
	if sshPort <= 0 {
		sshPort = 22
	}

	// Measure real TCP latency to the server (SSH port).
	latencyMS := 0
	reachable := false

	dialFn := h.dialTimeout
	if dialFn == nil {
		dialFn = net.DialTimeout
	}

	start := time.Now()
	// #nosec G704 -- connecting to managed server host for latency probe
	conn, err := dialFn("tcp", net.JoinHostPort(server.Host, strconv.Itoa(sshPort)), 3*time.Second)
	if err == nil {
		_ = conn.Close()
		latencyMS = int(time.Since(start).Milliseconds())
		if latencyMS <= 0 {
			latencyMS = 1
		}
		reachable = true
		status = models.ReachabilityOnline
		_ = h.db.UpdateServerReachability(ctx, serverID, models.ReachabilityOnline)
	} else {
		reachable = false
		latencyMS = 0
		if status == models.ReachabilityUnknown {
			status = models.ReachabilityOffline
		}
	}

	nowStr := time.Now().UTC().Format(time.RFC3339)
	reachMap := map[string]any{
		"reachable":    reachable,
		"latency_ms":   latencyMS,
		"status":       string(status),
		"last_checked": nowStr,
	}

	h.JSON(w, http.StatusOK, map[string]any{
		"status":        "ok",
		"reachable":     reachable,
		"reachability":  reachMap,
		"server_status": string(status),
		"latency_ms":    latencyMS,
		"last_checked":  nowStr,
	})
}

func parseServerID(r *http.Request) (int64, error) {
	idStr := chi.URLParam(r, "server_id")
	if idStr == "" {
		return 0, fmt.Errorf("missing server_id in URL")
	}
	return strconv.ParseInt(idStr, 10, 64)
}

var statsSectionPattern = regexp.MustCompile(`===(CPU|RAM|DISK|NET|UPTIME)===`)

func parseCPU(cpuStr string) (float64, error) {
	str := strings.TrimSpace(cpuStr)
	if str == "" {
		return 0, errors.New("empty cpu section")
	}
	val, err := strconv.ParseFloat(str, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid cpu metric %q: %w", str, err)
	}
	if val < 0 {
		return 0, fmt.Errorf("negative cpu metric: %f", val)
	}
	return val, nil
}

func parseUsagePair(sectionName, content string) (int64, int64, float64, error) {
	parts := strings.Fields(content)
	if len(parts) < 2 {
		return 0, 0, 0, fmt.Errorf("malformed %s section: expected at least 2 fields, got %d", sectionName, len(parts))
	}
	used, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid %s used metric %q: %w", sectionName, parts[0], err)
	}
	if used < 0 {
		return 0, 0, 0, fmt.Errorf("negative %s used metric: %d", sectionName, used)
	}
	total, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid %s total metric %q: %w", sectionName, parts[1], err)
	}
	if total <= 0 {
		return 0, 0, 0, fmt.Errorf("invalid non-positive %s total metric: %d", sectionName, total)
	}
	percent := float64(used) / float64(total) * 100.0
	return used, total, percent, nil
}

func parseNetPair(content string) (int64, int64, error) {
	parts := strings.Fields(content)
	if len(parts) < 2 {
		return 0, 0, fmt.Errorf("malformed net section: expected at least 2 fields, got %d", len(parts))
	}
	rx, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid net rx metric %q: %w", parts[0], err)
	}
	if rx < 0 {
		return 0, 0, fmt.Errorf("negative net rx metric: %d", rx)
	}
	tx, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid net tx metric %q: %w", parts[1], err)
	}
	if tx < 0 {
		return 0, 0, fmt.Errorf("negative net tx metric: %d", tx)
	}
	return rx, tx, nil
}

func parseCombinedStats(raw string) (models.ServerStatsResponse, error) {
	if strings.TrimSpace(raw) == "" {
		return models.ServerStatsResponse{}, errors.New("empty stats output")
	}

	var resp models.ServerStatsResponse
	sections := make(map[string]string)

	matches := statsSectionPattern.FindAllStringIndex(raw, -1)
	for i, m := range matches {
		name := raw[m[0]+3 : m[1]-3]
		start := m[1]
		end := len(raw)
		if i+1 < len(matches) {
			end = matches[i+1][0]
		}
		sections[name] = strings.TrimSpace(raw[start:end])
	}

	cpuStr, ok := sections["CPU"]
	if !ok {
		return models.ServerStatsResponse{}, errors.New("missing cpu section")
	}
	cpuVal, err := parseCPU(cpuStr)
	if err != nil {
		return models.ServerStatsResponse{}, err
	}
	resp.CPU = cpuVal

	ramStr, ok := sections["RAM"]
	if !ok {
		return models.ServerStatsResponse{}, errors.New("missing ram section")
	}
	usedRAM, totalRAM, ramPct, err := parseUsagePair("ram", ramStr)
	if err != nil {
		return models.ServerStatsResponse{}, err
	}
	resp.RAMUsed = usedRAM
	resp.RAMTotal = totalRAM
	resp.RAMPercent = ramPct

	diskStr, ok := sections["DISK"]
	if !ok {
		return models.ServerStatsResponse{}, errors.New("missing disk section")
	}
	usedDisk, totalDisk, diskPct, err := parseUsagePair("disk", diskStr)
	if err != nil {
		return models.ServerStatsResponse{}, err
	}
	resp.DiskUsed = usedDisk
	resp.DiskTotal = totalDisk
	resp.DiskPercent = diskPct

	netStr, ok := sections["NET"]
	if !ok {
		return models.ServerStatsResponse{}, errors.New("missing net section")
	}
	rx, tx, err := parseNetPair(netStr)
	if err != nil {
		return models.ServerStatsResponse{}, err
	}
	resp.NetRx = rx
	resp.NetTx = tx

	if uptimeStr, ok := sections["UPTIME"]; ok {
		resp.Uptime = uptimeStr
	}

	return resp, nil
}

// ListServersHandler returns all configured servers (with sensitive credentials stripped).
func (h *Handlers) ListServersHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	servers, err := h.db.GetAllServers(ctx)
	if err != nil {
		h.JSONError(w, http.StatusInternalServerError, "internal_error", "Failed to retrieve servers")
		return
	}

	sess := h.GetSession(r)
	isAdminOrSupport := sess != nil && (sess.Role == models.RoleAdmin || sess.Role == models.RoleSupport)

	result := make([]models.ServerItemResponse, 0, len(servers))
	for _, s := range servers {
		if !isAdminOrSupport {
			name := s.Name
			if strings.TrimSpace(name) == "" {
				name = fmt.Sprintf("Server #%d", s.ID)
			}
			sanitizedProtocols := make(map[string]any)
			for proto, pVal := range s.Protocols {
				installed := false
				if m, ok := pVal.(map[string]any); ok {
					if inst, ok := m["installed"].(bool); ok {
						installed = inst
					}
				} else if b, ok := pVal.(bool); ok {
					installed = b
				}
				sanitizedProtocols[proto] = map[string]bool{"installed": installed}
			}

			status := string(s.Status)
			if status == "" {
				status = "online"
			}
			reachable := s.Status == models.ReachabilityOnline || s.Status == ""

			result = append(result, models.ServerItemResponse{
				ID:        s.ID,
				Name:      name,
				Host:      "",
				SSHPort:   0,
				Username:  "",
				Protocols: sanitizedProtocols,
				Status:    status,
				Reachable: &reachable,
			})
		} else {
			protoMap := s.Protocols
			if protoMap == nil {
				protoMap = make(map[string]any)
			}
			status := string(s.Status)
			if status == "" {
				status = "unknown"
			}
			var createdAt *time.Time
			if !s.CreatedAt.IsZero() {
				createdAt = &s.CreatedAt
			}
			result = append(result, models.ServerItemResponse{
				ID:        s.ID,
				Name:      s.Name,
				Host:      s.Host,
				SSHPort:   s.SSHPort,
				Username:  s.SSHUser,
				Protocols: protoMap,
				CreatedAt: createdAt,
				Status:    status,
			})
		}
	}

	h.JSON(w, http.StatusOK, result)
}
