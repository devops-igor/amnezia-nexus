package handlers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/awg"
	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn"
)

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

	if req.Protocol == "awg" && h.awgMgr != nil {
		out, readErr := h.awgMgr.ReadConfiguration(ctx, server)
		if readErr != nil {
			h.JSONError(w, http.StatusInternalServerError, "read_failed", "Failed to read AWG configuration")
			return
		}
		h.JSON(w, http.StatusOK, map[string]any{"status": "ok", "config": out})
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

	if req.Protocol == "awg" && h.awgMgr != nil {
		saveErr := h.awgMgr.WriteConfigurationWithPostApply(ctx, server, req.Config, func(txCtx context.Context) error {
			err := h.reconcileAWGServerIdentity(txCtx, server, req.Config)
			if errors.Is(err, vpn.ErrVPNRollbackFailed) {
				return errors.Join(awg.ErrConfigurationPostApplyKeepApplied, err)
			}
			return err
		})
		if saveErr != nil {
			if errors.Is(saveErr, awg.ErrConfigurationRollbackFailed) && h.vpnSvc != nil {
				quarantineCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
				quarantineErr := h.vpnSvc.DisableBackend(quarantineCtx, server.ID)
				cancel()
				if quarantineErr != nil {
					saveErr = errors.Join(saveErr, fmt.Errorf("persist backend quarantine after remote rollback failure: %w", quarantineErr))
				}
				slog.Error("AWG rollback failed; backend quarantined before response", "server_id", server.ID, "error", saveErr)
			}
			if errors.Is(saveErr, awg.ErrConfigurationPostApply) {
				h.JSONError(w, http.StatusInternalServerError, "reconcile_failed", "Failed to reconcile AWG server identity")
			} else {
				h.JSONError(w, http.StatusInternalServerError, "save_failed", "Failed to apply AWG configuration")
			}
			return
		}

		h.audit(r, "server.config_save", map[string]any{"server_id": serverID, "protocol": req.Protocol})
		h.JSONOK(w)
		return
	}
	if err := client.UploadSudoFile(ctx, configPath, []byte(req.Config), 0600); err != nil {
		h.JSONError(w, http.StatusInternalServerError, "save_failed", "Failed to save config")
		return
	}

	h.audit(r, "server.config_save", map[string]any{"server_id": serverID, "protocol": req.Protocol})
	h.JSONOK(w)
}

func (h *Handlers) reconcileAWGServerIdentity(ctx context.Context, server *models.Server, config string) error {
	// The manager holds the per-server transaction lock during this callback.
	// Refresh request metadata here: a queued save may have read it before an
	// earlier save committed, and its rollback must restore that newer generation.
	fresh, err := h.db.GetServer(ctx, server.ID)
	if err != nil {
		return fmt.Errorf("load AWG identity transaction snapshot: %w", err)
	}
	if fresh == nil {
		return errors.New("AWG identity transaction server no longer exists")
	}
	*server = *fresh
	var (
		oldPub string
		oldAWG map[string]any
		hadAWG bool
	)
	if awgProto, ok := server.Protocols["awg"].(map[string]any); ok && awgProto != nil {
		hadAWG = true
		oldAWG = make(map[string]any, len(awgProto))
		for key, value := range awgProto {
			oldAWG[key] = value
		}
		oldPub, _ = awgProto["public_key"].(string)
	}

	newPub, err := awg.ExtractServerPublicKey(config)
	if err != nil {
		return fmt.Errorf("derive AWG configuration identity: %w", err)
	}
	if newPub == "" || newPub == oldPub {
		return nil
	}

	if server.Protocols == nil {
		server.Protocols = make(map[string]any)
	}
	awgProto, ok := server.Protocols["awg"].(map[string]any)
	if !ok || awgProto == nil {
		awgProto = make(map[string]any)
	}
	awgProto["public_key"] = newPub
	server.Protocols["awg"] = awgProto
	if err := h.updateServerProtocols(ctx, server.ID, server.Protocols); err != nil {
		return fmt.Errorf("failed to update server protocols: %w", err)
	}

	if h.vpnSvc != nil {
		if err := h.vpnSvc.UpdateBackendServerPublicKey(ctx, server.ID, newPub); err != nil {
			if errors.Is(err, vpn.ErrVPNRollbackFailed) {
				// The pool accepted the NEW identity but could not compensate back
				// to OLD. Rolling the DB and remote AWG back now would knowingly
				// create a split-brain identity. Keep NEW as the convergence target
				// and quarantine the backend so a stale forwarder device cannot
				// continue carrying traffic while the operator repairs the failure.
				quarantineCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
				defer cancel()
				if quarantineErr := h.vpnSvc.DisableBackend(quarantineCtx, server.ID); quarantineErr != nil {
					return errors.Join(
						fmt.Errorf("failed to reconcile VPN backend public key; keeping newly applied identity because VPN rollback failed: %w", err),
						fmt.Errorf("failed to quarantine backend after VPN rollback failure: %w", quarantineErr),
					)
				}
				return fmt.Errorf("failed to reconcile VPN backend public key; backend quarantined with newly applied identity: %w", err)
			}

			if hadAWG {
				server.Protocols["awg"] = oldAWG
			} else {
				delete(server.Protocols, "awg")
			}

			rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			if rbErr := h.updateServerProtocols(rollbackCtx, server.ID, server.Protocols); rbErr != nil {
				// The DB still carries NEW while VPN reconciliation compensated
				// to OLD. A blind remote rollback would leave DB NEW / remote+VPN
				// OLD. Keep NEW as the convergence target instead: restore the
				// in-memory protocol view, quarantine the backend fail-closed, and
				// move the disabled VPN tunnel forward to NEW. Even if one of
				// those emergency operations also fails, the backend must not
				// continue serving in a partially reconciled state.
				awgProto["public_key"] = newPub
				server.Protocols["awg"] = awgProto

				quarantineCtx, cancelQuarantine := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
				defer cancelQuarantine()

				var emergencyErrs []error
				if quarantineErr := h.vpnSvc.DisableBackend(quarantineCtx, server.ID); quarantineErr != nil {
					emergencyErrs = append(emergencyErrs, fmt.Errorf("failed to persist complete backend quarantine: %w", quarantineErr))
				}
				if convergeErr := h.vpnSvc.UpdateBackendServerPublicKey(quarantineCtx, server.ID, newPub); convergeErr != nil {
					emergencyErrs = append(emergencyErrs, fmt.Errorf("failed to converge quarantined VPN backend to new public key: %w", convergeErr))
				}

				baseErr := errors.Join(
					awg.ErrConfigurationPostApplyKeepApplied,
					fmt.Errorf("failed to reconcile VPN backend public key: %w", err),
					fmt.Errorf("failed to rollback server protocols: %w", rbErr),
				)
				return errors.Join(append([]error{baseErr}, emergencyErrs...)...)
			}
			return fmt.Errorf("failed to reconcile VPN backend public key: %w", err)
		}
	}
	return nil
}
