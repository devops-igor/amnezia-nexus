package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
	"github.com/go-chi/chi/v5"
	gossh "golang.org/x/crypto/ssh"
)

// Detailed deployment progression status constants.
const (
	DeployStatusDeploying          = "deploying"
	DeployStatusSSHVerifying       = "ssh_verifying"
	DeployStatusInstallingProtocol = "installing_protocol"
	DeployStatusEnablingBackend    = "enabling_backend"
	DeployStatusReady              = "ready"
	DeployStatusFailed             = "failed"
)

// ErrDuplicateServerID is returned when attempting to register an already-registered provider server ID.
var ErrDuplicateServerID = errors.New("duplicate server registration rejected")

// GigahostDeployRequest specifies parameters to onboard a ready Gigahost VPS order as a backend.
type GigahostDeployRequest struct {
	OrderID             string `json:"order_id"`
	ProviderServerID    int64  `json:"provider_server_id,omitempty"`
	AssignedIP          string `json:"assigned_ip,omitempty"`
	SSHUser             string `json:"ssh_user,omitempty"`
	SSHPort             int    `json:"ssh_port,omitempty"`
	SSHPassword         string `json:"ssh_password,omitempty"`
	SSHPrivateKey       string `json:"ssh_key,omitempty"`
	ServerName          string `json:"server_name,omitempty"`
	Protocol            string `json:"protocol,omitempty"` // awg, vless, naive
	Port                string `json:"port,omitempty"`
	EngineProfile       string `json:"engine_profile,omitempty"`
	TLSDomain           string `json:"tls_domain,omitempty"`
	MaxConnections      *int   `json:"max_connections,omitempty"`
	WaitReady           bool   `json:"wait_ready,omitempty"`
	WaitTimeoutSec      int    `json:"wait_timeout_sec,omitempty"`
	ExpectedFingerprint string `json:"expected_fingerprint,omitempty"`
	HostKeyFingerprint  string `json:"host_key_fingerprint,omitempty"`
	ConfirmHostKey      bool   `json:"confirm_host_key,omitempty"`
}

// Validate validates required inputs and protocol choice.
func (r *GigahostDeployRequest) Validate() error {
	if strings.TrimSpace(r.OrderID) == "" {
		return errors.New("order_id is required")
	}
	if strings.TrimSpace(r.SSHPassword) == "" && strings.TrimSpace(r.SSHPrivateKey) == "" {
		return errors.New("ssh_password or ssh_key is required")
	}
	proto := r.GetEffectiveProtocol()
	if proto != models.ProtocolAWG && proto != models.ProtocolVLESS && proto != models.ProtocolNaive {
		return fmt.Errorf("unsupported protocol %q: must be awg, vless, or naive", proto)
	}
	return nil
}

// GetEffectiveProtocol returns the normalized protocol, defaulting to awg.
func (r *GigahostDeployRequest) GetEffectiveProtocol() string {
	p := strings.TrimSpace(r.Protocol)
	if p == "" {
		return models.ProtocolAWG
	}
	return models.NormalizeProtocol(p)
}

// GetEffectivePort returns the default port for the protocol if omitted.
func (r *GigahostDeployRequest) GetEffectivePort() string {
	port := strings.TrimSpace(r.Port)
	if port != "" {
		return port
	}
	switch r.GetEffectiveProtocol() {
	case models.ProtocolVLESS, models.ProtocolNaive:
		return "443"
	default:
		return "51820"
	}
}

// GigahostDeployStatus tracks the execution state and diagnostics of a Gigahost VPS onboarding job.
type GigahostDeployStatus struct {
	OrderID          string    `json:"order_id"`
	ProviderServerID int64     `json:"provider_server_id,omitempty"`
	ServerID         int64     `json:"server_id,omitempty"` // Nexus DB server ID
	Status           string    `json:"status"`              // deploying, ssh_verifying, installing_protocol, enabling_backend, ready, failed
	Step             string    `json:"step,omitempty"`
	AssignedIP       string    `json:"assigned_ip,omitempty"`
	Protocol         string    `json:"protocol,omitempty"`
	Port             string    `json:"port,omitempty"`
	Error            string    `json:"error,omitempty"`
	Message          string    `json:"message,omitempty"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// SetSSHDialerForTest injects an SSH dialer hook for unit and integration testing.
func (h *Handlers) SetSSHDialerForTest(fn func(context.Context, ssh.Config) (ssh.SSHClient, error)) {
	h.sshDialerHook = fn
}

func (h *Handlers) dialDeploySSH(ctx context.Context, cfg ssh.Config) (ssh.SSHClient, error) {
	if h.sshDialerHook != nil {
		return h.sshDialerHook(ctx, cfg)
	}
	return ssh.Dial(ctx, cfg)
}

func (h *Handlers) verifyGigahostVPSReady(
	ctx context.Context,
	client gigahost.Client,
	req GigahostDeployRequest,
	order *GigahostOrderRecord,
) (string, int64, error) {
	assignedIP := strings.TrimSpace(req.AssignedIP)
	providerServerID := req.ProviderServerID
	if providerServerID == 0 && order != nil {
		providerServerID = order.ServerID
	}
	if assignedIP == "" && order != nil {
		assignedIP = order.AssignedIP
	}

	deployStatus, err := client.GetDeployStatus(ctx, req.OrderID)
	if err != nil && !errors.Is(err, gigahost.ErrNotFound) {
		return assignedIP, providerServerID, fmt.Errorf("failed to query gigahost deploy status: %w", err)
	}

	if deployStatus != nil {
		if isGigahostFailed(deployStatus.Status) {
			diag := deployStatus.Error
			if diag == "" {
				diag = "gigahost reported status " + deployStatus.Status
			}
			return assignedIP, providerServerID, fmt.Errorf("vps deployment failed at provider: %s", diag)
		}

		assignedIP, providerServerID = extractDeployIPAndID(deployStatus, assignedIP, providerServerID)

		if !isGigahostReady(deployStatus.Status) {
			if !req.WaitReady {
				return "", providerServerID, nil
			}
			polledStatus, pollErr := h.pollGigahostDeployReady(ctx, client, req.OrderID, req.WaitTimeoutSec)
			if pollErr != nil {
				return assignedIP, providerServerID, pollErr
			}
			if polledStatus == nil {
				return "", providerServerID, nil
			}
			assignedIP, providerServerID = extractDeployIPAndID(polledStatus, assignedIP, providerServerID)
		}
	}

	assignedIP, providerServerID = h.fallbackResolveServerInfo(ctx, client, req.OrderID, assignedIP, providerServerID)
	if assignedIP == "" {
		return "", providerServerID, errors.New("gigahost VPS is ready but no public IP assigned")
	}

	return assignedIP, providerServerID, nil
}

func (h *Handlers) pollGigahostDeployReady(
	ctx context.Context,
	client gigahost.Client,
	orderID string,
	timeoutSec int,
) (*gigahost.DeployStatusResponse, error) {
	maxWait := time.Duration(timeoutSec) * time.Second
	if maxWait <= 0 {
		maxWait = 30 * time.Second
	}
	pollCtx, cancel := context.WithTimeout(ctx, maxWait)
	defer cancel()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-pollCtx.Done():
			return nil, nil
		case <-ticker.C:
			st, pollErr := client.GetDeployStatus(pollCtx, orderID)
			if pollErr != nil {
				continue
			}
			if isGigahostFailed(st.Status) {
				return nil, fmt.Errorf("vps deployment failed at provider: %s", st.Error)
			}
			if isGigahostReady(st.Status) {
				return st, nil
			}
		}
	}
}

func (h *Handlers) failDeployStatus(
	ctx context.Context,
	orderID, step string,
	err error,
	providerServerID, nexusServerID int64,
	assignedIP, protocol, port string,
) (*GigahostDeployStatus, error) {
	diagErr := err.Error()
	persistCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	_ = h.updateDeployOrderStatus(persistCtx, orderID, DeployStatusFailed, step, diagErr, providerServerID, nexusServerID, assignedIP)
	if nexusServerID > 0 && h.vpnSvc != nil {
		_ = h.vpnSvc.DisableBackend(persistCtx, nexusServerID)
	}
	return &GigahostDeployStatus{
		OrderID:          orderID,
		ProviderServerID: providerServerID,
		ServerID:         nexusServerID,
		Status:           DeployStatusFailed,
		Step:             step,
		AssignedIP:       assignedIP,
		Protocol:         protocol,
		Port:             port,
		Error:            diagErr,
		UpdatedAt:        time.Now().UTC(),
	}, err
}

func (h *Handlers) resolveDeployServerID(ctx context.Context, assignedIP string, req GigahostDeployRequest) *int64 {
	if h.db != nil {
		if servers, err := h.db.GetAllServers(ctx); err == nil {
			for _, s := range servers {
				if strings.EqualFold(strings.TrimSpace(s.Host), strings.TrimSpace(assignedIP)) ||
					(req.ProviderServerID > 0 && matchProviderServerID(s.Protocols["provider_server_id"], req.ProviderServerID)) {
					id := s.ID
					return &id
				}
			}
		}
	}
	if req.OrderID != "" {
		if _, nexusID, _, _, err := h.getDeployOrderByID(ctx, req.OrderID); err == nil && nexusID > 0 {
			return &nexusID
		}
	}
	return nil
}

func validateSSHKeyInvariants(key gossh.PublicKey) error {
	if key == nil || len(key.Marshal()) < 32 {
		return errors.New("invalid host key: key material too short or nil")
	}
	keyType := key.Type()
	if keyType == gossh.KeyAlgoED25519 || keyType == gossh.KeyAlgoRSA ||
		strings.HasPrefix(keyType, "ecdsa-") || strings.HasPrefix(keyType, "ssh-") {
		return nil
	}
	return fmt.Errorf("invalid host key type: %s", keyType)
}

func (h *Handlers) buildDeployHostKeyCallback(
	ctx context.Context,
	req GigahostDeployRequest,
	serverID *int64,
	capturedFPOut *string,
) gossh.HostKeyCallback {
	expectedFP := strings.TrimSpace(req.ExpectedFingerprint)
	if expectedFP == "" {
		expectedFP = strings.TrimSpace(req.HostKeyFingerprint)
	}

	return func(hostname string, remote net.Addr, key gossh.PublicKey) error {
		if err := validateSSHKeyInvariants(key); err != nil {
			return err
		}

		actualFP := ssh.FingerprintSHA256(key)
		if capturedFPOut != nil {
			*capturedFPOut = actualFP
		}

		if expectedFP != "" {
			if !ssh.CompareFingerprints(expectedFP, actualFP) {
				return fmt.Errorf("host key fingerprint mismatch: expected %s, got %s", expectedFP, actualFP)
			}
			return nil
		}

		if serverID != nil && h.db != nil {
			knownFP, err := h.db.GetKnownHostFingerprint(ctx, *serverID)
			if err != nil {
				return fmt.Errorf("failed to query known host fingerprint: %w", err)
			}
			if strings.TrimSpace(knownFP) != "" {
				if ssh.CompareFingerprints(knownFP, actualFP) {
					return nil
				}
				return &ssh.ErrHostKeyMismatch{
					ServerID: *serverID,
					Host:     hostname,
					Expected: knownFP,
					Actual:   actualFP,
				}
			}
		}

		if !req.ConfirmHostKey {
			return fmt.Errorf("unconfirmed host key on first contact (%s); explicit confirmation or expected fingerprint required", actualFP)
		}
		return nil
	}
}

func (h *Handlers) verifyDeploySSHAccess(
	ctx context.Context,
	assignedIP string,
	req GigahostDeployRequest,
) (string, error) {
	sshPort := req.SSHPort
	if sshPort <= 0 {
		sshPort = 22
	}
	sshUser := strings.TrimSpace(req.SSHUser)
	if sshUser == "" {
		sshUser = "root"
	}

	serverID := h.resolveDeployServerID(ctx, assignedIP, req)
	var capturedFP string
	hostKeyCallback := h.buildDeployHostKeyCallback(ctx, req, serverID, &capturedFP)

	expectedFP := strings.TrimSpace(req.ExpectedFingerprint)
	if expectedFP == "" {
		expectedFP = strings.TrimSpace(req.HostKeyFingerprint)
	}

	sshCfg := ssh.Config{
		Host:                      assignedIP,
		Port:                      sshPort,
		User:                      sshUser,
		Password:                  req.SSHPassword,
		PrivateKey:                req.SSHPrivateKey,
		Timeout:                   15 * time.Second,
		Store:                     h.db,
		ServerID:                  serverID,
		RequireFingerprintConfirm: serverID == nil && expectedFP == "" && !req.ConfirmHostKey,
		HostKeyCallback:           hostKeyCallback,
	}

	client, err := h.dialDeploySSH(ctx, sshCfg)
	if err != nil {
		return "", err
	}
	defer client.Close()

	if fc, ok := client.(interface{ CapturedFingerprint() string }); ok {
		capturedFP = fc.CapturedFingerprint()
	}
	if capturedFP != "" {
		if err := validateFingerprintFormat(capturedFP); err != nil {
			return "", fmt.Errorf("invalid host key fingerprint received: %w", err)
		}
	}
	return capturedFP, nil
}

func validateFingerprintFormat(fp string) error {
	s := strings.TrimSpace(fp)
	if s == "" {
		return errors.New("empty host key fingerprint")
	}
	if len(s) < 8 {
		return fmt.Errorf("invalid host key fingerprint: %s", s)
	}
	return nil
}

func isDeployOrderResume(existingServer *models.Server, nexusServerID, providerServerID int64, order *GigahostOrderRecord, req GigahostDeployRequest, assignedIP string) bool {
	return (nexusServerID > 0 && nexusServerID == existingServer.ID) ||
		(order != nil && order.OrderID == req.OrderID && (order.ServerID == providerServerID || strings.EqualFold(order.AssignedIP, assignedIP)))
}

func (h *Handlers) reconcileExistingServerResume(
	ctx context.Context,
	existingServer *models.Server,
	req GigahostDeployRequest,
	fingerprint string,
) error {
	if fingerprint != "" {
		knownFP, err := h.db.GetKnownHostFingerprint(ctx, existingServer.ID)
		if err != nil {
			return fmt.Errorf("failed to query known host fingerprint: %w", err)
		}
		if strings.TrimSpace(knownFP) == "" {
			if err := h.db.SaveKnownHostFingerprint(ctx, existingServer.ID, fingerprint); err != nil {
				return fmt.Errorf("failed to save host key fingerprint: %w", err)
			}
		} else if !ssh.CompareFingerprints(knownFP, fingerprint) {
			return fmt.Errorf("host key mismatch for server %d: expected %s, got %s", existingServer.ID, knownFP, fingerprint)
		}
	}
	if req.SSHPassword != "" || req.SSHPrivateKey != "" {
		_ = h.db.UpdateServerCredentials(ctx, existingServer.ID, req.SSHPassword, req.SSHPrivateKey)
		if req.SSHPassword != "" {
			existingServer.SSHPass = req.SSHPassword
		}
		if req.SSHPrivateKey != "" {
			existingServer.SSHKey = req.SSHPrivateKey
		}
	}
	return nil
}

func (h *Handlers) registerDeployServer(
	ctx context.Context,
	req GigahostDeployRequest,
	order *GigahostOrderRecord,
	nexusServerID, providerServerID int64,
	assignedIP, fingerprint string,
) (*models.Server, error) {
	if h.db == nil {
		return nil, errors.New("database not available")
	}

	existingServer, registered, err := h.isProviderServerRegistered(ctx, "gigahost", providerServerID)
	if err != nil {
		return nil, fmt.Errorf("failed checking server deduplication: %w", err)
	}

	if registered && existingServer != nil {
		if isDeployOrderResume(existingServer, nexusServerID, providerServerID, order, req, assignedIP) {
			if err := h.reconcileExistingServerResume(ctx, existingServer, req, fingerprint); err != nil {
				return nil, err
			}
			return existingServer, nil
		}
		return nil, fmt.Errorf("%w: gigahost server ID %d is already registered as server %d", ErrDuplicateServerID, providerServerID, existingServer.ID)
	}

	serverName := strings.TrimSpace(req.ServerName)
	if serverName == "" {
		serverName = fmt.Sprintf("Gigahost-%s", req.OrderID)
	}
	sshPort := req.SSHPort
	if sshPort <= 0 {
		sshPort = 22
	}
	sshUser := strings.TrimSpace(req.SSHUser)
	if sshUser == "" {
		sshUser = "root"
	}

	newServer := &models.Server{
		Name:    serverName,
		Host:    assignedIP,
		SSHPort: sshPort,
		SSHUser: sshUser,
		SSHPass: req.SSHPassword,
		SSHKey:  req.SSHPrivateKey,
		Protocols: map[string]any{
			"provider":           "gigahost",
			"provider_server_id": providerServerID,
		},
		CreatedAt: time.Now().UTC(),
	}

	createdID, err := h.db.CreateServer(ctx, newServer)
	if err != nil {
		return nil, fmt.Errorf("failed to register server in database: %w", err)
	}
	newServer.ID = createdID

	if fingerprint != "" {
		if err := validateFingerprintFormat(fingerprint); err != nil {
			return nil, fmt.Errorf("invalid host key fingerprint: %w", err)
		}
		if err := h.db.SaveKnownHostFingerprint(ctx, createdID, fingerprint); err != nil {
			return nil, fmt.Errorf("failed to persist host key fingerprint: %w", err)
		}
	}

	return newServer, nil
}

func (h *Handlers) installDeployProtocol(
	ctx context.Context,
	server *models.Server,
	req GigahostDeployRequest,
) (string, error) {
	protocol := req.GetEffectiveProtocol()
	port := req.GetEffectivePort()

	// Ensure Docker prerequisite is bootstrapped for containerized protocols
	if err := h.ensureHostDockerPrerequisite(ctx, server, protocol); err != nil {
		return "", err
	}

	protoMgr, err := h.GetProtocolManager(protocol)
	if err != nil {
		return "", fmt.Errorf("protocol manager not found for %s: %w", protocol, err)
	}

	skipProbe := false
	if h.sshDialerHook != nil {
		skipProbe = true
	}

	params := map[string]any{
		"port":                port,
		"port_explicit":       true,
		"preserve_identity":   true,
		"preserve_containers": true,
		"reconcile":           true,
		"docker_bootstrapped": true,
		"skip_probe":          skipProbe,
	}
	if req.EngineProfile != "" {
		params["engine_profile"] = req.EngineProfile
	}
	if req.TLSDomain != "" {
		params["tls_domain"] = req.TLSDomain
	}
	if req.MaxConnections != nil {
		params["max_connections"] = *req.MaxConnections
	}
	if protocol == models.ProtocolVLESS {
		params["vless_options"] = &models.VLESSInstallOptions{
			Port:          port,
			ServerName:    req.TLSDomain,
			EngineProfile: req.EngineProfile,
		}
	} else if protocol == models.ProtocolNaive {
		params["naive_options"] = &models.NaiveInstallOptions{
			Port:   port,
			Domain: req.TLSDomain,
		}
	}

	if err := protoMgr.Install(ctx, server, params); err != nil {
		return "", err
	}

	auditPort, err := h.persistInstalledProtocol(ctx, server.ID, server, protocol, port)
	if err != nil {
		return "", fmt.Errorf("failed to persist installed protocol: %w", err)
	}
	return auditPort, nil
}

func (h *Handlers) enableDeployBackend(
	ctx context.Context,
	server *models.Server,
	protocol string,
) error {
	if h.vpnSvc == nil {
		return nil
	}

	normProto := models.NormalizeTunnelProtocol(protocol)
	if normProto == models.ProtocolVLESS || normProto == models.ProtocolNaive {
		params, _, _, err := h.resolveInstalledProxyParamsForProto(ctx, server, normProto)
		if err != nil {
			return fmt.Errorf("failed to provision proxy client credentials: %w", err)
		}
		opts := []tunnel.BackendTunnelOptions{
			{
				Protocol:       normProto,
				ProtocolParams: params,
			},
		}
		return h.vpnSvc.EnableBackendWithConfig(ctx, server.ID, opts...)
	}

	enrollCtx := context.WithValue(ctx, tunnel.DeployEnrollmentKey, true)
	opts := []tunnel.BackendTunnelOptions{
		{
			Protocol: normProto,
		},
	}
	if err := h.vpnSvc.EnableBackendWithConfig(enrollCtx, server.ID, opts...); err != nil {
		return err
	}
	return h.qualifyBackendTraffic(ctx, server, protocol)
}

func (h *Handlers) qualifyBackendTraffic(ctx context.Context, server *models.Server, protocol string) error {
	if h.vpnSvc == nil {
		return nil
	}
	tun, err := h.vpnSvc.GetTunnel(server.ID)
	if err != nil || tun == nil {
		return fmt.Errorf("backend tunnel not found for server %d", server.ID)
	}
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	latency, err := h.vpnSvc.ProbeTunnel(probeCtx, tun)
	if err != nil {
		_ = h.vpnSvc.SetTunnelStatus(ctx, server.ID, models.TunnelStatusDegraded, 0)
		_ = h.vpnSvc.DisableBackend(ctx, server.ID)
		return fmt.Errorf("backend traffic qualification probe failed: %w", err)
	}
	if latency <= 0 {
		latency = 10
	}
	return h.vpnSvc.SetTunnelStatus(ctx, server.ID, models.TunnelStatusActive, latency)
}

// DeployGigahostOrder orchestrates the multi-step onboarding of a ready Gigahost VPS into an active VPN backend.
func (h *Handlers) DeployGigahostOrder(ctx context.Context, req GigahostDeployRequest) (*GigahostDeployStatus, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	client, err := h.getGigahostClient(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("gigahost client unavailable: %w", err)
	}

	if err := h.ensureGigahostDeploySchema(ctx); err != nil {
		return nil, fmt.Errorf("failed to init deploy schema: %w", err)
	}

	unlock, ok := h.lockGigahostDeploy(req.OrderID)
	if !ok {
		return nil, fmt.Errorf("deployment already in progress for order %s", req.OrderID)
	}
	defer unlock()

	order, nexusServerID, _, _, err := h.getDeployOrderByID(ctx, req.OrderID)
	if err != nil {
		return nil, fmt.Errorf("failed to load order %s: %w", req.OrderID, err)
	}

	// 1. Verify Deployment Status
	assignedIP, providerServerID, err := h.verifyGigahostVPSReady(ctx, client, req, order)
	if err != nil {
		return h.failDeployStatus(ctx, req.OrderID, DeployStatusDeploying, err, providerServerID, nexusServerID, assignedIP, "", "")
	}
	if assignedIP == "" {
		_ = h.updateDeployOrderStatus(ctx, req.OrderID, DeployStatusDeploying, DeployStatusDeploying, "", providerServerID, nexusServerID, "")
		return &GigahostDeployStatus{
			OrderID:          req.OrderID,
			ProviderServerID: providerServerID,
			ServerID:         nexusServerID,
			Status:           DeployStatusDeploying,
			Step:             DeployStatusDeploying,
			Message:          "Gigahost VPS is currently deploying",
			UpdatedAt:        time.Now().UTC(),
		}, nil
	}

	// 2. SSH Verification & Host Identity Check
	_ = h.updateDeployOrderStatus(ctx, req.OrderID, DeployStatusSSHVerifying, DeployStatusSSHVerifying, "", providerServerID, nexusServerID, assignedIP)
	fingerprint, err := h.verifyDeploySSHAccess(ctx, assignedIP, req)
	if err != nil {
		return h.failDeployStatus(ctx, req.OrderID, DeployStatusSSHVerifying, fmt.Errorf("SSH verification failed: %w", err), providerServerID, nexusServerID, assignedIP, "", "")
	}

	// 3. Server Registration & Deduplication
	_ = h.updateDeployOrderStatus(ctx, req.OrderID, DeployStatusInstallingProtocol, "server_registration", "", providerServerID, nexusServerID, assignedIP)
	server, err := h.registerDeployServer(ctx, req, order, nexusServerID, providerServerID, assignedIP, fingerprint)
	if err != nil {
		return h.failDeployStatus(ctx, req.OrderID, "server_registration", err, providerServerID, nexusServerID, assignedIP, "", "")
	}
	nexusServerID = server.ID
	_ = h.updateDeployOrderStatus(ctx, req.OrderID, DeployStatusInstallingProtocol, "server_registration", "", providerServerID, nexusServerID, assignedIP)

	// 4. Protocol Installation
	if nexusServerID > 0 && h.vpnSvc != nil {
		_ = h.vpnSvc.DisableBackend(ctx, nexusServerID)
	}
	_ = h.updateDeployOrderStatus(ctx, req.OrderID, DeployStatusInstallingProtocol, DeployStatusInstallingProtocol, "", providerServerID, nexusServerID, assignedIP)
	protocol := req.GetEffectiveProtocol()
	port, err := h.installDeployProtocol(ctx, server, req)
	if err != nil {
		return h.failDeployStatus(ctx, req.OrderID, DeployStatusInstallingProtocol, fmt.Errorf("protocol %s installation failed: %w", protocol, err), providerServerID, nexusServerID, assignedIP, protocol, "")
	}

	// 5. Backend Enablement
	_ = h.updateDeployOrderStatus(ctx, req.OrderID, DeployStatusEnablingBackend, DeployStatusEnablingBackend, "", providerServerID, nexusServerID, assignedIP)
	if err := h.enableDeployBackend(ctx, server, protocol); err != nil {
		if nexusServerID > 0 && h.vpnSvc != nil {
			_ = h.vpnSvc.DisableBackend(ctx, nexusServerID)
		}
		if strings.Contains(err.Error(), "traffic qualification") {
			st, _ := h.failDeployStatus(ctx, req.OrderID, DeployStatusEnablingBackend, fmt.Errorf("backend enablement failed: %w", err), providerServerID, nexusServerID, assignedIP, protocol, port)
			return st, nil
		}
		return h.failDeployStatus(ctx, req.OrderID, DeployStatusEnablingBackend, fmt.Errorf("backend enablement failed: %w", err), providerServerID, nexusServerID, assignedIP, protocol, port)
	}

	// 6. Ready State
	_ = h.updateDeployOrderStatus(ctx, req.OrderID, DeployStatusReady, DeployStatusReady, "", providerServerID, nexusServerID, assignedIP)
	return &GigahostDeployStatus{
		OrderID:          req.OrderID,
		ProviderServerID: providerServerID,
		ServerID:         nexusServerID,
		Status:           DeployStatusReady,
		Step:             DeployStatusReady,
		AssignedIP:       assignedIP,
		Protocol:         protocol,
		Port:             port,
		Message:          "Gigahost VPS successfully onboarded as healthy VPN backend",
		UpdatedAt:        time.Now().UTC(),
	}, nil
}

// GetGigahostDeployStatus returns current deployment status and refreshes from upstream if in-flight.
func (h *Handlers) GetGigahostDeployStatus(ctx context.Context, orderID string) (*GigahostDeployStatus, error) {
	order, nexusServerID, lastError, step, err := h.getDeployOrderByID(ctx, orderID)
	if err != nil {
		return nil, err
	}
	if order == nil {
		return nil, fmt.Errorf("order %s not found", orderID)
	}

	if order.Status == DeployStatusDeploying || order.Status == gigahost.StatusPending || order.Status == gigahost.StatusWaiting {
		client, clientErr := h.getGigahostClient(ctx, nil)
		if clientErr == nil {
			if st, err := client.GetDeployStatus(ctx, orderID); err == nil && st != nil {
				if ip := st.GetIP(); ip != "" && order.AssignedIP == "" {
					order.AssignedIP = ip
				}
				if st.ServerID > 0 && order.ServerID == 0 {
					order.ServerID = st.ServerID
				}
				if isGigahostReady(st.Status) {
					order.Status = DeployStatusReady
				} else if isGigahostFailed(st.Status) {
					order.Status = DeployStatusFailed
					lastError = st.Error
				}
				_ = h.updateDeployOrderStatus(ctx, orderID, order.Status, step, lastError, order.ServerID, nexusServerID, order.AssignedIP)
			}
		}
	}

	return &GigahostDeployStatus{
		OrderID:          order.OrderID,
		ProviderServerID: order.ServerID,
		ServerID:         nexusServerID,
		Status:           order.Status,
		Step:             step,
		AssignedIP:       order.AssignedIP,
		Error:            lastError,
		UpdatedAt:        order.UpdatedAt,
	}, nil
}

// GigahostDeployHandler handles POST /api/admin/hosting/gigahost/deploy.
func (h *Handlers) GigahostDeployHandler(w http.ResponseWriter, r *http.Request) {
	sess := middleware.GetSession(r.Context())
	if sess == nil || sess.Role != models.RoleAdmin {
		h.JSONError(w, http.StatusForbidden, "forbidden", "Admin privileges required")
		return
	}

	var req GigahostDeployRequest
	if r.Body != nil && r.Body != http.NoBody {
		if err := json.NewDecoder(io.LimitReader(r.Body, 65536)).Decode(&req); err != nil {
			h.JSONError(w, http.StatusBadRequest, "invalid_payload", "Failed to parse request JSON")
			return
		}
	}

	if req.OrderID == "" {
		req.OrderID = chi.URLParam(r, "order_id")
	}
	if req.OrderID == "" {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "order_id is required")
		return
	}

	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Now().Add(middleware.InstallRequestTimeout))

	status, err := h.DeployGigahostOrder(r.Context(), req)
	if err != nil {
		if errors.Is(err, ErrDuplicateServerID) || strings.Contains(err.Error(), "duplicate server registration rejected") {
			h.JSONError(w, http.StatusConflict, "duplicate_server_id", err.Error())
			return
		}
		if strings.Contains(err.Error(), "already in progress") {
			h.JSONError(w, http.StatusConflict, "in_progress", err.Error())
			return
		}
		if strings.Contains(err.Error(), "validation") || strings.Contains(err.Error(), "required") || strings.Contains(err.Error(), "unsupported protocol") {
			h.JSONError(w, http.StatusBadRequest, "validation_failed", err.Error())
			return
		}
		h.JSON(w, http.StatusBadGateway, map[string]any{
			"status": DeployStatusFailed,
			"error":  err.Error(),
			"deploy": status,
		})
		return
	}

	h.JSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"deploy": status,
	})
}

// GigahostDeployStatusHandler handles GET /api/admin/hosting/gigahost/deploy/{order_id}.
func (h *Handlers) GigahostDeployStatusHandler(w http.ResponseWriter, r *http.Request) {
	sess := middleware.GetSession(r.Context())
	if sess == nil || sess.Role != models.RoleAdmin {
		h.JSONError(w, http.StatusForbidden, "forbidden", "Admin privileges required")
		return
	}

	orderID := chi.URLParam(r, "order_id")
	if orderID == "" {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "order_id is required")
		return
	}

	status, err := h.GetGigahostDeployStatus(r.Context(), orderID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || strings.Contains(err.Error(), "not found") {
			h.JSONError(w, http.StatusNotFound, "not_found", fmt.Sprintf("order %s not found", orderID))
			return
		}
		h.JSONError(w, http.StatusInternalServerError, "db_error", err.Error())
		return
	}

	h.JSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"deploy": status,
	})
}
