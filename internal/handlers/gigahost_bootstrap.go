package handlers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/naive"
	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/manager/xray"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// dockerBootstrapScript is the host prerequisite bootstrap script ensuring Docker is installed on Linux VPS.
const dockerBootstrapScript = `
if which apt-get > /dev/null 2>&1; then pm=$(which apt-get); silent_inst="-yq install"; check_pkgs="-yq update"; docker_pkg="docker.io"; dist="debian";
elif which dnf > /dev/null 2>&1; then pm=$(which dnf); silent_inst="-yq install"; check_pkgs="-yq check-update"; docker_pkg="docker"; dist="fedora";
elif which yum > /dev/null 2>&1; then pm=$(which yum); silent_inst="-y -q install"; check_pkgs="-y -q check-update"; docker_pkg="docker"; dist="centos";
else echo "Packet manager not found"; exit 1; fi;
if [ "$dist" = "debian" ]; then export DEBIAN_FRONTEND=noninteractive; fi;
if ! command -v docker > /dev/null 2>&1; then $pm $check_pkgs && $pm $silent_inst $docker_pkg && systemctl enable --now docker; fi;
systemctl start docker; docker --version
`

// ensureHostDockerPrerequisite verifies Docker is available on the remote server before invoking
// managers (like Xray and NaiveProxy) that require container runtime. If missing, it executes
// host bootstrap installation.
func (h *Handlers) ensureHostDockerPrerequisite(ctx context.Context, server *models.Server, protocol string) error {
	normProto := models.NormalizeProtocol(protocol)
	if normProto != models.ProtocolVLESS && normProto != models.ProtocolNaive {
		return nil
	}

	client, err := h.resolveDeploySSHClient(ctx, server, normProto)
	if err != nil {
		return fmt.Errorf("failed to obtain SSH client for Docker bootstrap: %w", err)
	}

	out, _, code, _ := client.RunCommand(ctx, "docker --version")
	if code == 0 && strings.Contains(strings.ToLower(out), "docker") {
		return nil
	}

	if _, errOut, dCode, err := client.RunSudoScript(ctx, dockerBootstrapScript); err != nil || dCode != 0 {
		return fmt.Errorf("failed to bootstrap Docker prerequisite on host (code %d): %s, %w", dCode, errOut, err)
	}

	return nil
}

func (h *Handlers) resolveDeploySSHClient(ctx context.Context, server *models.Server, protocol string) (ssh.SSHClient, error) {
	if h.registry != nil {
		if mgr, ok := h.registry.Get(protocol); ok && mgr != nil {
			if xm, ok := mgr.(*xray.XrayManager); ok && xm != nil && xm.SSHProvider() != nil {
				return xm.SSHProvider().Get(ctx, server)
			}
			if nm, ok := mgr.(*naive.NaiveManager); ok && nm != nil && nm.SSHProvider() != nil {
				return nm.SSHProvider().Get(ctx, server)
			}
		}
	}
	if h.sshDialerHook != nil {
		sshPort := server.SSHPort
		if sshPort <= 0 {
			sshPort = 22
		}
		sshUser := strings.TrimSpace(server.SSHUser)
		if sshUser == "" {
			sshUser = "root"
		}
		sshCfg := ssh.Config{
			Host:       server.Host,
			Port:       sshPort,
			User:       sshUser,
			Password:   server.SSHPass,
			PrivateKey: server.SSHKey,
			Timeout:    15 * time.Second,
			Store:      h.db,
		}
		return h.dialDeploySSH(ctx, sshCfg)
	}
	if h.sshPool != nil {
		return h.sshPool.Get(ctx, server)
	}
	return nil, errors.New("no SSH provider available for host bootstrap")
}

func (h *Handlers) ensureGigahostDeploySchema(ctx context.Context) error {
	if h.db == nil || h.db.SQLDB() == nil {
		return nil
	}
	if err := h.ensureGigahostOrdersTable(ctx); err != nil {
		return err
	}
	cols := []string{
		"ALTER TABLE gigahost_orders ADD COLUMN nexus_server_id INTEGER DEFAULT 0",
		"ALTER TABLE gigahost_orders ADD COLUMN last_error TEXT DEFAULT ''",
		"ALTER TABLE gigahost_orders ADD COLUMN step TEXT DEFAULT ''",
	}
	for _, q := range cols {
		_, _ = h.db.SQLDB().ExecContext(ctx, q)
	}
	return nil
}

func (h *Handlers) lockGigahostDeploy(orderID string) (func(), bool) {
	h.gigahostDeployMu.Lock()
	if h.gigahostDeployLocks == nil {
		h.gigahostDeployLocks = make(map[string]*sync.Mutex)
	}
	mu, ok := h.gigahostDeployLocks[orderID]
	if !ok {
		mu = &sync.Mutex{}
		h.gigahostDeployLocks[orderID] = mu
	}
	h.gigahostDeployMu.Unlock()

	if !mu.TryLock() {
		return nil, false
	}
	return mu.Unlock, true
}

func (h *Handlers) isProviderServerRegistered(ctx context.Context, provider string, providerServerID int64) (*models.Server, bool, error) {
	if h.db == nil {
		return nil, false, nil
	}
	servers, err := h.db.GetAllServers(ctx)
	if err != nil {
		return nil, false, err
	}
	for _, s := range servers {
		if s.Protocols == nil {
			continue
		}
		p, ok := s.Protocols["provider"].(string)
		if !ok || !strings.EqualFold(p, provider) {
			continue
		}
		if matchProviderServerID(s.Protocols["provider_server_id"], providerServerID) {
			match := s
			return &match, true, nil
		}
	}
	return nil, false, nil
}

func matchProviderServerID(val any, expected int64) bool {
	if val == nil {
		return false
	}
	switch v := val.(type) {
	case int64:
		return v == expected
	case int:
		return int64(v) == expected
	case float64:
		return int64(v) == expected
	case string:
		return v == strconv.FormatInt(expected, 10)
	}
	return false
}

func (h *Handlers) getDeployOrderByID(ctx context.Context, orderID string) (*GigahostOrderRecord, int64, string, string, error) {
	if err := h.ensureGigahostDeploySchema(ctx); err != nil {
		return nil, 0, "", "", err
	}
	if h.db == nil || h.db.SQLDB() == nil {
		return nil, 0, "", "", nil
	}
	q := `SELECT id, order_id, server_id, status, plan_id, region_id, hourly_price_nok, assigned_ip, created_at, updated_at, nexus_server_id, last_error, step
	      FROM gigahost_orders WHERE order_id = ?`
	row := h.db.SQLDB().QueryRowContext(ctx, q, orderID)
	var o GigahostOrderRecord
	var createdAtStr, updatedAtStr string
	var assignedIP, lastError, step sql.NullString
	var nexusServerID sql.NullInt64
	err := row.Scan(&o.ID, &o.OrderID, &o.ServerID, &o.Status, &o.PlanID, &o.RegionID, &o.HourlyPriceNOK, &assignedIP, &createdAtStr, &updatedAtStr, &nexusServerID, &lastError, &step)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, 0, "", "", nil
		}
		return nil, 0, "", "", err
	}
	if assignedIP.Valid {
		o.AssignedIP = assignedIP.String
	}
	o.CreatedAt, _ = time.Parse(time.RFC3339, createdAtStr)
	o.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAtStr)
	return &o, nexusServerID.Int64, lastError.String, step.String, nil
}

func (h *Handlers) updateDeployOrderStatus(
	ctx context.Context,
	orderID string,
	status, step, lastErr string,
	providerServerID, nexusServerID int64,
	assignedIP string,
) error {
	if h.db == nil || h.db.SQLDB() == nil {
		return nil
	}
	_ = h.ensureGigahostDeploySchema(ctx)
	now := time.Now().UTC().Format(time.RFC3339)
	q := `UPDATE gigahost_orders
	      SET status = ?,
	          step = ?,
	          last_error = ?,
	          server_id = CASE WHEN ? > 0 THEN ? ELSE server_id END,
	          nexus_server_id = CASE WHEN ? > 0 THEN ? ELSE nexus_server_id END,
	          assigned_ip = CASE WHEN ? != '' THEN ? ELSE assigned_ip END,
	          updated_at = ?
	      WHERE order_id = ?`
	res, err := h.db.SQLDB().ExecContext(ctx, q,
		status,
		step,
		lastErr,
		providerServerID, providerServerID,
		nexusServerID, nexusServerID,
		assignedIP, assignedIP,
		now,
		orderID,
	)
	if err != nil {
		return err
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		insertQ := `INSERT INTO gigahost_orders (
			order_id, server_id, status, plan_id, region_id, hourly_price_nok, assigned_ip, created_at, updated_at, nexus_server_id, last_error, step
		) VALUES (?, ?, ?, 0, 0, 0.0, ?, ?, ?, ?, ?, ?)`
		_, err = h.db.SQLDB().ExecContext(ctx, insertQ,
			orderID,
			providerServerID,
			status,
			assignedIP,
			now,
			now,
			nexusServerID,
			lastErr,
			step,
		)
		return err
	}
	return nil
}

func isGigahostReady(status string) bool {
	s := strings.ToLower(strings.TrimSpace(status))
	return s == gigahost.StatusReady || s == "active"
}

func isGigahostFailed(status string) bool {
	s := strings.ToLower(strings.TrimSpace(status))
	return s == gigahost.StatusFailed || s == "error" || s == statusCancelled || s == "canceled" || s == "deleted"
}

func extractDeployIPAndID(st *gigahost.DeployStatusResponse, currentIP string, currentID int64) (string, int64) {
	ip := currentIP
	if st != nil && st.GetIP() != "" {
		ip = st.GetIP()
	}
	id := currentID
	if st != nil && st.ServerID > 0 {
		id = st.ServerID
	}
	return ip, id
}

func (h *Handlers) fallbackResolveServerInfo(
	ctx context.Context,
	client gigahost.Client,
	orderID string,
	assignedIP string,
	providerServerID int64,
) (string, int64) {
	if client == nil {
		return assignedIP, providerServerID
	}
	servers, err := client.GetServers(ctx)
	if err != nil {
		return assignedIP, providerServerID
	}
	for _, s := range servers {
		if (orderID != "" && s.OrderID == orderID) || (providerServerID > 0 && s.ID == providerServerID) {
			ip := assignedIP
			if ip == "" && s.IPv4 != "" {
				ip = s.IPv4
			}
			id := providerServerID
			if id == 0 && s.ID > 0 {
				id = s.ID
			}
			return ip, id
		}
	}
	return assignedIP, providerServerID
}
