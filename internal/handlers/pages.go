package handlers

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// IndexPageHandler renders the primary admin dashboard or redirects normal users.
func (h *Handlers) IndexPageHandler(w http.ResponseWriter, r *http.Request) {
	sess := h.GetSession(r)
	if sess != nil && sess.Role == models.RoleUser {
		http.Redirect(w, r, "/my", http.StatusFound)
		return
	}

	ctx := r.Context()
	allServers, _ := h.db.GetAllServers(ctx)

	// The deployments section is decided against the whole server read, before the
	// grid is narrowed: a deployment whose server the provider no longer lists has a
	// server row of its own, and deciding the deployments from the narrowed list would
	// put that deployment back on the page as one that has no server yet - the exact
	// row the grid is hiding.
	deployments := h.gigahostDeploymentsForServersPage(ctx, allServers)

	// Deployments this panel has ordered but not set up have no servers row, so the
	// grid alone cannot show them; they are named here and rendered beside it.
	_ = RenderTemplate(w, r, h.db, "index.html", map[string]any{
		"servers":     serversListedOnServersPage(allServers),
		"deployments": deployments,
	})
}

// serversListedOnServersPage is the one decision about which server rows the Servers
// section lists.
//
// A row the provider's own inventory has confirmed absent is left out. The row itself
// is kept - it is the panel's record, and Recent Deployments still names the order - but
// it is not a server the panel can reach, so offering it as a card would offer actions
// the rest of the panel refuses. Every other row is passed through unchanged and in its
// original order, whether the panel provisioned it or an operator added it: the section
// has one grid and no provider-based grouping.
func serversListedOnServersPage(servers []models.Server) []models.Server {
	listed := make([]models.Server, 0, len(servers))
	for i := range servers {
		if servers[i].ProviderAbsent() {
			continue
		}
		listed = append(listed, servers[i])
	}
	return listed
}

// UsersPageHandler renders the multi-user management interface.
func (h *Handlers) UsersPageHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	users, _ := h.db.GetAllUsers(ctx)
	servers, _ := h.db.GetAllServers(ctx)

	_ = RenderTemplate(w, r, h.db, "users.html", map[string]any{
		"users":   users,
		"servers": servers,
	})
}

// ServerPageHandler renders a single server management interface.
func (h *Handlers) ServerPageHandler(w http.ResponseWriter, r *http.Request) {
	serverID, err := parseServerID(r)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	ctx := r.Context()
	server, err := h.db.GetServer(ctx, serverID)
	if err != nil || server == nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	users, _ := h.db.GetAllUsers(ctx)

	_ = RenderTemplate(w, r, h.db, "server.html", map[string]any{
		"server":    server,
		"server_id": serverID,
		"users":     users,
	})
}

// SettingsPageHandler renders system-wide settings.
func (h *Handlers) SettingsPageHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	servers, _ := h.db.GetAllServers(ctx)
	settings, _ := h.db.GetAllSettings(ctx)
	// The page obeys the same secret policy as GET /api/settings: no stored
	// credential reaches the markup.
	maskSettingsSecrets(settings)

	_ = RenderTemplate(w, r, h.db, "settings.html", map[string]any{
		"servers":  servers,
		"settings": settings,
	})
}

// VPNPageHandler renders the VPN overview: the four essential signals and the
// listener/public-endpoint disclosure. Everything it shows is fetched client-side
// from /api/vpn/status and /api/vpn/config, so the page itself carries no data.
//
// The VPN subject is split across three documents (overview, backends,
// diagnostics) and each one marks its own sidebar entry current here rather than
// by prefix, because /vpn is a prefix of the other two.
func (h *Handlers) VPNPageHandler(w http.ResponseWriter, r *http.Request) {
	_ = RenderTemplate(w, r, h.db, "vpn.html", map[string]any{
		"active_page": "vpn",
	})
}

// VPNBackendsPageHandler renders the VPN backend inventory: the table, its row
// actions and the add-backend dialog. The inventory, the eligible servers and the
// enable/disable/delete writes are all /api/vpn/* and /api/servers requests.
func (h *Handlers) VPNBackendsPageHandler(w http.ResponseWriter, r *http.Request) {
	_ = RenderTemplate(w, r, h.db, "vpn_backends.html", map[string]any{
		"active_page": "vpn_backends",
	})
}

// VPNDiagnosticsPageHandler renders forwarder health, the Advanced Diagnostics
// disclosure and the connection (sessions) table. Health and sessions are read
// from /api/vpn/status and /api/vpn/sessions after load.
func (h *Handlers) VPNDiagnosticsPageHandler(w http.ResponseWriter, r *http.Request) {
	_ = RenderTemplate(w, r, h.db, "vpn_diagnostics.html", map[string]any{
		"active_page": "vpn_diagnostics",
	})
}

// RoutingPageHandler renders the policy routing page: the four readouts, the
// configuration form and the per-client diagnosis card. It is its own page rather
// than a Settings section, so it is registered in the admin-only route group and
// marks the sidebar entry current server-side.
//
// The page renders no policy data of its own: every value on it is read from
// /api/vpn/policy after load, exactly as it was when the same cards lived in
// Settings.
func (h *Handlers) RoutingPageHandler(w http.ResponseWriter, r *http.Request) {
	_ = RenderTemplate(w, r, h.db, "routing.html", map[string]any{
		"active_page": "routing",
	})
}

// SanitizedServerForUser represents a safe server view for regular panel users.
type SanitizedServerForUser struct {
	ID        int64                      `json:"id"`
	Name      string                     `json:"name"`
	Protocols map[string]map[string]bool `json:"protocols"`
	Status    string                     `json:"status,omitempty"`
	Reachable bool                       `json:"reachable"`
}

// MyConnectionsPageHandler renders the user client connection dashboard.
func (h *Handlers) MyConnectionsPageHandler(w http.ResponseWriter, r *http.Request) {
	sess := h.GetSession(r)
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	ctx := r.Context()
	conns, _ := h.db.GetConnectionsByUserID(ctx, sess.UserID)
	rawServers, _ := h.db.GetAllServers(ctx)

	sanitizedServers := make([]SanitizedServerForUser, 0, len(rawServers))
	serversMap := make(map[int64]SanitizedServerForUser)
	for _, srv := range rawServers {
		name := srv.Name
		if strings.TrimSpace(name) == "" {
			name = fmt.Sprintf("Server #%d", srv.ID)
		}
		protoMap := make(map[string]map[string]bool)
		for proto, pVal := range srv.Protocols {
			installed := false
			if m, ok := pVal.(map[string]any); ok {
				if inst, ok := m["installed"].(bool); ok {
					installed = inst
				}
			} else if b, ok := pVal.(bool); ok {
				installed = b
			}
			protoMap[proto] = map[string]bool{"installed": installed}
		}
		status := string(srv.Status)
		if status == "" {
			status = "online"
		}
		reachable := srv.Reachable()
		sClean := SanitizedServerForUser{
			ID:        srv.ID,
			Name:      name,
			Protocols: protoMap,
			Status:    status,
			Reachable: reachable,
		}
		sanitizedServers = append(sanitizedServers, sClean)
		serversMap[srv.ID] = sClean
	}

	displayConns := make([]models.UserConnection, len(conns))
	for i := range conns {
		displayConns[i] = conns[i]
		if sClean, ok := serversMap[conns[i].ServerID]; ok {
			displayConns[i].ServerName = sClean.Name
		} else if conns[i].ServerID == 0 {
			displayConns[i].ServerName = "Load Balancer (Auto)"
		} else if conns[i].ServerID > 0 {
			displayConns[i].ServerName = fmt.Sprintf("Server #%d", conns[i].ServerID)
		}
	}

	vpnEnabled := h.vpnSvc != nil

	_ = RenderTemplate(w, r, h.db, "my_connections.html", map[string]any{
		"connections": displayConns,
		"servers":     sanitizedServers,
		"vpn_enabled": vpnEnabled,
	})
}

// SetupPageHandler renders the initial admin account setup wizard.
func (h *Handlers) SetupPageHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	count, _ := h.db.CountUsers(ctx)
	if count > 0 {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	_ = RenderTemplate(w, r, h.db, "setup.html", nil)
}

// ChangePasswordPageHandler renders the password change interface.
func (h *Handlers) ChangePasswordPageHandler(w http.ResponseWriter, r *http.Request) {
	forced := r.URL.Query().Get("forced") == "1"
	_ = RenderTemplate(w, r, h.db, "change_password.html", map[string]any{
		"forced": forced,
	})
}

// LeaderboardPageHandler renders the traffic leaderboard interface.
func (h *Handlers) LeaderboardPageHandler(w http.ResponseWriter, r *http.Request) {
	period := r.URL.Query().Get("period")
	if period != "monthly" && period != "last-month" {
		period = "all-time"
	}

	var monthlyLabel *string
	now := time.Now()
	if period == "monthly" {
		label := now.Format("January 2006")
		monthlyLabel = &label
	} else if period == "last-month" {
		lastMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location()).AddDate(0, -1, 0)
		label := lastMonth.Format("January 2006")
		monthlyLabel = &label
	}

	ctx := r.Context()
	entries, _ := h.db.GetLeaderboard(ctx, period)

	sess := h.GetSession(r)
	var currentUserRank *int
	for _, e := range entries {
		if sess != nil && sess.Username == e.Username {
			rankVal := e.Rank
			currentUserRank = &rankVal
			break
		}
	}

	_ = RenderTemplate(w, r, h.db, "leaderboard.html", map[string]any{
		"period":            period,
		"entries":           entries,
		"current_user_rank": currentUserRank,
		"monthly_label":     monthlyLabel,
	})
}
