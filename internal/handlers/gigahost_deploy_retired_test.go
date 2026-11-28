package handlers

// Retirement is a hard stop for the immediate setup entry too.
//
// The saved-approval path is not the only way setup starts. An administrator can open the
// Setup dialog on a ready order and submit it, and that request reaches one preamble through
// two routes: POST /deploy and POST /orders/{order_id}/setup. Neither route asked whether the
// order had ended, so an order the panel already presented as DELETED could still register a
// server, install a protocol and reach backend enablement.
//
// The window is the dialog, not the button. An inventory refresh records the absence while
// the form is open, and the form submits the identity the provider's detail read still
// reports - which is the inconsistent provider answer the order-absence record exists to
// represent. Removing the button would not have refused that request.
//
// Every case drives the real handler, the real SQLite ledger and the real install pipeline
// over the existing controlled provider/SSH/manager/traffic seams. The retirement itself is
// recorded by the real list read, so the fixture cannot claim an ending the product would not
// record.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// staleDialogRequestState is one immediate-setup submission against a real ledger row.
type staleDialogRequestState struct {
	// Retire makes the inventory omit the order before the request is submitted.
	Retire bool
	// Route is the path the administrator's form posts to. Both routes are aliases of one
	// handler, so a guard in one of them would leave the other reachable.
	Route string
}

// TestRetiredOrderRefusesImmediateSetup is the immediate-setup regression.
//
// The order is ready and its deployment detail still answers ready, so every identity the
// request needs is available. The inventory has already recorded a complete own-account
// omission, which is the panel's own statement that the deployment is gone. The submitted
// dialog must be refused before any provider detail read, SSH dial, registration, install or
// enablement, and the refusal must name the order rather than a transport fault.
//
// The control is the identical request against a live order, through the same route: it must
// still deploy, so the correction refuses retired orders rather than immediate setup.
func TestRetiredOrderRefusesImmediateSetup(t *testing.T) {
	cases := []staleDialogRequestState{
		{Retire: false, Route: "/api/admin/hosting/gigahost/deploy"},
		{Retire: false, Route: "/api/admin/hosting/gigahost/orders/%s/setup"},
		{Retire: true, Route: "/api/admin/hosting/gigahost/deploy"},
		{Retire: true, Route: "/api/admin/hosting/gigahost/orders/%s/setup"},
	}
	for _, tc := range cases {
		name := "live-control"
		if tc.Retire {
			name = "retired"
		}
		if strings.Contains(tc.Route, "%s") {
			name += "-setup-alias"
		} else {
			name += "-deploy"
		}
		t.Run(name, func(t *testing.T) {
			env := newInstallEnv(t, models.ProtocolAWG)
			ctx := context.Background()
			const orderID = "ord_stale_dialog"
			const providerServerID = int64(7402)
			const ip = "198.51.100.42"

			env.seedOrder(orderID, providerServerID, ip)
			env.seedManagedCredential(orderID)
			if err := env.h.updateDeployOrderStatus(ctx, orderID, gigahost.StatusReady, "", "", providerServerID, 0, ip); err != nil {
				t.Fatalf("record the ready ledger row: %v", err)
			}
			if err := env.db.SetGigahostOrderProviderAccount(ctx, orderID, existenceAccount); err != nil {
				t.Fatalf("record the order's account: %v", err)
			}

			// The provider's detail answer stays ready in both directions: the trigger is
			// the inventory's answer, which is the panel's own existence observation.
			inventory := []gigahost.ServerInfo{{ID: providerServerID, OrderID: orderID, Status: gigahost.StatusReady}}
			if tc.Retire {
				inventory = nil
			}
			provider := existenceProvider(t, inventory, nil, nil)
			provider.getDeployStatusFn = func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
				return &gigahost.DeployStatusResponse{OrderID: orderID, ServerID: providerServerID, AssignedIP: ip, Status: gigahost.StatusReady}, nil
			}
			env.h.SetGigahostClient(provider)

			// The inventory refresh that happens while the dialog is open.
			_ = gigahostOrderStatusRead(t, env.h, "")
			if stored := storedOrder(t, env.h, orderID); stored.Retired() != tc.Retire {
				t.Fatalf("fixture retirement = %v, want %v (row %+v)", stored.Retired(), tc.Retire, stored)
			}

			route := tc.Route
			if strings.Contains(route, "%s") {
				route = fmt.Sprintf(route, orderID)
			}
			body := fmt.Sprintf(`{"order_id":%q,"protocol":"awg","use_order_credential":true,"expected_fingerprint":%q}`,
				orderID, installFixtureFingerprint)
			req := httptest.NewRequest(http.MethodPost, route, strings.NewReader(body))
			req = req.WithContext(middleware.WithSession(req.Context(),
				&models.SessionData{UserID: "fixture-admin", Role: models.RoleAdmin}))
			rec := httptest.NewRecorder()
			env.h.GigahostDeployHandler(rec, req)

			installs := env.counters.totalInstalls()
			enables := env.counters.enables
			registered := env.registeredServer(providerServerID) != nil

			if tc.Retire {
				// No effect at all: the refusal precedes every step that touches a host.
				if installs != 0 {
					t.Errorf("a retired order started protocol installation: installs=%d", installs)
				}
				if enables != 0 {
					t.Errorf("a retired order reached backend enablement: enables=%d", enables)
				}
				if registered {
					t.Error("a retired order registered a panel server")
				}
				if rec.Code != http.StatusConflict {
					t.Fatalf("refusal = %d %s, want %d", rec.Code, rec.Body.String(), http.StatusConflict)
				}
				var answer struct {
					Code string `json:"code"`
				}
				if err := json.Unmarshal(rec.Body.Bytes(), &answer); err != nil {
					t.Fatalf("the refusal is not JSON: %v %s", err, rec.Body.String())
				}
				if answer.Code != orderEndedCode {
					t.Errorf("refusal code = %q, want %q (%s)", answer.Code, orderEndedCode, rec.Body.String())
				}
				// The order itself is untouched: a refused request must not rewrite the
				// ledger row it refused to act on.
				if stored := storedOrder(t, env.h, orderID); !stored.Retired() {
					t.Errorf("the refusal cleared the recorded ending: %+v", stored)
				}
				return
			}

			// The control: the same request against a live order deploys exactly once.
			if rec.Code != http.StatusOK {
				t.Fatalf("live control = %d %s, want 200", rec.Code, rec.Body.String())
			}
			if installs != 1 {
				t.Errorf("live control protocol installs = %d, want 1", installs)
			}
			if enables != 1 {
				t.Errorf("live control backend enablements = %d, want 1", enables)
			}
			if !registered {
				t.Error("live control did not register a panel server")
			}
		})
	}
}

// TestRetiredOrderRefusalPrecedesTheProviderDetailRead proves the refusal is not merely early
// in the effect path but ahead of the provider read that would otherwise supply identity.
//
// A deployment detail answer for an ended order is still a request to the provider about a
// deployment the panel has recorded as gone, and the ordering matters: a refusal that ran
// after it would leave the panel contacting the provider for an order it already knows is
// over, and would make the refusal depend on that answer.
func TestRetiredOrderRefusalPrecedesTheProviderDetailRead(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	ctx := context.Background()
	const orderID = "ord_refusal_ordering"
	const providerServerID = int64(7403)
	const ip = "198.51.100.43"

	env.seedOrder(orderID, providerServerID, ip)
	env.seedManagedCredential(orderID)
	if err := env.h.updateDeployOrderStatus(ctx, orderID, gigahost.StatusReady, "", "", providerServerID, 0, ip); err != nil {
		t.Fatalf("record the ready ledger row: %v", err)
	}
	if err := env.db.SetGigahostOrderProviderAccount(ctx, orderID, existenceAccount); err != nil {
		t.Fatalf("record the order's account: %v", err)
	}

	detailReads := 0
	provider := existenceProvider(t, nil, nil, &detailReads)
	provider.getDeployStatusFn = func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
		return &gigahost.DeployStatusResponse{OrderID: orderID, ServerID: providerServerID, AssignedIP: ip, Status: gigahost.StatusReady}, nil
	}
	env.h.SetGigahostClient(provider)

	// The inventory refresh retires the order before the dialog is submitted.
	_ = gigahostOrderStatusRead(t, env.h, "")
	if !storedOrder(t, env.h, orderID).Retired() {
		t.Fatal("the fixture did not retire the order through its inventory read")
	}
	before := detailReads

	req := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/deploy",
		strings.NewReader(fmt.Sprintf(`{"order_id":%q,"protocol":"awg","use_order_credential":true}`, orderID)))
	req = req.WithContext(middleware.WithSession(req.Context(),
		&models.SessionData{UserID: "fixture-admin", Role: models.RoleAdmin}))
	rec := httptest.NewRecorder()
	env.h.GigahostDeployHandler(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("refusal = %d %s, want %d", rec.Code, rec.Body.String(), http.StatusConflict)
	}
	if detailReads != before {
		t.Errorf("the refusal read the deployment detail of an ended order: %d -> %d reads", before, detailReads)
	}
	if env.counters.totalInstalls() != 0 || env.counters.enables != 0 {
		t.Errorf("a refused request performed work: installs=%d enables=%d",
			env.counters.totalInstalls(), env.counters.enables)
	}
	if env.registeredServer(providerServerID) != nil {
		t.Error("a refused request registered a panel server")
	}
	// The refusal precedes every step that touches the host.
	env.counters.mu.Lock()
	dials := env.counters.sshDials
	env.counters.mu.Unlock()
	if dials != 0 {
		t.Errorf("a refused request dialled the host: %d dials", dials)
	}
}
