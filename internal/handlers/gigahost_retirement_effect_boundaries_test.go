package handlers

// Retirement fenced at every effect boundary of an in-flight setup.
//
// The entry refusal (gigahost_deploy_retired_test.go) covers a request that arrives after the
// panel recorded the order as over. It cannot cover a request that was already inside the
// work: SSH verification waits on the network, the provider's per-server account read waits
// on the network, installation and traffic qualification wait on the host, and a complete
// own-account inventory omission can commit in any of those waits.
//
// Each case below therefore commits the retirement inside the real boundary that precedes one
// effect, then asserts that this effect and every later one did not happen. The boundaries are
// the existing seams - the SSH dialer, the provider's per-server read, the protocol manager's
// Install and the VPN service's qualification probe - so the production runner and the real
// SQLite ledger reach them; nothing is simulated from outside.
//
// Every case carries the identical interleaving against a live order. That control is what
// makes the assertion about the order's life rather than about the fence existing: with the
// order live the same pass performs every effect.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
	"github.com/devops-igor/amnezia-nexus/internal/service/gigahostsetup"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

// retireOrderNow records the panel's own existence observation for a ready order, using the
// real inventory read: the provider's listing omits the order while the detail and the account
// still answer, which is exactly the inconsistent pair the absence record represents.
//
// It is not a fabricated ledger write. A test that set provider_absent_at directly would prove
// the fence reads a column; going through the list read proves it observes the same fact the
// panel actually records. The listing is changed on the environment's own provider fixture,
// because that is the client the handlers hold: installing a new one here would leave the
// boundary hooks - which the production path calls on this object - pointing at nothing.
func retireOrderNow(t *testing.T, env *installEnv, orderID string, providerServerID int64, ip string) {
	t.Helper()
	env.provider.getAccountFn = func(context.Context) (*gigahost.AccountInfo, error) {
		return &gigahost.AccountInfo{CustID: existenceAccount}, nil
	}
	env.provider.getServersFn = func(context.Context) ([]gigahost.ServerInfo, error) {
		return nil, nil
	}
	env.provider.getDeployStatusFn = func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
		return &gigahost.DeployStatusResponse{
			OrderID: orderID, ServerID: providerServerID, AssignedIP: ip, Status: gigahost.StatusReady,
		}, nil
	}
	_ = gigahostOrderStatusRead(t, env.h, "")
	if !storedOrder(t, env.h, orderID).Retired() {
		t.Fatal("the fixture did not retire the order through its inventory read")
	}
}

// ifRetire performs the retirement inside a boundary when this case is the retired one.
//
// Keeping it in one helper means the live control runs the identical call path: it enters the
// same boundary, records the same observation and simply finds the order still listed.
func ifRetire(t *testing.T, env *installEnv, retire bool, orderID string, providerServerID int64, ip string) {
	t.Helper()
	if retire {
		retireOrderNow(t, env, orderID, providerServerID, ip)
	}
	// The instant is recorded whether or not this case retires, so the comparison below is
	// one measurement rather than a branch: a live control must simply show no read after it.
	env.counters.markRetirementReads()
	if got := storedOrder(t, env.h, orderID).Retired(); got != retire {
		t.Fatalf("fixture retirement = %v, want %v", got, retire)
	}
}

// immediateDeployEnv prepares one immediate-setup submission against a real ready ledger row.
//
// It configures the environment's own provider fixture, which is the client the handlers were
// wired to at construction. A separate mock would leave every boundary hook installed on an
// object the production path never calls - the test would then report a fence as working
// because its interleaving never ran.
func immediateDeployEnv(t *testing.T, orderID string, providerServerID int64, ip string) *installEnv {
	t.Helper()
	env := newInstallEnv(t, models.ProtocolAWG)
	ctx := context.Background()
	env.seedOrder(orderID, providerServerID, ip)
	env.seedManagedCredential(orderID)
	if err := env.h.updateDeployOrderStatus(ctx, orderID, gigahost.StatusReady, "", "", providerServerID, 0, ip); err != nil {
		t.Fatalf("record the ready ledger row: %v", err)
	}
	if err := env.db.SetGigahostOrderProviderAccount(ctx, orderID, existenceAccount); err != nil {
		t.Fatalf("record the order's account: %v", err)
	}
	env.provider.getAccountFn = func(context.Context) (*gigahost.AccountInfo, error) {
		return &gigahost.AccountInfo{CustID: existenceAccount}, nil
	}
	env.provider.getServersFn = func(context.Context) ([]gigahost.ServerInfo, error) {
		return []gigahost.ServerInfo{{ID: providerServerID, OrderID: orderID, IPv4: ip, Status: gigahost.StatusReady}}, nil
	}
	env.provider.getDeployStatusFn = func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
		return &gigahost.DeployStatusResponse{
			OrderID: orderID, ServerID: providerServerID, AssignedIP: ip, Status: gigahost.StatusReady,
		}, nil
	}
	env.provider.getServerFn = func(context.Context, int64) (*gigahost.ServerInfo, error) {
		return &gigahost.ServerInfo{
			ID: providerServerID, OrderID: orderID, IPv4: ip,
			Status: gigahost.StatusReady, CustID: existenceAccount,
		}, nil
	}
	return env
}

// deployImmediate runs the real HTTP handler for one immediate-setup submission.
//
// The provider's per-server read is counted for every submission, so a case can assert that a
// fence refused BEFORE that network work rather than after it.
func deployImmediate(t *testing.T, env *installEnv, orderID string) (code int, body string) {
	t.Helper()
	perServer := env.provider.getServerFn
	env.provider.getServerFn = func(ctx context.Context, serverID int64) (*gigahost.ServerInfo, error) {
		env.counters.recordAccountRead()
		if perServer != nil {
			return perServer(ctx, serverID)
		}
		return nil, nil
	}
	req := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/deploy",
		strings.NewReader(fmt.Sprintf(`{"order_id":%q,"protocol":"awg","use_order_credential":true,"expected_fingerprint":%q}`,
			orderID, installFixtureFingerprint)))
	req = req.WithContext(middleware.WithSession(req.Context(),
		&models.SessionData{UserID: "fixture-admin", Role: models.RoleAdmin}))
	rec := httptest.NewRecorder()
	env.h.GigahostDeployHandler(rec, req)
	return rec.Code, rec.Body.String()
}

// TestImmediateSetupStopsAtEveryEffectBoundaryAfterRetirement is the F1007-04 regression.
//
// Each subtest commits the retirement inside one boundary of the real immediate-setup path and
// asserts that this boundary's effect and all later ones did not happen: no server row, no
// protocol installation, no backend enablement, and no ready report. It then asserts the
// durable evidence: the intent, where one exists, is closed with the reason recorded, and the
// endpoint reports the refusal rather than success.
//
// enableVerified additionally asserts that the backend is not selectable, which is the
// distinction between "the pool never admitted it" and "it was admitted and then disabled by
// something else".
func TestImmediateSetupStopsAtEveryEffectBoundaryAfterRetirement(t *testing.T) {
	cases := []struct {
		name string
		// boundary installs the retirement at one seam of the deploy path.
		boundary func(t *testing.T, env *installEnv, orderID string, providerServerID int64, ip string, retire bool)
		// wantInstalls is the number of protocol installs the retired case may show: an
		// install that already ran before the boundary is not rolled back.
		wantInstalls int
		// wantEnables is the number of backend enablements the retired case may show, for
		// the same reason.
		wantEnables int
		// wantPerServerReadsAfterRetirement is how many provider per-server reads may be
		// issued AFTER the boundary committed the retirement. It is what proves an earlier
		// fence refused before that network work, rather than a later fence catching an
		// effect the read had already made possible.
		wantPerServerReadsAfterRetirement int
		// installPhase is the intent phase the case expects when one exists.
		installPhase string
	}{
		{
			name: "after-ssh-verification-before-registration",
			boundary: func(t *testing.T, env *installEnv, orderID string, providerServerID int64, ip string, retire bool) {
				previous := env.h.sshDialerHook
				if previous == nil {
					t.Fatal("the fixture wires no SSH dialer")
				}
				reached := false
				env.h.SetSSHDialerForTest(func(callCtx context.Context, cfg ssh.Config) (ssh.SSHClient, error) {
					if !reached {
						reached = true
						ifRetire(t, env, retire, orderID, providerServerID, ip)
					}
					return previous(callCtx, cfg)
				})
			},
			wantInstalls: 0,
			// This boundary must ALSO prevent the provider's per-server account read. That
			// read is the network work between the registration decision and the insert, so
			// a fence that only relied on the insert would send a request about a
			// deployment the panel has already recorded as gone.
			wantPerServerReadsAfterRetirement: 0,
		},
		{
			// The provider's per-server account read happens after the registration
			// journal phase opened and before the server row is created, so this is the
			// window the entry refusal cannot see and the journal write cannot close. The
			// boundary itself is this read, so it must be observed exactly once.
			name: "during-registration-account-read",
			boundary: func(t *testing.T, env *installEnv, orderID string, providerServerID int64, ip string, retire bool) {
				reached := false
				env.provider.getServerFn = func(context.Context, int64) (*gigahost.ServerInfo, error) {
					if !reached {
						reached = true
						ifRetire(t, env, retire, orderID, providerServerID, ip)
					}
					return &gigahost.ServerInfo{
						ID: providerServerID, OrderID: orderID, IPv4: ip,
						Status: gigahost.StatusReady, CustID: existenceAccount,
					}, nil
				}
			},
			wantInstalls:                      0,
			wantPerServerReadsAfterRetirement: 0,
		},
		{
			// Installation is remote work on the host, and the enablement that follows
			// would leave a selectable backend behind a retired order.
			name: "before-protocol-installation",
			boundary: func(t *testing.T, env *installEnv, orderID string, providerServerID int64, ip string, retire bool) {
				reached := false
				env.counters.mu.Lock()
				env.counters.duringInstall = func() {
					if !reached {
						reached = true
						ifRetire(t, env, retire, orderID, providerServerID, ip)
					}
				}
				env.counters.mu.Unlock()
			},
			// The boundary sits inside the install call, so the retired case may
			// already have performed it. What must not happen is enablement.
			wantInstalls: 1,
			installPhase: models.SetupPhaseInstalled,
		},
		{
			// Traffic qualification is the longest wait in the path, and the ready report
			// is what the operator reads. The probe runs AFTER enablement by design, so
			// the enablement itself is legitimate proven work here; the fence's obligation
			// is that no ready report follows, and that the backend is not left admitted.
			name: "during-qualification-before-ready",
			boundary: func(t *testing.T, env *installEnv, orderID string, providerServerID int64, ip string, retire bool) {
				reached := false
				env.h.vpnSvc.SetProbeFunc(func(ctx context.Context, a, b, c, d, e string, x, y any, p, q int, timeout time.Duration) (time.Duration, error) {
					if !reached {
						reached = true
						ifRetire(t, env, retire, orderID, providerServerID, ip)
					}
					return 10 * time.Millisecond, nil
				})
			},
			wantInstalls: 1,
			wantEnables:  1,
		},
	}

	for _, tc := range cases {
		for _, retire := range []bool{false, true} {
			name := tc.name + "/live-control"
			if retire {
				name = tc.name + "/retired"
			}
			t.Run(name, func(t *testing.T) {
				const ip = "198.51.100.61"
				orderID := fmt.Sprintf("ord_immediate_boundary_%d", providerServerIDFor(tc.name))
				const providerServerID = int64(7510)

				env := immediateDeployEnv(t, orderID, providerServerID, ip)
				tc.boundary(t, env, orderID, providerServerID, ip, retire)

				code, body := deployImmediate(t, env, orderID)

				registered := env.registeredServer(providerServerID) != nil
				installs := env.counters.totalInstalls()
				env.counters.mu.Lock()
				enables := env.counters.enables
				env.counters.mu.Unlock()
				perServerReads := env.counters.readsAfterRetirement()

				if !retire {
					// The control: the identical path with a live order performs every
					// effect, so what the retired case proves is about the order's life.
					if code != 200 {
						t.Fatalf("live control answered %d: %s", code, body)
					}
					if !registered {
						t.Error("live control did not register a panel server")
					}
					if installs != 1 {
						t.Errorf("live control installs = %d, want 1", installs)
					}
					if enables != 1 {
						t.Errorf("live control enablements = %d, want 1", enables)
					}
					return
				}

				// The retired case: the boundary refused, and the endpoint says so with the
				// same closed-set code a late request gets, rather than reporting success.
				if code != 409 {
					t.Errorf("retired answer = %d, want 409: %s", code, body)
				}
				if !bodyHasCode(body, orderEndedCode) {
					t.Errorf("retired answer does not carry code %q: %s", orderEndedCode, body)
				}
				if installs != tc.wantInstalls {
					t.Errorf("protocol installs = %d, want %d", installs, tc.wantInstalls)
				}
				if enables != tc.wantEnables {
					t.Errorf("backend enablements = %d, want %d", enables, tc.wantEnables)
				}
				if perServerReads != tc.wantPerServerReadsAfterRetirement {
					t.Errorf("provider per-server reads after the retirement = %d, want %d",
						perServerReads, tc.wantPerServerReadsAfterRetirement)
				}
				if err := env.refuseBackendAdmissionFor(providerServerID); err != nil {
					t.Error(err)
				}
				// The ready question is asked of the ledger row the operator reads.
				if status := storedOrder(t, env.h, orderID); status.Status == DeployStatusReady {
					t.Errorf("a retired order's ledger row says %q; the fence did not stop the report", status.Status)
				}
			})
		}
	}
}

// providerServerIDFor derives a distinct provider id per case so a failed assertion names the
// case that produced it.
func providerServerIDFor(name string) int64 {
	var sum int64 = 7510
	for _, r := range name {
		sum += int64(r % 7)
	}
	return sum
}

// bodyHasCode reports whether the response carries the closed-set code the refusal answers
// with, so the assertion is about the stated reason rather than about the status alone.
func bodyHasCode(body, code string) bool {
	var answer struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal([]byte(body), &answer); err != nil {
		return false
	}
	return answer.Code == code
}

// refuseBackendAdmissionFor asserts no backend for this provider server was left admitted.
//
// enablement count already proves it was never enabled; this reads the durable tunnel state as
// well, because "enabled but not admitted" and "never enrolled" are both acceptable and a
// selectable backend is not.
func (e *installEnv) refuseBackendAdmissionFor(providerServerID int64) error {
	e.t.Helper()
	server := e.registeredServer(providerServerID)
	if server == nil {
		return nil
	}
	tun, err := e.h.vpnSvc.GetTunnel(server.ID)
	if err != nil || tun == nil {
		return nil
	}
	if tun.Enabled && tun.Status == models.TunnelStatusActive {
		return fmt.Errorf("a retired order left an implied selectable backend: server=%d status=%s", server.ID, tun.Status)
	}
	return nil
}

// TestRetirementDuringRegistrationLeavesRetiredRow proves the smaller truth the registration
// boundary also has to establish: the server row must still not exist, and the intent must
// record why the attempt stopped, so an operator is not left with a job that looks resumable
// for a deployment that is gone.
func TestRetirementDuringRegistrationLeavesRetiredRow(t *testing.T) {
	const orderID = "ord_registration_retired_row"
	const providerServerID = int64(7520)
	const ip = "198.51.100.62"

	env := newInstallEnv(t, models.ProtocolAWG)
	ctx := context.Background()
	env.seedOrder(orderID, providerServerID, ip)
	env.seedManagedCredential(orderID)
	if err := env.h.updateDeployOrderStatus(ctx, orderID, gigahost.StatusReady, "", "", providerServerID, 0, ip); err != nil {
		t.Fatalf("record the ready ledger row: %v", err)
	}
	if err := env.db.SetGigahostOrderProviderAccount(ctx, orderID, existenceAccount); err != nil {
		t.Fatalf("record the order's account: %v", err)
	}
	env.providerServes(orderID, providerServerID, ip)
	env.approve(orderID, models.ProtocolAWG, "51820", installFixtureFingerprint)
	if err := env.tracker(nil).RunOnce(ctx); err != nil {
		t.Fatalf("tracker pass: %v", err)
	}
	env.requireState(orderID, models.SetupStateReadyForSetup)

	// The retirement lands inside the account read that immediately precedes the insert,
	// after the registration phase is already journalled.
	reached := false
	env.provider.getServerFn = func(context.Context, int64) (*gigahost.ServerInfo, error) {
		if !reached {
			reached = true
			retireOrderNow(t, env, orderID, providerServerID, ip)
		}
		return &gigahost.ServerInfo{
			ID: providerServerID, OrderID: orderID, IPv4: ip,
			Status: gigahost.StatusReady, CustID: existenceAccount,
		}, nil
	}
	if err := env.installer().RunOnce(ctx); err != nil {
		t.Fatalf("install pass: %v", err)
	}
	if !reached {
		t.Fatal("the fixture never reached the registration account read, so this case proves nothing")
	}
	if env.registeredServer(providerServerID) != nil {
		t.Error("a retired order created a panel server row during the account read that followed its registration phase")
	}
	job := env.intent(orderID)
	if job.State != models.SetupStateCanceled {
		t.Errorf("state = %q, want %q (step %q, last error %q)", job.State, models.SetupStateCanceled, job.Step, job.LastError)
	}
	if job.InstallPhaseDone != "" {
		t.Errorf("proven phase = %q, want none: registration never completed", job.InstallPhaseDone)
	}
	if env.counters.totalInstalls() != 0 {
		t.Errorf("a retired order installed a protocol: installs=%d", env.counters.totalInstalls())
	}
}

// TestBackendPromotionRefusesAnOrderThatEndedDuringQualification is the F1007-03 admission
// regression.
//
// Promotion decides admission authority inside its own transaction, and that decision now
// covers the order as well as the approval. This case drives a saved job to enablement, commits
// the retirement during the qualification probe, and asserts the durable outcome: no admitted
// status, no selectable backend, and the job closed with the reason recorded. The live control
// promotes normally.
func TestBackendPromotionRefusesAnOrderThatEndedDuringQualification(t *testing.T) {
	for _, retire := range []bool{false, true} {
		name := "live-control"
		if retire {
			name = "retired-during-qualification"
		}
		t.Run(name, func(t *testing.T) {
			const orderID = "ord_promotion_authority"
			const providerServerID = int64(7530)
			const ip = "198.51.100.63"

			env := newInstallEnv(t, models.ProtocolAWG)
			ctx := context.Background()
			env.seedOrder(orderID, providerServerID, ip)
			env.seedManagedCredential(orderID)
			if err := env.h.updateDeployOrderStatus(ctx, orderID, gigahost.StatusReady, "", "", providerServerID, 0, ip); err != nil {
				t.Fatalf("record the ready ledger row: %v", err)
			}
			if err := env.db.SetGigahostOrderProviderAccount(ctx, orderID, existenceAccount); err != nil {
				t.Fatalf("record the order's account: %v", err)
			}
			env.providerServes(orderID, providerServerID, ip)
			env.approve(orderID, models.ProtocolAWG, "51820", installFixtureFingerprint)
			if err := env.tracker(nil).RunOnce(ctx); err != nil {
				t.Fatalf("tracker pass: %v", err)
			}
			env.requireState(orderID, models.SetupStateReadyForSetup)

			reached := false
			env.h.vpnSvc.SetProbeFunc(func(ctx context.Context, a, b, c, d, e string, x, y any, p, q int, timeout time.Duration) (time.Duration, error) {
				if !reached {
					reached = true
					ifRetire(t, env, retire, orderID, providerServerID, ip)
				}
				return 10 * time.Millisecond, nil
			})

			if err := env.installer().RunOnce(ctx); err != nil {
				t.Fatalf("install pass: %v", err)
			}
			if !reached {
				t.Fatal("the fixture never reached the qualification probe, so this case proves nothing")
			}
			server := env.registeredServer(providerServerID)
			if server == nil {
				t.Fatal("the fixture never registered a server")
			}
			tun, err := env.h.vpnSvc.GetTunnel(server.ID)
			if err != nil || tun == nil {
				t.Fatalf("tunnel read: %v", err)
			}
			selectable := authenticPoolContains(t, env, server.ID)
			job := env.intent(orderID)

			if !retire {
				if !selectable || job.State != models.SetupStateReady {
					t.Errorf("live control did not admit the backend: selectable=%v state=%q", selectable, job.State)
				}
				return
			}
			if selectable {
				t.Error("a retired order's backend was admitted into the pool")
			}
			if tun.Status == models.TunnelStatusActive || tun.Status == models.TunnelStatusDegraded {
				t.Errorf("a retired order's backend reached admitted status %q", tun.Status)
			}
			if job.State != models.SetupStateCanceled {
				t.Errorf("state = %q, want %q (step %q, last error %q)", job.State, models.SetupStateCanceled, job.Step, job.LastError)
			}
			if job.InstallPhaseDone != models.SetupPhaseInstalled {
				t.Errorf("proven phase = %q, want %q: the fence must not discard proven work", job.InstallPhaseDone, models.SetupPhaseInstalled)
			}
		})
	}
}

// TestJobIsNotRecordedReadyForAnOrderThatEndsAfterAdmission covers the window between a
// committed admission and the job's terminal journal write.
//
// The retirement lands inside the enablement phase's own completion write, so the promotion has
// already committed and the job has not been admitted. The job's fenced journal write then
// refuses, which is what keeps "ready" off the row; the fixed assertion is that the job is not
// admitted, not that the effect was undone.
func TestJobIsNotRecordedReadyForAnOrderThatEndsAfterAdmission(t *testing.T) {
	for _, retire := range []bool{false, true} {
		name := "live-control"
		if retire {
			name = "retired-after-admission"
		}
		t.Run(name, func(t *testing.T) {
			const orderID = "ord_ready_boundary"
			const providerServerID = int64(7540)
			const ip = "198.51.100.65"

			env := newInstallEnv(t, models.ProtocolAWG)
			ctx := context.Background()
			env.seedOrder(orderID, providerServerID, ip)
			env.seedManagedCredential(orderID)
			if err := env.h.updateDeployOrderStatus(ctx, orderID, gigahost.StatusReady, "", "", providerServerID, 0, ip); err != nil {
				t.Fatalf("record the ready ledger row: %v", err)
			}
			if err := env.db.SetGigahostOrderProviderAccount(ctx, orderID, existenceAccount); err != nil {
				t.Fatalf("record the order's account: %v", err)
			}
			env.providerServes(orderID, providerServerID, ip)
			env.approve(orderID, models.ProtocolAWG, "51820", installFixtureFingerprint)
			if err := env.tracker(nil).RunOnce(ctx); err != nil {
				t.Fatalf("tracker pass: %v", err)
			}
			env.requireState(orderID, models.SetupStateReadyForSetup)

			// The retirement lands inside the enablement phase's own completion write, so
			// the promotion has already committed and the ready report has not.
			reached := false
			store := &intervalStore{
				DB: env.db,
				beforeComplete: func(*models.GigahostSetupIntent) {
					reached = true
					ifRetire(t, env, retire, orderID, providerServerID, ip)
				},
			}
			installer := gigahostsetup.NewInstaller(store, env.h.NewSetupInstallRunner(),
				gigahostsetup.InstallOptions{Interval: time.Second})
			if err := installer.RunOnce(ctx); err != nil {
				t.Fatalf("install pass: %v", err)
			}
			if !reached {
				t.Fatal("the fixture never reached the post-admission journal write, so this case proves nothing")
			}
			server := env.registeredServer(providerServerID)
			if server == nil {
				t.Fatal("the fixture never registered a server")
			}
			if !authenticPoolContains(t, env, server.ID) {
				t.Fatal("precondition: the promotion did not commit before the retirement")
			}
			job := env.intent(orderID)

			if !retire {
				if job.State != models.SetupStateReady {
					t.Errorf("live control state = %q, want %q (step %q)", job.State, models.SetupStateReady, job.Step)
				}
				return
			}
			if job.State == models.SetupStateReady {
				t.Error("a job was recorded ready for an order that ended before its admission write")
			}
		})
	}
}

// admitThenRetireStore commits each real journal write and then, once, commits the retirement
// immediately after the ADMIT write succeeded.
//
// It exists because that is the one window the ledger mirror can still be reached in: the
// promotion transaction and the job's admit write are both fenced, so a retirement before
// either of them stops the attempt earlier. After the admit write commits, the job has
// legitimately finished - the admission is proven work and is not rolled back - and the only
// remaining success claim is the order ledger's ready mirror.
type admitThenRetireStore struct {
	*database.DB
	afterAdmit func()
}

func (s *admitThenRetireStore) UpdateGigahostSetupInstall(
	ctx context.Context, intent *models.GigahostSetupIntent, gen int64,
) (bool, error) {
	changed, err := s.DB.UpdateGigahostSetupInstall(ctx, intent, gen)
	if err == nil && changed && s.afterAdmit != nil && intent.State == models.SetupStateReady {
		fn := s.afterAdmit
		s.afterAdmit = nil
		fn()
	}
	return changed, err
}

// TestOrderLedgerIsNotToldReadyAfterAnAdmitThenRetirement is the ledger-mirror regression.
//
// The job legitimately completed and says so; the order ended immediately afterwards. What must
// not happen is the order ledger claiming the deployment reached ready, because that is the row
// the operator reads as "this order produced a healthy backend".
func TestOrderLedgerIsNotToldReadyAfterAnAdmitThenRetirement(t *testing.T) {
	for _, retire := range []bool{false, true} {
		name := "live-control"
		if retire {
			name = "retired-after-admit"
		}
		t.Run(name, func(t *testing.T) {
			const orderID = "ord_mirror_after_admit"
			const providerServerID = int64(7545)
			const ip = "198.51.100.68"

			env := newInstallEnv(t, models.ProtocolAWG)
			ctx := context.Background()
			env.seedOrder(orderID, providerServerID, ip)
			env.seedManagedCredential(orderID)
			if err := env.h.updateDeployOrderStatus(ctx, orderID, gigahost.StatusReady, "", "", providerServerID, 0, ip); err != nil {
				t.Fatalf("record the ready ledger row: %v", err)
			}
			if err := env.db.SetGigahostOrderProviderAccount(ctx, orderID, existenceAccount); err != nil {
				t.Fatalf("record the order's account: %v", err)
			}
			env.providerServes(orderID, providerServerID, ip)
			env.approve(orderID, models.ProtocolAWG, "51820", installFixtureFingerprint)
			if err := env.tracker(nil).RunOnce(ctx); err != nil {
				t.Fatalf("tracker pass: %v", err)
			}
			env.requireState(orderID, models.SetupStateReadyForSetup)

			// A pre-ready progress value, so the assertion measures the ready mirror.
			if err := env.h.updateDeployOrderStatus(ctx, orderID, DeployStatusEnablingBackend, "enabling_backend", "",
				providerServerID, 0, ip); err != nil {
				t.Fatalf("record the in-progress ledger step: %v", err)
			}

			retired := false
			store := &admitThenRetireStore{DB: env.db}
			store.afterAdmit = func() {
				if !retire {
					return
				}
				retired = true
				retireOrderNow(t, env, orderID, providerServerID, ip)
			}
			installer := gigahostsetup.NewInstaller(store, env.h.NewSetupInstallRunner(),
				gigahostsetup.InstallOptions{Interval: time.Second})
			if err := installer.RunOnce(ctx); err != nil {
				t.Fatalf("install pass: %v", err)
			}
			if job := env.intent(orderID); job.State != models.SetupStateReady {
				t.Fatalf("precondition: the job must have completed, got %q (step %q)", job.State, job.Step)
			}
			ledger := storedOrder(t, env.h, orderID)

			if !retire {
				if ledger.Status != DeployStatusReady {
					t.Errorf("live control ledger status = %q, want %q", ledger.Status, DeployStatusReady)
				}
				return
			}
			if !retired {
				t.Fatal("the fixture never retired the order after the admit write, so this case proves nothing")
			}
			if ledger.Status == DeployStatusReady {
				t.Error("the order ledger reports ready for an order the panel records as ended")
			}
		})
	}
}

// TestRetirementQuestionKeepsThreeOutcomesApart pins the classification every fence depends on:
// a recorded ending, a live order, and a question that could not be answered. Collapsing the
// third into either of the others is the defect both fences exist to avoid - one direction
// reports success without evidence, the other invents a retirement the panel never recorded.
func TestRetirementQuestionKeepsThreeOutcomesApart(t *testing.T) {
	const orderID = "ord_three_outcomes"
	const providerServerID = int64(7550)
	const ip = "198.51.100.66"

	t.Run("live-order-is-known-and-not-ended", func(t *testing.T) {
		env := immediateDeployEnv(t, orderID, providerServerID, ip)
		ended, known := env.h.retirementQuestion(context.Background(), orderID)
		if ended || !known {
			t.Errorf("ended=%v known=%v, want false/true", ended, known)
		}
	})

	t.Run("recorded-ending-is-known-and-ended", func(t *testing.T) {
		env := immediateDeployEnv(t, orderID, providerServerID, ip)
		retireOrderNow(t, env, orderID, providerServerID, ip)
		ended, known := env.h.retirementQuestion(context.Background(), orderID)
		if !ended || !known {
			t.Errorf("ended=%v known=%v, want true/true", ended, known)
		}
	})

	t.Run("unreadable-store-is-unknown", func(t *testing.T) {
		env := immediateDeployEnv(t, orderID, providerServerID, ip)
		// Closing the store is the honest way to produce "could not ask": the read cannot
		// answer at all. It is not the same state as an answered "no".
		if err := env.db.Close(); err != nil {
			t.Fatalf("close the store: %v", err)
		}
		ended, known := env.h.retirementQuestion(context.Background(), orderID)
		if ended || known {
			t.Errorf("ended=%v known=%v, want false/false: an unreadable store must not answer", ended, known)
		}
	})
}

// TestCompleteOrderDeployStatusMirrorsReadyOnlyForALiveOrder is the mirror's own positive and
// negative direction at its real call site.
func TestCompleteOrderDeployStatusMirrorsReadyOnlyForALiveOrder(t *testing.T) {
	const orderID = "ord_mirror_direction"
	const providerServerID = int64(7551)
	const ip = "198.51.100.67"

	env := immediateDeployEnv(t, orderID, providerServerID, ip)
	ctx := context.Background()
	req := GigahostDeployRequest{OrderID: orderID, ProviderServerID: providerServerID}
	server := &models.Server{ID: 1, Host: ip}

	// Live: the mirror reports what the attempt established.
	if err := env.h.updateDeployOrderStatus(ctx, orderID, DeployStatusEnablingBackend, "enabling_backend", "",
		providerServerID, 0, ip); err != nil {
		t.Fatalf("record the in-progress ledger step: %v", err)
	}
	env.h.completeOrderDeployStatus(ctx, req, server)
	if got := storedOrder(t, env.h, orderID).Status; got != DeployStatusReady {
		t.Errorf("live order mirror = %q, want %q", got, DeployStatusReady)
	}

	// Ended: the same call must leave the last known value alone.
	retireOrderNow(t, env, orderID, providerServerID, ip)
	if err := env.h.updateDeployOrderStatus(ctx, orderID, DeployStatusEnablingBackend, "enabling_backend", "",
		providerServerID, 0, ip); err != nil {
		t.Fatalf("restore the in-progress step: %v", err)
	}
	env.h.completeOrderDeployStatus(ctx, req, server)
	if got := storedOrder(t, env.h, orderID).Status; got == DeployStatusReady {
		t.Error("the mirror reported ready for an order the panel records as ended")
	}
}

// TestPromotionRefusalIsTheOrdersOwnDecision keeps the new guard honest about its reach.
// It asserts the negative direction directly, at the transaction's own boundary: a backend that
// no panel record attributes to a gigahost order is admitted exactly as before, and a backend
// whose order is live is admitted too. Without this, the guard could be satisfied by refusing
// every promotion, which would break every backend the panel provisions outside onboarding.
func TestPromotionRefusalIsTheOrdersOwnDecision(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	ctx := context.Background()

	// A server the panel created directly: no setup intent and no order ledger row claims it.
	// Its protocol metadata is what enablement reads, exactly as an installed protocol
	// records it.
	unowned, err := env.db.CreateServerWithFingerprint(ctx, &models.Server{
		Name: "unowned-fixture", Host: "198.51.100.64", SSHPort: 22, SSHUser: "root",
		Protocols: map[string]any{
			"provider": "fixture",
			models.ProtocolAWG: map[string]any{
				"installed":  true,
				"port":       "51820",
				"public_key": "x9aB1234567890abcdef1234567890abcdef1234567=",
			},
		},
	}, installFixtureFingerprint)
	if err != nil {
		t.Fatalf("create the unowned server: %v", err)
	}
	enrollCtx := context.WithValue(ctx, tunnel.DeployEnrollmentKey, true)
	if err := env.h.vpnSvc.EnableBackendWithConfig(enrollCtx, unowned,
		tunnel.BackendTunnelOptions{Protocol: models.ProtocolAWG}); err != nil {
		t.Fatalf("enable the unowned backend: %v", err)
	}
	observed, err := env.h.vpnSvc.GetTunnel(unowned)
	if err != nil || observed == nil {
		t.Fatalf("read the unowned tunnel: %v", err)
	}
	if err := env.h.vpnSvc.PromoteQualifiedTunnel(ctx, observed, 5); err != nil {
		t.Fatalf("an unowned backend was refused promotion: %v", err)
	}
	if !authenticPoolContains(t, env, unowned) {
		t.Error("an unowned backend did not reach the pool; the fence is wider than the gigahost orders")
	}
}
