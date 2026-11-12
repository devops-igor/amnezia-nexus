package handlers

// Child side of the provider-outage proof.
//
// The C3a provider-failure test proved the wrong thing: it kept the provider answering
// "ready" and gave the SSH dial a closed port, which is a *host contact* failure. A
// provider OUTAGE is a different event - the deploy-status read itself fails - and it is
// what a purchase experiences while a VPS is being provisioned or while the provider's API
// is down.
//
// This child exists to produce that event honestly, and to make two facts visible across
// the process boundary:
//
//  1. **the provider read really failed**, counted in a file both processes append to, so
//     "an error occurred" is measured rather than inferred from a state label;
//  2. **no purchase was attempted**, counted the same way, because a provider stub that
//     fails cannot also be the oracle for "we did not ask it to sell anything". The same
//     fixture records and rejects any purchase call.
//
// Nothing here is a new production seam. The provider stub, the database and the effect
// journal are the same fixture boundaries the earlier process proofs already use.

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"errors"
	"github.com/devops-igor/amnezia-nexus/internal/config"
	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/manager"
	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
	"github.com/devops-igor/amnezia-nexus/internal/service/gigahostsetup"
	"github.com/devops-igor/amnezia-nexus/internal/vpn"
)

// Environment the provider-outage child needs.
const (
	// envProcessProviderMode selects the provider's behaviour for this child:
	//
	//	down     every deploy-status read fails, as during a provider outage;
	//	pending  the provider answers "deploying", as during ordinary provisioning;
	//	ready    the provider answers "ready" with an address and server id;
	//
	// Unset is treated as "ready" so a child that does not care cannot silently become a
	// failure case.
	envProcessProviderMode = "GIGAHOST_PROCESS_PROVIDER"
	// envProcessProviderJournal is the file the provider stub appends to: one line per
	// call, `<method> <outcome>`. Both processes read it, so the parent counts the child's
	// provider reads and purchase attempts from outside the child.
	envProcessProviderJournal = "GIGAHOST_PROCESS_PROVIDER_JOURNAL"
)

// Provider journal line kinds. They are separate words rather than a boolean so a reader
// cannot confuse "an order was placed" with "a status was read".
const (
	providerCallDeployStatus = "deploy_status"
	providerCallServers      = "servers"
	providerCallPurchase     = "purchase"
	providerOutcomeError     = "error"
	providerOutcomeAnswered  = "answered"
)

// Provider behaviour modes.
const (
	providerModeDown    = "down"
	providerModePending = "pending"
	providerModeReady   = "ready"
)

// runProviderRecoveryMode runs one tracking pass in a fresh process against a provider
// whose behaviour is chosen by the environment.
//
// It reports the same durable facts the other automatic modes report, plus the provider
// read and purchase counts this process produced.
func runProviderRecoveryMode(ctx context.Context, mode string) int {
	dbPath := os.Getenv(envProcessDBPath)
	journal := os.Getenv(envProcessJournal)
	secret := os.Getenv(envProcessSecret)
	providerJournal := os.Getenv(envProcessProviderJournal)
	if dbPath == "" || journal == "" || secret == "" || providerJournal == "" {
		fmt.Fprintln(os.Stderr, "provider helper: required environment is missing")
		return 4
	}
	providerMode := strings.TrimSpace(os.Getenv(envProcessProviderMode))
	if providerMode == "" {
		providerMode = providerModeReady
	}
	if providerMode != providerModeDown && providerMode != providerModePending && providerMode != providerModeReady {
		fmt.Fprintf(os.Stderr, "provider helper: unknown provider mode %q\n", providerMode)
		return 4
	}

	h, err := newProviderRecoveryHandlers(dbPath, secret, journal, providerJournal, providerMode,
		os.Getenv(envProcessPolicy))
	if err != nil {
		fmt.Fprintf(os.Stderr, "provider helper: %v\n", err)
		return 4
	}

	now := childClock(os.Getenv(envProcessClock))
	opts := gigahostsetup.Options{
		Resolve:                 h.ResolveGigahostSetupProvider,
		ChallengeHost:           h.challengeGigahostSetupHostIdentity,
		FirstContactEligible:    h.firstContactEligible,
		Pinner:                  h.db,
		AutomaticEffectAllowed:  h.automaticEffectPermitted,
		AutomaticBindingGrantor: h.GrantAutomaticGigahostSetupBinding,
		Interval:                gigahostsetup.DefaultInterval,
		CallTimeout:             30 * time.Second,
	}
	if now != nil {
		opts.Now = now
	}
	tracker := gigahostsetup.New(h.db, opts)
	if err := tracker.RunOnce(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "provider helper: tracking pass failed: %v\n", err)
		return 3
	}

	intent, found, readErr := h.db.GetGigahostSetupIntent(ctx, autoProcessOrderID)
	if readErr != nil || !found {
		fmt.Fprintf(os.Stderr, "provider helper: intent unreadable: found=%v err=%v\n", found, readErr)
		return 3
	}
	fmt.Printf("pass=%s state=%s step=%s phase=%s phase_done=%s generation=%d\n",
		mode, intent.State, intent.Step, intent.InstallPhase, intent.InstallPhaseDone,
		intent.InstallGeneration)
	fmt.Printf("provider_status=%q last_error=%q read_failures=%d attempts=%d\n",
		intent.ProviderStatus, intent.LastError, intent.ReadFailures, intent.Attempts)
	fmt.Printf("policy=%s grant_order=%s grant_server=%d grant_address=%s\n",
		intent.HostTrustPolicy, intent.HostTrustOrderID, intent.HostTrustServerID,
		intent.HostTrustAddress)
	fmt.Printf("fingerprint=%s protocol=%s port=%s assigned_ip=%s provider_server_id=%d\n",
		intent.HostFingerprint, intent.Protocol, intent.Port, intent.AssignedIP, intent.ProviderServerID)
	// The process-visible provider facts. These are the numbers the earlier checkpoint
	// claimed from a state label instead of from a counter.
	fmt.Printf("provider_reads=%d provider_errors=%d purchases=%d\n",
		providerJournalCount(providerJournal, providerCallDeployStatus, providerOutcomeAnswered),
		providerJournalCount(providerJournal, providerCallDeployStatus, providerOutcomeError),
		providerJournalCount(providerJournal, providerCallPurchase, ""))
	return 0
}

// newProviderRecoveryHandlers builds the child's handlers with a provider whose behaviour is
// driven by a mode string, and whose every call is recorded in a shared file.
//
// The purchase methods are recorded and refused. That refusal is the point: a purchase
// attempt during an outage would be a duplicate-order hazard, and a counter that only the
// child could see could not prove its absence to the parent.
func newProviderRecoveryHandlers(
	dbPath, secret, journal, providerJournal, providerMode, policyMode string,
) (*Handlers, error) {
	db, err := database.Open(dbPath, secret)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	vpnCfg := &models.VPNConfig{EnableMultiProtocolBackends: true, ListenPort: 51820}
	vpnSvc, err := vpn.NewVPNService(db, vpnCfg)
	if err != nil {
		return nil, fmt.Errorf("init vpn service: %w", err)
	}
	vpnSvc.SetProbeFunc(func(context.Context, string, string, string, string, string, any, any, int, int, time.Duration) (time.Duration, error) {
		return 10 * time.Millisecond, nil
	})
	vpnSvc.SetProxyTrafficProbeFuncForTest(func(context.Context, *models.BackendTunnel) (int64, error) {
		return 5, nil
	})
	vpnSvc.SetEnableBackendPreAddTunnelHookForTest(func() { appendEffect(journal, "enable") })

	reg := manager.NewRegistry()
	reg.Register(&processProofProtocolManager{journal: journal})

	h := NewHandlers(Dependencies{
		Config:     &config.Config{SecretKey: secret},
		DB:         db,
		Registry:   reg,
		VPNService: vpnSvc,
	})
	h.vpnSvc = vpnSvc
	h.registry = reg

	h.SetGigahostClient(&providerRecoveryClient{
		journal:  providerJournal,
		mode:     providerMode,
		orderID:  autoProcessOrderID,
		serverID: autoProcessServerID,
		address:  providerStubAddress,
	})
	// The host is a fixture address; the SSH dial itself is replaced, because this test is
	// about the provider's behaviour rather than the transport. The transport is covered by
	// the loopback-peer tests.
	h.SetSSHDialerForTest(func(context.Context, ssh.Config) (ssh.SSHClient, error) {
		return &mockDeploySSHClient{fingerprint: installFixtureFingerprint}, nil
	})

	if err := applyChildPolicy(h, policyMode); err != nil {
		return nil, err
	}
	return h, nil
}

// providerStubAddress is the address the "ready" provider mode reports. It is a fixture
// address in the documentation range, never a real host.
const providerStubAddress = "198.51.100.77"

// providerRecoveryClient is a provider stub whose behaviour is chosen per child and whose
// every call is appended to a shared file.
//
// It implements the read surface the tracker uses and records purchase attempts instead of
// performing them, so the parent can assert "zero purchases" from outside the child.
type providerRecoveryClient struct {
	journal  string
	mode     string
	orderID  string
	serverID int64
	address  string
}

// GetDeployStatus answers according to the configured mode, recording the outcome.
func (c *providerRecoveryClient) GetDeployStatus(context.Context, string) (*gigahost.DeployStatusResponse, error) {
	switch c.mode {
	case providerModeDown:
		recordProviderCall(c.journal, providerCallDeployStatus, providerOutcomeError)
		return nil, errors.New("the provider API is unavailable")
	case providerModePending:
		recordProviderCall(c.journal, providerCallDeployStatus, providerOutcomeAnswered)
		return &gigahost.DeployStatusResponse{
			OrderID: c.orderID, Status: "deploying",
		}, nil
	default:
		recordProviderCall(c.journal, providerCallDeployStatus, providerOutcomeAnswered)
		return &gigahost.DeployStatusResponse{
			OrderID: c.orderID, Status: gigahost.StatusReady,
			ServerID: c.serverID, AssignedIP: c.address,
		}, nil
	}
}

// GetServers answers according to the configured mode, recording the outcome.
func (c *providerRecoveryClient) GetServers(context.Context) ([]gigahost.ServerInfo, error) {
	if c.mode == providerModeDown {
		recordProviderCall(c.journal, providerCallServers, providerOutcomeError)
		return nil, errors.New("the provider API is unavailable")
	}
	recordProviderCall(c.journal, providerCallServers, providerOutcomeAnswered)
	return []gigahost.ServerInfo{
		{ID: c.serverID, OrderID: c.orderID, IPv4: c.address, Status: "ready"},
	}, nil
}

// GetCatalog, GetProducts, GetOperatingSystems and GetAccount are not used by the tracker;
// they record nothing and answer empty, so an unexpected call is visible as an absence
// rather than mistaken for a purchase.
func (c *providerRecoveryClient) GetCatalog(context.Context) ([]gigahost.HourlyPlan, error) {
	return nil, nil
}

func (c *providerRecoveryClient) GetProducts(context.Context) ([]gigahost.Product, error) {
	return nil, nil
}

func (c *providerRecoveryClient) GetOperatingSystems(context.Context) ([]gigahost.OperatingSystem, error) {
	return nil, nil
}

func (c *providerRecoveryClient) GetAccount(context.Context) (*gigahost.AccountInfo, error) {
	return &gigahost.AccountInfo{Balance: 0, Currency: "NOK"}, nil
}

// ListSSHKeys and RegisterSSHKey are the pre-purchase key steps. A purchase path would call
// them, so they are recorded for the same reason the purchase itself is.
func (c *providerRecoveryClient) ListSSHKeys(context.Context) ([]gigahost.SSHKeyInfo, error) {
	recordProviderCall(c.journal, providerCallPurchase, "list_keys")
	return nil, errors.New("this fixture never performs purchase work")
}

func (c *providerRecoveryClient) RegisterSSHKey(context.Context, string, string) error {
	recordProviderCall(c.journal, providerCallPurchase, "register_key")
	return errors.New("this fixture never performs purchase work")
}

// OrderServer and OrderServerSafe record the attempt and refuse it. A caller that reached
// either would have ordered a second VPS, which is the exact hazard this counter exists to
// detect.
func (c *providerRecoveryClient) OrderServer(context.Context, gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
	recordProviderCall(c.journal, providerCallPurchase, "order")
	return nil, errors.New("this fixture never performs purchase work")
}

func (c *providerRecoveryClient) OrderServerSafe(context.Context, gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
	recordProviderCall(c.journal, providerCallPurchase, "order_safe")
	return nil, errors.New("this fixture never performs purchase work")
}

// recordProviderCall appends `<method> <outcome>` to the shared provider journal.
func recordProviderCall(path, method, outcome string) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	_, _ = f.WriteString(method + " " + outcome + "\n")
}

// providerJournalCount counts provider journal lines matching a method and, when outcome is
// non-empty, that outcome too.
func providerJournalCount(path, method, outcome string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	count := 0
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != method {
			continue
		}
		if outcome != "" && (len(fields) < 2 || fields[1] != outcome) {
			continue
		}
		count++
	}
	return count
}

// providerReadFailuresTotal counts every deploy-status call that failed, in any child.
func providerReadFailuresTotal(path string) int {
	return providerJournalCount(path, providerCallDeployStatus, providerOutcomeError)
}

// providerReadSuccessesTotal counts every deploy-status call that was answered.
func providerReadSuccessesTotal(path string) int {
	return providerJournalCount(path, providerCallDeployStatus, providerOutcomeAnswered)
}

// purchaseAttemptsTotal counts every purchase-path call, whatever its outcome.
func purchaseAttemptsTotal(path string) int {
	return providerJournalCount(path, providerCallPurchase, "")
}
