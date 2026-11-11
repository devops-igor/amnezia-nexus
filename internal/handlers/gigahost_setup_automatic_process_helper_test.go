package handlers

// Child side of the automatic fresh-process proof.
//
// Every mode here hands a genuinely separate OS process nothing but a database path, the
// application secret, an effect-journal path and a loopback SSH endpoint. It builds its
// handlers from those facts alone - no closure, policy or provider stub is inherited from
// the parent - so whatever it manages to do, it did from durable state.
//
// Two kinds of evidence come back:
//
//   - a machine-readable line on stdout, which the parent parses and asserts on. The child
//     never decides pass/fail for the parent;
//   - the effect journal file, appended by the child's own protocol manager and VPN hook,
//     which is how "did it install again?" is answered across a process boundary.
//
// The SSH peer belongs to the parent. The child dials it over TCP with the credential it
// decrypted from SQLite, so "the child offered no credential" is a real socket counter in
// another process rather than an assertion about this code.
//
// Boundaries kept explicit: the protocol install and the traffic qualification are the
// repository's existing fixture replacements. This is NOT VPN traffic, NOT a real host and
// NOT a healthy-pool proof.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/config"
	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/manager"
	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
	"github.com/devops-igor/amnezia-nexus/internal/service/gigahostsetup"
	"github.com/devops-igor/amnezia-nexus/internal/vpn"
)

// Environment the automatic modes need beyond the shared harness contract. Each value is
// a path, an endpoint or a mode name; no credential material and no policy object crosses
// the boundary.
const (
	// envProcessSSHEndpoint is the parent's loopback peer as host:port. It is the only
	// way the child can reach the host, and it stands in for the provider's address.
	envProcessSSHEndpoint = "GIGAHOST_PROCESS_SSH_ENDPOINT"
	// envProcessPolicy is the child's own policy answer: "on", "off", "error" or
	// unset for "no policy installed at all". It is a fixture opt-in, never a live
	// setting, and it exists so a child can be started in each policy state.
	envProcessPolicy = "GIGAHOST_PROCESS_POLICY"
	// envProcessClock pins the child's tracker clock, so a pass can be made due without
	// waiting for real time.
	envProcessClock = "GIGAHOST_PROCESS_CLOCK"
)

// The single order and provider identity these automatic proofs use. They are distinct
// from the manual-proof constants so the two sets of process tests cannot interfere.
const (
	autoProcessOrderID  = "ord_auto_process_proof"
	autoProcessServerID = 8801
)

// Automatic child modes.
const (
	// procAutomaticTrack: one production tracker pass over the entry-created job. This is
	// the pass that must discover the provider facts, record the association, grant, and
	// pin - all from durable state.
	procAutomaticTrack = "automatic_track"
	// procAutomaticInstall: one production installer pass. Used both to complete a job
	// the tracking pass prepared and to prove a refusal at a later boundary.
	procAutomaticInstall = "automatic_install"
	// procAutomaticTrackAndInstall: both passes in one process, for the cases where the
	// interesting boundary is inside a single fresh run.
	procAutomaticTrackAndInstall = "automatic_track_and_install"
)

// childAutomationPolicy is the child's fixture opt-in.
//
// It is the only implementation in the child, and it is chosen by an environment variable,
// so a deployment that sets nothing gets the shipped answer: no policy, which refuses.
type childAutomationPolicy struct {
	enabled bool
	err     error
}

func (p childAutomationPolicy) Enabled(context.Context) (bool, error) { return p.enabled, p.err }

// newAutoProcessHelperHandlers builds the child's handlers from durable facts only.
//
// This is deliberately close to the production wiring: the same tracker constructor, the
// same installer constructor, the same wiring functions. What differs is exactly the set
// of external boundaries the existing fixtures replace - provider, protocol manager, VPN
// probes - plus the policy, which has no production implementation at all.
func newAutoProcessHelperHandlers(dbPath, secret, journal, endpoint, policyMode string) (*Handlers, error) {
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

	// The provider answers from the fixture, and its address is the parent's loopback
	// peer so the real handshake happens at a socket the parent owns.
	host := endpoint
	if i := strings.LastIndex(endpoint, ":"); i > 0 {
		host = endpoint[:i]
	}
	h.SetGigahostClient(&mockGigahostClient{
		getDeployStatusFn: func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
			return &gigahost.DeployStatusResponse{
				OrderID: autoProcessOrderID, Status: gigahost.StatusReady,
				ServerID: autoProcessServerID, AssignedIP: host,
			}, nil
		},
		getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) {
			return []gigahost.ServerInfo{
				{ID: autoProcessServerID, OrderID: autoProcessOrderID, IPv4: host, Status: "ready"},
			}, nil
		},
	})

	// A real dial to the parent's peer. The fingerprint the parent's peer presents is
	// discovered by the child's own challenge; nothing is inherited.
	h.SetSSHDialerForTest(func(ctx context.Context, cfg ssh.Config) (ssh.SSHClient, error) {
		if endpoint == "" {
			return nil, errors.New("no SSH endpoint was configured for this child")
		}
		if i := strings.LastIndex(endpoint, ":"); i > 0 {
			port, convErr := strconv.Atoi(endpoint[i+1:])
			if convErr != nil {
				return nil, fmt.Errorf("bad SSH endpoint %q", endpoint)
			}
			cfg.Port = port
		}
		cfg.Timeout = 5 * time.Second
		return ssh.Dial(ctx, cfg)
	})

	if err := applyChildPolicy(h, policyMode); err != nil {
		return nil, err
	}
	return h, nil
}

// applyChildPolicy installs the child's fixture opt-in, or none at all.
func applyChildPolicy(h *Handlers, mode string) error {
	switch strings.TrimSpace(mode) {
	case "":
		// No policy installed: the shipped configuration, which refuses everything.
		return nil
	case "on":
		h.SetGigahostSetupAutomationPolicyForTest(childAutomationPolicy{enabled: true})
	case "off":
		h.SetGigahostSetupAutomationPolicyForTest(childAutomationPolicy{enabled: false})
	case "error":
		h.SetGigahostSetupAutomationPolicyForTest(
			childAutomationPolicy{err: errors.New("the unattended setup setting could not be read")})
	default:
		return fmt.Errorf("unknown policy mode %q", mode)
	}
	return nil
}

// childClock returns the tracker clock a child should use.
//
// A pinned clock is how a pass is made due without waiting: the parent seeds a job whose
// next attempt is already in the past relative to the pinned instant.
func childClock(mode string) func() time.Time {
	if mode == "" {
		return nil
	}
	if fixed, err := strconv.ParseInt(mode, 10, 64); err == nil {
		instant := time.Unix(fixed, 0).UTC()
		return func() time.Time { return instant }
	}
	return nil
}

// runAutomaticMode performs one automatic child mode and returns its exit code.
//
// The child reports facts on stdout in `key=value` form and decides only two things: that
// it ran the passes it was asked to run, and that its own credential load worked. Every
// judgment about whether an effect was allowed belongs to the parent, which is the
// process that can see the peer counters and the journal.
func runAutomaticMode(ctx context.Context, mode string) int {
	dbPath := os.Getenv(envProcessDBPath)
	journal := os.Getenv(envProcessJournal)
	secret := os.Getenv(envProcessSecret)
	endpoint := os.Getenv(envProcessSSHEndpoint)
	if dbPath == "" || journal == "" || secret == "" {
		fmt.Fprintln(os.Stderr, "automatic helper: required environment is missing")
		return 4
	}
	h, err := newAutoProcessHelperHandlers(dbPath, secret, journal, endpoint,
		os.Getenv(envProcessPolicy))
	if err != nil {
		fmt.Fprintf(os.Stderr, "automatic helper: %v\n", err)
		return 4
	}

	now := childClock(os.Getenv(envProcessClock))
	report := func(passName string) int {
		intent, found, readErr := h.db.GetGigahostSetupIntent(ctx, autoProcessOrderID)
		if readErr != nil || !found {
			fmt.Fprintf(os.Stderr, "automatic helper: intent unreadable: found=%v err=%v\n", found, readErr)
			return 3
		}
		fmt.Printf("pass=%s state=%s step=%s phase=%s phase_done=%s generation=%d\n",
			passName, intent.State, intent.Step, intent.InstallPhase, intent.InstallPhaseDone,
			intent.InstallGeneration)
		fmt.Printf("policy=%s grant_order=%s grant_server=%d grant_address=%s grant_key=%d granted_at=%s\n",
			intent.HostTrustPolicy, intent.HostTrustOrderID, intent.HostTrustServerID,
			intent.HostTrustAddress, intent.HostTrustKeyID, intent.HostTrustGrantedAt.Format(time.RFC3339Nano))
		fmt.Printf("fingerprint=%s mode=%s server_id=%d last_error=%q\n",
			intent.HostFingerprint, intent.HostTrustMode, intent.NexusServerID, intent.LastError)
		fmt.Printf("effects install=%d enable=%d\n",
			effectCount(journal, "install"), effectCount(journal, "enable"))
		// The digest of the credential THIS process decrypted from the database. It is how
		// the parent proves the child used the material the purchase stored, without either
		// process printing a key. A child that could not decrypt reports an empty digest and
		// a refusal reason, which is the correct evidence for those cases.
		if digest, digestErr := credentialDigestOfOrder(ctx, h, autoProcessOrderID); digestErr == nil {
			fmt.Printf("credential_sha256=%s\n", digest)
		}
		return 0
	}

	switch mode {
	case procAutomaticTrack:
		tracker := h.newAutoProcessTracker(now)
		if tracker == nil {
			fmt.Fprintln(os.Stderr, "automatic helper: the tracker was not constructed")
			return 4
		}
		if err := tracker.RunOnce(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "automatic helper: tracking pass failed: %v\n", err)
			return 3
		}
		return report("track")
	case procAutomaticInstall:
		installer := h.NewGigahostSetupInstaller()
		if installer == nil {
			fmt.Fprintln(os.Stderr, "automatic helper: the installer was not constructed")
			return 4
		}
		if err := installer.RunOnce(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "automatic helper: install pass failed: %v\n", err)
			return 3
		}
		return report("install")
	case procAutomaticTrackAndInstall:
		tracker := h.newAutoProcessTracker(now)
		if tracker == nil {
			fmt.Fprintln(os.Stderr, "automatic helper: the tracker was not constructed")
			return 4
		}
		if err := tracker.RunOnce(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "automatic helper: tracking pass failed: %v\n", err)
			return 3
		}
		installer := h.NewGigahostSetupInstaller()
		if installer == nil {
			fmt.Fprintln(os.Stderr, "automatic helper: the installer was not constructed")
			return 4
		}
		if err := installer.RunOnce(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "automatic helper: install pass failed: %v\n", err)
			return 3
		}
		return report("track_and_install")
	default:
		fmt.Fprintf(os.Stderr, "automatic helper: unknown mode %q\n", mode)
		return 4
	}
}

// newAutoProcessTracker builds the tracker the application supervises, optionally with a
// pinned clock so a pass can be made due without waiting for real time.
//
// It goes through the production constructor and then applies the clock through the same
// Options the application uses, so nothing about the tracker is test-shaped except the
// instant it believes it is.
func (h *Handlers) newAutoProcessTracker(now func() time.Time) *gigahostsetup.Tracker {
	if h == nil || h.db == nil {
		return nil
	}
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
	return gigahostsetup.New(h.db, opts)
}

// credentialDigestOfOrder reports the SHA-256 of the decrypted managed credential, or a
// refusal. The parent compares digests across processes; the material never leaves the
// child.
func credentialDigestOfOrder(ctx context.Context, h *Handlers, orderID string) (string, error) {
	credential, found, err := h.db.GetGigahostOrderCredential(ctx, orderID)
	if err != nil {
		return "", err
	}
	if !found || credential == nil || credential.PrivateKey == "" {
		return "", errors.New("no managed credential is stored")
	}
	sum := sha256.Sum256([]byte(credential.PrivateKey))
	return hex.EncodeToString(sum[:]), nil
}
