package handlers

// Fresh-process proof of saved-installation ownership and credential continuity.
//
// Why this file exists
// --------------------
// Every earlier checkpoint proved durability by reloading the worker over a
// reopened database IN THE SAME PROCESS. That cannot distinguish durable state
// from process memory. Here a genuinely different OS process is started - the Go
// test binary re-executed with the repository's existing subprocess pattern
// (`internal/config/secret_key_test.go`) - over the same temporary database, and
// it must reach a decided outcome without repeating any effect.
//
// What makes the claim about a different process rather than a spy
// ---------------------------------------------------------------
// Controlled external effects (protocol install, backend enablement) are recorded
// by APPENDING TO A FILE that both processes open. A counter held in the parent's
// memory would prove nothing about a child. The protocol manager and the VPN
// service's pre-add hook both append to that file, so the parent can count what
// the child actually did.
//
// Boundaries kept explicit: the "remote command" result here is a synthetic
// fixture append. It is NOT VPN traffic, NOT a real host, and NOT a provider call.

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/config"
	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/manager"
	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
	"github.com/devops-igor/amnezia-nexus/internal/vpn"
)

// Environment variables shared with the child process. Each value is a temp path,
// a mode name or the application secret; no credential material is passed through
// the environment, because the child loads that from the encrypted database.
const (
	envProcessMode    = "GIGAHOST_PROCESS_MODE"
	envProcessDBPath  = "GIGAHOST_PROCESS_DB_PATH"
	envProcessJournal = "GIGAHOST_PROCESS_EFFECT_LOG"
	envProcessSecret  = "GIGAHOST_PROCESS_SECRET"
	// envProcessStaleGeneration makes the stale-generation control hand the child a
	// SPECIFIC superseded generation instead of the one it reads from the row.
	envProcessStaleGeneration = "GIGAHOST_PROCESS_STALE_GENERATION"
)

// Child modes. Each names one persisted situation and the decided outcome it must
// reach.
const (
	// procCrashTakeoverComplete: interrupted inside enablement, and the persisted
	// state proves enablement never landed. The child may take the claim over with
	// a new generation, enable once, verify admission and finish.
	procCrashTakeoverComplete = "crash_takeover_complete"
	// procCrashUnknownPauses: interrupted inside protocol installation with no
	// persisted proof of the install. The child must pause, not retry.
	procCrashUnknownPauses = "crash_unknown_pauses"
	// procAlreadyCompleteNoop: a genuinely finished row; the child must do nothing.
	procAlreadyCompleteNoop = "already_complete_noop"
	// procRevokedRefuses: a revoked row; the child must produce no effect.
	procRevokedRefuses = "revoked_refuses"
	// procStaleGenerationRefuses: an installing row owned by a superseded attempt.
	procStaleGenerationRefuses = "stale_generation_refuses"
	// procCredentialOK: the stored credential decrypts after the schema upgrade.
	procCredentialOK = "credential_ok"
	// procCredentialWrongSecret: the same row cannot be decrypted with another key.
	procCredentialWrongSecret = "credential_wrong_secret"
	// procCredentialMissing: no stored credential; access is refused before any
	// remote-command fixture effect.
	procCredentialMissing = "credential_missing"
)

// processProofOrderID is the single order id these proofs use.
const processProofOrderID = "ord_process_proof"

// processProofPlaintext is the fixture private-key body. It is synthetic and must
// never be printed: the child reports only its SHA-256.
const processProofPlaintext = "FIXTURE-ONLY-PRIVATE-KEY-BODY-NOT-A-REAL-KEY"

// TestSetupInstallProcessHelper is the child entry point.
//
// It returns immediately unless the parent set the mode variable, so it is inert
// during an ordinary test run. This is the same pattern `internal/config` already
// uses for its multi-process secret-key tests, not a new runtime mode.
func TestSetupInstallProcessHelper(t *testing.T) {
	mode := os.Getenv(envProcessMode)
	if mode == "" {
		return
	}
	// os.Exit inside a test terminates the child only; the exit code is the
	// child's report and the parent asserts on it.
	os.Exit(runProcessHelperMode(mode))
}

// runProcessHelperMode performs one child mode and returns its exit code.
//
// Exit codes are the child's out-of-band report:
//
//	0  the mode reached its expected outcome
//	3  the mode's expectation was violated
//	4  setup failed (missing environment, unreadable database, bad mode)
func runProcessHelperMode(mode string) int {
	dbPath := os.Getenv(envProcessDBPath)
	journal := os.Getenv(envProcessJournal)
	secret := os.Getenv(envProcessSecret)
	if dbPath == "" || journal == "" || secret == "" {
		fmt.Fprintln(os.Stderr, "process helper: required environment is missing")
		return 4
	}
	ctx := context.Background()

	switch mode {
	case procCredentialOK, procCredentialWrongSecret, procCredentialMissing:
		return runCredentialContinuityMode(ctx, mode, dbPath, secret, journal)
	case procCrashTakeoverComplete, procCrashUnknownPauses,
		procAlreadyCompleteNoop, procRevokedRefuses, procStaleGenerationRefuses:
		return runInstallOwnershipMode(ctx, mode, dbPath, secret, journal)
	case procAutomaticTrack, procAutomaticInstall, procAutomaticTrackAndInstall:
		return runAutomaticMode(ctx, mode)
	default:
		fmt.Fprintf(os.Stderr, "process helper: unknown mode %q\n", mode)
		return 4
	}
}

// runCredentialContinuityMode loads the stored order credential through the real
// application path after the schema upgrade, and reports only its digest.
func runCredentialContinuityMode(ctx context.Context, mode, dbPath, secret, journal string) int {
	h, err := newProcessHelperHandlers(dbPath, secret, journal)
	if err != nil {
		fmt.Fprintf(os.Stderr, "process helper: %v\n", err)
		return 4
	}
	req, pause, err := h.prepareInstall(ctx, models.GigahostSetupIntent{
		OrderID:          processProofOrderID,
		ProviderServerID: 7001,
		Protocol:         models.ProtocolAWG,
		Port:             "51820",
		CredentialMode:   models.SetupCredentialManaged,
		AssignedIP:       "198.51.100.200",
		HostFingerprint:  installFixtureFingerprint,
		State:            models.SetupStateReadyForSetup,
	})
	switch mode {
	case procCredentialMissing, procCredentialWrongSecret:
		// A decryption failure must be a hard error and a missing credential must be
		// a refusal - never an empty key accepted as "no authentication".
		if err == nil {
			fmt.Fprintf(os.Stderr, "process helper: %s produced a usable credential\n", mode)
			return 3
		}
		if effectCount(journal, "install") != 0 || effectCount(journal, "enable") != 0 {
			fmt.Fprintln(os.Stderr, "process helper: a refused credential produced an effect")
			return 3
		}
		return 0
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "process helper: credential load failed: %v\n", err)
		return 3
	}
	if pause != nil {
		fmt.Fprintf(os.Stderr, "process helper: credential load paused at %q\n", pause.step)
		return 3
	}
	if req.SSHPrivateKey == "" {
		fmt.Fprintln(os.Stderr, "process helper: no credential was loaded")
		return 3
	}
	// Report a digest, never the material.
	sum := sha256.Sum256([]byte(req.SSHPrivateKey))
	fmt.Printf("credential_sha256=%s\n", hex.EncodeToString(sum[:]))
	if effectCount(journal, "install") != 0 || effectCount(journal, "enable") != 0 {
		fmt.Fprintln(os.Stderr, "process helper: credential loading produced a remote-command effect")
		return 3
	}
	return 0
}

// runInstallOwnershipMode loads the persisted intent in a fresh process and drives
// exactly one installer pass over it.
func runInstallOwnershipMode(ctx context.Context, mode, dbPath, secret, journal string) int {
	h, err := newProcessHelperHandlers(dbPath, secret, journal)
	if err != nil {
		fmt.Fprintf(os.Stderr, "process helper: %v\n", err)
		return 4
	}
	if stale := os.Getenv(envProcessStaleGeneration); stale != "" {
		return runStaleGenerationMode(ctx, h, mode, journal, stale)
	}
	if err := h.NewGigahostSetupInstaller().RunOnce(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "process helper: installer pass failed: %v\n", err)
		return 3
	}
	intent, found, err := h.db.GetGigahostSetupIntent(ctx, processProofOrderID)
	if err != nil || !found {
		fmt.Fprintf(os.Stderr, "process helper: intent unreadable: found=%v err=%v\n", found, err)
		return 3
	}
	// The child prints the persisted outcome; the parent asserts on it. Nothing here
	// decides pass/fail, so a violation cannot be hidden inside the child.
	fmt.Printf("state=%s generation=%d phase=%s phase_done=%s nexus_server_id=%d installs=%d enables=%d\n",
		intent.State, intent.InstallGeneration, intent.InstallPhase, intent.InstallPhaseDone,
		intent.NexusServerID, effectCount(journal, "install"), effectCount(journal, "enable"))
	_ = mode
	return 0
}

// newProcessHelperHandlers builds a handlers instance over the persisted database
// with the same controlled boundaries as the lifecycle fixture, except that the
// effect journal is a FILE both processes append to.
func newProcessHelperHandlers(dbPath, secret, journal string) (*Handlers, error) {
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
	h.SetSSHDialerForTest(func(context.Context, ssh.Config) (ssh.SSHClient, error) {
		return &mockDeploySSHClient{fingerprint: installFixtureFingerprint}, nil
	})
	h.SetGigahostClient(&mockGigahostClient{
		getDeployStatusFn: func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
			return &gigahost.DeployStatusResponse{
				OrderID: processProofOrderID, Status: gigahost.StatusReady,
				ServerID: 7001, AssignedIP: "198.51.100.200",
			}, nil
		},
		getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) {
			return []gigahost.ServerInfo{
				{ID: 7001, OrderID: processProofOrderID, IPv4: "198.51.100.200", Status: "ready"},
			}, nil
		},
	})
	return h, nil
}

// processProofProtocolManager records its install effect in the shared journal
// file and writes the server row the enablement step needs.
type processProofProtocolManager struct {
	journal string
}

func (m *processProofProtocolManager) Protocol() string { return models.ProtocolAWG }

func (m *processProofProtocolManager) Install(_ context.Context, server *models.Server, params map[string]any) error {
	appendEffect(m.journal, "install")
	if server.Protocols == nil {
		server.Protocols = map[string]any{}
	}
	port, _ := params["port"].(string)
	if port == "" {
		port = "51820"
	}
	server.Protocols[models.ProtocolAWG] = map[string]any{
		"installed":  true,
		"port":       port,
		"public_key": "x9aB1234567890abcdef1234567890abcdef1234567=",
	}
	return nil
}

func (m *processProofProtocolManager) Uninstall(context.Context, *models.Server) error { return nil }

func (m *processProofProtocolManager) GetClients(context.Context, *models.Server) ([]map[string]any, error) {
	return nil, nil
}

func (m *processProofProtocolManager) AddClient(context.Context, *models.Server, map[string]any) (map[string]any, error) {
	return map[string]any{"client_id": "fixture"}, nil
}

func (m *processProofProtocolManager) RemoveClient(context.Context, *models.Server, string) error {
	return nil
}

func (m *processProofProtocolManager) GetClientConfig(context.Context, *models.Server, string) (string, error) {
	return "", nil
}

// appendEffect appends "kind\n" to the shared journal file. Appending is the point:
// two OS processes record into one file, so the parent can count the child's work.
func appendEffect(path, kind string) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	_, _ = f.WriteString(kind + "\n")
}

// effectCount counts journal lines of one kind.
func effectCount(path, kind string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer func() { _ = f.Close() }()
	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == kind {
			count++
		}
	}
	return count
}

// runStaleGenerationMode proves, in this other process, that an attempt holding a
// superseded generation is refused by the persisted row rather than trusted.
//
// The proof goes through the REAL fenced store write - the same
// UpdateGigahostSetupInstall the production journal uses - rather than a
// test-only constructor: a stale generation must match no row and report
// changed=false, and the live generation must match. The exit code encodes which
// happened, so the parent can distinguish "correctly refused" from "incorrectly
// accepted" without parsing prose.
func runStaleGenerationMode(ctx context.Context, h *Handlers, mode, journal, rawGeneration string) int {
	generation, err := strconv.ParseInt(rawGeneration, 10, 64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "process helper: bad generation %q\n", rawGeneration)
		return 4
	}
	intent, found, err := h.db.GetGigahostSetupIntent(ctx, processProofOrderID)
	if err != nil || !found {
		fmt.Fprintf(os.Stderr, "process helper: intent unreadable: found=%v err=%v\n", found, err)
		return 4
	}
	// A journal write in every respect except the generation it presents.
	attempt := *intent
	attempt.Step = "install_taken_over"
	attempt.State = models.SetupStateInstalling

	changed, err := h.db.UpdateGigahostSetupInstall(ctx, &attempt, generation)
	if err != nil {
		fmt.Fprintf(os.Stderr, "process helper: fenced write failed: %v\n", err)
		return 4
	}
	if generation != intent.InstallGeneration {
		if changed {
			fmt.Fprintln(os.Stderr, "process helper: a superseded generation wrote to the row")
			return 3
		}
		if effectCount(journal, "install") != 0 || effectCount(journal, "enable") != 0 {
			fmt.Fprintln(os.Stderr, "process helper: a superseded attempt produced an effect")
			return 3
		}
		fmt.Printf("refused_generation=%d live_generation=%d\n", generation, intent.InstallGeneration)
		return 0
	}
	// The live generation is accepted, which is the contrast that makes the refusal
	// above meaningful.
	if !changed {
		fmt.Fprintln(os.Stderr, "process helper: the live generation was refused")
		return 3
	}
	fmt.Printf("accepted_generation=%d\n", generation)
	return 1
}
