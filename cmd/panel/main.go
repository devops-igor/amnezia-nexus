package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/config"
	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/handlers"
	"github.com/devops-igor/amnezia-nexus/internal/manager"
	"github.com/devops-igor/amnezia-nexus/internal/manager/awg"
	"github.com/devops-igor/amnezia-nexus/internal/manager/dns"
	"github.com/devops-igor/amnezia-nexus/internal/manager/mtproxyl"
	"github.com/devops-igor/amnezia-nexus/internal/manager/naive"
	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/manager/xray"
	"github.com/devops-igor/amnezia-nexus/internal/policy"
	"github.com/devops-igor/amnezia-nexus/internal/router"
	"github.com/devops-igor/amnezia-nexus/internal/service"
	"github.com/devops-igor/amnezia-nexus/internal/service/orchestrator"
	"github.com/devops-igor/amnezia-nexus/internal/vpn"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--version", "-version", "-v", "version":
			fmt.Printf("amnezia-nexus %s (%s)\n", config.AppVersion, config.AppCodename)
			return
		case "--check-wan-capabilities":
			// Deployment smoke assertion: report whether this process holds the
			// capabilities direct WAN egress needs, and exit non-zero when it does
			// not, so a container start-up probe or CI step fails here instead of
			// discovering the gap when PBR is first enabled.
			fmt.Printf("effective capabilities: %s\n", strings.Join(vpn.EffectiveCapabilityNames(), " "))
			failed := false
			for _, result := range vpn.RunStandaloneWANChecks(os.Stdout) {
				if !result.OK() {
					failed = true
				}
			}
			if failed {
				os.Exit(1)
			}
			return
		}
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := run(ctx); err != nil {
		slog.Error("Application terminated with error", "err", err)
		os.Exit(1)
	}
}

// envVPNListenPort reports the VPN_LISTEN_PORT environment variable.
//
// config.Load() always populates cfg.VPNListenPort (51820 even when the env
// var is unset), so "unset" cannot be distinguished from an explicit 51820
// via cfg.VPNListenPort. This reads the env var directly so an unset or
// invalid VPN_LISTEN_PORT leaves the DB-stored listen port in effect
// (Issue #16 edge case) instead of pinning it to the 51820 default.
func envVPNListenPort() (port int, ok bool) {
	raw := strings.TrimSpace(os.Getenv("VPN_LISTEN_PORT"))
	if raw == "" {
		return 0, false
	}
	p, err := strconv.Atoi(raw)
	if err != nil || p <= 0 || p > 65535 {
		return 0, false
	}
	return p, true
}

// startVPNDataPlane wires VPN_LISTEN_PORT into the VPN service and starts
// the VPN data plane.
//
// Issue #16: the env value is authoritative per boot - it is applied to the
// service config BEFORE Start (so the listener binds the port compose maps)
// and persisted via UpdateConfig, so subsequent boots read the persisted
// value even if the env var is later removed. If the operator changes the
// env, the next boot updates the persisted value again. An unset or invalid
// env value leaves the DB config in effect. The wiring runs before Start,
// so UpdateConfig never hits the running-listener rejection.
//
// When the TUN device is unavailable the panel continues in management-only
// mode (API up, data plane down); other startup errors are fatal.
func startVPNDataPlane(ctx context.Context, vpnSvc *vpn.Service, cfg *config.Config) (bool, bool, error) {
	envPort, envPortSet := envVPNListenPort()
	if envPortSet {
		cfgVPN, err := vpnSvc.GetConfig(ctx)
		if err != nil {
			return false, false, fmt.Errorf("failed to load VPN config for VPN_LISTEN_PORT wiring: %w", err)
		}
		if cfgVPN.ListenPort != envPort {
			wasPort := cfgVPN.ListenPort
			cfgVPN.ListenPort = envPort
			if err := vpnSvc.UpdateConfig(ctx, cfgVPN); err != nil {
				return false, false, fmt.Errorf("failed to apply VPN_LISTEN_PORT=%d to VPN config: %w", envPort, err)
			}
			slog.Info("VPN listen port set from VPN_LISTEN_PORT env", "port", envPort, "was", wasPort)
		}
	}

	if !cfg.VPNEnabled {
		return false, false, nil
	}

	if err := vpnSvc.Start(ctx); err != nil {
		return false, false, fmt.Errorf("failed to start VPN service: %w", err)
	}

	// Log the port the service is actually configured to bind, not
	// cfg.VPNListenPort (a hardcoded 51820 default when the env is
	// unset - misleading, Issue #16).
	boundPort := 0
	if boundCfg, cfgErr := vpnSvc.GetConfig(ctx); cfgErr == nil && boundCfg != nil {
		boundPort = boundCfg.ListenPort
	}
	slog.Info("VPN endpoint started", "engine", "upstream", "listen_port", boundPort)
	return true, true, nil
}

// loadPolicySettings reads the persisted policy routing record. An absent row
// yields the disabled default, which keeps existing and fresh installs on the
// old all-proxy route.
func loadPolicySettings(ctx context.Context, db *database.DB) (policy.Settings, error) {
	settings := policy.DefaultSettings()
	if db == nil {
		return settings, nil
	}
	var stored policy.Settings
	if err := db.GetSetting(ctx, policy.SettingsKey, &stored); err != nil {
		return settings, err
	}
	// Settings contains a slice and is not comparable, so emptiness is checked
	// field by field. An absent row leaves the target untouched.
	if stored.Preset == "" && !stored.Enabled && stored.SyncInterval == 0 && len(stored.CustomURLs) == 0 {
		return settings, nil
	}
	return stored.Normalize(), nil
}

// startPersistedPolicyRouting activates policy routing from the persisted record
// before the data plane accepts traffic (#678).
//
// The persisted record is authoritative and activation fails closed through the
// VPN prerequisite guards: a missing policy snapshot or an unavailable direct
// egress path leaves PBR disabled with a logged reason instead of routing traffic
// unproxied. A disabled record is the default for existing and fresh installs and
// does nothing here.
func startPersistedPolicyRouting(ctx context.Context, db *database.DB, vpnSvc *vpn.Service, cfg *config.Config) error {
	policySettings, err := loadPolicySettings(ctx, db)
	if err != nil {
		// Policy routing is an optional feature and its configuration read is not
		// worth failing panel start over. Failing closed here means leaving PBR
		// disabled, which is exactly the existing all-proxy behavior, so nothing
		// is routed more permissively than before the read was attempted.
		slog.Warn("Could not load policy routing settings; policy routing stays disabled", "err", err)
		return nil
	}
	if !policySettings.Enabled || !cfg.VPNEnabled {
		return nil
	}

	policyStore := policy.NewFileStore(filepath.Join(cfg.DataDir, "policy"))
	if startErr := vpnSvc.StartPolicyRouting(ctx, policySettings, policyStore, string(policySettings.Preset)); startErr != nil {
		// Fail closed: never start the data plane with PBR enabled but not
		// actually activated, because that would silently proxy everything while
		// the operator believes policy routing is on.
		return fmt.Errorf("failed to activate persisted policy routing: %w", startErr)
	}
	slog.Info("Policy routing activated from persisted settings",
		"preset", string(policySettings.Preset), "interval_seconds", policySettings.SyncInterval)
	return nil
}

func run(ctx context.Context) error {
	// 1. Load configuration
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// 2. Setup structured logging
	var level slog.Level
	switch cfg.LogLevel {
	case "DEBUG":
		level = slog.LevelDebug
	case "WARN":
		level = slog.LevelWarn
	case "ERROR":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)

	slog.Info("Starting Amnezia Web Panel", "version", cfg.AppVersion, "codename", cfg.AppCodename, "port", cfg.Port)

	// 3. Writability preflight check & SQLite database initialization
	if err := database.CheckPreflight(cfg.DataDir, cfg.DBPath); err != nil {
		return err
	}
	_ = config.LoadTranslations()

	if err := database.MigrateFromDataJSON(filepath.Join(cfg.DataDir, "data.json"), cfg.DBPath, cfg.SecretKey); err != nil {
		return fmt.Errorf("legacy data.json migration failed (data left untouched at %s): %w", filepath.Join(cfg.DataDir, "data.json"), err)
	}

	db, err := database.New(cfg.DBPath, cfg.SecretKey)
	if err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			slog.Warn("Error closing database", "err", closeErr)
		}
	}()

	// 4. Initialize protocol managers & registry
	sshPool := ssh.NewSSHClientPool(ssh.PoolConfig{
		IdleTimeout:     5 * time.Minute,
		KeepAlivePeriod: 30 * time.Second,
	}, db)

	awgMgr := awg.NewAWGManager(sshPool)
	if db != nil {
		awgMgr.SetIPAllocator(db)
	}
	mtproxylMgr := mtproxyl.NewMTProxyLManager(sshPool)
	dnsMgr := dns.NewDNSManager(sshPool)
	xrayMgr := xray.NewXrayManager(sshPool)
	naiveMgr := naive.NewNaiveManager(sshPool)

	reg := manager.NewRegistry()
	reg.Register(awgMgr)
	reg.Register(mtproxylMgr)
	reg.Register(dnsMgr)
	reg.Register(xrayMgr)
	reg.Register(naiveMgr)

	// 5. Startup Protocol Reconciliation
	reconciler := service.NewReconciler(db, reg)
	if err := reconciler.CleanupStaleProtocols(ctx); err != nil {
		slog.Warn("Startup reconciliation encountered error", "err", err)
	}

	// 6. User Operations
	userOps := service.NewUserOpsService(db, reg)

	// 7. Background Orchestrator
	orch := orchestrator.New(db, reg,
		orchestrator.WithUserOps(userOps),
	)

	// 8. VPN data plane (opt-in via VPN_ENABLED). When the TUN device is
	// unavailable the panel continues in management-only mode (API up, data
	// plane down); other startup errors are fatal.
	vpnSvc, err := vpn.NewVPNService(db, nil)
	if err != nil {
		return fmt.Errorf("failed to init VPN service: %w", err)
	}
	vpnSvc.SetAWGStatusProvider(awgMgr)
	reconciler.SetVPNService(vpnSvc)
	userOps.SetVPNService(vpnSvc)

	// 8b. Start persisted policy routing (#678) before the data plane accepts
	// traffic.
	if err := startPersistedPolicyRouting(ctx, db, vpnSvc, cfg); err != nil {
		return err
	}

	vpnStarted, poolSynced, err := startVPNDataPlane(ctx, vpnSvc, cfg)
	if err != nil {
		return err
	}
	if poolSynced {
		orch.SetTunnelStatusUpdater(vpnSvc)
		orch.SetSessionMigrator(vpnSvc)
	}

	// 9. Background Supervisor (started strictly after VPN data plane and status updater wiring)
	sup := service.NewSupervisor()
	sup.RegisterService(orch)
	sup.RegisterService(reconciler)

	supErrCh := make(chan error, 1)
	go func() {
		supErrCh <- sup.Start(ctx)
	}()

	// 10. Initialize HTTP Router and Server
	r := router.NewRouterWithDeps(handlers.Dependencies{
		Config:          cfg,
		DB:              db,
		Registry:        reg,
		SSHPool:         sshPool,
		AWGManager:      awgMgr,
		MTProxyLManager: mtproxylMgr,
		DNSManager:      dnsMgr,
		XrayManager:     xrayMgr,
		NaiveManager:    naiveMgr,
		VPNService:      vpnSvc,
	})
	srv := router.NewServer(cfg, r, db)

	serverErrCh := make(chan error, 1)
	go func() {
		slog.Info("Listening for HTTP connections", "host", cfg.Host, "port", cfg.Port)
		if err := srv.Start(); err != nil {
			serverErrCh <- err
		}
	}()

	// 10. Block until termination signal or server error
	select {
	case <-ctx.Done():
		slog.Info("Shutdown signal received, draining active connections...")
	case err := <-serverErrCh:
		return fmt.Errorf("HTTP server error: %w", err)
	case err := <-supErrCh:
		if err != nil && err != context.Canceled {
			return fmt.Errorf("background supervisor error: %w", err)
		}
	}

	// 11. Graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()

	if vpnStarted {
		if stopErr := vpnSvc.Stop(); stopErr != nil {
			slog.Warn("VPN service stop error", "err", stopErr)
		}
	}

	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Warn("HTTP server shutdown encountered error", "err", err)
	}

	if err := sup.Stop(shutdownCtx); err != nil {
		slog.Warn("Supervisor stop encountered error", "err", err)
	}

	slog.Info("Amnezia Web Panel stopped cleanly")
	return nil
}
