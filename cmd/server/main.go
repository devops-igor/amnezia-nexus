package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/devops-igor/amnezia-web-ui-go/internal/config"
	"github.com/devops-igor/amnezia-web-ui-go/internal/database"
	"github.com/devops-igor/amnezia-web-ui-go/internal/manager"
	"github.com/devops-igor/amnezia-web-ui-go/internal/manager/awg"
	"github.com/devops-igor/amnezia-web-ui-go/internal/manager/dns"
	"github.com/devops-igor/amnezia-web-ui-go/internal/manager/mtproxyl"
	"github.com/devops-igor/amnezia-web-ui-go/internal/manager/ssh"
	"github.com/devops-igor/amnezia-web-ui-go/internal/router"
	"github.com/devops-igor/amnezia-web-ui-go/internal/service"
	"github.com/devops-igor/amnezia-web-ui-go/internal/service/orchestrator"
	"github.com/devops-igor/amnezia-web-ui-go/internal/vpn"
	"github.com/devops-igor/amnezia-web-ui-go/internal/vpn/endpoint"
)

func main() {
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
// Issue #16: the env value is authoritative per boot — it is applied to the
// service config BEFORE Start (so the listener binds the port compose maps)
// and persisted via UpdateConfig, so subsequent boots read the persisted
// value even if the env var is later removed. If the operator changes the
// env, the next boot updates the persisted value again. An unset or invalid
// env value leaves the DB config in effect. The wiring runs before Start,
// so UpdateConfig never hits the running-listener rejection.
//
// When the TUN device is unavailable the server continues in management-only
// mode (API up, data plane down); other startup errors are fatal.
func startVPNDataPlane(ctx context.Context, vpnSvc *vpn.Service, cfg *config.Config) (bool, error) {
	envPort, envPortSet := envVPNListenPort()
	if envPortSet {
		cfgVPN, err := vpnSvc.GetConfig(ctx)
		if err != nil {
			return false, fmt.Errorf("failed to load VPN config for VPN_LISTEN_PORT wiring: %w", err)
		}
		if cfgVPN.ListenPort != envPort {
			wasPort := cfgVPN.ListenPort
			cfgVPN.ListenPort = envPort
			if err := vpnSvc.UpdateConfig(ctx, cfgVPN); err != nil {
				return false, fmt.Errorf("failed to apply VPN_LISTEN_PORT=%d to VPN config: %w", envPort, err)
			}
			slog.Info("VPN listen port set from VPN_LISTEN_PORT env", "port", envPort, "was", wasPort)
		}
	}

	if !cfg.VPNEnabled {
		return false, nil
	}

	vpnSvc.RequireTunDevice()
	stErr := vpnSvc.Start(ctx)
	switch {
	case stErr == nil:
		// Log the port the service is actually configured to bind, not
		// cfg.VPNListenPort (a hardcoded 51820 default when the env is
		// unset — misleading, Issue #16).
		boundPort := 0
		if boundCfg, cfgErr := vpnSvc.GetConfig(ctx); cfgErr == nil && boundCfg != nil {
			boundPort = boundCfg.ListenPort
		}
		slog.Info("VPN endpoint started", "listen_port", boundPort)
		return true, nil
	case errors.Is(stErr, endpoint.ErrTunUnavailable):
		slog.Warn("VPN endpoint unavailable (no TUN device): running management-only", "err", stErr)
		return false, nil
	default:
		return false, fmt.Errorf("failed to start VPN service: %w", stErr)
	}
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

	slog.Info("Starting Amnezia Web Panel Server", "version", cfg.AppVersion, "port", cfg.Port)

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
	mtproxylMgr := mtproxyl.NewMTProxyLManager(sshPool)
	dnsMgr := dns.NewDNSManager(sshPool)

	reg := manager.NewRegistry()
	reg.Register(awgMgr)
	reg.Register(mtproxylMgr)
	reg.Register(dnsMgr)

	// 5. Startup Protocol Reconciliation
	reconciler := service.NewReconciler(db, reg)
	if err := reconciler.CleanupStaleProtocols(ctx); err != nil {
		slog.Warn("Startup reconciliation encountered error", "err", err)
	}

	// 6. User Operations & RemnaWave Syncer
	userOps := service.NewUserOpsService(db, reg)
	remnaSyncer := service.NewRemnaWaveSyncer(db, nil, userOps)

	// 7. Background Orchestrator & Supervisor
	orch := orchestrator.New(db, reg,
		orchestrator.WithUserOps(userOps),
		orchestrator.WithRemnaWaveSyncer(remnaSyncer),
	)

	sup := service.NewSupervisor()
	sup.RegisterService(orch)

	supErrCh := make(chan error, 1)
	go func() {
		supErrCh <- sup.Start(ctx)
	}()

	// 8. VPN data plane (opt-in via VPN_ENABLED). When the TUN device is
	// unavailable the server continues in management-only mode (API up, data
	// plane down); other startup errors are fatal.
	vpnSvc, err := vpn.NewVPNService(db, nil)
	if err != nil {
		return fmt.Errorf("failed to init VPN service: %w", err)
	}

	vpnStarted, err := startVPNDataPlane(ctx, vpnSvc, cfg)
	if err != nil {
		return err
	}

	// 9. Initialize HTTP Router and Server
	r := router.NewRouter(cfg, db, vpnSvc)
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

	slog.Info("Amnezia Web Panel Server stopped cleanly")
	return nil
}
