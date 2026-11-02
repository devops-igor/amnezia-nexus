package naive

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

type naiveConfigFile struct {
	Listen            string `json:"listen"`
	Proxy             string `json:"proxy"`
	Log               string `json:"log"`
	HostResolverRules string `json:"host-resolver-rules,omitempty"`
}

// GenerateConfigJSON produces the JSON configuration payload expected by the upstream naive binary.
func GenerateConfigJSON(listenPort int, endpoint string, p models.NaiveProxyParams) ([]byte, error) {
	if listenPort <= 0 || listenPort > 65535 {
		return nil, fmt.Errorf("naive: invalid listen port %d", listenPort)
	}
	endpoint = strings.TrimSpace(endpoint)
	host, portStr, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, fmt.Errorf("naive: invalid endpoint %q: %w", endpoint, err)
	}

	domain := strings.TrimSpace(p.Domain)
	if domain == "" {
		return nil, errors.New("naive: domain cannot be empty")
	}

	scheme := "https"
	if p.EnableH3 {
		scheme = "quic"
	}

	proxyHostPort := net.JoinHostPort(domain, portStr)
	userPass := url.UserPassword(p.Username, p.Password)
	u := url.URL{
		Scheme: scheme,
		User:   userPass,
		Host:   proxyHostPort,
	}

	cfg := naiveConfigFile{
		Listen: fmt.Sprintf("socks://127.0.0.1:%d", listenPort),
		Proxy:  u.String(),
		Log:    "",
	}

	if host != domain {
		cfg.HostResolverRules = fmt.Sprintf("MAP %s %s", domain, host)
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("naive: failed to marshal config JSON: %w", err)
	}
	return data, nil
}

func writeTempConfig(listenPort int, endpoint string, p models.NaiveProxyParams) (string, error) {
	data, err := GenerateConfigJSON(listenPort, endpoint, p)
	if err != nil {
		return "", err
	}

	tmpFile, err := os.CreateTemp("", "naive-cfg-*.json")
	if err != nil {
		return "", fmt.Errorf("naive: failed to create temporary config file: %w", err)
	}
	tmpPath := tmpFile.Name()

	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("naive: failed to write temporary config: %w", err)
	}

	// Mode 0600 is mandatory to prevent exposure of credentials to other users.
	if err := tmpFile.Chmod(0600); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("naive: failed to chmod config file: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("naive: failed to close config file: %w", err)
	}

	return tmpPath, nil
}

func allocateLoopbackPort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("naive: failed to allocate loopback port: %w", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		return 0, err
	}
	return port, nil
}

// Daemon represents a supervised upstream naive process instance.
type Daemon struct {
	mu             sync.Mutex
	binPath        string
	endpoint       string
	params         models.NaiveProxyParams
	port           int
	configPath     string
	cmd            *exec.Cmd
	cmdCancel      context.CancelFunc
	exitCh         chan struct{}
	stopped        bool
	socksDialer    StreamDialer
	readinessWait  time.Duration
	restartDelay   time.Duration
	stopSupervisor chan struct{}
}

// NewDaemon initializes a Daemon supervisor without starting the child process.
func NewDaemon(binPath, endpoint string, params models.NaiveProxyParams) (*Daemon, error) {
	if binPath == "" {
		return nil, errors.New("naive: empty binary path for daemon")
	}
	if endpoint == "" {
		return nil, errors.New("naive: empty endpoint for daemon")
	}
	if params.Username == "" || params.Password == "" || params.Domain == "" {
		return nil, errors.New("naive: incomplete NaiveProxyParams")
	}

	return &Daemon{
		binPath:        binPath,
		endpoint:       endpoint,
		params:         params,
		readinessWait:  5 * time.Second,
		restartDelay:   200 * time.Millisecond,
		stopSupervisor: make(chan struct{}),
	}, nil
}

// SetPort sets an explicit port for the daemon to listen on (useful for testing or fixed ports).
func (d *Daemon) SetPort(port int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.port = port
}

// SetReadinessTimeout configures the maximum duration to wait for the local SOCKS5 listener.
func (d *Daemon) SetReadinessTimeout(dur time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.readinessWait = dur
}

// Start launches the naive child process and polls until the local SOCKS5 listener is accepting connections.
func (d *Daemon) Start(ctx context.Context) error {
	d.mu.Lock()
	if d.stopped {
		d.mu.Unlock()
		return errors.New("naive: daemon has been stopped")
	}
	if d.cmd != nil {
		d.mu.Unlock()
		return errors.New("naive: daemon is already running")
	}

	if d.port == 0 {
		port, err := allocateLoopbackPort()
		if err != nil {
			d.mu.Unlock()
			return err
		}
		d.port = port
	}

	cfgPath, err := writeTempConfig(d.port, d.endpoint, d.params)
	if err != nil {
		d.mu.Unlock()
		return err
	}
	d.configPath = cfgPath

	if err := d.startProcessLocked(); err != nil {
		_ = os.Remove(d.configPath)
		d.configPath = ""
		d.mu.Unlock()
		return err
	}
	port := d.port
	readinessWait := d.readinessWait
	d.mu.Unlock()

	// Readiness probe
	readyCtx := ctx
	var readyCancel context.CancelFunc
	if _, ok := ctx.Deadline(); !ok {
		readyCtx, readyCancel = context.WithTimeout(ctx, readinessWait)
		defer readyCancel()
	}

	if err := d.waitForReady(readyCtx, port); err != nil {
		_ = d.Stop()
		return fmt.Errorf("naive: readiness probe failed: %w", err)
	}

	dialer, err := NewSocks5Dialer(fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		_ = d.Stop()
		return fmt.Errorf("naive: failed to create SOCKS5 dialer: %w", err)
	}

	d.mu.Lock()
	d.socksDialer = dialer
	d.mu.Unlock()

	return nil
}

func (d *Daemon) startProcessLocked() error {
	cmdCtx, cancel := context.WithCancel(context.Background())
	// #nosec G204 -- supervised binary path and config path are validated internal paths
	cmd := exec.CommandContext(cmdCtx, d.binPath, d.configPath)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard

	if err := cmd.Start(); err != nil {
		cancel()
		return fmt.Errorf("naive: failed to start process: %w", err)
	}

	exitCh := make(chan struct{})
	d.cmd = cmd
	d.cmdCancel = cancel
	d.exitCh = exitCh

	go func(c *exec.Cmd, ch chan struct{}) {
		_ = c.Wait()
		close(ch)
		d.handleProcessExit(c)
	}(cmd, exitCh)

	return nil
}

func (d *Daemon) handleProcessExit(c *exec.Cmd) {
	d.mu.Lock()
	if d.stopped || d.cmd != c {
		d.mu.Unlock()
		return
	}
	d.cmd = nil
	if d.cmdCancel != nil {
		d.cmdCancel()
		d.cmdCancel = nil
	}
	delay := d.restartDelay
	d.restartDelay *= 2
	if d.restartDelay > 5*time.Second {
		d.restartDelay = 5 * time.Second
	}
	d.mu.Unlock()

	select {
	case <-d.stopSupervisor:
		return
	case <-time.After(delay):
	}

	d.mu.Lock()
	if d.stopped {
		d.mu.Unlock()
		return
	}
	if err := d.startProcessLocked(); err != nil {
		d.mu.Unlock()
		return
	}
	port := d.port
	d.mu.Unlock()

	probeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := d.waitForReady(probeCtx, port); err == nil {
		// Successfully recovered, reset backoff after healthy uptime
		time.AfterFunc(30*time.Second, func() {
			d.mu.Lock()
			defer d.mu.Unlock()
			if !d.stopped && d.cmd != nil {
				d.restartDelay = 200 * time.Millisecond
			}
		})
	}
}

func (d *Daemon) waitForReady(ctx context.Context, port int) error {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			conn, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
			if err == nil {
				_ = conn.Close()
				return nil
			}

			// Check if process died prematurely
			d.mu.Lock()
			cmd := d.cmd
			d.mu.Unlock()
			if cmd != nil && cmd.ProcessState != nil && cmd.ProcessState.Exited() {
				return fmt.Errorf("process exited with status %d before readiness", cmd.ProcessState.ExitCode())
			}
		}
	}
}

// Stop gracefully terminates the daemon with SIGTERM, waiting up to 5s before SIGKILL, and removes temp config.
func (d *Daemon) Stop() error {
	d.mu.Lock()
	if d.stopped {
		d.mu.Unlock()
		return nil
	}
	d.stopped = true
	close(d.stopSupervisor)

	cmd := d.cmd
	exitCh := d.exitCh
	cancel := d.cmdCancel
	configPath := d.configPath
	d.cmd = nil
	d.cmdCancel = nil
	d.configPath = ""
	d.socksDialer = nil
	d.mu.Unlock()

	if cmd != nil && cmd.Process != nil && exitCh != nil {
		_ = cmd.Process.Signal(syscall.SIGTERM)

		select {
		case <-exitCh:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-exitCh
		}
	}

	if cancel != nil {
		cancel()
	}

	if configPath != "" {
		_ = os.Remove(configPath)
	}

	return nil
}

// Port returns the local loopback port the daemon is listening on.
func (d *Daemon) Port() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.port
}

// ConfigPath returns the temporary configuration file path.
func (d *Daemon) ConfigPath() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.configPath
}

// IsActive reports whether the daemon is running and has an active SOCKS5 dialer.
func (d *Daemon) IsActive() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return !d.stopped && d.cmd != nil && d.socksDialer != nil
}

// Socks5Dialer returns the SOCKS5 stream dialer connected to this daemon.
func (d *Daemon) Socks5Dialer() StreamDialer {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.socksDialer
}

// StartDaemon initializes and starts a new supervised Daemon.
func StartDaemon(ctx context.Context, binPath, endpoint string, params models.NaiveProxyParams) (*Daemon, error) {
	d, err := NewDaemon(binPath, endpoint, params)
	if err != nil {
		return nil, err
	}
	if err := d.Start(ctx); err != nil {
		_ = d.Stop()
		return nil, err
	}
	return d, nil
}

// DaemonManager manages a pool of supervised Naive daemons keyed by endpoint and connection parameters.
type DaemonManager struct {
	mu      sync.Mutex
	binPath string
	daemons map[string]*Daemon
}

// NewDaemonManager constructs a DaemonManager.
func NewDaemonManager(binPath string) *DaemonManager {
	if binPath == "" {
		binPath = GetNaiveBinPath()
	}
	return &DaemonManager{
		binPath: binPath,
		daemons: make(map[string]*Daemon),
	}
}

// GetOrCreate returns an existing running daemon for the given endpoint and parameters,
// or starts a new supervised daemon instance.
func (m *DaemonManager) GetOrCreate(ctx context.Context, endpoint string, params models.NaiveProxyParams) (*Daemon, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := fmt.Sprintf("%s|%s|%s|%v", endpoint, params.Username, params.Domain, params.EnableH3)
	if d, ok := m.daemons[key]; ok && d.IsActive() {
		return d, nil
	}

	binPath := m.binPath
	if binPath == "" {
		binPath = GetNaiveBinPath()
	}
	if !isExecutable(binPath) {
		var err error
		binPath, err = EnsureNaiveBinary(ctx)
		if err != nil {
			return nil, fmt.Errorf("naive: cannot acquire naive binary: %w", err)
		}
		m.binPath = binPath
	}

	d, err := NewDaemon(binPath, endpoint, params)
	if err != nil {
		return nil, err
	}
	if err := d.Start(ctx); err != nil {
		_ = d.Stop()
		return nil, err
	}

	m.daemons[key] = d
	return d, nil
}

// Stop terminates and removes all daemons associated with endpoint.
func (m *DaemonManager) Stop(endpoint string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var firstErr error
	for k, d := range m.daemons {
		if strings.HasPrefix(k, endpoint+"|") {
			if err := d.Stop(); err != nil && firstErr == nil {
				firstErr = err
			}
			delete(m.daemons, k)
		}
	}
	return firstErr
}

// Close shuts down all supervised daemons in the manager.
func (m *DaemonManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var firstErr error
	for k, d := range m.daemons {
		if err := d.Stop(); err != nil && firstErr == nil {
			firstErr = err
		}
		delete(m.daemons, k)
	}
	return firstErr
}
