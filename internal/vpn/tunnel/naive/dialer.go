package naive

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// testRootCAs allows in-process test fixtures to supply an ephemeral root CA
// without altering the public New() constructor signature. In production, this
// remains nil, prompting standard crypto/tls system root verification.
var testRootCAs *x509.CertPool

// SetTestRootCAs allows test harnesses outside package naive to configure an ephemeral root CA pool.
func SetTestRootCAs(pool *x509.CertPool) {
	testRootCAs = pool
}

// Option configures optional parameters for a Dialer.
type Option func(*Dialer)

// WithDialContext overrides the transport dialing function for the Dialer.
func WithDialContext(fn func(ctx context.Context, network, addr string) (net.Conn, error)) Option {
	return func(d *Dialer) {
		d.dialContext = fn
	}
}

// WithResolver overrides the DNS resolver used by the Dialer.
func WithResolver(r *net.Resolver) Option {
	return func(d *Dialer) {
		d.resolver = r
	}
}

// WithDaemon sets an existing Daemon instance for the Dialer.
func WithDaemon(dm *Daemon) Option {
	return func(d *Dialer) {
		d.daemon = dm
		if dm != nil && dm.Socks5Dialer() != nil {
			d.socks5Dialer = dm.Socks5Dialer()
		}
	}
}

// WithSocks5Dialer sets a custom SOCKS5 StreamDialer for the Dialer.
func WithSocks5Dialer(sd StreamDialer) Option {
	return func(d *Dialer) {
		d.socks5Dialer = sd
	}
}

// WithDaemonDisabled explicitly disables the upstream naive daemon sidecar.
func WithDaemonDisabled(disabled bool) Option {
	return func(d *Dialer) {
		d.disableDaemon = disabled
	}
}

// WithInProcessFallback enables in-process Go HTTP/2 or HTTP/3 transport fallback.
// In production, the native daemon is mandatory; in-process fallback is permitted only for tests.
func WithInProcessFallback() Option {
	return func(d *Dialer) {
		d.inProcessFallback = true
	}
}

// h3FailureCooldown is how long DialContext skips H3 and dials H2 directly
// after a transport-level H3 failure, so UDP loss costs one timeout, not one per dial.
var h3FailureCooldown = 30 * time.Second

// Dialer establishes authenticated HTTP/2 or HTTP/3 CONNECT tunnels to a NaiveProxy
// endpoint, satisfying the StreamDialer interface.
type Dialer struct {
	endpoint string
	params   models.NaiveProxyParams
	tlsCfg   *tls.Config
	h2Pool   *h2Pool
	h3Pool   *h3Pool
	// h3CooldownUntil is a UnixNano deadline; H3 is skipped until then.
	// The shared QUIC conn is deliberately left open so healthy sibling tunnels survive.
	h3CooldownUntil atomic.Int64

	dialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	resolver    *net.Resolver

	daemon            *Daemon
	socks5Dialer      StreamDialer
	daemonMu          sync.Mutex
	disableDaemon     bool
	inProcessFallback bool
	closed            bool
	lastErr           error
}

// New constructs a new NaiveProxy Dialer with defensive input validation.
func New(endpoint string, p models.NaiveProxyParams, opts ...Option) (*Dialer, error) {
	endpoint = strings.TrimSpace(endpoint)
	host, portStr, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, fmt.Errorf("naive: invalid endpoint %q: %w", endpoint, err)
	}
	if host == "" {
		return nil, errors.New("naive: endpoint host cannot be empty")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("naive: invalid endpoint port %q", portStr)
	}

	domain := strings.TrimSpace(p.Domain)
	if domain == "" {
		return nil, errors.New("naive: domain cannot be empty")
	}
	if strings.ContainsAny(domain, " 	\r\n:/\\") {
		return nil, fmt.Errorf("naive: invalid domain name %q", domain)
	}

	if p.Username == "" {
		return nil, errors.New("naive: username cannot be empty")
	}
	if p.Password == "" {
		return nil, errors.New("naive: password cannot be empty")
	}

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: domain,
		RootCAs:    testRootCAs,
	}

	d := &Dialer{
		endpoint: endpoint,
		params:   p,
		tlsCfg:   tlsCfg,
		h2Pool:   newH2Pool(),
		h3Pool:   newH3Pool(),
		resolver: net.DefaultResolver,
	}

	for _, opt := range opts {
		if opt != nil {
			opt(d)
		}
	}

	if d.dialContext == nil {
		netDialer := &net.Dialer{
			Timeout:  10 * time.Second,
			Resolver: d.resolver,
		}
		d.dialContext = netDialer.DialContext
	}

	return d, nil
}

func (d *Dialer) allowsInProcess() bool {
	return testRootCAs != nil || d.inProcessFallback
}

// DialContext establishes a TCP stream tunnel to address through the NaiveProxy endpoint.
// It satisfies streambridge.StreamDialer.
// NaiveProxy only tunnels TCP streams; requests for any other network return an error.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("naive: unsupported network %q (NaiveProxy only tunnels TCP streams)", network)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	d.daemonMu.Lock()
	if d.closed {
		d.daemonMu.Unlock()
		return nil, net.ErrClosed
	}
	d.daemonMu.Unlock()

	// 1. If in-process Go transport is allowed and no daemon is configured, use in-process Go transport.
	if d.allowsInProcess() {
		return d.dialAllowsInProcess(ctx, network, address)
	}

	// 2. Production: Native daemon is mandatory. Fail closed on download, startup, or connection failure.
	sd, err := d.getOrStartDaemon(ctx)
	if err != nil {
		d.daemonMu.Lock()
		d.lastErr = err
		d.daemonMu.Unlock()
		return nil, fmt.Errorf("naive: native daemon required: %w", err)
	}

	conn, err := sd.DialContext(ctx, network, address)
	if err != nil {
		d.daemonMu.Lock()
		h3Active := d.params.EnableH3 && d.params.H3Supported
		dm := d.daemon
		d.daemonMu.Unlock()
		daemonUnhealthy := dm != nil && !dm.IsHealthy()
		isDestErr := isDestinationConnectionError(err, address)
		if h3Active && ctx.Err() == nil && (daemonUnhealthy || !isDestErr) {
			d.fallbackToH2()
			if fallbackSd, fallbackErr := d.getOrStartDaemon(ctx); fallbackErr == nil {
				if fbConn, fbErr := fallbackSd.DialContext(ctx, network, address); fbErr == nil {
					return fbConn, nil
				}
			}
		}
		if !isDestErr {
			d.daemonMu.Lock()
			d.lastErr = err
			d.daemonMu.Unlock()
		}
		return nil, fmt.Errorf("naive: native daemon dial failed: %w", err)
	}

	return conn, nil
}

func (d *Dialer) dialAllowsInProcess(ctx context.Context, network, address string) (net.Conn, error) {
	d.daemonMu.Lock()
	sd := d.socks5Dialer
	h3Active := d.params.EnableH3 && d.params.H3Supported
	dm := d.daemon
	d.daemonMu.Unlock()
	if sd != nil {
		conn, err := sd.DialContext(ctx, network, address)
		if err == nil {
			return conn, nil
		}
		daemonUnhealthy := dm != nil && !dm.IsHealthy()
		isDestErr := isDestinationConnectionError(err, address)
		if h3Active && ctx.Err() == nil && (daemonUnhealthy || !isDestErr) {
			d.fallbackToH2()
			if fallbackSd, fallbackErr := d.getOrStartDaemon(ctx); fallbackErr == nil {
				if fbConn, fbErr := fallbackSd.DialContext(ctx, network, address); fbErr == nil {
					return fbConn, nil
				}
			}
		}
		if isDestErr {
			return nil, err
		}
		if d.inProcessFallback {
			return d.dialInProcess(ctx, address)
		}
		return nil, err
	}
	if d.inProcessFallback && testRootCAs == nil {
		sd, err := d.getOrStartDaemon(ctx)
		if err == nil {
			conn, err := sd.DialContext(ctx, network, address)
			if err == nil {
				return conn, nil
			}
			if isDestinationConnectionError(err, address) {
				return nil, err
			}
		}
		return d.dialInProcess(ctx, address)
	}
	return d.dialInProcess(ctx, address)
}

// EnsureReady verifies that the dialer is ready to handle traffic.
// In production, it ensures the native daemon binary is downloaded, started,
// and accepting SOCKS5 connections. When in-process fallback is allowed (in tests)
// and no daemon is configured, it returns nil.
func (d *Dialer) EnsureReady(ctx context.Context) error {
	if d.allowsInProcess() && d.socks5Dialer == nil {
		return nil
	}
	sd, err := d.getOrStartDaemon(ctx)
	if err != nil {
		d.daemonMu.Lock()
		d.lastErr = err
		d.daemonMu.Unlock()
		return err
	}
	d.daemonMu.Lock()
	h3Active := d.params.EnableH3 && d.params.H3Supported
	d.daemonMu.Unlock()
	if h3Active {
		port := resolveProbePort(d.params, d.endpoint)
		camTarget := net.JoinHostPort(d.params.Domain, strconv.Itoa(port))
		if _, probeErr := d.probeViaDaemonWithFallback(ctx, camTarget, d.params, sd); probeErr != nil {
			return probeErr
		}
	}
	return nil
}

// IsHealthy reports whether the underlying native daemon or in-process transport is healthy.
func (d *Dialer) IsHealthy() bool {
	d.daemonMu.Lock()
	dm := d.daemon
	sd := d.socks5Dialer
	lastErr := d.lastErr
	d.daemonMu.Unlock()

	if lastErr != nil {
		return false
	}
	if dm != nil {
		return dm.IsHealthy()
	}
	if d.allowsInProcess() {
		return true
	}
	return sd != nil
}

// LastError returns the most recent error encountered by the dialer or its supervisor.
func (d *Dialer) LastError() error {
	d.daemonMu.Lock()
	dm := d.daemon
	lastErr := d.lastErr
	d.daemonMu.Unlock()

	if dm != nil {
		if err := dm.LastError(); err != nil {
			return err
		}
	}
	return lastErr
}

func (d *Dialer) dialInProcess(ctx context.Context, address string) (net.Conn, error) {
	if d.params.EnableH3 && time.Now().UnixNano() >= d.h3CooldownUntil.Load() {
		h3Ctx := ctx
		if deadline, ok := ctx.Deadline(); ok {
			timeout := time.Until(deadline) / 2
			if timeout > 2*time.Second {
				timeout = 2 * time.Second
			}
			if timeout > 0 {
				var cancel context.CancelFunc
				h3Ctx, cancel = context.WithTimeout(ctx, timeout)
				defer cancel()
			}
		} else {
			var cancel context.CancelFunc
			h3Ctx, cancel = context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
		}

		conn, err := d.dialH3(h3Ctx, address)
		if err == nil {
			d.h3CooldownUntil.Store(0)
			return conn, nil
		}
		// If the proxy actively rejected with an HTTP status (e.g. 407 auth failure),
		// do not fall through to H2 — propagate the rejection.
		var statusErr *statusError
		if errors.As(err, &statusErr) {
			return nil, statusErr
		}
		// If the caller's outer context has expired, abort immediately.
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// On any transport-level H3 failure (UDP blocked, handshake timeout, network drop),
		// start the cooldown and gracefully fall through to H2.
		if !errors.Is(err, net.ErrClosed) {
			d.h3CooldownUntil.Store(time.Now().Add(h3FailureCooldown).UnixNano())
		}
	}

	return d.dialH2(ctx, address)
}

// Daemon returns the supervised Daemon instance, if active.
func (d *Dialer) Daemon() *Daemon {
	d.daemonMu.Lock()
	defer d.daemonMu.Unlock()
	return d.daemon
}

// getOrStartDaemon initializes and starts a supervised upstream naive daemon if available.
func (d *Dialer) getOrStartDaemon(ctx context.Context) (StreamDialer, error) {
	d.daemonMu.Lock()
	if d.closed {
		d.daemonMu.Unlock()
		return nil, errors.New("naive: dialer is closed")
	}
	if d.socks5Dialer != nil {
		sd := d.socks5Dialer
		d.daemonMu.Unlock()
		return sd, nil
	}
	d.daemonMu.Unlock()

	if d.disableDaemon {
		return nil, errors.New("naive: daemon is disabled")
	}

	binPath := GetNaiveBinPath()
	if !isExecutable(binPath) {
		if os.Getenv("NAIVE_DISABLE_DOWNLOAD") == "1" {
			return nil, errors.New("naive: binary not found and NAIVE_DISABLE_DOWNLOAD is set")
		}
		var err error
		binPath, err = EnsureNaiveBinary(ctx)
		if err != nil {
			return nil, fmt.Errorf("naive: failed to acquire native binary: %w", err)
		}
	}

	d.daemonMu.Lock()
	defer d.daemonMu.Unlock()
	if d.closed {
		return nil, errors.New("naive: dialer is closed")
	}
	if d.socks5Dialer != nil {
		return d.socks5Dialer, nil
	}

	daemon, err := StartDaemon(ctx, binPath, d.endpoint, d.params)
	if err != nil {
		return nil, fmt.Errorf("naive: failed to start native daemon: %w", err)
	}
	d.daemon = daemon
	d.socks5Dialer = daemon.Socks5Dialer()
	return d.socks5Dialer, nil
}

// Close closes all pooled connections and terminates any supervised naive daemon.
func (d *Dialer) Close() error {
	d.daemonMu.Lock()
	d.closed = true
	if d.daemon != nil {
		_ = d.daemon.Stop()
		d.daemon = nil
		d.socks5Dialer = nil
	}
	d.daemonMu.Unlock()

	d.h2Pool.close()
	d.h3Pool.close()
	return nil
}

// SupportsUDP returns false because NaiveProxy only tunnels TCP streams.
func (d *Dialer) SupportsUDP() bool {
	return false
}

// fallbackToH2 disables H3 capability and terminates the supervised H3 daemon if running.
func (d *Dialer) fallbackToH2() {
	d.daemonMu.Lock()
	defer d.daemonMu.Unlock()
	if !d.params.EnableH3 || !d.params.H3Supported {
		return
	}
	d.params.H3Supported = false
	if d.daemon != nil {
		_ = d.daemon.Stop()
		d.daemon = nil
		d.socks5Dialer = nil
	}
}

// basicAuth returns the HTTP Basic authentication credentials formatted for Proxy-Authorization.
func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

// isDestinationConnectionError reports whether err represents a failure connecting to
// the remote destination (e.g. SOCKS5 status rejection like connection refused, network/host
// unreachable), rather than an upstream transport or local proxy daemon failure.
func isDestinationConnectionError(err error, dstAddress string) bool {
	if err == nil {
		return false
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		var innerOp *net.OpError
		if errors.As(opErr.Err, &innerOp) && innerOp.Op == "dial" {
			if !isSameTarget(innerOp.Addr, dstAddress) {
				return false
			}
		}
	}
	errStr := strings.ToLower(err.Error())
	for _, p := range []string{
		"unknown error connection refused", "unknown error host unreachable",
		"unknown error network unreachable", "unknown error connection not allowed",
		"unknown error ttl expired", "unknown error command not supported",
		"unknown error address type not supported", "connection refused",
		"host unreachable", "network unreachable", "no route to host",
		"connection not allowed",
	} {
		if strings.Contains(errStr, p) {
			return true
		}
	}
	var sysErr syscall.Errno
	if errors.As(err, &sysErr) {
		switch sysErr {
		case syscall.ECONNREFUSED, syscall.EHOSTUNREACH, syscall.ENETUNREACH, syscall.ETIMEDOUT:
			return true
		}
	}
	return false
}

func isSameTarget(addr net.Addr, target string) bool {
	if addr == nil || target == "" {
		return false
	}
	if addr.String() == target {
		return true
	}
	h1, p1, err1 := net.SplitHostPort(addr.String())
	h2, p2, err2 := net.SplitHostPort(target)
	if err1 != nil || err2 != nil || p1 != p2 {
		return false
	}
	return strings.EqualFold(h1, h2) || (h1 == "127.0.0.1" && h2 == "localhost") || (h1 == "localhost" && h2 == "127.0.0.1")
}
