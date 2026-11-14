//go:build with_utls

package handlers

// A real NaiveProxy site for the automatic admission consumer: Caddy with
// forward_proxy plus a counted origin behind the same site.
//
// Why this exists. Every earlier automatic-admission fixture injected the
// qualification verdict. The AWG and VLESS consumers removed that injection and let
// production decide. Naive needs one extra fact those two did not: production
// qualification runs through the native daemon, and the only durable proof that the
// *payload* traversed the tunnel is a request observed at an origin behind the
// proxy. Nothing in the probe's return value distinguishes "the proxy authenticated
// me" from "the proxy carried my request and answered it" - see the downgrade seam
// documented below.
//
// The topology is the production one, not a shortcut:
//
//	probe -> native daemon (SOCKS5) -> TLS + Caddy auth -> CONNECT -> TLS -> HEAD /
//
// Production derives the probe destination as `<Domain>:<endpoint port>`
// (resolveProbePort falls back to the tunnel endpoint port because the ordinary
// producer never sets Params.Port), so the CONNECT target is the proxy's own
// listener. That hairpin is what this fixture reproduces: the tunneled TLS session
// lands on the same Caddy site, which routes the non-CONNECT request to the counted
// origin. The origin is therefore reached only through the authenticated tunnel,
// with a real HTTP request.
//
// Fixture boundaries, stated plainly:
//   - the provider answer, the SSH transport and the protocol installation are
//     controlled outcomes, exactly as in every earlier checkpoint;
//   - the Caddy site is a fixture-owned configuration: it serves forward_proxy for
//     CONNECT and reverse_proxies everything else to the counted origin. Production
//     renders its own Caddyfile (decoy site + forward_proxy); the request/reply shape
//     the probe exercises is identical, and the counted origin is what makes the
//     payload observable at all. That substitution is the disclosed boundary;
//   - the Caddy certificate is signed by a fixture CA installed as the process-global
//     naive test root pool, because there is no public certificate for a loopback
//     site. The pool is restored to nil afterwards; see installNaiveConsumerTrust.
//
// What is NOT controlled: qualification. There is no probe override, no success
// callback and no destination injection. Production derives every value it uses.
//
// THE DOWNGRADE SEAM (why the payload counter is mandatory).
// naive.Dialer.allowsInProcess() is true whenever the test root pool is set. In that
// mode the probe prefers the native daemon but swallows a daemon start failure and
// falls through to an in-process HTTP/2 CONNECT, which is satisfied by any
// authenticated 200. That path never carries the inner request, so it admits on
// handshake-level evidence alone. The fixture CA is required for TLS trust, so a
// consumer here can always fall into it. Two assertions defend against that: the
// positive requires the origin to have counted the inner request, and the
// no-payload negative requires a refusal - a downgraded probe would admit it and
// turn that test red. TestAutomaticSetupRefusesWhenTheNaivePayloadIsNeverAnswered
// also asserts the request WAS delivered, which a downgraded probe cannot produce.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel/naive"
)

const (
	naiveConsumerUsername = "fixtureuser"
	naiveConsumerPassword = "fixturepass"
	// naiveConsumerOriginGrace bounds how long a silent origin holds a connection
	// open. The probe's own deadline is shorter, so this only avoids a leaked
	// goroutine when a test ends early.
	naiveConsumerOriginGrace = 30 * time.Second
)

// naiveConsumerSite is a real Caddy forward_proxy site plus a counted origin.
type naiveConsumerSite struct {
	// endpoint is host:port of the Caddy listener, which is also the CONNECT target
	// production derives (the hairpin).
	endpoint string
	// originAddr is the counted origin behind the site's ordinary route.
	originAddr string
	// port is endpoint's numeric port, which the install records on the server row.
	port int
	// originRequests counts the PROBE's own request: a HEAD like the one
	// probeNaiveExchange writes. Nothing else is counted, because the native client's
	// padding sends browser-shaped GET requests of its own to the same site, and those
	// would otherwise be mistaken for the probe's payload. A COUNTED request therefore
	// proves production's qualification exchange reached a real origin.
	originRequests *atomic.Int64
	// originReplies counts replies the origin actually sent back, i.e. the
	// application exchange completed.
	originReplies *atomic.Int64
	params        models.NaiveProxyParams
	stop          func()
}

// startNaiveConsumerSite builds the site with the fixture credentials and a counted
// origin that either answers the request or withholds the reply.
//
// `answerPayload` false is the "authentication and delivery succeeded, the reply
// never came" shape: the origin reads the request (and counts it) and then holds the
// connection without writing anything.
func startNaiveConsumerSite(t *testing.T, answerPayload bool) *naiveConsumerSite {
	t.Helper()

	caddyBin := resolveNaiveConsumerCaddy()
	if caddyBin == "" {
		t.Fatalf("no caddy binary with forward_proxy is available: build it with xcaddy " +
			"(--with github.com/caddyserver/forwardproxy@caddy2=github.com/klzgrad/forwardproxy) " +
			"or put it on PATH. A naive consumer proof cannot be synthesised without it")
	}

	dir := t.TempDir()
	caCertPath, srvCertPath, srvKeyPath, roots := writeNaiveConsumerCerts(t, dir)
	// The native daemon is a separate process and reads SSL_CERT_FILE for its own
	// TLS to Caddy; the in-process and probe paths read the exported test root pool.
	t.Setenv("SSL_CERT_FILE", caCertPath)
	installNaiveConsumerTrust(t, roots)

	var requests, replies atomic.Int64
	stopOrigin := make(chan struct{})

	// --- counted origin ---------------------------------------------------------
	originLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen origin: %v", err)
	}
	originPort := originLn.Addr().(*net.TCPAddr).Port

	var originWg sync.WaitGroup
	originWg.Add(1)
	go func() {
		defer originWg.Done()
		for {
			conn, acceptErr := originLn.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				// Read the request head so the method is known before deciding whether
				// this is the probe's payload or the client's own padding traffic.
				buf := make([]byte, 4096)
				n, readErr := c.Read(buf)
				isProbePayload := n > 0 && isNaiveProbeRequest(buf[:n])
				if isProbePayload {
					requests.Add(1)
				}
				if readErr != nil || !answerPayload {
					if !isProbePayload {
						// Padding traffic: close promptly, since no verdict depends on it.
						return
					}
					// The probe's request was delivered; the reply is withheld. That is
					// the case the no-payload negative exists for.
					select {
					case <-stopOrigin:
					case <-time.After(naiveConsumerOriginGrace):
					}
					return
				}
				if _, writeErr := fmt.Fprintf(c,
					"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"); writeErr == nil {
					if isProbePayload {
						replies.Add(1)
					}
				}
			}(conn)
		}
	}()

	// --- Caddy forward_proxy site ----------------------------------------------
	// The listener has no host matcher, so the CONNECT target (the hairpin back to
	// this same listener) is accepted the way production's hostless listener
	// accepts arbitrary destinations.
	proxyPort := freeNaiveConsumerPort(t)
	httpPort := freeNaiveConsumerPort(t)
	caddyfile := fmt.Sprintf(`{
    admin off
    auto_https disable_redirects
    http_port %d
}
https://127.0.0.1:%d {
    bind 127.0.0.1
    tls %s %s
    @tunnel method CONNECT
    route @tunnel {
        forward_proxy {
            basic_auth %s %s
            hide_ip
            hide_via
            acl {
                allow 127.0.0.1
            }
        }
    }
    route {
        reverse_proxy 127.0.0.1:%d
    }
}
`, httpPort, proxyPort, srvCertPath, srvKeyPath,
		naiveConsumerUsername, naiveConsumerPassword, originPort)

	caddyfilePath := filepath.Join(dir, "Caddyfile")
	if err := os.WriteFile(caddyfilePath, []byte(caddyfile), 0o600); err != nil {
		t.Fatalf("write Caddyfile: %v", err)
	}

	caddyCtx, caddyCancel := context.WithCancel(context.Background())
	// #nosec G204 -- the binary is resolved from PATH/GOPATH and the config from
	// t.TempDir(); no test-controlled string reaches the shell.
	caddyCmd := exec.CommandContext(caddyCtx, caddyBin, "run", "--config", caddyfilePath, "--adapter", "caddyfile")
	if err := caddyCmd.Start(); err != nil {
		caddyCancel()
		t.Fatalf("start caddy: %v", err)
	}

	endpoint := net.JoinHostPort("127.0.0.1", strconv.Itoa(proxyPort))
	ready := false
	for i := 0; i < 80; i++ {
		time.Sleep(50 * time.Millisecond)
		conn, dialErr := net.DialTimeout("tcp", endpoint, 100*time.Millisecond)
		if dialErr == nil {
			_ = conn.Close()
			ready = true
			break
		}
	}
	if !ready {
		caddyCancel()
		_ = caddyCmd.Wait()
		t.Fatalf("caddy did not become ready on %s", endpoint)
	}

	site := &naiveConsumerSite{
		endpoint:       endpoint,
		originAddr:     originLn.Addr().String(),
		port:           proxyPort,
		originRequests: &requests,
		originReplies:  &replies,
		params: models.NaiveProxyParams{
			Username: naiveConsumerUsername,
			Password: naiveConsumerPassword,
			// Production derives the probe destination from Params.Domain plus the
			// endpoint port, so this is the loopback site the fixture serves.
			Domain:   "127.0.0.1",
			EnableH3: false,
			// Port stays 0: production's AddClient never sets it, and a nonzero value
			// would steer the probe away from the endpoint the backend was qualified on.
		},
	}
	var once sync.Once
	site.stop = func() {
		once.Do(func() {
			caddyCancel()
			_ = caddyCmd.Wait()
			close(stopOrigin)
			_ = originLn.Close()
			originWg.Wait()
		})
	}
	t.Cleanup(site.stop)
	return site
}

// naiveConsumerTrustInstalled guards the process-global test root pool: two
// concurrent installers would silently swap each other's CA.
var naiveConsumerTrustInstalled atomic.Bool

// installNaiveConsumerTrust installs the fixture CA as the naive package's test root
// pool and restores it afterwards.
//
// The prior value is restored to nil rather than captured, because the pool has no
// exported getter and production code is frozen for this checkpoint. That is the
// truthful prior state: no test in the handlers package calls SetTestRootCAs (grep:
// the only callers are this fixture and the naive package's own tests, which are a
// different test binary), and no handlers test runs in parallel, so there is nothing
// to collide with. The guard turns a future violation into a loud failure rather
// than a silent trust mix-up.
func installNaiveConsumerTrust(t *testing.T, roots *x509.CertPool) {
	t.Helper()
	if !naiveConsumerTrustInstalled.CompareAndSwap(false, true) {
		t.Fatal("another naive consumer fixture already installed a test root pool; " +
			"these tests must not run in parallel")
	}
	naive.SetTestRootCAs(roots)
	t.Cleanup(func() {
		naive.SetTestRootCAs(nil)
		naiveConsumerTrustInstalled.Store(false)
	})
}

// isNaiveProbeRequest reports whether a request head is the one production's
// qualification writes: `HEAD / HTTP/1.1`.
//
// The native client sends its own browser-shaped `GET` padding requests to the same
// site, so "the origin received something" is not evidence of the probe's payload.
// Matching the method the production probe actually uses is what makes the counter
// mean "production's qualification exchange arrived", not "the client is chatty".
func isNaiveProbeRequest(head []byte) bool {
	if len(head) < 16 {
		return false
	}
	return strings.HasPrefix(string(head), "HEAD / HTTP/1.")
}

// resolveNaiveConsumerCaddy finds a caddy binary on PATH, then in GOPATH/bin and
// ~/go/bin, which is where the CI job installs the forwardproxy build.
func resolveNaiveConsumerCaddy() string {
	if bin, err := exec.LookPath("caddy"); err == nil {
		return bin
	}
	var candidates []string
	if gopath := os.Getenv("GOPATH"); gopath != "" {
		candidates = append(candidates, filepath.Join(gopath, "bin", "caddy"))
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(home, "go", "bin", "caddy"))
	}
	for _, cand := range candidates {
		if fi, err := os.Stat(cand); err == nil && !fi.IsDir() && fi.Mode().Perm()&0o111 != 0 {
			return cand
		}
	}
	return ""
}

// freeNaiveConsumerPort reserves and releases a loopback port.
func freeNaiveConsumerPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve loopback port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatalf("release loopback port: %v", err)
	}
	return port
}

// writeNaiveConsumerCerts mints a fixture CA plus a leaf for 127.0.0.1 and returns
// the CA pool the probe must trust. Verification stays fully enabled on both sides;
// nothing here disables TLS or accepts arbitrary certificates.
func writeNaiveConsumerCerts(
	t *testing.T, dir string,
) (caPath, certPath, keyPath string, roots *x509.CertPool) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "naive consumer fixture CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	caPath = filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatalf("write ca.crt: %v", err)
	}
	certPath = filepath.Join(dir, "server.crt")
	if err := os.WriteFile(certPath,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), 0o600); err != nil {
		t.Fatalf("write server.crt: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatalf("marshal leaf key: %v", err)
	}
	keyPath = filepath.Join(dir, "server.key")
	if err := os.WriteFile(keyPath,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write server.key: %v", err)
	}

	roots = x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("failed to install the fixture CA into a root pool")
	}
	return caPath, certPath, keyPath, roots
}

// naiveConsumerBinary holds the process-wide result of resolving the native binary,
// so three consumer tests download and validate it at most once.
var (
	naiveConsumerBinaryOnce sync.Once
	naiveConsumerBinaryPath string
	naiveConsumerBinaryErr  error
)

// requireNaiveConsumerBinary points the naive package at a runnable native binary,
// or skips.
//
// A pre-set NAIVE_BIN_PATH that already runs wins: that is how an operator (or a CI
// step) supplies a binary this package must not re-download, and it is the same
// precedence resolveRunnableNaiveBinary uses in the naive package. Otherwise the
// pinned release is acquired once per process.
//
// A missing binary is never turned into a synthetic success: the test skips with an
// explicit reason and the named CI step shows the skip. CI provisions the binary
// (musl loader + pinned release asset) precisely so the skip does not appear there.
func requireNaiveConsumerBinary(t *testing.T) string {
	t.Helper()

	naiveConsumerBinaryOnce.Do(func() {
		if preset := strings.TrimSpace(os.Getenv(naive.NaiveBinPathEnv)); preset != "" {
			if path, err := runnableNaiveBinary(preset); err == nil {
				naiveConsumerBinaryPath = path
				return
			}
		}
		scratch, err := os.MkdirTemp("", "naive-consumer-bin-*")
		if err != nil {
			naiveConsumerBinaryErr = fmt.Errorf("create binary directory: %w", err)
			return
		}
		if err := os.Setenv(naive.NaiveBinPathEnv, filepath.Join(scratch, "naive")); err != nil {
			naiveConsumerBinaryErr = fmt.Errorf("set %s: %w", naive.NaiveBinPathEnv, err)
			return
		}
		path, err := naive.EnsureNaiveBinary(context.Background())
		if err != nil {
			naiveConsumerBinaryErr = err
			return
		}
		verified, err := runnableNaiveBinary(path)
		if err != nil {
			naiveConsumerBinaryErr = err
			return
		}
		naiveConsumerBinaryPath = verified
	})

	if naiveConsumerBinaryPath == "" {
		t.Skipf("native naive binary unavailable, so the automatic admission chain cannot be "+
			"exercised truthfully: %v", naiveConsumerBinaryErr)
	}
	// t.Setenv points the package (probe daemon and enablement dialer alike) at the
	// resolved binary for this test only, and records the restore automatically.
	t.Setenv(naive.NaiveBinPathEnv, naiveConsumerBinaryPath)
	return naiveConsumerBinaryPath
}

// runnableNaiveBinary confirms path executes and reports itself as naive.
func runnableNaiveBinary(path string) (string, error) {
	out, err := exec.Command(path, "--version").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("binary %s did not run: %w (%s)", path, err, strings.TrimSpace(string(out)))
	}
	if !strings.Contains(strings.ToLower(string(out)), "naive") {
		return "", fmt.Errorf("binary %s does not report itself as naive: %s", path,
			strings.TrimSpace(string(out)))
	}
	return path, nil
}

// naiveConsumerFixture is one automatic Naive job wired to a real site with no
// qualification override and no pre-acquired authority.
type naiveConsumerFixture struct {
	*installEnv
	site             *naiveConsumerSite
	orderID          string
	providerServerID int64
	pinnedPresented  string
	purchaseAttempts *purchaseCounter
}

// newNaiveConsumerJob builds the state a real purchase leaves - a purchase stamp and
// an encrypted managed credential, and nothing else - then lets the production
// background chain produce the association, the grant and the pin.
//
// `credentials` is the AddClient answer, which is the production provisioning
// contract: whatever the protocol manager returns becomes the tunnel's real
// parameters. The wrong-auth negative passes credentials Caddy does not know.
func newNaiveConsumerJob(
	t *testing.T, orderID string, providerServerID int64, answerPayload bool,
	credentials models.NaiveProxyParams,
) *naiveConsumerFixture {
	t.Helper()

	env := newInstallEnv(t, models.ProtocolNaive)
	// One SSH identity for the whole job, so the pin the tracker records is the
	// identity the install observes.
	env.useAuthenticSSHBoundary()
	// Qualification is the production probe, not the shared fixture's success stub.
	env.useAuthenticQualification()

	site := startNaiveConsumerSite(t, answerPayload)
	// The install records the deployed port and domain, which is what a real Naive
	// installation records on the server row; production reads the port from there to
	// build the tunnel endpoint.
	installNaiveConsumerSite(env, site)
	// The provisioning contract hands out the credentials the backend will use.
	provisionNaiveConsumerIdentity(t, env, credentials)

	// --- the purchase: stamp + credential, and nothing else ---------------------
	key := newManagedTestKey(t)
	env.seedFreshPurchase(orderID, key)
	env.providerServes(orderID, providerServerID, "127.0.0.1")
	purchases := newPurchaseCounter()
	env.provider.orderServerFn = purchases.refuse
	env.provider.orderServerSafeFn = purchases.refuse

	env.enableAutomaticSetup(true)
	env.startAutomatic(orderID, AutomaticGigahostSetupOptions{
		Protocol: models.ProtocolNaive,
		Port:     strconv.Itoa(site.port),
	})

	// --- assert the starting state is genuinely bare ---------------------------
	requireNoAuthorityYet(t, env, orderID, "before the production tracking pass")

	// --- production background consumers acquire everything ---------------------
	if err := env.h.NewGigahostSetupTracker().RunOnce(context.Background()); err != nil {
		t.Fatalf("tracking pass: %v", err)
	}
	env.requireState(orderID, models.SetupStateReadyForSetup)

	order, found, err := env.db.GetGigahostOrder(context.Background(), orderID)
	if err != nil || !found {
		t.Fatalf("read order after tracking: found=%v err=%v", found, err)
	}
	if order.ServerID != providerServerID {
		t.Fatalf("the background pass did not record the provider server id: ledger has %d, want %d",
			order.ServerID, providerServerID)
	}
	if order.AssignedIP == "" {
		t.Fatal("the background pass did not record the provider address on the ledger")
	}
	granted := env.intent(orderID)
	if granted.HostTrustOrderID != orderID || granted.HostTrustServerID != providerServerID {
		t.Fatalf("the background pass did not acquire the scoped grant: order=%q server=%d",
			granted.HostTrustOrderID, granted.HostTrustServerID)
	}
	if granted.HostTrustGrantedAt.IsZero() {
		t.Fatal("the background pass did not record when the grant was issued")
	}
	if granted.HostFingerprint == "" {
		t.Fatal("the background pass did not pin a host identity")
	}
	requireNoFingerprintRewrite(t, granted.HostFingerprint, installFixtureFingerprint, "after tracking")

	return &naiveConsumerFixture{
		installEnv:       env,
		site:             site,
		orderID:          orderID,
		providerServerID: providerServerID,
		pinnedPresented:  granted.HostFingerprint,
		purchaseAttempts: purchases,
	}
}

// installNaiveConsumerSite gives the fixture's protocol manager an installation that
// records what a real Naive installation records: the port it deployed and the domain
// the site serves.
//
// The shared install stub writes only "installed" and the port. Production reads the
// port from the server row to build the tunnel endpoint, so recording it is what a
// real install does; it is not a production change.
func installNaiveConsumerSite(env *installEnv, site *naiveConsumerSite) {
	env.t.Helper()
	base := env.counters.installFnFor(models.ProtocolNaive)
	mgr, ok := env.h.registry.Get(models.ProtocolNaive)
	if !ok {
		env.t.Fatal("no Naive protocol manager is registered")
	}
	fixture, ok := mgr.(*mockProtocolManager)
	if !ok {
		env.t.Fatalf("naive manager is %T, want the fixture manager", mgr)
	}
	port := strconv.Itoa(site.port)
	domain := site.params.Domain
	fixture.installFn = func(ctx context.Context, server *models.Server, params map[string]any) error {
		if err := base(ctx, server, params); err != nil {
			return err
		}
		meta, _ := server.Protocols[models.ProtocolNaive].(map[string]any)
		if meta == nil {
			return fmt.Errorf("the install did not record the naive protocol")
		}
		meta["port"] = port
		meta["domain"] = domain
		return nil
	}
}

// provisionNaiveConsumerIdentity makes the fixture's protocol manager hand out these
// credentials, which is the production provisioning contract.
//
// `resolveInstalledProxyParamsForProto` asks the manager's AddClient for the client
// credentials when the server row carries none yet, so whatever it returns becomes the
// tunnel's real parameters. That is how derivation ends up pointing at this fixture's
// site with no override and no rewritten row: the username, password and domain are
// exactly what a real Naive manager returns, and Port stays at production's value.
func provisionNaiveConsumerIdentity(
	t *testing.T, env *installEnv, credentials models.NaiveProxyParams,
) {
	t.Helper()
	mgr, ok := env.h.registry.Get(models.ProtocolNaive)
	if !ok {
		t.Fatal("no Naive protocol manager is registered")
	}
	fixture, ok := mgr.(*mockProtocolManager)
	if !ok {
		t.Fatalf("naive manager is %T, want the fixture manager", mgr)
	}
	username, password, domain := credentials.Username, credentials.Password, credentials.Domain
	fixture.addClientFn = func(context.Context, *models.Server, map[string]any) (map[string]any, error) {
		return map[string]any{
			"client_id": username,
			"username":  username,
			"password":  password,
			"domain":    domain,
		}, nil
	}
}

// requirePayloadDelivered asserts the inner request reached a real origin through the
// authenticated tunnel and was answered.
func (f *naiveConsumerFixture) requirePayloadDelivered(t *testing.T, when string) {
	t.Helper()
	requests := f.site.originRequests.Load()
	replies := f.site.originReplies.Load()
	if requests == 0 {
		t.Fatalf("%s: the origin never received the inner request, so nothing proves the "+
			"payload traversed the tunnel (only a handshake-level CONNECT was accepted)", when)
	}
	if replies == 0 {
		t.Fatalf("%s: the origin received %d requests but sent no reply, so the application "+
			"exchange never completed", when, requests)
	}
	t.Logf("%s: payload evidence: origin_requests=%d origin_replies=%d", when, requests, replies)
}

// requireNoPurchases asserts no purchase-path call was made.
func (f *naiveConsumerFixture) requireNoPurchases(t *testing.T, when string) {
	t.Helper()
	if n := f.purchaseAttempts.load(); n != 0 {
		t.Fatalf("%s: the provider received %d purchase-path calls, want 0", when, n)
	}
}

// countRegisteredServers counts the panel server rows claiming this provider server.
func (f *naiveConsumerFixture) countRegisteredServers(t *testing.T) int {
	t.Helper()
	servers, err := f.db.GetAllServers(context.Background())
	if err != nil {
		t.Fatalf("list servers: %v", err)
	}
	count := 0
	for k := range servers {
		if servers[k].Protocols == nil {
			continue
		}
		if provider, _ := servers[k].Protocols["provider"].(string); provider != "gigahost" {
			continue
		}
		if matchProviderServerID(servers[k].Protocols["provider_server_id"], f.providerServerID) {
			count++
		}
	}
	return count
}

// countEnrollments counts durable enrollment markers for this backend.
func (f *naiveConsumerFixture) countEnrollments(t *testing.T) int {
	t.Helper()
	servers, err := f.db.GetAllServers(context.Background())
	if err != nil {
		t.Fatalf("list servers: %v", err)
	}
	marks, err := f.db.GetBackendPendingEnrollments(context.Background())
	if err != nil {
		t.Fatalf("read durable enrollment markers: %v", err)
	}
	count := 0
	for k := range servers {
		if servers[k].Protocols == nil {
			continue
		}
		if provider, _ := servers[k].Protocols["provider"].(string); provider != "gigahost" {
			continue
		}
		if matchProviderServerID(servers[k].Protocols["provider_server_id"], f.providerServerID) &&
			marks[servers[k].ID] {
			count++
		}
	}
	return count
}
