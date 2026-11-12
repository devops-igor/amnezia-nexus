package gigahost

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The catalog load the panel performs is one GET /deploy/servers, one
// GET /reinstall/distro and one GET /reinstall/distro/{dist_id} per active
// distribution, all sequentially on one client. The production trace shows the
// fourth of those calls stalling with no response header for 30 s on a
// connection the client had reused, while the same call answers in about 90 ms
// on a fresh connection.
//
// These tests pin the transport policy that separates those two conditions. The
// fixtures model a peer that withholds the response for a request arriving on a
// connection it has already served; that models the observed behaviour, it does
// not claim to be the provider-side mechanism.

const (
	// fixtureStallAfterReuses is how many requests a fixture connection serves
	// before it withholds the response to the next one. Three served requests
	// put the fourth call of a reused-connection catalog load into the
	// disputed branch, which is where the production stall appeared.
	fixtureStallAfterReuses = 3
	// fixtureStallBudget bounds a withheld response so a test cannot hang.
	fixtureStallBudget = 5 * time.Second
)

// connectionLedger counts requests per accepted connection and can withhold the
// response for a connection's (fixtureStallAfterReuses+1)-th request.
type connectionLedger struct {
	mu        sync.Mutex
	perConn   map[string]int
	served    int
	withholds int
}

func newConnectionLedger() *connectionLedger {
	return &connectionLedger{perConn: make(map[string]int)}
}

// arrive records one request on its connection and reports whether the response
// must be withheld.
func (l *connectionLedger) arrive(remoteAddr string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.perConn[remoteAddr]++
	l.served++
	withhold := l.perConn[remoteAddr] > fixtureStallAfterReuses
	if withhold {
		l.withholds++
	}
	return withhold
}

func (l *connectionLedger) connections() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.perConn)
}

func (l *connectionLedger) requests() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.served
}

func (l *connectionLedger) withheld() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.withholds
}

// catalogFixture is the four-active-distribution catalog body set: one
// product tier, a distribution list with an explicitly inactive entry, and one
// documented image page per active distribution.
type catalogFixture struct {
	server *httptest.Server
	ledger *connectionLedger
}

// newCatalogFixture serves the documented catalog bodies over TLS. http2
// selects the ALPN protocol the fixture offers, so both the HTTP/2 and the
// ordinary HTTP/1.1 transport path can be exercised.
func newCatalogFixture(t *testing.T, http2 bool) *catalogFixture {
	t.Helper()
	ledger := newConnectionLedger()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ledger.arrive(r.RemoteAddr) {
			// Withhold the response until the client gives up. This is the
			// fixture's model of the observed stall, not a reproduced cause.
			select {
			case <-r.Context().Done():
			case <-time.After(fixtureStallBudget):
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/deploy/servers":
			_, _ = w.Write([]byte(catalogSelectionDoc))
		case r.URL.Path == "/reinstall/distro":
			_, _ = w.Write([]byte(catalogDistroListDoc))
		case strings.HasPrefix(r.URL.Path, "/reinstall/distro/"):
			_, _ = w.Write([]byte(catalogImagesDoc(strings.TrimPrefix(r.URL.Path, "/reinstall/distro/"))))
		default:
			http.NotFound(w, r)
		}
	})

	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = http2
	server.StartTLS()
	t.Cleanup(server.Close)
	return &catalogFixture{server: server, ledger: ledger}
}

// roots returns the fixture's trust anchor. The test server presents a
// self-signed certificate, so it must be trusted explicitly.
func (f *catalogFixture) roots(t *testing.T) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(f.server.Certificate())
	return pool
}

// catalogDistroListDoc keeps one explicitly inactive distribution so the
// skip rule stays covered while four active entries drive at least four calls.
const catalogDistroListDoc = `{"meta":{"status":200},"data":[
  {"dist_id":"1","type_id":"1","dist_name":"Debian","dist_value":"debian","dist_active":"1"},
  {"dist_id":"9","type_id":"2","dist_name":"Ubuntu","dist_value":"ubuntu","dist_active":"1"},
  {"dist_id":"3","type_id":"3","dist_name":"AlmaLinux","dist_value":"almalinux","dist_active":"1"},
  {"dist_id":"15","type_id":"4","dist_name":"Fedora","dist_value":"fedora","dist_active":"1"},
  {"dist_id":"20","type_id":"5","dist_name":"Retired","dist_value":"retired","dist_active":"0"}
]}`

// catalogImagesDoc returns one documented image page for a distribution.
func catalogImagesDoc(distID string) string {
	names := map[string]string{"1": "Debian 12", "9": "Ubuntu 24.04", "3": "AlmaLinux 9", "15": "Fedora 41"}
	name, ok := names[distID]
	if !ok {
		return `{"meta":{"status":200},"data":[]}`
	}
	return `{"meta":{"status":200},"data":[` + sprintfImages(distID+"0", distID, name, "stable", "0", "0") + `]}`
}

// ownedTransportOf exposes the transport a default-constructed client owns, so a
// test can assert the policy that client actually ships with.
func ownedTransportOf(t *testing.T, c Client) *http.Transport {
	t.Helper()
	cl, ok := c.(*client)
	if !ok {
		t.Fatalf("client is %T, want *client", c)
	}
	tr, ok := cl.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("owned transport is %T, want *http.Transport", cl.httpClient.Transport)
	}
	return tr
}

// fixtureClient returns a client whose transport is the one a default client
// owns, with the policy unchanged, plus the fixture's trust anchor. Trust
// anchors are the only delta: they cannot influence connection reuse.
func fixtureClient(t *testing.T, f *catalogFixture, timeout time.Duration) Client {
	t.Helper()
	base, err := NewClient(Config{APIKey: testAPIKey})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	tr := ownedTransportOf(t, base).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: f.roots(t)}
	c, err := NewClient(Config{
		BaseURL:   f.server.URL,
		APIKey:    testAPIKey,
		Transport: tr,
		Timeout:   timeout,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

// keepAliveFixtureClient is the pre-change setting: the standard transport's
// settings with connection reuse left on.
func keepAliveFixtureClient(t *testing.T, f *catalogFixture, timeout time.Duration) Client {
	t.Helper()
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		t.Fatalf("http.DefaultTransport is %T, want *http.Transport", http.DefaultTransport)
	}
	tr := base.Clone()
	tr.DisableKeepAlives = false
	tr.TLSClientConfig = &tls.Config{RootCAs: f.roots(t)}
	c, err := NewClient(Config{
		BaseURL:   f.server.URL,
		APIKey:    testAPIKey,
		Transport: tr,
		Timeout:   timeout,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

// loadFullCatalog is the consumer sequence: catalog plans, then every
// distribution's image page.
func loadFullCatalog(ctx context.Context, c Client) (int, int, error) {
	plans, err := c.GetCatalog(ctx)
	if err != nil {
		return 0, 0, err
	}
	images, err := c.GetOperatingSystems(ctx)
	if err != nil {
		return len(plans), 0, err
	}
	return len(plans), len(images), nil
}

// TestDefaultClientOwnsTransportWithReuseDisabled pins the shipped policy: a
// default-constructed client gets its own transport with keep-alives off, and
// the global transport is neither replaced nor mutated.
func TestDefaultClientOwnsTransportWithReuseDisabled(t *testing.T) {
	globalBefore, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		t.Fatalf("http.DefaultTransport is %T, want *http.Transport", http.DefaultTransport)
	}
	globalKeepAlivesBefore := globalBefore.DisableKeepAlives

	c, err := NewClient(Config{APIKey: testAPIKey})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	owned := ownedTransportOf(t, c)

	if owned == http.DefaultTransport {
		t.Error("default client shares http.DefaultTransport; it must own its transport")
	}
	if !owned.DisableKeepAlives {
		t.Error("owned transport has keep-alives enabled; the catalog mitigation requires them disabled")
	}
	if owned.TLSClientConfig != nil && owned.TLSClientConfig.InsecureSkipVerify {
		t.Error("owned transport disables TLS verification")
	}
	if owned.ForceAttemptHTTP2 != globalBefore.ForceAttemptHTTP2 {
		t.Errorf("owned transport ForceAttemptHTTP2 = %v, want the standard %v",
			owned.ForceAttemptHTTP2, globalBefore.ForceAttemptHTTP2)
	}

	globalAfter, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		t.Fatalf("http.DefaultTransport became %T", http.DefaultTransport)
	}
	if globalAfter != globalBefore {
		t.Error("NewClient replaced http.DefaultTransport")
	}
	if globalAfter.DisableKeepAlives != globalKeepAlivesBefore {
		t.Errorf("NewClient mutated http.DefaultTransport.DisableKeepAlives to %v", globalAfter.DisableKeepAlives)
	}
}

// TestDefaultClientTransportIsIndependent pins that two default clients do not
// share one transport: a caller-visible transport must not become shared state.
func TestDefaultClientTransportIsIndependent(t *testing.T) {
	first, err := NewClient(Config{APIKey: testAPIKey})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	second, err := NewClient(Config{APIKey: testAPIKey})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if ownedTransportOf(t, first) == ownedTransportOf(t, second) {
		t.Error("two default clients share one transport")
	}
}

// TestCatalogLoad_ReusedConnectionSettingReachesStallBranch is the red
// reproduction of the observed association: with connection reuse on, the fourth
// catalog call arrives on an already-reused connection, the fixture withholds
// its response, and the call fails on the client's own timeout with no response
// header. This proves the disputed reuse branch is reachable and that the
// pre-change setting produces the controlled failure.
func TestCatalogLoad_ReusedConnectionSettingReachesStallBranch(t *testing.T) {
	fixture := newCatalogFixture(t, true)
	shipped := keepAliveFixtureClient(t, fixture, 400*time.Millisecond)

	plans, images, err := loadFullCatalog(context.Background(), shipped)

	if err == nil {
		t.Fatalf("reused-connection catalog load succeeded; the stall branch was not reached (plans=%d images=%d)", plans, images)
	}
	var netErr interface{ Timeout() bool }
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("catalog error = %v, want a client timeout", err)
	}
	if fixture.ledger.withheld() == 0 {
		t.Fatal("fixture never withheld a response; the fourth call did not arrive on a reused connection")
	}
	if got := fixture.ledger.connections(); got != 1 {
		t.Errorf("fixture accepted %d connections with reuse on, want 1", got)
	}
	if got := fixture.ledger.requests(); got != fixtureStallAfterReuses+1 {
		t.Errorf("fixture served %d requests before the stall, want %d", got, fixtureStallAfterReuses+1)
	}
}

// TestCatalogLoad_OwnedTransportCompletesOnFreshConnections is the positive
// control for the same fixture: the shipped transport completes the whole
// catalog, and the peer sees one connection per request.
//
// The oracle is server-side deliberately: it observes the connections the peer
// actually accepted, so it proves the policy at the wire, not just the settings
// on a struct.
func TestCatalogLoad_OwnedTransportCompletesOnFreshConnections(t *testing.T) {
	for _, tc := range []struct {
		name  string
		http2 bool
	}{
		{name: "http2", http2: true},
		{name: "http1", http2: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newCatalogFixture(t, tc.http2)
			c := fixtureClient(t, fixture, 5*time.Second)

			plans, images, err := loadFullCatalog(context.Background(), c)
			if err != nil {
				t.Fatalf("catalog load failed on fresh connections: %v", err)
			}
			if plans == 0 || images == 0 {
				t.Fatalf("catalog load returned plans=%d images=%d, want both non-empty", plans, images)
			}

			// One products call, one distribution list, one page per active
			// distribution (the inactive entry is skipped).
			const wantCalls = 6
			if got := fixture.ledger.requests(); got != wantCalls {
				t.Errorf("provider requests = %d, want %d", got, wantCalls)
			}
			if fixture.ledger.withheld() != 0 {
				t.Errorf("fixture withheld %d responses, want none", fixture.ledger.withheld())
			}
			if got, want := fixture.ledger.connections(), wantCalls; got != want {
				t.Errorf("peer accepted %d connections for %d requests, want one connection per request", got, want)
			}
		})
	}
}

// TestOrderPost_OwnedTransportSendsOneAttemptOnSeveredConnection pins that the
// fresh-connection policy adds no retry: a non-idempotent order POST whose
// connection is severed after the request is still transmitted exactly once.
func TestOrderPost_OwnedTransportSendsOneAttemptOnSeveredConnection(t *testing.T) {
	var posts atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"meta":{"status":200,"page":1,"total_pages":1,"total":0},"data":[]}`))
			return
		}
		posts.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		// Sever the connection without answering: an uncertain outcome.
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		_ = conn.Close()
	}))
	server.StartTLS()
	t.Cleanup(server.Close)

	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	tr := ownedTransportOf(t, mustDefaultClient(t)).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: roots}

	c, err := NewClient(Config{
		BaseURL:   server.URL,
		APIKey:    testAPIKey,
		Transport: tr,
		Timeout:   2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	req := OrderRequest{PID: 101, PriceID: 555, RegionID: 1, OSID: 12, BillingPeriod: BillingPeriodHourly, Quantity: 1}
	if _, err := c.OrderServer(context.Background(), req); err == nil {
		t.Fatal("expected an error for a severed order connection")
	}
	if got := posts.Load(); got != 1 {
		t.Errorf("order POST attempts = %d, want exactly 1", got)
	}
}

// mustDefaultClient returns a default-constructed client or fails the test.
func mustDefaultClient(t *testing.T) Client {
	t.Helper()
	c, err := NewClient(Config{APIKey: testAPIKey})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

// TestOwnedTransport_CallerCancellationAndTimeoutStillClassified pins that the
// new transport keeps caller deadline, caller cancellation and client timeout
// distinct: the mitigation must not blur how a call ended.
func TestOwnedTransport_CallerCancellationAndTimeoutStillClassified(t *testing.T) {
	t.Run("caller deadline", func(t *testing.T) {
		blocking := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-time.After(fixtureStallBudget):
			}
		}))
		defer blocking.Close()
		recorder := &sink{}
		c, err := NewClient(Config{BaseURL: blocking.URL, APIKey: testAPIKey, Timeout: 5 * time.Second, OnCall: recorder.collect})
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		if _, err := c.GetServers(ctx); err == nil {
			t.Fatal("expected the caller deadline to end the call")
		}
		records := recorder.all()
		if len(records) != 1 || records[0].Outcome != OutcomeCallerDeadline {
			t.Fatalf("records = %+v, want one caller_deadline record", records)
		}
	})

	t.Run("caller cancellation", func(t *testing.T) {
		blocking := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-time.After(fixtureStallBudget):
			}
		}))
		defer blocking.Close()
		recorder := &sink{}
		c, err := NewClient(Config{BaseURL: blocking.URL, APIKey: testAPIKey, Timeout: 5 * time.Second, OnCall: recorder.collect})
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(50 * time.Millisecond)
			cancel()
		}()
		defer cancel()
		if _, err := c.GetServers(ctx); err == nil {
			t.Fatal("expected cancellation to end the call")
		}
		records := recorder.all()
		if len(records) != 1 || records[0].Outcome != OutcomeCallerCanceled {
			t.Fatalf("records = %+v, want one caller_canceled record", records)
		}
	})

	t.Run("client timeout", func(t *testing.T) {
		blocking := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-time.After(fixtureStallBudget):
			}
		}))
		defer blocking.Close()
		recorder := &sink{}
		c, err := NewClient(Config{BaseURL: blocking.URL, APIKey: testAPIKey, Timeout: 100 * time.Millisecond, OnCall: recorder.collect})
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		if _, err := c.GetServers(context.Background()); err == nil {
			t.Fatal("expected the client timeout to end the call")
		}
		records := recorder.all()
		if len(records) != 1 || records[0].Outcome != OutcomeClientTimeout {
			t.Fatalf("records = %+v, want one client_timeout record", records)
		}
	})
}
