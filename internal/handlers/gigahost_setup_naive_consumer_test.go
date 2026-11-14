//go:build with_utls

package handlers

// The automatic Naive consumer: admission decided by a real authenticated payload
// that traversed the proxy, driven through the production chain.
//
// The chain under test, with no qualification override anywhere:
//
//	StartAutomaticGigahostSetup      entry; policy opt-in
//	tracker.RunOnce                  provider discovery, association, grant, pin
//	installer.RunOnce
//	  installSSL/register/install    controlled boundaries, as in every checkpoint
//	  enableDeployBackend
//	    resolveInstalledProxyParamsForProto  reads the server row, else AddClient
//	    EnableBackendWithConfig              naive dialer + streambridge device
//	    qualifyProxyBackendTraffic
//	      QualifyProxyTraffic -> naive.ProbeNaiveProxyTunnel   (no override)
//	        native daemon -> SOCKS5 -> TLS + CONNECT auth -> TLS -> HEAD /
//	  promotion / durable quarantine release
//
// Every assertion about the payload is a count at a real origin behind the proxy, not
// an inference from a return value. See the fixture file for the topology, the
// disclosed Caddy-site substitution, and the in-process downgrade seam the negatives
// defend against.
//
// Scope, stated: this proves the automatic Naive admission path over loopback with a
// real proxy, a real native client and a real HTTP request/reply. The provider answer,
// the SSH transport and the protocol installation remain controlled outcomes. It says
// nothing about Linux routing, a public certificate or DNS.

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel/naive"
)

// naiveProbeWithInProcessFallback runs the production probe entry with the downgrade
// option enabled, which is the weaker verdict the consumer negatives must refuse.
//
// WithInProcessFallback is a production option, not a test seam: Dialer.dialAllowsInProcess
// honours it whenever a daemon is absent. It is used here only to demonstrate what
// handshake-level evidence looks like, never to qualify anything.
func naiveProbeWithInProcessFallback(ctx context.Context, site *naiveConsumerSite) (int64, error) {
	return naive.ProbeNaiveProxyWithOptions(ctx, site.endpoint, site.params, 10*time.Second,
		naive.WithInProcessFallback())
}

// TestAutomaticSetupAdmitsAfterAuthenticNaivePayload is the positive.
//
// The job starts with no association, no grant and no pin, and production acquires all
// three. The backend is admitted only after the inner request reached a real origin
// through the authenticated tunnel and was answered.
func TestAutomaticSetupAdmitsAfterAuthenticNaivePayload(t *testing.T) {
	const orderID = "ord_naive_consumer_positive"
	const providerServerID = 9991

	requireNaiveConsumerBinary(t)

	f := newNaiveConsumerJob(t, orderID, providerServerID, true, models.NaiveProxyParams{
		Username: naiveConsumerUsername,
		Password: naiveConsumerPassword,
		Domain:   "127.0.0.1",
	})
	ctx := context.Background()

	if err := f.h.NewGigahostSetupInstaller().RunOnce(ctx); err != nil {
		t.Fatalf("install pass: %v", err)
	}

	final := f.intent(orderID)
	if final.State != models.SetupStateReady {
		t.Fatalf("state = %q, want %q (step %q, last error %q)",
			final.State, models.SetupStateReady, final.Step, final.LastError)
	}

	// The payload really traversed the tunnel: the origin was reached only through the
	// authenticated CONNECT and answered the inner request.
	f.requirePayloadDelivered(t, "after admission")

	server := f.registeredServer(providerServerID)
	if server == nil {
		t.Fatal("no panel server was registered")
	}
	if !authenticPoolContains(t, f.installEnv, server.ID) {
		t.Fatal("the qualified naive backend is not selectable by the production pool path")
	}
	if authenticDurableQuarantine(t, f.installEnv, server.ID) {
		t.Fatal("an admitted backend still carries the durable enrollment quarantine")
	}

	// One durable identity from tracking through install, never rewritten.
	requireNoFingerprintRewrite(t, final.HostFingerprint, f.pinnedPresented, "after install")
	if final.HostTrustPolicy != models.SetupTrustPolicyFirstContact {
		t.Fatalf("the automation provenance was rewritten to %q", final.HostTrustPolicy)
	}

	// One install, one registration, no durable marker, and no purchase anywhere.
	if n := f.counters.totalInstalls(); n != 1 {
		t.Fatalf("protocol installs = %d, want exactly 1", n)
	}
	if n := f.countRegisteredServers(t); n != 1 {
		t.Fatalf("registered panel servers for this provider server = %d, want exactly 1", n)
	}
	if n := f.countEnrollments(t); n != 0 {
		t.Fatalf("durable enrollment markers for the admitted backend = %d, want 0", n)
	}
	f.requireNoPurchases(t, "after admission")

	// A repeated normal tracker+installer pass must add nothing: no second install, no
	// second registration, no second enrollment, and no purchase.
	beforeInstalls := f.counters.totalInstalls()
	beforeServers := f.countRegisteredServers(t)
	beforeRequests := f.site.originRequests.Load()
	if err := f.h.NewGigahostSetupTracker().RunOnce(ctx); err != nil {
		t.Fatalf("second tracking pass: %v", err)
	}
	if err := f.h.NewGigahostSetupInstaller().RunOnce(ctx); err != nil {
		t.Fatalf("second install pass: %v", err)
	}
	if n := f.counters.totalInstalls(); n != beforeInstalls {
		t.Fatalf("a repeated pass installed again: installs went from %d to %d", beforeInstalls, n)
	}
	if n := f.countRegisteredServers(t); n != beforeServers {
		t.Fatalf("a repeated pass registered another server: %d, want %d", n, beforeServers)
	}
	if n := f.countEnrollments(t); n != 0 {
		t.Fatalf("a repeated pass left %d durable enrollment markers", n)
	}
	f.requireNoPurchases(t, "after a repeated pass")
	// An already-admitted backend must not be re-qualified on a repeated pass: no new
	// payload request reaches the origin.
	if n := f.site.originRequests.Load(); n != beforeRequests {
		t.Fatalf("a repeated pass re-ran the payload qualification: origin requests went "+
			"from %d to %d", beforeRequests, n)
	}

	// The backend is still admitted exactly once after the repeat.
	if !authenticPoolContains(t, f.installEnv, server.ID) {
		t.Fatal("a repeated pass removed the admitted backend from the pool")
	}
	if got := f.intent(orderID); got.State != models.SetupStateReady {
		t.Fatalf("a repeated pass changed the terminal state to %q", got.State)
	}
	requireNoFingerprintRewrite(t, f.intent(orderID).HostFingerprint, f.pinnedPresented,
		"after a repeated pass")
}

// TestAutomaticSetupRefusesWhenTheNaivePayloadIsNeverAnswered is the subtlest negative.
//
// The proxy authenticates the client, the request is delivered and counted, and the
// reply never comes. A handshake-only oracle - including the in-process CONNECT
// fallback the fixture CA makes reachable - would admit this backend. Production
// qualification must refuse, keep the backend out of the pool, and leave the durable
// quarantine in place.
func TestAutomaticSetupRefusesWhenTheNaivePayloadIsNeverAnswered(t *testing.T) {
	const orderID = "ord_naive_consumer_no_payload"
	const providerServerID = 9992

	requireNaiveConsumerBinary(t)

	f := newNaiveConsumerJob(t, orderID, providerServerID, false, models.NaiveProxyParams{
		Username: naiveConsumerUsername,
		Password: naiveConsumerPassword,
		Domain:   "127.0.0.1",
	})
	ctx := context.Background()

	if err := f.h.NewGigahostSetupInstaller().RunOnce(ctx); err != nil {
		t.Fatalf("install pass: %v", err)
	}

	// The failure must be the missing reply, not a failed handshake: the request has to
	// have reached the origin. If it did not, the tunnel never authenticated and this
	// test would be proving something else.
	if n := f.site.originRequests.Load(); n == 0 {
		t.Fatal("the origin never received the request, so the failure was not the missing " +
			"reply and the negative does not discriminate a payload oracle from a " +
			"handshake-level one")
	}
	if n := f.site.originReplies.Load(); n != 0 {
		t.Fatalf("the origin sent %d replies, so this is not the missing-reply case", n)
	}
	t.Logf("no-payload negative: origin_requests=%d origin_replies=%d",
		f.site.originRequests.Load(), f.site.originReplies.Load())

	final := f.intent(orderID)
	if final.State == models.SetupStateReady {
		t.Fatal("a backend whose payload was never answered was reported ready")
	}
	if final.LastError == "" {
		t.Fatal("the refusal recorded no reason")
	}

	server := f.registeredServer(providerServerID)
	if server == nil {
		t.Fatal("no panel server was registered, so admission was never reached")
	}
	if authenticPoolContains(t, f.installEnv, server.ID) {
		t.Fatal("a backend whose payload was never answered is selectable by the production pool path")
	}
	if !authenticDurableQuarantine(t, f.installEnv, server.ID) {
		t.Fatal("the durable quarantine was released without an answered payload")
	}
	// The pin survives the refusal untouched.
	requireNoFingerprintRewrite(t, final.HostFingerprint, f.pinnedPresented, "after refusal")
	f.requireNoPurchases(t, "after a refused admission")
}

// TestAutomaticSetupRefusesWhenNaiveAuthenticationIsRejected is the wrong-credentials
// negative.
//
// The AddClient answer carries a password the site does not accept, so the outer CONNECT
// is rejected with 407 and no payload can follow. Production must refuse; the origin must
// show that nothing was ever delivered, which is what distinguishes this case from the
// missing-reply one.
func TestAutomaticSetupRefusesWhenNaiveAuthenticationIsRejected(t *testing.T) {
	const orderID = "ord_naive_consumer_bad_auth"
	const providerServerID = 9993

	requireNaiveConsumerBinary(t)

	f := newNaiveConsumerJob(t, orderID, providerServerID, true, models.NaiveProxyParams{
		Username: naiveConsumerUsername,
		Password: "not-the-fixture-password",
		Domain:   "127.0.0.1",
	})
	ctx := context.Background()

	if err := f.h.NewGigahostSetupInstaller().RunOnce(ctx); err != nil {
		t.Fatalf("install pass: %v", err)
	}

	// A rejected CONNECT cannot deliver a payload, and it must not be counted as one.
	if n := f.site.originRequests.Load(); n != 0 {
		t.Fatalf("the origin received %d requests although the proxy rejected the credentials, "+
			"so this test is not exercising the authentication refusal", n)
	}

	final := f.intent(orderID)
	if final.State == models.SetupStateReady {
		t.Fatal("a backend whose protocol credentials were rejected was reported ready")
	}
	if final.LastError == "" {
		t.Fatal("the refusal recorded no reason")
	}

	server := f.registeredServer(providerServerID)
	if server == nil {
		t.Fatal("no panel server was registered, so admission was never reached")
	}
	if authenticPoolContains(t, f.installEnv, server.ID) {
		t.Fatal("a backend whose credentials were rejected is selectable by the production pool path")
	}
	if !authenticDurableQuarantine(t, f.installEnv, server.ID) {
		t.Fatal("the durable quarantine was released without authentication")
	}
	requireNoFingerprintRewrite(t, final.HostFingerprint, f.pinnedPresented, "after a refused authentication")
	f.requireNoPurchases(t, "after a refused authentication")
}

// TestNaiveConsumerFixturesAreNotHandshakeOnly is the mutation check the acceptance
// requires: it demonstrates that this fixture distinguishes a payload oracle from a
// handshake-only one, rather than assuming it.
//
// Qualifying the same site with `WithInProcessFallback` - the downgrade the test CA
// makes reachable in production code - returns success for BOTH sites, including the
// one whose reply is never sent, and in neither case does the origin see a request.
// That is exactly the weaker verdict the consumer negatives must refuse, proven here so
// a future change that silently switched the consumer onto that path would be caught by
// these tests instead of passing.
//
// It deliberately needs no native binary: the point is the path that runs without one.
// NAIVE_BIN_PATH points at a path that does not exist, so the daemon is neither started
// nor downloaded and the in-process transport is what answers.
func TestNaiveConsumerFixturesAreNotHandshakeOnly(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-naive-binary")
	t.Setenv(naive.NaiveBinPathEnv, missing)

	for _, answerPayload := range []bool{true, false} {
		answerPayload := answerPayload
		name := "answered"
		if !answerPayload {
			name = "unanswered"
		}
		t.Run(name, func(t *testing.T) {
			site := startNaiveConsumerSite(t, answerPayload)

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			// The downgraded path: in-process HTTP/2 CONNECT only, no daemon payload.
			latencyMS, err := naiveProbeWithInProcessFallback(ctx, site)
			if err != nil {
				t.Fatalf("the handshake-only probe failed, so it is not the weaker oracle this "+
					"check needs to demonstrate: %v", err)
			}
			if latencyMS < 1 {
				t.Fatalf("expected a positive latency from the handshake-only probe, got %d", latencyMS)
			}
			if n := site.originRequests.Load(); n != 0 {
				t.Fatalf("the handshake-only probe delivered %d requests to the origin, so it is "+
					"not handshake-only", n)
			}
			t.Logf("handshake-only probe admitted payload_answered=%t with no request delivered",
				answerPayload)
		})
	}
}
