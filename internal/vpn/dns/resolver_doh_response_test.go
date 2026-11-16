package gatewaydns

import (
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// dohFailureResolver builds a resolver for one DoH fixture with a short attempt
// budget, so a stall fails the test quickly instead of waiting out a default.
func dohFailureResolver(t *testing.T, handler http.HandlerFunc) (*UpstreamResolver, policy.Upstream, *dohTestServer) {
	t.Helper()
	ca := newDoTTestCA(t)
	certificate, _ := ca.issue(t, dotLeafOptions{ips: []net.IP{net.ParseIP("127.0.0.1")}})
	server := startDoHTestServer(t, certificate, true, handler)
	entry := dohEntryOf(server.addr, "")
	resolver := mustLoopbackResolver(t, ResolverConfig{
		Upstreams:      []policy.Upstream{entry},
		AttemptTimeout: 400 * time.Millisecond,
		tlsRootCAs:     ca.trustPool(),
	})
	return resolver, entry, server
}

// TestResolver_DoHHTTPStatus proves a non-2xx answer is a transport failure with
// its own kind and never an empty or partial DNS answer.
func TestResolver_DoHHTTPStatus(t *testing.T) {
	for _, code := range []int{http.StatusBadRequest, http.StatusForbidden, http.StatusNotFound, http.StatusInternalServerError, http.StatusServiceUnavailable} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			resolver, entry, _ := dohFailureResolver(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", dohMediaType)
				w.WriteHeader(code)
			})
			assertDoHFailure(t, resolver, entry, FailureHTTPStatus)
		})
	}
}

// TestResolver_DoHContentType proves a 2xx answer that is not a DNS message is
// refused before its body is parsed.
func TestResolver_DoHContentType(t *testing.T) {
	for _, contentType := range []string{"text/html", "application/json", "application/octet-stream", ""} {
		t.Run("type "+contentType, func(t *testing.T) {
			resolver, entry, _ := dohFailureResolver(t, func(w http.ResponseWriter, r *http.Request) {
				capture := &dohCaptureWriter{}
				answerHandler(t, "203.0.113.97").ServeDNS(capture, testQuery("x."))
				wire, _ := capture.msg.Pack()
				if contentType != "" {
					w.Header().Set("Content-Type", contentType)
				} else {
					w.Header()["Content-Type"] = nil
				}
				_, _ = w.Write(wire)
			})
			assertDoHFailure(t, resolver, entry, FailureContentType)
		})
	}
}

// TestResolver_DoHGarbageBody proves a well-typed body that is not a DNS message
// is an invalid response, not an answer.
func TestResolver_DoHGarbageBody(t *testing.T) {
	resolver, entry, _ := dohFailureResolver(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", dohMediaType)
		_, _ = w.Write([]byte("not a dns message"))
	})
	assertDoHFailure(t, resolver, entry, FailureInvalidResponse)
}
