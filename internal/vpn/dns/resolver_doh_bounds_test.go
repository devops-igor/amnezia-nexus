package gatewaydns

import (
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// TestResolver_DoHRedirectNotFollowed proves a 3xx is its own failure and the
// redirect target is never contacted. The target is a second, fully valid DoH
// server that answers every query, so following the Location header would be
// visible both as a request on it and as a successful exchange.
func TestResolver_DoHRedirectNotFollowed(t *testing.T) {
	for _, code := range []int{
		http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect,
	} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			ca := newDoTTestCA(t)
			certificate, _ := ca.issue(t, dotLeafOptions{ips: []net.IP{net.ParseIP("127.0.0.1")}})
			target := startDoHTestServer(t, certificate, true, dohAnswerHandler(t, "203.0.113.98"))
			location := "https://" + target.addr.String() + "/dns-query"

			redirector := startDoHTestServer(t, certificate, true, func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, location, code)
			})
			entry := dohEntryOf(redirector.addr, "")
			resolver := mustLoopbackResolver(t, ResolverConfig{
				Upstreams:  []policy.Upstream{entry},
				tlsRootCAs: ca.trustPool(),
			})

			assertDoHFailure(t, resolver, entry, FailureRedirect)
			if got := len(redirector.requests()); got != 1 {
				t.Fatalf("redirector saw %d requests, want exactly 1", got)
			}
			if got := len(target.requests()); got != 0 {
				t.Fatalf("redirect target received %d request(s): the redirect was followed", got)
			}
		})
	}
}

// TestResolver_DoHOversizedBody proves a body past the 65535-byte bound is a
// failure of its own and never a truncated answer. The three cases cover the
// declared-length check, an undeclared (chunked) stream, and the exact boundary,
// which must still be accepted by the size rule and then fail only as a message.
func TestResolver_DoHOversizedBody(t *testing.T) {
	oversize := strings.Repeat("a", maxDoHResponseBytes+1)

	t.Run("declared length over the bound", func(t *testing.T) {
		resolver, entry, _ := dohFailureResolver(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", dohMediaType)
			_, _ = w.Write([]byte(oversize))
		})
		assertDoHFailure(t, resolver, entry, FailureResponseTooLarge)
	})

	t.Run("undeclared length streamed past the bound", func(t *testing.T) {
		resolver, entry, _ := dohFailureResolver(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", dohMediaType)
			w.WriteHeader(http.StatusOK)
			flusher, _ := w.(http.Flusher)
			for sent := 0; sent <= maxDoHResponseBytes; sent += 4096 {
				_, _ = w.Write([]byte(oversize[:4096]))
				flusher.Flush()
			}
		})
		assertDoHFailure(t, resolver, entry, FailureResponseTooLarge)
	})

	t.Run("exactly at the bound is judged as a message", func(t *testing.T) {
		resolver, entry, _ := dohFailureResolver(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", dohMediaType)
			_, _ = w.Write([]byte(oversize[:maxDoHResponseBytes]))
		})
		assertDoHFailure(t, resolver, entry, FailureInvalidResponse)
	})
}
