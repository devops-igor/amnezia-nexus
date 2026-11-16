package gatewaydns

import (
	"net/http"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// dohStallBudget is the per-attempt budget the stall tests use, and the ceiling
// they allow for an exchange to give up: the budget plus generous scheduler slack.
const (
	dohStallBudget  = 400 * time.Millisecond
	dohStallCeiling = 2 * time.Second
)

// assertDoHTimeout requires a timeout failure inside the attempt budget.
func assertDoHTimeout(t *testing.T, resolver *UpstreamResolver, entry policy.Upstream) {
	t.Helper()
	start := time.Now()
	assertDoHFailure(t, resolver, entry, FailureTimeout)
	if elapsed := time.Since(start); elapsed > dohStallCeiling {
		t.Fatalf("a stalled DoH peer held the exchange for %v, past the %v budget", elapsed, dohStallBudget)
	}
}

// TestResolver_DoHStalledPeer covers the three places a peer can stop talking:
// before the TLS handshake, after the handshake before any response, and in the
// middle of the body. Each must end inside the attempt budget as a timeout, not
// hold the query to its overall deadline and not be reported as a network error.
func TestResolver_DoHStalledPeer(t *testing.T) {
	t.Run("silent before the handshake", func(t *testing.T) {
		addr := startStalledTLSListener(t)
		entry := dohEntryOf(addr, "")
		resolver := mustLoopbackResolver(t, ResolverConfig{Upstreams: []policy.Upstream{entry}, AttemptTimeout: dohStallBudget})
		assertDoHTimeout(t, resolver, entry)
	})

	t.Run("silent after the handshake", func(t *testing.T) {
		resolver, entry, _ := dohFailureResolver(t, func(_ http.ResponseWriter, r *http.Request) {
			<-r.Context().Done()
		})
		assertDoHTimeout(t, resolver, entry)
	})

	t.Run("stops in the middle of the body", func(t *testing.T) {
		resolver, entry, _ := dohFailureResolver(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", dohMediaType)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("partial"))
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		})
		assertDoHTimeout(t, resolver, entry)
	})
}
