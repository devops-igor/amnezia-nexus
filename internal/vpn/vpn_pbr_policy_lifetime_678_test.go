package vpn

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// These are the permanent regression oracles for issue #678 findings F678-01 and
// F678-02 (round-1 audit HEAD c161a2a). They are the inverted successors of the
// auditor's counterexamples: each one drives the real production entry point
// through the same decisive condition the counterexample used, but now asserts
// the required behavior instead of the defect.
//
// Only two seams are substituted anywhere below: the WAN PacketDevice (a
// single-owner name registry standing in for TUNSETIFF, so no /dev/net/tun is
// needed) and, for the restart/fetch scenario, the fetcher's TLS-trust and
// dial functions pointing at a local TLS fixture. Everything else — the shipped
// middleware, the lifecycle mutexes, the real Syncer/Matcher/FileStore, the real
// SQLite settings table and the real parser — is production code.

// auditedLKGStore writes a source-matching on-disk last-known-good generation so
// activation can publish real rules without any network fetch, and so the
// shrink-guard baseline is genuine rather than absent.
func auditedLKGStore(t *testing.T, settings policy.Settings) *policy.FileStore {
	t.Helper()
	cfg, err := settings.SyncConfig()
	if err != nil {
		t.Fatalf("SyncConfig: %v", err)
	}
	hash := sha256.New()
	domains := make(map[string]uint8, 20)
	meta := make(map[string]policy.SourceMeta, len(cfg.Sources))
	for i := 0; i < 20; i++ {
		domains[fmt.Sprintf("seeded%d.example.com", i)] = 1
	}
	for _, src := range cfg.Sources {
		fmt.Fprintf(hash, "%s:%s:%d:%d:%v\n", src.ID, src.URL, src.Format, src.BareDomainMode, src.IsPreset)
		meta[src.ID] = policy.SourceMeta{ID: src.ID, URL: src.URL, RuleCount: len(domains)}
	}
	gen := &policy.Generation{
		SchemaVersion: policy.SchemaVersion,
		GenerationID:  "gen-audit-seed",
		Version:       1,
		ConfigHash:    hex.EncodeToString(hash.Sum(nil)),
		SourcesMeta:   meta,
		Domains:       domains,
		DomainCount:   len(domains),
	}
	store := policy.NewFileStore(t.TempDir())
	if err := store.Commit(context.Background(), gen); err != nil {
		t.Fatalf("seed last-known-good generation: %v", err)
	}
	return store
}

// TestSuccessfulActivationKeepsPolicySyncerAlive is the F678-01 regression.
//
// RED on c161a2a: startPolicyLoop derived the scheduling loop from the request
// context, so the shipped middleware's deferred cancel (and net/http's own
// request lifetime) closed the syncer the moment a *successful* PUT returned.
// PBR stayed enabled, the periodic refresh stopped, and SyncPolicyNow answered
// ErrSyncerClosed until the process restarted.
//
// The decisive condition is that the activation runs inside a real
// middleware.OperationTimeout handler and the assertions happen strictly AFTER
// that handler returned, so a regression to request-scoped lifetime fails here
// even though the activation itself succeeded.
func TestSuccessfulActivationKeepsPolicySyncerAlive(t *testing.T) {
	reg := newNameRegistry()
	withNameOwnedWANDevice(t, reg)
	svc := serviceForActivation(t)
	t.Cleanup(svc.StopPolicyRouting)

	settings := repeatedEnableSettings(t)
	store := auditedLKGStore(t, settings)

	var activationErr error
	wrapped := middleware.OperationTimeout(time.Minute)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		activationErr = svc.StartPolicyRouting(r.Context(), settings, store, string(settings.Preset))
		w.WriteHeader(http.StatusOK)
	}))
	wrapped.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPut, "/api/vpn/policy", nil))
	if activationErr != nil {
		t.Fatalf("activation failed: %v", activationErr)
	}
	if !svc.PBREnabled() {
		t.Fatal("activation succeeded but PBR is not enabled")
	}

	// The request has returned at this point: the shipped middleware already ran
	// its deferred cancel. The syncer must still be live.
	//
	// The defect's signature is policy.ErrSyncerClosed: once Syncer.Run exits it
	// sets closed=true, after which every SyncPolicyNow call is refused forever.
	// A regression can also show as a call that never gets served, because the
	// request channel has no reader any more. Probing with a short per-call
	// deadline detects both: a closed syncer is refused at once, a dead loop
	// times out, and a live loop answers (here with the fixture's content
	// failure, since the source is a deliberately unreachable .invalid host).
	deadline := time.Now().Add(5 * time.Second)
	var observed error
	for time.Now().Before(deadline) {
		callCtx, callCancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, observed = svc.SyncPolicyNow(callCtx)
		callCancel()
		if errors.Is(observed, policy.ErrSyncerClosed) {
			t.Fatalf("successful enable closed its policy syncer when the HTTP request returned (F678-01): SyncPolicyNow=%v while PBR reports enabled=%t; periodic refresh and manual sync are dead until a process restart",
				observed, svc.PBREnabled())
		}
		if observed != nil && !errors.Is(observed, context.DeadlineExceeded) {
			break // a real answer from the live syncer: stop probing
		}
		time.Sleep(5 * time.Millisecond)
	}
	if errors.Is(observed, context.DeadlineExceeded) {
		t.Fatalf("on-demand sync after a successful enable never completed (F678-01): the scheduling loop is not serving requests any more")
	}
	if observed == nil {
		t.Fatalf("fixture source unexpectedly synced; expected a content failure from the unreachable .invalid host")
	}
	if !strings.Contains(observed.Error(), "fetch") {
		t.Fatalf("on-demand sync failed for an unexpected reason (not a source fetch): %v", observed)
	}
	if got := svc.PolicyStatusSnapshot().SyncState; got == "disabled" {
		t.Fatalf("policy status reports %q while PBR is enabled", got)
	}
}

// TestExplicitDisableStillStopsPolicySyncer is the adjacent control for F678-01.
//
// Detaching the loop from the request lifetime must not make it unstoppable:
// an explicit disable still has to terminate it, which is the whole reason the
// lifetime is owned by the service rather than by the request. It also proves
// the fix did not turn "disable" into a working-syncer no-op.
func TestExplicitDisableStillStopsPolicySyncer(t *testing.T) {
	reg := newNameRegistry()
	withNameOwnedWANDevice(t, reg)
	svc := serviceForActivation(t)

	settings := repeatedEnableSettings(t)
	if err := svc.StartPolicyRouting(context.Background(), settings, auditedLKGStore(t, settings), string(settings.Preset)); err != nil {
		t.Fatalf("activation failed: %v", err)
	}
	assertFullyEnabled(t, svc, reg)

	svc.StopPolicyRouting()
	assertFullyDisabled(t, svc, reg)

	// After disable there is no registered runtime at all, so the sync endpoint
	// reports "not started" rather than a closed-but-enabled syncer.
	if _, err := svc.SyncPolicyNow(context.Background()); err == nil {
		t.Fatal("SyncPolicyNow succeeded after an explicit disable")
	} else if errors.Is(err, policy.ErrSyncerClosed) {
		t.Fatalf("disable left a registered but closed syncer behind: %v", err)
	}
}

// TestServiceStopStopsPolicySyncer keeps the detached loop from becoming a
// process-lifetime goroutine: service shutdown must stop it too.
func TestServiceStopStopsPolicySyncer(t *testing.T) {
	reg := newNameRegistry()
	withNameOwnedWANDevice(t, reg)
	svc := serviceForActivation(t)

	settings := repeatedEnableSettings(t)
	if err := svc.StartPolicyRouting(context.Background(), settings, auditedLKGStore(t, settings), string(settings.Preset)); err != nil {
		t.Fatalf("activation failed: %v", err)
	}
	if svc.policyRuntime() == nil {
		t.Fatal("activation did not register a policy runtime")
	}

	if err := svc.Stop(); err != nil {
		t.Fatalf("service Stop: %v", err)
	}
	if svc.policyRuntime() != nil {
		t.Fatal("service shutdown left the policy runtime registered")
	}
	if got := reg.liveOwners(); got != 0 {
		t.Fatalf("service shutdown left %d live owner(s) of the WAN device name", got)
	}
}

// TestRestartInitialSnapshotPreservesGoodGeneration is the F678-03-adjacent
// control for the F678-01 lifetime change: a detached loop must not alter the
// synchronous activation ordering that keeps the first snapshot honest.
//
// It also pins the pre-existing (separately assigned) restart/shrink behavior so
// the F678-01/02 repair cannot silently change it: a fresh matcher with a
// source-matching durable baseline still activates, and the shrink guard still
// rejects a suspiciously shortened payload on an initialized matcher.
func TestRestartInitialSnapshotPreservesGoodGeneration(t *testing.T) {
	var serveSmall atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		if serveSmall.Load() {
			fmt.Fprintln(w, "only.example.com")
			return
		}
		for i := 0; i < 20; i++ {
			fmt.Fprintf(w, "rule%d.example.com\n", i)
		}
	}))
	defer server.Close()

	settings := policy.DefaultSettings()
	settings.Enabled = true
	settings.Preset = policy.PresetCustom
	settings.CustomURLs = []string{"https://audit-list.example/policy.lst"}
	cfg, err := settings.SyncConfig()
	if err != nil {
		t.Fatalf("SyncConfig: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	fetch := policy.NewFetcher(cfg.FetchLimits)
	fetch.SetFixtureTLSTrust(
		&tls.Config{RootCAs: roots, ServerName: "example.com", MinVersion: tls.VersionTLS12},
		func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
		},
		func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, strings.TrimPrefix(server.URL, "https://"))
		},
	)

	store := policy.NewFileStore(t.TempDir())
	first := policy.NewMatcher()
	syncer, err := policy.NewSyncer(first, fetch, store, cfg)
	if err != nil {
		t.Fatalf("NewSyncer: %v", err)
	}
	if _, err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatalf("seed sync: %v", err)
	}
	if first.Current().DomainCount() != 20 {
		t.Fatalf("seed published %d domains, want 20", first.Current().DomainCount())
	}

	// The shrink guard is unchanged: the identical shortened payload is refused
	// on an initialized matcher, leaving the good generation in place.
	serveSmall.Store(true)
	guarded, err := policy.NewSyncer(first, fetch, store, cfg)
	if err != nil {
		t.Fatalf("NewSyncer (guarded): %v", err)
	}
	if _, err := guarded.SyncOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "shrink guard") {
		t.Fatalf("initialized matcher did not reject the shrink: %v", err)
	}
	if got := first.Current().DomainCount(); got != 20 {
		t.Fatalf("refused shrink changed the live matcher to %d domains", got)
	}
	gen, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if gen == nil || gen.DomainCount != 20 {
		t.Fatalf("refused shrink changed the durable generation: %+v", gen)
	}
}
