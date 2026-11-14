package gatewaydns

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
	mdns "github.com/miekg/dns"
)

type countingRouteObserver struct {
	calls int
}

func (o *countingRouteObserver) ObserveDNSResponse(string, *mdns.Msg, *mdns.Msg) error {
	o.calls++
	return nil
}

// emptyPolicySource reports no compiled snapshot, so only the observer path of
// ObserveResponseWithSessionID is exercised here.
type emptyPolicySource struct{}

func (emptyPolicySource) Current() *policy.Snapshot { return nil }

type unusedResolver struct{}

func (unusedResolver) Exchange(context.Context, *mdns.Msg) (*mdns.Msg, error) {
	return nil, errors.New("resolver must not be used by this control")
}

// TestObserveResponse_SkipsObserverForRetiredScope requires a response that
// completes after its session scope was retired to be dropped instead of being
// re-observed by session ID, which would allocate a replacement scope for a
// session that already released it.
func TestObserveResponse_SkipsObserverForRetiredScope(t *testing.T) {
	srv, err := NewServer(ServerConfig{Gateway: netip.MustParseAddrPort("10.100.0.1:53")}, unusedResolver{}, emptyPolicySource{})
	if err != nil {
		t.Fatalf("build dns server: %v", err)
	}
	observer := &countingRouteObserver{}
	srv.SetObserver(observer)

	cache, err := policy.NewRouteCache(policy.CacheConfig{})
	if err != nil {
		t.Fatalf("build route cache: %v", err)
	}
	cache.SetPolicyGeneration("gen-observe-retirement")
	scope := policy.Scope{SessionID: "sess-observe-retirement", OwnershipEpoch: 1}
	session, err := cache.Open(scope)
	if err != nil {
		t.Fatalf("open session scope: %v", err)
	}

	req := new(mdns.Msg)
	req.SetQuestion("unlisted.example.", mdns.TypeA)
	resp := new(mdns.Msg)
	resp.SetReply(req)

	srv.ObserveResponseWithSessionID(req, resp, session, scope.SessionID, time.Now())
	if observer.calls != 1 {
		t.Fatalf("live scope: observer calls = %d want 1", observer.calls)
	}

	session.Invalidate()
	srv.ObserveResponseWithSessionID(req, resp, session, scope.SessionID, time.Now())
	if observer.calls != 1 {
		t.Fatalf("retired scope: observer recorded the response (%d calls)", observer.calls)
	}
	if n := cache.SessionCount(); n != 0 {
		t.Fatalf("retired scope still admitted: %d session(s)", n)
	}
}
