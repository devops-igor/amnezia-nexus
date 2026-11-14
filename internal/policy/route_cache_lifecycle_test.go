package policy

import "testing"

// TestRouteCache_GetAndSessionCount_LifecycleAccessors pins the read accessors
// that let session-scope owners inspect evidence without allocating it, and the
// identity-bounded invalidation that keeps a stale retirement from deleting a
// replacement scope.
func TestRouteCache_GetAndSessionCount_LifecycleAccessors(t *testing.T) {
	rc, err := NewRouteCache(CacheConfig{})
	if err != nil {
		t.Fatalf("build route cache: %v", err)
	}
	rc.SetPolicyGeneration("gen-lifecycle")

	scope := Scope{SessionID: "sess-lifecycle", OwnershipEpoch: 1}
	if got := rc.Get(scope); got != nil {
		t.Fatalf("Get on a session without evidence returned a cache")
	}
	if n := rc.SessionCount(); n != 0 {
		t.Fatalf("Get allocated a scope: %d session(s)", n)
	}
	if got := rc.Get(Scope{}); got != nil {
		t.Fatalf("Get with an empty session ID returned a cache")
	}

	first, err := rc.Open(scope)
	if err != nil {
		t.Fatalf("open session scope: %v", err)
	}
	if got := rc.Get(scope); got != first {
		t.Fatalf("Get did not return the admitted scope")
	}
	if n := rc.SessionCount(); n != 1 {
		t.Fatalf("SessionCount = %d want 1", n)
	}
	if first.Retired() {
		t.Fatalf("fresh scope reported retired")
	}

	first.Invalidate()
	if !first.Retired() {
		t.Fatalf("invalidated scope did not report retired")
	}
	if got := rc.Get(scope); got != nil {
		t.Fatalf("invalidated scope is still admitted")
	}
	if n := rc.SessionCount(); n != 0 {
		t.Fatalf("invalidation left %d session(s)", n)
	}

	// A re-admission of the same session creates a fresh scope.
	second, err := rc.Open(scope)
	if err != nil {
		t.Fatalf("re-open session scope: %v", err)
	}
	if second == first {
		t.Fatalf("re-open returned the retired scope")
	}
	if second.Retired() {
		t.Fatalf("re-admitted scope reported retired")
	}

	// A stale invalidation must not delete the scope that now owns the key.
	first.Invalidate()
	if got := rc.Get(scope); got != second {
		t.Fatalf("stale invalidation removed the replacement scope")
	}
	if n := rc.SessionCount(); n != 1 {
		t.Fatalf("stale invalidation changed the admitted count to %d", n)
	}
}
