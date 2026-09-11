package middleware

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
)

// CookieSecureSource describes where the current cookie Secure decision came from.
type CookieSecureSource string

const (
	// CookieSecureFromTLS means Secure is derived from live TLS certificate state.
	CookieSecureFromTLS CookieSecureSource = "tls"
	// CookieSecureFromOverride means Secure is forced false by the explicit
	// COOKIE_INSECURE=1 development override.
	CookieSecureFromOverride CookieSecureSource = "override"
)

// TLSCertLookupFunc reports whether a TLS certificate is currently loaded.
// It is implemented by the router server on top of its dynamic certificate
// loading; implementations must not block on the request hot path.
type TLSCertLookupFunc func(ctx context.Context) (present bool, err error)

// SessionCookiePolicy is the single owner of session-cookie security
// attributes. The Secure decision is cached in an atomic flag so the request
// hot path never touches the database; the server refreshes the flag whenever
// the dynamic TLS certificate is loaded or reloaded.
//
// When the insecureOverride is active (dev-only, COOKIE_INSECURE=1) Secure is
// always false regardless of TLS state.
type SessionCookiePolicy struct {
	insecureOverride bool
	tlsHasCert       atomic.Bool
}

// NewSessionCookiePolicy builds a policy. When insecureOverride is true
// (COOKIE_INSECURE=1), Secure() always returns false and TLS state is ignored.
func NewSessionCookiePolicy(insecureOverride bool) *SessionCookiePolicy {
	return &SessionCookiePolicy{insecureOverride: insecureOverride}
}

// SetTLSCertPresent updates the cached TLS-certificate state (true when a
// certificate is currently loaded). Called by the server on cert load/reload.
func (p *SessionCookiePolicy) SetTLSCertPresent(present bool) {
	p.tlsHasCert.Store(present)
}

// Secure reports whether session cookies must carry the Secure attribute.
func (p *SessionCookiePolicy) Secure() bool {
	return !p.insecureOverride && p.tlsHasCert.Load()
}

// Source reports where the current Secure decision comes from.
func (p *SessionCookiePolicy) Source() CookieSecureSource {
	if p.insecureOverride {
		return CookieSecureFromOverride
	}
	return CookieSecureFromTLS
}

var (
	cookiePolicyMu      sync.RWMutex
	sessionCookiePolicy *SessionCookiePolicy
)

// InstallSessionCookiePolicy installs the process-wide session cookie policy.
// Call once during server startup, before any handler writes a cookie.
func InstallSessionCookiePolicy(p *SessionCookiePolicy) {
	cookiePolicyMu.Lock()
	sessionCookiePolicy = p
	cookiePolicyMu.Unlock()
}

// CurrentSessionCookiePolicy returns the installed policy. When nothing has
// been installed (unit tests, CLI tools) it returns a non-override policy
// defaulting to Secure=false so cookie helpers stay safe to call.
func CurrentSessionCookiePolicy() *SessionCookiePolicy {
	cookiePolicyMu.RLock()
	defer cookiePolicyMu.RUnlock()
	if sessionCookiePolicy == nil {
		return &SessionCookiePolicy{}
	}
	return sessionCookiePolicy
}

// LoadSessionCookiePolicy builds, installs and returns the process-wide cookie
// policy. Unless the insecure override is active, the initial flag is seeded
// from the lookup function's view of the current TLS certificate state; a
// lookup error is logged and treated as "no certificate" (Secure=false) so
// that startup never fails because of policy wiring.
func LoadSessionCookiePolicy(ctx context.Context, insecureOverride bool, lookup TLSCertLookupFunc) *SessionCookiePolicy {
	p := NewSessionCookiePolicy(insecureOverride)
	if !insecureOverride && lookup != nil {
		present, err := lookup(ctx)
		if err != nil {
			slog.Warn("Could not read TLS state for session cookie policy; defaulting Secure=false", "err", err)
		} else {
			p.SetTLSCertPresent(present)
		}
	}
	InstallSessionCookiePolicy(p)
	return p
}
