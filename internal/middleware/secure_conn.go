package middleware

import (
	"context"
	"net/http"
	"strings"
)

// secureConnKey is the context key for the per-request secure-connection flag.
type secureConnKey struct{}

// WithSecureConn stores the per-request secure-connection flag in ctx.
func WithSecureConn(ctx context.Context, secure bool) context.Context {
	return context.WithValue(ctx, secureConnKey{}, secure)
}

// IsSecureConn reports the per-request secure-connection flag. The second
// return value is false when no flag was set (tests, non-HTTP callers), in
// which case callers must fall back to the process-wide cookie policy.
func IsSecureConn(ctx context.Context) (secure, ok bool) {
	if ctx == nil {
		return false, false
	}
	v, ok := ctx.Value(secureConnKey{}).(bool)
	return v, ok
}

// SecureConn creates the middleware deriving the per-request secure-connection flag and
// storing it in the request context. The flag is true when the request arrived
// over TLS directly, OR when the direct peer is a trusted proxy (same trust
// gate as RealIP) and sent X-Forwarded-Proto: https. X-Forwarded-Proto from
// any other peer is ignored. The resolver parameter is kept for API symmetry
// with RealIP; nil means no trusted proxies (only direct TLS counts).
func SecureConn(resolver *RealIPResolver) func(next http.Handler) http.Handler {
	_ = resolver
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			secure := secureFromRequest(r, resolver)
			next.ServeHTTP(w, r.WithContext(WithSecureConn(r.Context(), secure)))
		})
	}
}

// secureFromRequest implements the trust decision: direct TLS wins; otherwise
// X-Forwarded-Proto is honored only from a trusted direct peer.
func secureFromRequest(r *http.Request, resolver *RealIPResolver) bool {
	if r == nil {
		return false
	}
	if r.TLS != nil {
		return true
	}
	if resolver == nil {
		return false
	}
	_, directIP := ExtractIP(r.RemoteAddr)
	if directIP == nil || !resolver.IsTrusted(directIP) {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https")
}
