package middleware

import (
	"context"
	"net/http"
	"strings"
	"time"
)

const (
	// DefaultRequestTimeout is the baseline request context timeout for standard routes.
	DefaultRequestTimeout = 60 * time.Second

	// InstallRequestTimeout is the context timeout for protocol installation operations.
	InstallRequestTimeout = 15 * time.Minute

	// UninstallRequestTimeout is the context timeout for protocol uninstallation operations.
	UninstallRequestTimeout = 5 * time.Minute
)

// RequestTimeout returns the configured timeout duration based on the request URL path.
// - Routes ending in /install receive InstallRequestTimeout (15 minutes).
// - Routes ending in /uninstall receive UninstallRequestTimeout (5 minutes).
// - All other routes receive defaultTimeout (or DefaultRequestTimeout if defaultTimeout <= 0).
func RequestTimeout(path string, defaultTimeout time.Duration) time.Duration {
	if defaultTimeout <= 0 {
		defaultTimeout = DefaultRequestTimeout
	}
	trimmed := strings.TrimRight(path, "/")
	if strings.HasSuffix(trimmed, "/install") {
		return InstallRequestTimeout
	}
	if strings.HasSuffix(trimmed, "/uninstall") {
		return UninstallRequestTimeout
	}
	return defaultTimeout
}

// OperationTimeout returns an HTTP middleware that applies an operation-aware context timeout.
// Protocol install and uninstall routes receive extended budgets (15m and 5m), while
// standard routes retain defaultTimeout (or 60s). Client disconnection cancellation is
// preserved through standard context inheritance.
func OperationTimeout(defaultTimeout time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path := r.URL.Path
			if path == "" && r.URL.RawPath != "" {
				path = r.URL.RawPath
			}
			timeout := RequestTimeout(path, defaultTimeout)
			ctx, cancel := context.WithTimeout(r.Context(), timeout)
			defer func() {
				cancel()
				if ctx.Err() == context.DeadlineExceeded {
					w.WriteHeader(http.StatusGatewayTimeout)
				}
			}()

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
