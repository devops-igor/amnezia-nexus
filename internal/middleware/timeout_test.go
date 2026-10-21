package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRequestTimeout(t *testing.T) {
	tests := []struct {
		name           string
		path           string
		defaultTimeout time.Duration
		expected       time.Duration
	}{
		{
			name:           "api server install",
			path:           "/api/servers/1/install",
			defaultTimeout: 60 * time.Second,
			expected:       15 * time.Minute,
		},
		{
			name:           "api server install trailing slash",
			path:           "/api/servers/1/install/",
			defaultTimeout: 60 * time.Second,
			expected:       15 * time.Minute,
		},
		{
			name:           "legacy server install",
			path:           "/1/install",
			defaultTimeout: 60 * time.Second,
			expected:       15 * time.Minute,
		},
		{
			name:           "bare install path",
			path:           "/install",
			defaultTimeout: 60 * time.Second,
			expected:       15 * time.Minute,
		},
		{
			name:           "api server uninstall",
			path:           "/api/servers/1/uninstall",
			defaultTimeout: 60 * time.Second,
			expected:       5 * time.Minute,
		},
		{
			name:           "api server uninstall trailing slash",
			path:           "/api/servers/1/uninstall/",
			defaultTimeout: 60 * time.Second,
			expected:       5 * time.Minute,
		},
		{
			name:           "legacy server uninstall",
			path:           "/1/uninstall",
			defaultTimeout: 60 * time.Second,
			expected:       5 * time.Minute,
		},
		{
			name:           "bare uninstall path",
			path:           "/uninstall",
			defaultTimeout: 60 * time.Second,
			expected:       5 * time.Minute,
		},
		{
			name:           "standard health route",
			path:           "/api/health",
			defaultTimeout: 60 * time.Second,
			expected:       60 * time.Second,
		},
		{
			name:           "standard server reboot route",
			path:           "/api/servers/1/reboot",
			defaultTimeout: 60 * time.Second,
			expected:       60 * time.Second,
		},
		{
			name:           "install suffix with extra segment does not match",
			path:           "/api/servers/1/install/progress",
			defaultTimeout: 60 * time.Second,
			expected:       60 * time.Second,
		},
		{
			name:           "prefix with install in word does not match",
			path:           "/api/servers/1/preinstall",
			defaultTimeout: 60 * time.Second,
			expected:       60 * time.Second,
		},
		{
			name:           "root path",
			path:           "/",
			defaultTimeout: 60 * time.Second,
			expected:       60 * time.Second,
		},
		{
			name:           "empty path",
			path:           "",
			defaultTimeout: 60 * time.Second,
			expected:       60 * time.Second,
		},
		{
			name:           "custom default timeout",
			path:           "/api/health",
			defaultTimeout: 45 * time.Second,
			expected:       45 * time.Second,
		},
		{
			name:           "zero default timeout falls back to 60s",
			path:           "/api/health",
			defaultTimeout: 0,
			expected:       60 * time.Second,
		},
		{
			name:           "negative default timeout falls back to 60s",
			path:           "/api/health",
			defaultTimeout: -5 * time.Second,
			expected:       60 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RequestTimeout(tt.path, tt.defaultTimeout)
			if got != tt.expected {
				t.Errorf("RequestTimeout(%q, %v) = %v, expected %v", tt.path, tt.defaultTimeout, got, tt.expected)
			}
		})
	}
}

func TestOperationTimeout_Deadlines(t *testing.T) {
	mw := OperationTimeout(60 * time.Second)

	tests := []struct {
		name     string
		path     string
		minBound time.Duration
		maxBound time.Duration
	}{
		{
			name:     "install gets 15m",
			path:     "/api/servers/1/install",
			minBound: 14 * time.Minute,
			maxBound: 16 * time.Minute,
		},
		{
			name:     "uninstall gets 5m",
			path:     "/api/servers/1/uninstall",
			minBound: 4 * time.Minute,
			maxBound: 6 * time.Minute,
		},
		{
			name:     "standard route gets 60s",
			path:     "/api/servers/1/reboot",
			minBound: 55 * time.Second,
			maxBound: 65 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedDeadline time.Time
			var hasDeadline bool

			handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capturedDeadline, hasDeadline = r.Context().Deadline()
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(http.MethodPost, tt.path, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if !hasDeadline {
				t.Fatal("expected request context to have a deadline")
			}
			remaining := time.Until(capturedDeadline)
			if remaining < tt.minBound || remaining > tt.maxBound {
				t.Fatalf("expected deadline remaining between %v and %v, got %v", tt.minBound, tt.maxBound, remaining)
			}
		})
	}
}

func TestOperationTimeout_Cancellation(t *testing.T) {
	mw := OperationTimeout(60 * time.Second)
	canceled := make(chan struct{})

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			if r.Context().Err() == context.Canceled {
				close(canceled)
			}
			w.WriteHeader(http.StatusRequestTimeout)
		case <-time.After(2 * time.Second):
			w.WriteHeader(http.StatusOK)
		}
	}))

	reqCtx, reqCancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodPost, "/api/servers/1/install", nil).WithContext(reqCtx)
	rec := httptest.NewRecorder()

	go func() {
		time.Sleep(50 * time.Millisecond)
		reqCancel()
	}()

	handler.ServeHTTP(rec, req)

	select {
	case <-canceled:
	case <-time.After(3 * time.Second):
		t.Fatal("expected handler context to be canceled when client canceled request")
	}
}

func TestOperationTimeout_DeadlineExceeded(t *testing.T) {
	mw := OperationTimeout(20 * time.Millisecond)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusGatewayTimeout {
		t.Fatalf("expected 504 Gateway Timeout when deadline exceeded, got %d", rec.Code)
	}
}
