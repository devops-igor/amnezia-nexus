package notifications

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestValidateEndpoint(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{name: "public https", raw: "https://gotify.example.com", wantErr: false},
		{name: "https with path", raw: "https://example.com/gotify", wantErr: false},
		{name: "loopback http for tests", raw: "http://127.0.0.1:8080", wantErr: false},
		{name: "localhost http for tests", raw: "http://localhost:8080", wantErr: false},
		{name: "plain http public host", raw: "http://gotify.example.com", wantErr: true},
		{name: "file scheme", raw: "file:///etc/passwd", wantErr: true},
		{name: "embedded credentials", raw: "https://user:pass@example.com", wantErr: true},
		{name: "query string", raw: "https://example.com?token=secret", wantErr: true},
		{name: "fragment", raw: "https://example.com/#fragment", wantErr: true},
		{name: "metadata link-local", raw: "https://169.254.169.254", wantErr: true},
		{name: "unspecified address", raw: "https://0.0.0.0", wantErr: true},
		{name: "multicast address", raw: "https://224.0.0.1", wantErr: true},
		{name: "empty", raw: "", wantErr: true},
		{name: "missing host", raw: "https://", wantErr: true},
		{name: "invalid escape", raw: "https://exa%mple.com", wantErr: true},
		{name: "localhost https", raw: "https://localhost", wantErr: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ValidateEndpoint(tc.raw)
			if tc.wantErr && err == nil {
				t.Fatalf("ValidateEndpoint(%q) accepted the destination", tc.raw)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("ValidateEndpoint(%q) error: %v", tc.raw, err)
			}
		})
	}
}

func TestCheckDialIPRejectsUnsafeAddresses(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		host string
		ok   bool
	}{
		{name: "public", ip: "198.51.100.10", host: "gotify.example.com", ok: true},
		{name: "private allowed", ip: "10.0.0.5", host: "gotify.internal", ok: true},
		{name: "loopback literal", ip: "127.0.0.1", host: "127.0.0.1", ok: true},
		{name: "loopback from hostname", ip: "127.0.0.1", host: "rebind.example.com", ok: false},
		{name: "unspecified", ip: "0.0.0.0", host: "0.0.0.0", ok: false},
		{name: "multicast", ip: "224.0.0.1", host: "224.0.0.1", ok: false},
		{name: "link-local", ip: "169.254.169.254", host: "169.254.169.254", ok: false},
		{name: "ipv6 link-local", ip: "fe80::1", host: "fe80::1", ok: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := checkDialIP(net.ParseIP(tc.ip), tc.host)
			if tc.ok && err != nil {
				t.Fatalf("checkDialIP rejected: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("checkDialIP accepted %s", tc.ip)
			}
		})
	}
}

func TestSafeDialContextRefusesUnsafeResolutions(t *testing.T) {
	ctx := context.Background()
	if _, err := safeDialContext(ctx, "tcp", "missing-port"); err == nil {
		t.Fatal("address without a port was accepted")
	}
	if _, err := safeDialContext(ctx, "tcp", "169.254.169.254:80"); err == nil {
		t.Fatal("link-local address was dialed")
	}
	if _, err := safeDialContext(ctx, "tcp", "224.0.0.1:80"); err == nil {
		t.Fatal("multicast address was dialed")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(server.Close)
	address := strings.TrimPrefix(server.URL, "http://")
	conn, err := safeDialContext(ctx, "tcp", address)
	if err != nil {
		t.Fatalf("loopback receiver was refused: %v", err)
	}
	_ = conn.Close()
}

func TestConnectionVerifiesEndpointAndToken(t *testing.T) {
	var gotToken, gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.Header.Get("X-Gotify-Key")
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	client := NewClient()
	if err := client.TestConnection(context.Background(), server.URL, "token"); err != nil {
		t.Fatalf("test connection: %v", err)
	}
	if gotPath != "/version" || gotToken != "token" {
		t.Fatalf("path=%q token=%q", gotPath, gotToken)
	}
	if err := client.TestConnection(context.Background(), server.URL, ""); err == nil {
		t.Fatal("empty token was accepted")
	}
	if err := client.TestConnection(context.Background(), "http://example.com", "token"); err == nil {
		t.Fatal("unsafe endpoint was accepted")
	}
}

func TestConnectionReportsNon2xx(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("bad token"))
	}))
	t.Cleanup(server.Close)
	err := NewClient().TestConnection(context.Background(), server.URL, "token")
	if err == nil {
		t.Fatal("non-2xx response was accepted")
	}
	var statusErr *HTTPStatusError
	if !errors.As(err, &statusErr) || statusErr.Status != http.StatusUnauthorized {
		t.Fatalf("error = %v, want HTTPStatusError 401", err)
	}
}

func TestSendUsesHeaderTokenAndRedactsItFromPayload(t *testing.T) {
	var gotToken, gotPath string
	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.Header.Get("X-Gotify-Key")
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	client := NewClient()
	status, err := client.Send(context.Background(), server.URL, "top-secret", Message{
		Title:    "Token top-secret leaked into title",
		Body:     "body top-secret",
		Priority: Priority(models.NotificationSeverityCritical),
	})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	if gotPath != "/message" {
		t.Fatalf("path = %q, want /message", gotPath)
	}
	if gotToken != "top-secret" {
		t.Fatalf("X-Gotify-Key = %q", gotToken)
	}
	title, _ := gotBody["title"].(string)
	body, _ := gotBody["message"].(string)
	if strings.Contains(title, "top-secret") || strings.Contains(body, "top-secret") {
		t.Fatalf("token leaked into payload: title=%q body=%q", title, body)
	}
	if gotBody["priority"] != float64(8) {
		t.Fatalf("priority = %v, want 8", gotBody["priority"])
	}
}

func TestSendRefusesRedirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("redirect target received the notification")
	}))
	t.Cleanup(target.Close)
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(redirector.Close)

	client := NewClient()
	if _, err := client.Send(context.Background(), redirector.URL, "token", Message{Title: "t", Body: "b"}); err == nil {
		t.Fatal("redirect was followed")
	}
}

func TestHTTPStatusErrorClassification(t *testing.T) {
	tests := []struct {
		status    int
		permanent bool
	}{
		{status: http.StatusBadRequest, permanent: true},
		{status: http.StatusUnauthorized, permanent: true},
		{status: http.StatusTooManyRequests, permanent: false},
		{status: http.StatusRequestTimeout, permanent: false},
		{status: http.StatusInternalServerError, permanent: false},
		{status: http.StatusBadGateway, permanent: false},
	}
	for _, tc := range tests {
		err := &HTTPStatusError{Status: tc.status}
		if got := IsPermanent(err); got != tc.permanent {
			t.Fatalf("IsPermanent(%d) = %v, want %v", tc.status, got, tc.permanent)
		}
		if StatusCode(err) != tc.status {
			t.Fatalf("StatusCode(%d) = %d", tc.status, StatusCode(err))
		}
	}
}
