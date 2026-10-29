package naive

import (
	"context"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

const customCaddyfile = `{
    admin 127.0.0.1:2019
}

# operator comment
:443, vpn.example.com {
    header {
        Strict-Transport-Security "max-age=31536000"
        -Server
    }
    route {
        forward_proxy {
            basic_auth alice secret-a
            hide_ip
            hide_via
            probe_resistance
        }
        reverse_proxy /api/* 127.0.0.1:9000 {
            header_up X-Real-IP {remote_host}
        }
        root * /srv
        file_server
    }
}
`

var customDirectives = []string{
	"# operator comment",
	"Strict-Transport-Security \"max-age=31536000\"",
	"-Server",
	"reverse_proxy /api/* 127.0.0.1:9000 {",
	"header_up X-Real-IP {remote_host}",
	"root * /srv",
	"hide_ip",
	"probe_resistance",
}

func requireContains(t *testing.T, stage, content string, want []string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(content, w) {
			t.Errorf("%s: lost %q in:\n%s", stage, w, content)
		}
	}
}

func TestNaiveManager_ClientOpsPreserveCustomCaddyfile(t *testing.T) {
	mock := newMockNaiveSSHClient()
	mgr := NewNaiveManager(&mockNaivePool{client: mock})
	server := &models.Server{ID: 636, Host: "198.51.100.36", SSHPort: 22}
	ctx := context.Background()
	mock.files[NaiveCaddyfilePath] = []byte(customCaddyfile)

	if _, err := mgr.AddClient(ctx, server, map[string]any{"username": "bob", "password": "secret-b"}); err != nil {
		t.Fatalf("AddClient: %v", err)
	}
	got := string(mock.files[NaiveCaddyfilePath])
	requireContains(t, "after add", got, customDirectives)
	requireContains(t, "after add", got, []string{"basic_auth alice secret-a", "basic_auth bob secret-b"})

	if err := mgr.RemoveClient(ctx, server, "alice"); err != nil {
		t.Fatalf("RemoveClient alice: %v", err)
	}
	got = string(mock.files[NaiveCaddyfilePath])
	requireContains(t, "after remove", got, customDirectives)
	requireContains(t, "after remove", got, []string{"basic_auth bob secret-b"})
	if strings.Contains(got, "alice") {
		t.Errorf("alice not removed:\n%s", got)
	}

	// Removing the last client must drop the auth-less forward_proxy block (open proxy) but keep the rest.
	if err := mgr.RemoveClient(ctx, server, "bob"); err != nil {
		t.Fatalf("RemoveClient bob: %v", err)
	}
	got = string(mock.files[NaiveCaddyfilePath])
	requireContains(t, "after last remove", got, []string{"# operator comment", "-Server", "reverse_proxy /api/*", "root * /srv"})
	if strings.Contains(got, "forward_proxy") || strings.Contains(got, "basic_auth") {
		t.Errorf("forward_proxy block should be removed with last client:\n%s", got)
	}

	// Adding to a zero-client Caddyfile recreates forward_proxy ahead of file_server.
	if _, err := mgr.AddClient(ctx, server, map[string]any{"username": "carol", "password": "secret-c"}); err != nil {
		t.Fatalf("AddClient carol: %v", err)
	}
	got = string(mock.files[NaiveCaddyfilePath])
	requireContains(t, "after re-add", got, []string{"# operator comment", "-Server", "basic_auth carol secret-c", "probe_resistance"})
	if strings.Index(got, "forward_proxy") > strings.Index(got, "file_server") {
		t.Errorf("forward_proxy must precede file_server:\n%s", got)
	}
	if _, _, clients, err := ParseCaddyfile(got); err != nil || len(clients) != 1 {
		t.Errorf("ParseCaddyfile after re-add: clients=%v err=%v", clients, err)
	}
}
