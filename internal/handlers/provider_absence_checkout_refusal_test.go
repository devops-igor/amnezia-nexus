package handlers

// A refusal raised by the pool itself is a refusal at the caller too: both
// automatic endpoints answer "not measured" rather than a failed connection, and
// a pool that does hand out a client still measures. The row is listed in the
// database, so the handler's own early return cannot be what produces the
// answer: only the error identity coming back from checkout can.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestAutomaticChecks_CheckoutRefusalIsReportedAsNotMeasured(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()
	id, err := db.CreateServer(ctx, &models.Server{
		Name: "listed row, refused checkout", Host: "192.0.2.10", SSHPort: 22, SSHUser: "root", SSHPass: "test-password",
	})
	if err != nil {
		t.Fatalf("seeding the listed server: %v", err)
	}

	h.sshPool = &testMockSSHPool{err: ssh.ErrProviderAbsent}
	check := callServerCheck(t, h, id)
	if check["not_measured"] != true || check["provider_absent"] != true || check["status"] != models.ProviderAbsentStatus {
		t.Fatalf("check on a refused checkout = %v", check)
	}
	for _, key := range []string{"connection", "docker_installed", "protocols"} {
		if _, exists := check[key]; exists {
			t.Errorf("refused checkout reported a measurement %q: %v", key, check)
		}
	}
	stats := callServerStats(t, h, id)
	if stats["not_measured"] != true || stats["provider_absent"] != true {
		t.Fatalf("stats on a refused checkout = %v", stats)
	}
	for _, key := range []string{"cpu", "ram_used", "ram_total", "disk_used", "disk_total", "net_rx", "net_tx", "uptime"} {
		if _, exists := stats[key]; exists {
			t.Errorf("refused checkout reported a fabricated %q sample: %v", key, stats)
		}
	}

	// Live control: the same endpoints with a pool that serves a client measure.
	h.sshPool = &testMockSSHPool{client: &testMockSSHClient{cmdFunc: func(context.Context, string) (string, string, int, error) {
		return "===CPU===\n12.5\n===RAM===\n1000 2000\n===DISK===\n500 4000\n===NET===\n10 20\n===UPTIME===\nup 1 day", "", 0, nil
	}}}
	check = callServerCheck(t, h, id)
	if check["connection"] != "ok" || check["not_measured"] == true {
		t.Fatalf("listed control = %v", check)
	}
	stats = callServerStats(t, h, id)
	if _, measured := stats["cpu"]; !measured || stats["not_measured"] == true {
		t.Fatalf("listed control stats = %v", stats)
	}
}

func callServerStats(t *testing.T, h *Handlers, id int64) map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/servers/%d/stats", id), nil)
	route := chi.NewRouteContext()
	route.URLParams.Add("server_id", strconv.FormatInt(id, 10))
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, route))
	rec := httptest.NewRecorder()
	h.ServerStatsHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("stats status %d: %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body
}
