package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/go-chi/chi/v5"
	gossh "golang.org/x/crypto/ssh"
)

func TestServerCheckHandler_ColdAndWarmAbsenceNotMeasured(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()
	config := &gossh.ServerConfig{PasswordCallback: func(gossh.ConnMetadata, []byte) (*gossh.Permissions, error) { return nil, nil }}
	config.AddHostKey(newHandshakeSigner(t))
	var commands atomic.Int32
	host, port := startHandshakeServerOn(t, "127.0.0.1", config, &commands)
	var refused map[string]any
	for _, warm := range []bool{false, true} {
		name := "cold"
		if warm {
			name = "warm"
		}
		t.Run(name, func(t *testing.T) {
			id, err := db.CreateServer(ctx, &models.Server{Name: name, Host: host, SSHPort: port, SSHUser: "root", SSHPass: "pass", Protocols: map[string]any{"awg": map[string]any{"installed": true, "port": "12345"}}})
			if err != nil {
				t.Fatal(err)
			}
			if err := db.UpdateServerReachability(ctx, id, models.ReachabilityOffline); err != nil {
				t.Fatal(err)
			}
			row, err := db.GetServer(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			if warm {
				if _, err := h.GetSSHClient(ctx, row); err != nil {
					t.Fatal(err)
				}
			}
			if err := db.SetServerProviderAbsence(ctx, id, time.Now().UTC(), ""); err != nil {
				t.Fatal(err)
			}
			before, err := db.GetServer(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			attempts := commands.Load()
			body := callServerCheck(t, h, id)
			if body["not_measured"] != true || body["provider_absent"] != true || body["status"] != models.ProviderAbsentStatus {
				t.Errorf("refusal = %v", body)
			}
			for _, key := range []string{"connection", "docker_installed", "protocols"} {
				if _, exists := body[key]; exists {
					t.Errorf("refusal contains measurement %q", key)
				}
			}
			if refused == nil {
				refused = body
			} else if !reflect.DeepEqual(refused, body) {
				t.Errorf("warm/cold responses differ: %v vs %v", refused, body)
			}
			if commands.Load() != attempts {
				t.Error("absent check opened an SSH session")
			}
			after, err := db.GetServer(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, after) {
				t.Error("refusal changed row, credentials, protocols or prior observation")
			}
			// A listed control in both runs must still acquire and attempt commands.
			if err := db.SetServerProviderAbsence(ctx, id, time.Time{}, ""); err != nil {
				t.Fatal(err)
			}
			body = callServerCheck(t, h, id)
			if body["connection"] != "ok" || body["not_measured"] == true {
				t.Errorf("live control = %v", body)
			}
			if commands.Load() <= attempts {
				t.Error("live control attempted no commands")
			}
		})
	}
}

func TestServerCheckHandler_AbsenceDuringOperationPreservesObservation(t *testing.T) {
	client := &testMockSSHClient{}
	h, db, _ := setupTestHandlersWithMockSSH(t, client)
	ctx := context.Background()
	id, err := db.CreateServer(ctx, &models.Server{Name: "listed", Host: "192.0.2.10", SSHPort: 22, SSHUser: "root", SSHPass: "pass"})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateServerReachability(ctx, id, models.ReachabilityOffline); err != nil {
		t.Fatal(err)
	}
	client.cmdFunc = func(context.Context, string) (string, string, int, error) {
		if err := db.SetServerProviderAbsence(ctx, id, time.Now().UTC(), ""); err != nil {
			t.Error(err)
		}
		return "Docker version test", "", 0, nil
	}
	body := callServerCheck(t, h, id)
	if body["not_measured"] != true {
		t.Errorf("late absence recorded a sample: %v", body)
	}
	status, err := db.GetServerStatus(ctx, id)
	if err != nil || status != models.ReachabilityOffline {
		t.Errorf("prior status changed: %s, %v", status, err)
	}
}

func callServerCheck(t *testing.T, h *Handlers, id int64) map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/servers/%d/check", id), nil)
	route := chi.NewRouteContext()
	route.URLParams.Add("server_id", strconv.FormatInt(id, 10))
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, route))
	rec := httptest.NewRecorder()
	h.ServerCheckHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("check status %d: %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body
}
