package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/manager/naive"
	"github.com/devops-igor/amnezia-nexus/internal/manager/xray"
	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

const testXrayConfig = `{"log":{"loglevel":"none"},"inbounds":[],"outbounds":[]}`

const testNaiveConfig = `{
    admin 127.0.0.1:2019
}

:443, naive.example.com {
    route {
        root * /srv
        file_server
    }
}
`

func testRawConfigForProtocol(protocol string) string {
	switch protocol {
	case models.ProtocolVLESS:
		return testXrayConfig
	case models.ProtocolNaive:
		return testNaiveConfig
	default:
		return "raw config"
	}
}

func enableRawConfigManagers(h *Handlers) {
	h.xrayMgr = xray.NewXrayManager(h.sshPool)
	h.naiveMgr = naive.NewNaiveManager(h.sshPool)
}

type configApplyMock struct {
	client    *testMockSSHClient
	files     map[string][]byte
	uploads   int
	downloads int
	applies   int
}

func newConfigApplyMock(path, initialContent, applyMarker string, failFirstApply bool) *configApplyMock {
	state := &configApplyMock{
		client: &testMockSSHClient{},
		files:  map[string][]byte{path: []byte(initialContent)},
	}
	state.client.downloadFn = func(_ context.Context, remotePath string) ([]byte, error) {
		state.downloads++
		content, ok := state.files[remotePath]
		if !ok {
			return nil, os.ErrNotExist
		}
		return append([]byte(nil), content...), nil
	}
	state.client.uploadFn = func(_ context.Context, remotePath string, content []byte) error {
		state.uploads++
		state.files[remotePath] = append([]byte(nil), content...)
		return nil
	}
	state.client.cmdFunc = func(_ context.Context, cmd string) (string, string, int, error) {
		if strings.Contains(cmd, applyMarker) {
			state.applies++
			if failFirstApply && state.applies == 1 {
				return "", "forced apply failure", 1, errors.New("forced apply failure")
			}
		}
		return "", "", 0, nil
	}
	return state
}

func setupServerConfigHandlerTest(t *testing.T, client *testMockSSHClient) (http.Handler, int64) {
	t.Helper()
	h, db, _ := setupTestHandlersWithMockSSH(t, client)
	enableRawConfigManagers(h)
	serverID, err := db.CreateServer(context.Background(), &models.Server{
		Name:      "raw-config-server",
		Host:      "192.0.2.64",
		SSHUser:   "root",
		Protocols: map[string]any{},
	})
	if err != nil {
		t.Fatalf("CreateServer: %v", err)
	}
	return setupFullServerRouter(h), serverID
}

func performServerConfigSave(
	t *testing.T,
	router http.Handler,
	serverID int64,
	protocol string,
	config string,
) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(models.ServerConfigSaveRequest{Protocol: protocol, Config: config})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	path := fmt.Sprintf("/api/servers/%d/server_config/save", serverID)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
		UserID: "config-admin",
		Role:   models.RoleAdmin,
	}))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func assertServerConfigResponse(t *testing.T, w *httptest.ResponseRecorder, wantStatus int, wantError string) {
	t.Helper()
	if w.Code != wantStatus {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, wantStatus, w.Body.String())
	}
	if wantError == "" {
		return
	}
	var response struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if response.Error != wantError {
		t.Errorf("error = %q, want %q", response.Error, wantError)
	}
}

func TestSaveServerConfigHandlerXrayRestartsContainer(t *testing.T) {
	const original = `{"inbounds":[{"port":443}],"outbounds":[]}`
	remote := newConfigApplyMock(xray.XrayConfigPath, original, "docker restart", false)
	router, serverID := setupServerConfigHandlerTest(t, remote.client)

	w := performServerConfigSave(t, router, serverID, models.ProtocolVLESS, testXrayConfig)

	assertServerConfigResponse(t, w, http.StatusOK, "")
	if remote.applies != 1 {
		t.Errorf("xray restarts = %d, want 1", remote.applies)
	}
	if got := string(remote.files[xray.XrayConfigPath]); got != testXrayConfig {
		t.Errorf("saved config = %q, want %q", got, testXrayConfig)
	}
	if remote.client.uploadSudoMode != 0600 {
		t.Errorf("upload mode = %04o, want 0600", remote.client.uploadSudoMode)
	}
}

func TestSaveServerConfigHandlerRejectsInvalidXrayWithoutRemoteChanges(t *testing.T) {
	const original = `{"inbounds":[],"outbounds":[]}`
	remote := newConfigApplyMock(xray.XrayConfigPath, original, "docker restart", false)
	router, serverID := setupServerConfigHandlerTest(t, remote.client)

	w := performServerConfigSave(t, router, serverID, models.ProtocolVLESS, `{"inbounds":`)

	assertServerConfigResponse(t, w, http.StatusBadRequest, "validation_failed")
	if remote.uploads != 0 || remote.downloads != 0 || remote.applies != 0 {
		t.Errorf("invalid config caused remote operations: uploads=%d downloads=%d restarts=%d",
			remote.uploads, remote.downloads, remote.applies)
	}
	if got := string(remote.files[xray.XrayConfigPath]); got != original {
		t.Errorf("config changed to %q, want original %q", got, original)
	}
}

func TestSaveServerConfigHandlerXrayRestartFailureRollsBack(t *testing.T) {
	const original = `{"inbounds":[{"port":443}],"outbounds":[]}`
	remote := newConfigApplyMock(xray.XrayConfigPath, original, "docker restart", true)
	router, serverID := setupServerConfigHandlerTest(t, remote.client)

	w := performServerConfigSave(t, router, serverID, models.ProtocolVLESS, testXrayConfig)

	assertServerConfigResponse(t, w, http.StatusInternalServerError, "apply_failed")
	if remote.applies != 2 {
		t.Errorf("xray restarts = %d, want failed apply plus recovery", remote.applies)
	}
	if remote.uploads != 2 {
		t.Errorf("uploads = %d, want new config plus rollback", remote.uploads)
	}
	if got := string(remote.files[xray.XrayConfigPath]); got != original {
		t.Errorf("rolled-back config = %q, want original %q", got, original)
	}
}

func TestSaveServerConfigHandlerNaiveReloadsCaddy(t *testing.T) {
	remote := newConfigApplyMock(naive.NaiveCaddyfilePath, testNaiveConfig, "caddy reload", false)
	router, serverID := setupServerConfigHandlerTest(t, remote.client)
	updated := strings.Replace(testNaiveConfig, "naive.example.com", "new.example.com", 1)

	w := performServerConfigSave(t, router, serverID, models.ProtocolNaive, updated)

	assertServerConfigResponse(t, w, http.StatusOK, "")
	if remote.applies != 1 {
		t.Errorf("caddy reloads = %d, want 1", remote.applies)
	}
	if got := string(remote.files[naive.NaiveCaddyfilePath]); got != updated {
		t.Errorf("saved Caddyfile = %q, want %q", got, updated)
	}
	if remote.client.uploadSudoMode != 0600 {
		t.Errorf("upload mode = %04o, want 0600", remote.client.uploadSudoMode)
	}
}

func TestSaveServerConfigHandlerRejectsInvalidCaddyfileWithoutRemoteChanges(t *testing.T) {
	remote := newConfigApplyMock(naive.NaiveCaddyfilePath, testNaiveConfig, "caddy reload", false)
	router, serverID := setupServerConfigHandlerTest(t, remote.client)

	w := performServerConfigSave(t, router, serverID, models.ProtocolNaive, ":443 {\n route {\n")

	assertServerConfigResponse(t, w, http.StatusBadRequest, "validation_failed")
	if remote.uploads != 0 || remote.downloads != 0 || remote.applies != 0 {
		t.Errorf("invalid config caused remote operations: uploads=%d downloads=%d reloads=%d",
			remote.uploads, remote.downloads, remote.applies)
	}
	if got := string(remote.files[naive.NaiveCaddyfilePath]); got != testNaiveConfig {
		t.Errorf("Caddyfile changed to %q, want original %q", got, testNaiveConfig)
	}
}

func TestSaveServerConfigHandlerCaddyReloadFailureRollsBack(t *testing.T) {
	remote := newConfigApplyMock(naive.NaiveCaddyfilePath, testNaiveConfig, "caddy reload", true)
	router, serverID := setupServerConfigHandlerTest(t, remote.client)
	updated := strings.Replace(testNaiveConfig, "naive.example.com", "new.example.com", 1)

	w := performServerConfigSave(t, router, serverID, models.ProtocolNaive, updated)

	assertServerConfigResponse(t, w, http.StatusInternalServerError, "apply_failed")
	if remote.applies != 2 {
		t.Errorf("caddy reloads = %d, want failed apply plus recovery", remote.applies)
	}
	if remote.uploads != 2 {
		t.Errorf("uploads = %d, want new config plus rollback", remote.uploads)
	}
	if got := string(remote.files[naive.NaiveCaddyfilePath]); got != testNaiveConfig {
		t.Errorf("rolled-back Caddyfile = %q, want original %q", got, testNaiveConfig)
	}
}
