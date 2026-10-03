package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestAWGConfigAdapterUsesContainerAndRestoresFailedSave(t *testing.T) {
	original := "[Interface]\nPrivateKey = fixture-key\nAddress = 192.0.2.1/24\nListenPort = 51820\nTable = off\n"
	current := original
	uploads := map[string][]byte{}
	syncFailures := 0
	hostWrites := 0
	mock := &testMockSSHClient{}
	mock.cmdFunc = func(_ context.Context, cmd string) (string, string, int, error) {
		switch {
		case strings.Contains(cmd, "docker ps"):
			return "amnezia-awg2", "", 0, nil
		case strings.Contains(cmd, "docker inspect"):
			return "container-fixture", "", 0, nil
		case strings.Contains(cmd, "docker exec") && strings.Contains(cmd, " cat ") && strings.Contains(cmd, "awg0.conf"):
			return current, "", 0, nil
		case strings.HasPrefix(cmd, "cat ") && strings.Contains(cmd, "awg0.conf"):
			return "", "missing host file", 1, errors.New("host configuration absent")
		case strings.Contains(cmd, "docker cp") && strings.Contains(cmd, "_amnz_edit_config"):
			for path, data := range uploads {
				if strings.Contains(cmd, path) {
					current = string(data)
					return "", "", 0, nil
				}
			}
			return "", "missing temporary upload", 1, errors.New("missing temporary upload")
		case strings.Contains(cmd, "syncconf"):
			if syncFailures > 0 {
				syncFailures--
				return "", "fixture sync failure", 1, errors.New("fixture sync failure")
			}
			return "", "", 0, nil
		default:
			return "", "", 0, nil
		}
	}
	mock.uploadFn = func(_ context.Context, path string, p []byte) error {
		if !strings.Contains(path, "_amnz_edit_config") {
			hostWrites++
		}
		uploads[path] = append([]byte(nil), p...)
		return nil
	}
	h, db, _ := setupTestHandlersWithMockSSH(t, mock)
	id, err := db.CreateServer(t.Context(), &models.Server{Name: "config-fixture", Host: "192.0.2.20", SSHUser: "fixture", Protocols: map[string]any{"awg": map[string]any{"installed": true}}})
	if err != nil {
		t.Fatal(err)
	}
	r := setupFullServerRouter(h)
	request := func(action string, payload any) *httptest.ResponseRecorder {
		t.Helper()
		body, _ := json.Marshal(payload)
		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/servers/%d/server_config%s", id, action), bytes.NewReader(body))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}
	read := request("", map[string]any{"protocol": "awg"})
	var got map[string]any
	_ = json.Unmarshal(read.Body.Bytes(), &got)
	if read.Code != 200 || got["config"] != original {
		t.Errorf("provisioned container config unavailable: status=%d body=%v", read.Code, got)
	}
	modified := strings.ReplaceAll(original, "51820", "51821")
	save := request("/save", map[string]any{"protocol": "awg", "config": modified})
	if save.Code != 200 || current != modified || hostWrites != 0 {
		t.Errorf("save missed actual container: status=%d changed=%v hostWrites=%d", save.Code, current == modified, hostWrites)
	}
	restore := request("/save", map[string]any{"protocol": "awg", "config": original})
	if restore.Code != 200 || current != original {
		t.Fatal("fixture restoration failed")
	}
	syncFailures = 2 // first attempt and retry fail; rollback synchronization succeeds
	failed := request("/save", map[string]any{"protocol": "awg", "config": modified})
	if failed.Code != 500 || current != original {
		t.Errorf("failed runtime save must report failure and restore prior config: status=%d restored=%v", failed.Code, current == original)
	}
}
