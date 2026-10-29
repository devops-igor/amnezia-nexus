package xray

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestXrayManager_ClientOpsPreserveCustomConfig(t *testing.T) {
	mock := newMockXraySSHClient()
	mgr := NewXrayManager(&mockXrayPool{client: mock})
	server := &models.Server{ID: 636, Host: "192.0.2.36", SSHPort: 22}
	ctx := context.Background()

	// Operator-edited config: unmodeled top-level blocks, inbound sniffing, custom client field.
	seedXrayConfig(t, mock)
	var cfg map[string]any
	if err := json.Unmarshal(mock.files[XrayConfigPath], &cfg); err != nil {
		t.Fatal(err)
	}
	cfg["routing"] = map[string]any{"rules": []any{map[string]any{"type": "field", "outboundTag": "block", "ip": []any{"geoip:private"}}}}
	cfg["dns"] = map[string]any{"servers": []any{"1.1.1.1"}, "queryStrategy": "UseIPv4", "tag": "custom-dns"}
	cfg["policy"] = map[string]any{"levels": map[string]any{"0": map[string]any{"handshake": 4}}}
	inbound := cfg["inbounds"].([]any)[0].(map[string]any)
	inbound["sniffing"] = map[string]any{"enabled": true, "destOverride": []any{"http", "tls"}}
	settings := inbound["settings"].(map[string]any)
	settings["clients"] = []any{map[string]any{"id": "11111111-1111-1111-1111-111111111111", "email": "legacy", "level": 7}}
	seeded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	mock.files[XrayConfigPath] = seeded

	assertPreserved := func(stage string, wantClients int) map[string]any {
		t.Helper()
		var got map[string]any
		if err := json.Unmarshal(mock.files[XrayConfigPath], &got); err != nil {
			t.Fatalf("%s: invalid JSON: %v", stage, err)
		}
		for _, key := range []string{"routing", "dns", "policy"} {
			want, _ := json.Marshal(cfg[key])
			have, _ := json.Marshal(got[key])
			if string(want) != string(have) {
				t.Errorf("%s: %s changed:\n got %s\nwant %s", stage, key, have, want)
			}
		}
		in := got["inbounds"].([]any)[0].(map[string]any)
		wantSniff, _ := json.Marshal(inbound["sniffing"])
		haveSniff, _ := json.Marshal(in["sniffing"])
		if string(wantSniff) != string(haveSniff) {
			t.Errorf("%s: sniffing changed: got %s want %s", stage, haveSniff, wantSniff)
		}
		clients := in["settings"].(map[string]any)["clients"].([]any)
		if len(clients) != wantClients {
			t.Fatalf("%s: clients = %d, want %d", stage, len(clients), wantClients)
		}
		if legacy := clients[0].(map[string]any); legacy["level"] != float64(7) {
			t.Errorf("%s: legacy client custom field lost: %v", stage, legacy)
		}
		return in
	}

	added, err := mgr.AddClient(ctx, server, map[string]any{"name": "phone"})
	if err != nil {
		t.Fatalf("AddClient: %v", err)
	}
	clientID, _ := added["client_id"].(string)
	in := assertPreserved("after add", 2)
	if id := in["settings"].(map[string]any)["clients"].([]any)[1].(map[string]any)["id"]; id != clientID {
		t.Errorf("new client id = %v, want %s", id, clientID)
	}

	if err := mgr.RemoveClient(ctx, server, clientID); err != nil {
		t.Fatalf("RemoveClient: %v", err)
	}
	assertPreserved("after remove", 1)
}
