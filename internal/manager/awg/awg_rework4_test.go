package awg

import (
	"context"
	"encoding/base64"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// Unlike the round-3 command-only fixture, this models the actual container disk:
// config uploads/copies mutate it, reads return it, and stopped containers reject exec.
type rework4Host struct {
	*mockAWGSSHClient
	status     string
	config     string
	runtime    string
	commands   []string
	readErr    bool
	startErr   bool
	inspectErr bool
	listErr    bool
	listOutput string
	runtimeErr bool
	remnants   string
}

func newRework4Host(t *testing.T, status string) *rework4Host {
	t.Helper()
	key, _, err := GenerateWGKeypair()
	if err != nil {
		t.Fatal(err)
	}
	_, pub, err := GenerateWGKeypair()
	if err != nil {
		t.Fatal(err)
	}
	psk, err := GeneratePSK()
	if err != nil {
		t.Fatal(err)
	}
	p, err := GenerateAWGParams("standard", true)
	if err != nil {
		t.Fatal(err)
	}
	conf := RenderServerConfig(key, "192.0.2.1", "24", "51999", "1320", p, []AWGPeer{{PublicKey: pub, PresharedKey: psk, AllowedIPs: "192.0.2.2/32"}})
	conf += "# retained operator comment\n"
	return &rework4Host{mockAWGSSHClient: newMockAWGSSHClient(), status: status, config: conf, runtime: conf}
}

func (h *rework4Host) RunSudoCommand(ctx context.Context, cmd string) (string, string, int, error) {
	h.commands = append(h.commands, cmd)
	switch {
	case strings.Contains(cmd, "find /opt/amnezia"):
		return h.remnants, "", 0, nil
	case strings.Contains(cmd, "docker ps -a"):
		if h.listOutput != "" {
			return h.listOutput, "", 0, nil
		}
		if h.listErr {
			return "", "daemon unavailable", 1, nil
		}
		if h.status == "missing" {
			return "", "", 0, nil
		}
		return "amnezia-awg2\n", "", 0, nil
	case strings.Contains(cmd, "docker inspect"):
		if h.inspectErr {
			return "running", "", 1, nil
		}
		return h.status, "", 0, nil
	case strings.Contains(cmd, "docker cp") && strings.Contains(cmd, "tar -xOf"):
		if h.readErr {
			return "", "read failed", 1, nil
		}
		return h.config, "", 0, nil
	case strings.HasPrefix(cmd, "docker start"):
		if h.startErr {
			return "", "start failed", 1, nil
		}
		h.status = "running"
		return "amnezia-awg2", "", 0, nil
	case strings.Contains(cmd, "showconf awg0"):
		if h.status != "running" || h.runtimeErr {
			return "", "container stopped", 1, nil
		}
		return h.runtime, "", 0, nil
	case strings.Contains(cmd, "docker cp") && strings.Contains(cmd, "_amnz_awg0.conf"):
		h.config = string(h.files["/tmp/_amnz_awg0.conf"])
	case strings.Contains(cmd, "docker run -d"):
		h.status = "running"
	}
	return h.mockAWGSSHClient.defaultRunSudo(cmd)
}

func TestRework4RetryPreservesInstalledState(t *testing.T) {
	for _, state := range []string{"running", "exited", "created"} {
		t.Run(state, func(t *testing.T) {
			h := newRework4Host(t, state)
			before := h.config
			mgr := NewAWGManager(&testAWGSSHProvider{client: h})
			s := &models.Server{ID: 703, Host: "198.51.100.70", Protocols: map[string]any{"awg": map[string]any{"HeaderProtectionKey": "stale"}, "other": "retained"}}
			opts := map[string]any{"reconcile": true, "port": "51820", "awg_profile": "invalid-on-purpose", "server_private_key": "must-not-be-used"}
			for attempt := 0; attempt < 2; attempt++ {
				if err := mgr.Install(context.Background(), s, opts); err != nil {
					t.Fatalf("retry %d: %v", attempt, err)
				}
				if h.config != before {
					t.Fatal("retry replaced saved config, key, wire parameters or peers")
				}
				pub, err := ExtractServerPublicKey(before)
				if err != nil {
					t.Fatal(err)
				}
				meta := s.Protocols["awg"].(map[string]any)
				if meta["public_key"] != pub || meta["port"] != "51999" {
					t.Fatal("metadata did not use actual saved identity/port")
				}
				parsed, _, _ := ParseServerConfig(before)
				wire := meta["awg_params"].(map[string]any)
				for k, v := range parsed {
					if _, ok := wire[k]; ok && wire[k] != v {
						t.Errorf("metadata %s differs from disk", k)
					}
				}
				if s.Protocols["other"] != "retained" {
					t.Fatal("unrelated protocol lost")
				}
			}
			if len(h.files) != 5 { // Only the original mock seed files; no provisioning uploads.
				t.Fatalf("retry uploaded files: %v", reflect.ValueOf(h.files).MapKeys())
			}
			joined := strings.Join(h.commands, "\n")
			for _, forbidden := range []string{"docker run -d", "docker build", "docker restart", "_amnz_awg0.conf", "wireguard_server_private_key.key"} {
				if strings.Contains(joined, forbidden) {
					t.Errorf("retry attempted destructive provisioning: %s", forbidden)
				}
			}
		})
	}
}

func TestRework4LegacyAndShowconfSemantics(t *testing.T) {
	h := newRework4Host(t, "running")
	key := interfacePrivateKey(h.config)
	h.config = "[Interface]\nPrivateKey = " + key + "\nListenPort = 51999\nMTU = 1320\nAddress = 192.0.2.1/24\nTable = off\nJc = 3\nS1 = 5\nS2 = 9\nH1 = 10\nH2 = 20\nH3 = 30\nH4 = 40\n"
	// showconf omits awg-quick fields and may clamp the private scalar.
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		t.Fatal(err)
	}
	raw[0] &= 248
	raw[31] &= 127
	raw[31] |= 64
	h.runtime = strings.ReplaceAll(h.config, key, base64.StdEncoding.EncodeToString(raw))
	for _, line := range []string{"MTU = 1320\n", "Address = 192.0.2.1/24\n", "Table = off\n"} {
		h.runtime = strings.ReplaceAll(h.runtime, line, "")
	}
	s := &models.Server{ID: 703, Host: "198.51.100.70", Protocols: map[string]any{"awg": map[string]any{"HeaderProtectionKey": "stale", "S3": "stale"}}}
	mgr := NewAWGManager(&testAWGSSHProvider{client: h})
	if err := mgr.Install(context.Background(), s, map[string]any{"preserve_identity": true}); err != nil {
		t.Fatal(err)
	}
	meta := s.Protocols["awg"].(map[string]any)
	if _, ok := meta["HeaderProtectionKey"]; ok {
		t.Fatal("stale HP key survived legacy recovery")
	}
	wire := meta["awg_params"].(map[string]any)
	if wire["cookie_reply_packet_junk_size"] != "" || wire["transport_packet_junk_size"] != "" {
		t.Fatal("legacy absent S3/S4 replaced by new-install defaults")
	}
}

func TestRework4MissingContainerRequiresFreshEvidence(t *testing.T) {
	for _, remnants := range []string{"", "/opt/amnezia/awg/awg0.conf"} {
		t.Run(fmt.Sprintf("remnants=%t", remnants != ""), func(t *testing.T) {
			h := newRework4Host(t, "missing")
			h.remnants = remnants
			mgr := NewAWGManager(&testAWGSSHProvider{client: h})
			s := &models.Server{ID: 703, Host: "198.51.100.70"}
			err := mgr.Install(context.Background(), s, map[string]any{"reconcile": true})
			if remnants != "" {
				if err == nil {
					t.Fatal("orphaned identity overwritten")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if h.status != "running" || h.config == "" {
				t.Fatal("fresh installation did not create/configure container")
			}
		})
	}
}

func TestRework4RetryFailsClosed(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*rework4Host)
	}{
		{"list_error", func(h *rework4Host) { h.listErr = true }},
		{"multiple_containers", func(h *rework4Host) { h.listOutput = "amnezia-awg\namnezia-awg2" }},
		{"invalid_container", func(h *rework4Host) { h.listOutput = "unrelated" }},
		{"runtime_error", func(h *rework4Host) { h.runtimeErr = true }},
		{"runtime_empty", func(h *rework4Host) { h.runtime = "" }},
		{"runtime_peer_loss", func(h *rework4Host) { h.runtime = strings.Split(h.runtime, "[Peer]")[0] }},
		{"runtime_key_change", func(h *rework4Host) {
			key, _, _ := GenerateWGKeypair()
			h.runtime = strings.ReplaceAll(h.runtime, interfacePrivateKey(h.runtime), key)
		}},
		{"runtime_wire_change", func(h *rework4Host) { h.runtime = strings.ReplaceAll(h.runtime, "Jc = ", "Jc = 99") }},
		{"unknown_section", func(h *rework4Host) { h.config += "[Unknown]\n" }},
		{"malformed_directive", func(h *rework4Host) { h.config += "invalid\n" }},
		{"bad_psk", func(h *rework4Host) {
			h.config = strings.ReplaceAll(h.config, "PresharedKey = ", "PresharedKey = invalid")
		}},
		{"inspect_error", func(h *rework4Host) { h.inspectErr = true }},
		{"unknown_state", func(h *rework4Host) { h.status = "restarting" }},
		{"read_error", func(h *rework4Host) { h.readErr = true }},
		{"missing_config", func(h *rework4Host) { h.config = "" }},
		{"malformed_key", func(h *rework4Host) {
			h.config = strings.Replace(h.config, interfacePrivateKey(h.config), "invalid", 1)
		}},
		{"duplicate_key", func(h *rework4Host) {
			h.config = strings.Replace(h.config, "[Interface]", "[Interface]\nPrivateKey = invalid", 1)
		}},
		{"missing_port", func(h *rework4Host) { h.config = strings.ReplaceAll(h.config, "ListenPort = 51999", "") }},
		{"bad_peer", func(h *rework4Host) { h.config += "\n[Peer]\nPublicKey = invalid\n" }},
		{"runtime_drift", func(h *rework4Host) {
			h.runtime = strings.ReplaceAll(h.runtime, "ListenPort = 51999", "ListenPort = 52000")
		}},
		{"start_error", func(h *rework4Host) { h.status = "exited"; h.startErr = true }},
		{"missing_existing_container", func(h *rework4Host) { h.status = "missing" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newRework4Host(t, "running")
			tc.mutate(h)
			before := h.config
			mgr := NewAWGManager(&testAWGSSHProvider{client: h})
			s := &models.Server{ID: 703, Host: "198.51.100.70", Protocols: map[string]any{"awg": map[string]any{"public_key": "existing"}}}
			if err := mgr.Install(context.Background(), s, map[string]any{"preserve_containers": true}); err == nil {
				t.Fatal("uncertain retry succeeded")
			}
			if h.config != before {
				t.Fatal("failed retry changed disk")
			}
			if fmt.Sprint(s.Protocols["awg"].(map[string]any)["public_key"]) != "existing" {
				t.Fatal("failed retry committed metadata")
			}
			if _, ok := h.files["/tmp/_amnz_awg0.conf"]; ok {
				t.Fatal("failed retry uploaded replacement")
			}
		})
	}
}
