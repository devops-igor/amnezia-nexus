package vpn

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestQualificationSubject_LifecycleAndConfigFreezing(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "panel_test.db")
	configPath := filepath.Join(tempDir, "frozen-client.conf")
	readyPath := filepath.Join(tempDir, "subject.ready")

	// Allocate a free ephemeral port for testing
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen ephemeral udp: %v", err)
	}
	listenPort := socket.LocalAddr().(*net.UDPAddr).Port
	_ = socket.Close()

	cfg := QualificationSubjectConfig{
		DBPath:           dbPath,
		FrozenConfigPath: configPath,
		ReadyPath:        readyPath,
		ListenPort:       listenPort,
		EchoPort:         40001,
		UnderlayHostIP:   "10.254.250.1",
		DestinationIP:    "10.100.0.1",
	}

	subject, err := NewQualificationSubject(cfg)
	if err != nil {
		t.Fatalf("NewQualificationSubject failed: %v", err)
	}

	// 1. Verify frozen-client.conf was written BEFORE and exists with 0600 permissions
	fi, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("frozen-client.conf stat: %v", err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Errorf("frozen-client.conf permissions = %o, want 0600", fi.Mode().Perm())
	}
	confBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read frozen-client.conf: %v", err)
	}
	confStr := string(confBytes)
	for _, expected := range []string{
		"[Interface]",
		"Address = 10.100.",
		"PrivateKey = ",
		"H1 = ",
		"H2 = ",
		"H3 = ",
		"H4 = ",
		"S1 = 50",
		"S2 = 100",
		"S3 = 150",
		"S4 = 200",
		"HeaderProtectionKey = ",
		"[Peer]",
		"PublicKey = ",
		"Endpoint = 10.254.250.1:",
		"AllowedIPs = 0.0.0.0/0",
	} {
		if !strings.Contains(confStr, expected) {
			t.Errorf("frozen-client.conf missing line/token %q", expected)
		}
	}

	// 2. Verify subject.ready was written and contains valid JSON metadata
	readyBytes, err := os.ReadFile(readyPath)
	if err != nil {
		t.Fatalf("read subject.ready: %v", err)
	}
	var readyMeta map[string]any
	if err := json.Unmarshal(readyBytes, &readyMeta); err != nil {
		t.Fatalf("unmarshal subject.ready: %v", err)
	}
	if readyMeta["status"] != "ready" {
		t.Errorf("ready status = %v, want ready", readyMeta["status"])
	}
	if int(readyMeta["listen_port"].(float64)) != listenPort {
		t.Errorf("ready listen_port = %v, want %d", readyMeta["listen_port"], listenPort)
	}

	// 3. Verify component accessors
	if subject.DB() == nil {
		t.Error("subject.DB() returned nil")
	}
	if subject.Service() == nil {
		t.Error("subject.Service() returned nil")
	}
	if subject.Engine() == nil {
		t.Error("subject.Engine() returned nil")
	}

	// 4. Clean shutdown and idempotence
	if err := subject.Stop(); err != nil {
		t.Fatalf("subject.Stop() failed: %v", err)
	}
	if _, err := os.Stat(readyPath); !os.IsNotExist(err) {
		t.Errorf("subject.ready should have been removed on stop, err: %v", err)
	}
	// Verify double stop is idempotent
	if err := subject.Stop(); err != nil {
		t.Errorf("second subject.Stop() returned error: %v", err)
	}
}
